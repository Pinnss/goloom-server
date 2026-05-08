// Package mobile is the gomobile-friendly entry point for embedding the
// goloom tunnel into Android and iOS apps.
//
// Build:
//
//	gomobile bind -target=android -o build/goloom.aar       ./mobile
//	gomobile bind -target=ios     -o build/Goloom.xcframework ./mobile
//
// Usage from Kotlin (Android):
//
//	val client = Goloom.newClient()
//	client.setSocketProtector(object : SocketProtector { override fun protect(fd: Long) = vpnService.protect(fd.toInt()) })
//	val ipsJSON = client.connect("goloom://...", "127.0.0.1:51820")
//	// pass ipsJSON to VpnService.Builder.addDisallowedApplication / addRoute split-tunnel logic
//
// Usage from Swift (iOS):
//
//	let client = MobileNewClient()
//	let ipsJSON = client?.connect("goloom://...", listenAddr: "127.0.0.1:51820", error: ...)
//	// pass ipsJSON to NEPacketTunnelNetworkSettings excluded routes
//
// Constraints: gomobile only accepts basic types (string, int, bool, []byte,
// error) and exported pointer-to-struct types as parameters/returns. No
// slices of strings, no maps, no channels, no generics. We work around
// this by serialising structured data as JSON strings.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/identity"
	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/session"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// SocketProtector lets the native side mark sockets as bypass-VPN.
// Android: VpnService.protect(int fd). iOS: usually unnecessary because
// NEPacketTunnelProvider handles socket scoping, but we accept the hook
// for parity. Implement this interface in Java/Kotlin/Swift; pass it to
// SetSocketProtector before calling Connect.
type SocketProtector interface {
	// Protect marks the given file descriptor as outside the VPN tunnel.
	// Return true on success. Called from Go goroutines, must be
	// reentrant.
	Protect(fd int64) bool
}

// LogSink lets the native side capture goloom log lines (so they appear
// in logcat / NSLog instead of stdout, which on mobile is /dev/null).
type LogSink interface {
	Write(line string)
}

// PhaseListener lets the native side observe high-level connect phases —
// "auth_ladder", "lobby_dial", "target_handshake" etc. — between
// Connect() entry and ConnectResult return. Used by mobile UIs to show
// сменяющиеся статусы вместо одного безмолвного "Connecting..."
// indicator'а.
type PhaseListener interface {
	// OnPhase вызывается каждый раз когда меняется состояние подключения.
	// Реентерабельно безопасен; native-side обычно проксирует в
	// StateFlow / @Published.
	OnPhase(phase string, detail string)
}

// CaptchaSolver — native-side hook для решения VK captcha. Передаётся
// challenge URL (https://id.vk.ru/not_robot_captcha?...), native
// открывает её в WebView с правильным UA + JS-anti-bot масками
// (см. tun/CaptchaWebViewDialog.kt), захватывает success_token из
// captchaNotRobot.check ответа и возвращает.
//
// На таймаут/cancel возвращает "" + non-nil error — auth ladder
// тогда фейлится с понятным сообщением.
type CaptchaSolver interface {
	Solve(challengeURL string) (successToken string, err error)
}

// Client is the singleton-ish tunnel handle. One per VpnService /
// PacketTunnelProvider instance.
type Client struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running atomic.Bool

	logger  *log.Logger
	logSink LogSink

	phaseMu    sync.Mutex
	phaseHook  PhaseListener
	captchaCB  CaptchaSolver

	connectedTo string
	displayName string
	listenAddr  string
	connStr     string
	// vkTargetMeeting — VK call link, заданный native-стороной из
	// локального UI поля. В client-meeting режиме (S2/S3) connstr.Meeting
	// пустой; user вводит meeting сам и Kotlin'ом ставит сюда.
	vkTargetMeeting string
	lastErr         error

	// sessionDone сигнализирует supervisor'у конец текущей сессии. Канал
	// обновляется на каждую новую runSession (peer rehandshake / retry).
	// Defends Connect() от блокировки на joiner.Run — мобильный клиент
	// должен получить ConnectResult сразу после handshake, а не после
	// падения сессии.
	sessionDone chan error

	tx, rx atomic.Uint64
}

// NewClient returns an idle Client. Hook up SetSocketProtector and
// SetLogSink before calling Connect.
func NewClient() *Client {
	c := &Client{}
	c.logger = log.New(&clientLogWriter{c: c}, "[goloom] ", log.LstdFlags|log.Lmicroseconds)
	return c
}

// SetSocketProtector registers the native bypass-VPN hook. Without this,
// our internal Telemost sockets get captured by the VpnService TUN and
// the WebRTC handshake never completes.
func (c *Client) SetSocketProtector(p SocketProtector) {
	setSocketProtector(p)
}

// SetLogSink redirects log output to the native side.
func (c *Client) SetLogSink(s LogSink) {
	c.mu.Lock()
	c.logSink = s
	c.mu.Unlock()
}

// SetPhaseListener регистрирует native-side hook на изменения фазы
// подключения. Передавай listener ДО вызова Connect, иначе ранние
// фазы (auth, lobby) пройдут без notification'ов.
func (c *Client) SetPhaseListener(p PhaseListener) {
	c.phaseMu.Lock()
	c.phaseHook = p
	c.phaseMu.Unlock()
}

// SetCaptchaSolver регистрирует native-side hook на решение VK captcha.
// Если не задан — captcha challenge на step 1 auth-ладдера фейлится
// сразу. Native обычно реализует через WebView dialog (см.
// tun/CaptchaWebViewDialog.kt в проде vk-turn-proxy/Android).
func (c *Client) SetCaptchaSolver(s CaptchaSolver) {
	c.phaseMu.Lock()
	c.captchaCB = s
	c.phaseMu.Unlock()
}

// SetVKTargetMeeting устанавливает meeting URL для client-meeting
// режима (S2/S3). Native-side вызывает перед Connect когда у connstr
// LobbyMeetingURL заполнен, а user из UI ввёл свой meeting URL.
func (c *Client) SetVKTargetMeeting(url string) {
	c.mu.Lock()
	c.vkTargetMeeting = url
	c.mu.Unlock()
}

// emitPhase шлёт фазу в native-listener (если есть). Безопасен для
// вызова из любых горутин.
func (c *Client) emitPhase(phase, detail string) {
	c.phaseMu.Lock()
	hook := c.phaseHook
	c.phaseMu.Unlock()
	if hook != nil {
		hook.OnPhase(phase, detail)
	}
	c.logger.Printf("phase: %s%s", phase, func() string {
		if detail != "" {
			return " — " + detail
		}
		return ""
	}())
}

// ConnectResult is what Connect() returns serialised as JSON. Callers
// parse it on the native side to set up VPN routes / excluded ranges.
type ConnectResult struct {
	DisplayName  string   `json:"display_name"`
	PeerID       string   `json:"peer_id"`
	ListenAddr   string   `json:"listen_addr"`
	TelemostIPs  []string `json:"telemost_ips"` // /32 networks the native side should route via underlying iface, NOT through the VPN
	WGEndpoint   string   `json:"wg_endpoint"`  // matches ListenAddr — what the WG client config should set as Endpoint

	// Populated when the connection string carries a complete embedded
	// WG profile (admin-panel auto-provisioned inbounds). Native code
	// can hand WGClientConfig straight to wg-tools / WireGuardKit
	// without asking the user to import a .conf file.
	WGClientConfig string `json:"wg_client_config,omitempty"`
	WGClientAddr   string `json:"wg_client_addr,omitempty"` // e.g. "10.66.1.2/24"
}

// Connect parses the connection string, establishes the Telemost session,
// completes handshake, and starts listening for WG packets on listenAddr.
// Returns a JSON-serialised ConnectResult on success.
//
// After Connect succeeds, a background supervisor keeps the tunnel
// alive: if the server restarts and asks us to re-handshake, we do so
// transparently without the native side needing to be told. Watch
// IsConnected() / StatsJSON() for liveness.
func (c *Client) Connect(connectionString string, listenAddr string) (string, error) {
	c.mu.Lock()
	if c.running.Load() {
		c.mu.Unlock()
		err := mobileErr(ErrAlreadyConnected, errors.New("already connected"))
		c.recordErr(err)
		return "", err
	}
	c.mu.Unlock()

	params, err := connstr.Decode(connectionString)
	if err != nil {
		typed := mobileErr(ErrInvalidConnString, err)
		c.recordErr(typed)
		return "", typed
	}

	if listenAddr == "" {
		listenAddr = "127.0.0.1:51820"
	}

	c.mu.Lock()
	c.connStr = connectionString
	c.listenAddr = listenAddr
	c.mu.Unlock()

	parentCtx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.cancel = cancel
	c.connectedTo = params.Meeting
	if params.LobbyMeetingURL != "" && c.vkTargetMeeting != "" {
		c.connectedTo = c.vkTargetMeeting
	}
	c.mu.Unlock()

	c.emitPhase("init", "")

	// Dispatch на нужный transport. Telemost — старый монолитный
	// session.SetupSession path. VK Calls — lobby flow + vkcalls.Transport.
	var res ConnectResult
	switch params.Transport {
	case "vk-calls":
		res, err = c.runVKSession(parentCtx, params, listenAddr)
	case "", "telemost":
		res, err = c.runSession(parentCtx, params, listenAddr)
	default:
		err = fmt.Errorf("unsupported transport %q", params.Transport)
	}
	if err != nil {
		cancel()
		typed := classify(err)
		c.recordErr(typed)
		c.emitPhase("error", typed.Error())
		return "", typed
	}

	c.recordErr(nil)
	c.running.Store(true)
	c.emitPhase("ready", "")
	go c.supervise(parentCtx)

	out, _ := json.Marshal(res)
	return string(out), nil
}

// runSession sets up a single Telemost session and runs the joiner until
// it exits. Returns ConnectResult on the first successful handshake; the
// joiner keeps running on a background goroutine and signals completion
// via c.sessionDone, which supervise() drains.
//
// IMPORTANT: ресурсы (sess.Pub/Sub, cameraSender, ctx) НЕЛЬЗЯ закрывать
// через `defer` на уровне этой функции — иначе они умрут в момент
// возврата ConnectResult, а joiner ещё работает. Закрытие происходит
// в финализирующей горутине, которая ждёт окончания joiner.Run.
func (c *Client) runSession(parentCtx context.Context, params *connstr.Params, listenAddr string) (ConnectResult, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	displayName := identity.NameOrGenerate(params.DisplayName)
	c.logger.Printf("display name: %s", displayName)
	c.mu.Lock()
	c.displayName = displayName
	c.mu.Unlock()

	c.emitPhase("resolving", "Telemost edge IPs")
	telemostIPs, _ := resolveTelemostIPs(params.Meeting)

	c.emitPhase("auth", "Telemost session setup")
	sess, err := session.SetupSession(ctx, c.logger, params.Meeting, displayName)
	if err != nil {
		cancel()
		return ConnectResult{}, fmt.Errorf("session setup: %w", err)
	}

	if sess.ServerHello() != nil {
		for _, ice := range sess.ServerHello().RtcConfiguration.ICEServers {
			for _, u := range ice.URLs {
				if host := extractHost(u); host != "" {
					ips, err := net.LookupIP(host)
					if err == nil {
						telemostIPs = append(telemostIPs, ips...)
					}
				}
			}
		}
	}

	go session.RunOpusSilenceLoop(ctx, c.logger, sess.AudioTrack)
	go session.RunKeyframeRefresh(ctx, c.logger, sess.VideoTrack)
	if err := session.SendInitialKeyframes(c.logger, sess.VideoTrack, 10); err != nil {
		cancel()
		sess.Close()
		return ConnectResult{}, fmt.Errorf("camera keyframe warmup: %w", err)
	}

	merged := make(chan tunnel.ReceivedFrame, 512)
	go fanInTracks(ctx, sess, merged, c.logger)

	c.emitPhase("waiting_for_peer", "Telemost peer to join the call")
	if _, err := sess.WaitForPeer(ctx, 5*time.Minute); err != nil {
		cancel()
		sess.Close()
		return ConnectResult{}, fmt.Errorf("wait for peer: %w", err)
	}

	cameraSender := tunnel.NewSender(sess.VideoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP8BlackKeyframe
	cameraSender.Start()

	c.emitPhase("handshake", "exchanging HELLO with peer")
	peerID, err := session.Handshake(ctx, c.logger, sess, cameraSender, merged, 1)
	if err != nil {
		cameraSender.Close()
		cancel()
		sess.Close()
		return ConnectResult{}, fmt.Errorf("handshake: %w", err)
	}

	pushKeyframeOnPLI := session.MakeKeyframePusher(sess.VideoTrack, c.logger, 100*time.Millisecond)
	session.StartRTCPLoop(ctx, c.logger, "PUB-rtcp", sess.Pub.PC, pushKeyframeOnPLI)

	go func() {
		for i, delay := range []time.Duration{3 * time.Second, 8 * time.Second, 15 * time.Second} {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				sess.RebindSlots(ctx, 4+i)
			}
		}
	}()

	dt := wgrelay.New(cameraSender, merged, c.logger)
	joiner := wgrelay.NewJoiner(listenAddr, dt, c.logger)

	go dt.Run(ctx)
	go c.statsLoop(ctx, joiner)
	// rx-stall watchdog. Симметрия серверному (manager.go::watchdog) и
	// клиенту (cmd/goloom-wg-client/main.go::run): при шейпинге
	// media-tracks Telemost SFU control-channel остаётся живым, а
	// WG-payload через video-track замирает. Watchdog ловит это и
	// форсит cancel(ctx) → joiner.Run возвращается → финализирующая
	// горутина видит dt.WasRxStalled() и пишет ErrRxStall в done →
	// supervise() делает быстрый retry.
	go wgrelay.RunRxStallWatchdogDefault(ctx, cancel, dt, c.logger)

	// joiner.Run blocks indefinitely. Run его в горутине и сообщи о
	// результате через c.sessionDone — supervisor (или сам Connect)
	// решит что делать дальше. На мобильном клиенте это критично:
	// Kotlin-сторона ждёт возврата Connect() с ConnectResult, чтобы
	// поднять VpnService.Builder, иначе UI висит "Connecting..." вечно.
	done := make(chan error, 1)
	c.mu.Lock()
	prevDone := c.sessionDone
	c.sessionDone = done
	c.mu.Unlock()
	if prevDone != nil {
		// На случай если предыдущая runSession ещё держала канал —
		// считаем его отрабатавшим, чтобы старый supervise не залип.
		select {
		case prevDone <- context.Canceled:
		default:
		}
	}
	go func() {
		joinErr := joiner.Run(ctx)
		// Если watchdog успел сорваться раньше joiner — заменяем
		// generic ctx-cancel ошибку на специфичный ErrRxStall, чтобы
		// supervise() мог выбрать fast-retry стратегию.
		if dt.WasRxStalled() {
			joinErr = wgrelay.ErrRxStall
		}
		// Закрываем ресурсы здесь, потому что runSession уже вернулся
		// (defer'ы на уровне runSession неприменимы — иначе они
		// сработают сразу после ConnectResult, до joiner.Run).
		cameraSender.Close()
		sess.Close()
		cancel()
		select {
		case done <- joinErr:
		default:
		}
	}()

	res := ConnectResult{
		DisplayName: displayName,
		PeerID:      peerID,
		ListenAddr:  listenAddr,
		WGEndpoint:  listenAddr,
		TelemostIPs: ipsToStrings(telemostIPs),
	}
	if params.HasWG() {
		params.WGEndpoint = listenAddr
		res.WGClientConfig = params.WGClientConfig()
		res.WGClientAddr = params.WGClientAddr
	}
	return res, nil
}

// supervise keeps the tunnel up across peer-rehandshake events and
// transient failures. Runs after the first successful Connect().
func (c *Client) supervise(parentCtx context.Context) {
	defer c.running.Store(false)

	c.mu.Lock()
	connStr := c.connStr
	listenAddr := c.listenAddr
	c.mu.Unlock()

	params, err := connstr.Decode(connStr)
	if err != nil {
		c.logger.Printf("supervisor: invalid stored connstr: %v", err)
		return
	}

	backoff := 5 * time.Second
	for {
		if parentCtx.Err() != nil {
			return
		}

		// На первой итерации supervise() runSession УЖЕ запущена
		// инлайн в Connect() — остаётся только дождаться окончания
		// этой первой сессии. На последующих итерациях запускаем
		// новые runSession после backoff'а.
		c.mu.Lock()
		done := c.sessionDone
		c.mu.Unlock()

		var err error
		if done != nil {
			select {
			case <-parentCtx.Done():
				return
			case err = <-done:
			}
			c.mu.Lock()
			if c.sessionDone == done {
				c.sessionDone = nil
			}
			c.mu.Unlock()
		} else {
			_, err = c.runSession(parentCtx, params, listenAddr)
			// runSession теперь возвращается сразу после handshake.
			// Дождёмся её завершения через sessionDone.
			c.mu.Lock()
			done = c.sessionDone
			c.mu.Unlock()
			if err == nil && done != nil {
				select {
				case <-parentCtx.Done():
					return
				case err = <-done:
				}
				c.mu.Lock()
				if c.sessionDone == done {
					c.sessionDone = nil
				}
				c.mu.Unlock()
			}
		}

		if parentCtx.Err() != nil {
			return
		}

		retryAfter := backoff
		if errors.Is(err, wgrelay.ErrPeerRehandshake) {
			// 1s pause lets the SFU process WS-bye + DTLS close from
			// the old session before we rejoin. Skipping it leaves a
			// zombie participant for the ~30s ICE timeout.
			c.logger.Printf("supervisor: peer rehandshake — reconnecting in 1s (SFU cleanup)")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		} else if errors.Is(err, wgrelay.ErrRxStall) {
			// Watchdog поймал шейпинг media-tracks. Та же fast-retry
			// стратегия что у peer-rehandshake — старая SFU сессия
			// нуждается в небольшой паузе чтобы освободить наш
			// participant slot, иначе новая сессия столкнётся с
			// зомби-подпиской.
			c.logger.Printf("supervisor: rx stall — Telemost SFU shaped tracks; reconnecting in 1s")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		} else if err != nil {
			c.logger.Printf("supervisor: session ended: %v — retrying in %s", err, backoff)
		} else {
			c.logger.Printf("supervisor: session ended cleanly — retrying in %s", backoff)
		}

		fastRetry := errors.Is(err, wgrelay.ErrPeerRehandshake) ||
			errors.Is(err, wgrelay.ErrRxStall)

		select {
		case <-parentCtx.Done():
			return
		case <-time.After(retryAfter):
		}
		if !fastRetry && backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// Disconnect tears down the tunnel. Idempotent.
func (c *Client) Disconnect() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.running.Store(false)
	// Также гасим embedded wg-userspace, если он был поднят native-стороной
	// через AdoptTun.
	disconnectEmbedded(c.logger)
}

// IsConnected returns whether the relay goroutine is still alive.
func (c *Client) IsConnected() bool {
	return c.running.Load()
}

// StatsJSON returns "{tx_bytes:N, rx_bytes:N, tx_packets:N, rx_packets:N}".
// Cheap enough to call from a UI timer.
func (c *Client) StatsJSON() string {
	out := struct {
		TxBytes   uint64 `json:"tx_bytes"`
		RxBytes   uint64 `json:"rx_bytes"`
		Connected bool   `json:"connected"`
	}{
		TxBytes:   c.tx.Load(),
		RxBytes:   c.rx.Load(),
		Connected: c.running.Load(),
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (c *Client) statsLoop(ctx context.Context, j *wgrelay.WGJoiner) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tx.Store(j.TxBytes.Load())
			c.rx.Store(j.RxBytes.Load())
		}
	}
}

// fanInTracks is the receiver fan-in we use in every cmd binary.
func fanInTracks(ctx context.Context, sess *session.Session, out chan<- tunnel.ReceivedFrame, lg *log.Logger) {
	idx := 0
	for {
		select {
		case <-ctx.Done():
			return
		case tr, ok := <-sess.NewVideoTracks():
			if !ok {
				return
			}
			idx++
			r := tunnel.NewReceiver(256)
			go r.Run(ctx, tr, lg)
			go func(recv *tunnel.Receiver) {
				for f := range recv.Frames() {
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
			}(r)
		}
	}
}

func resolveTelemostIPs(meetingURL string) ([]net.IP, error) {
	hosts := []string{
		"cloud-api.yandex.ru",
		"telemost.yandex.ru",
		"goloom.strm.yandex.net",
		"strm.yandex.net",
	}
	if u, err := url.Parse(meetingURL); err == nil && u.Host != "" && u.Host != "telemost.yandex.ru" {
		hosts = append(hosts, u.Host)
	}
	var out []net.IP
	for _, h := range hosts {
		ips, err := net.LookupIP(h)
		if err == nil {
			out = append(out, ips...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no Telemost IPs resolved")
	}
	return out, nil
}

func extractHost(rawURL string) string {
	for _, prefix := range []string{"turn:", "turns:", "stun:", "stuns:"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			if idx := strings.Index(rest, "?"); idx >= 0 {
				rest = rest[:idx]
			}
			host, _, err := net.SplitHostPort(rest)
			if err == nil && host != "" {
				return host
			}
			return rest
		}
	}
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host, _, _ := net.SplitHostPort(u.Host)
		if host != "" {
			return host
		}
		return u.Host
	}
	return ""
}

func ipsToStrings(ips []net.IP) []string {
	seen := make(map[string]bool, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// clientLogWriter routes Go log output through the registered LogSink
// (so it surfaces in logcat/NSLog) AND keeps stdout for desktop builds.
type clientLogWriter struct {
	c *Client
}

func (w *clientLogWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	sink := w.c.logSink
	w.c.mu.Unlock()
	if sink != nil {
		sink.Write(strings.TrimRight(string(p), "\n"))
	} else {
		_, _ = os.Stdout.Write(p)
	}
	return len(p), nil
}
