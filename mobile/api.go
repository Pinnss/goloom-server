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

	"github.com/Sv9toslavPinigin/goloom-server/internal/connstr"
	"github.com/Sv9toslavPinigin/goloom-server/internal/identity"
	mediastubs "github.com/Sv9toslavPinigin/goloom-server/internal/media"
	"github.com/Sv9toslavPinigin/goloom-server/internal/session"
	"github.com/Sv9toslavPinigin/goloom-server/internal/tunnel"
	"github.com/Sv9toslavPinigin/goloom-server/internal/wgrelay"
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

// Client is the singleton-ish tunnel handle. One per VpnService /
// PacketTunnelProvider instance.
type Client struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running atomic.Bool

	logger  *log.Logger
	logSink LogSink

	connectedTo string
	displayName string
	listenAddr  string
	connStr     string
	lastErr     error

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
	c.mu.Unlock()

	// First session is run inline so we can return success/failure to
	// the native caller. Subsequent reconnects (peer-rehandshake or
	// transient failures) happen on the supervisor goroutine.
	res, err := c.runSession(parentCtx, params, listenAddr)
	if err != nil {
		cancel()
		typed := classify(err)
		c.recordErr(typed)
		return "", typed
	}

	c.recordErr(nil)
	c.running.Store(true)
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

	telemostIPs, _ := resolveTelemostIPs(params.Meeting)

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

	if _, err := sess.WaitForPeer(ctx, 5*time.Minute); err != nil {
		cancel()
		sess.Close()
		return ConnectResult{}, fmt.Errorf("wait for peer: %w", err)
	}

	cameraSender := tunnel.NewSender(sess.VideoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP8BlackKeyframe
	cameraSender.Start()

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
		} else if err != nil {
			c.logger.Printf("supervisor: session ended: %v — retrying in %s", err, backoff)
		} else {
			c.logger.Printf("supervisor: session ended cleanly — retrying in %s", backoff)
		}

		select {
		case <-parentCtx.Done():
			return
		case <-time.After(retryAfter):
		}
		if !errors.Is(err, wgrelay.ErrPeerRehandshake) && backoff < 60*time.Second {
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
