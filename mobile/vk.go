// VK Calls транспорт для мобильного клиента. Выполняет тот же in-band
// lobby flow что и pkg/wgclient (см. lobby_dial.go), плюс адаптирует
// captcha solver к native PhotoView dialog'у через [CaptchaSolver]
// callback.

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// runVKSession — мобильный аналог wgclient.runOnce для VK Calls. На
// успех возвращает ConnectResult; joiner работает в фоне и
// сигналит через c.sessionDone.
func (c *Client) runVKSession(parentCtx context.Context, params *connstr.Params, listenAddr string) (ConnectResult, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	displayName := identity.NameOrGenerate(params.DisplayName)
	c.mu.Lock()
	c.displayName = displayName
	target := c.vkTargetMeeting
	c.mu.Unlock()

	if target == "" {
		// Если в connstr meeting прямой — используем его (старый h264
		// non-lobby режим). Иначе требуем native-side задать через
		// SetVKTargetMeeting.
		target = params.Meeting
	}
	if target == "" {
		cancel()
		return ConnectResult{}, errors.New("vk-calls: target meeting URL не задан (SetVKTargetMeeting перед Connect)")
	}

	captchaSolver := c.buildVKCaptchaSolver()
	if captchaSolver == nil {
		c.logger.Printf("vk-calls: WARN no captcha solver registered — auth will fail on captcha")
	}

	// Lobby bootstrap (S2/S3) — если в connstr заданы lobby поля.
	var serverTargetUID int64
	if params.LobbyMeetingURL != "" && params.Bearer != "" {
		c.emitPhase("lobby_join", "joining VK lobby call")
		uid, err := c.lobbyDialMobile(ctx, params.LobbyMeetingURL, params.Bearer, target, displayName, captchaSolver)
		if err != nil {
			cancel()
			return ConnectResult{}, fmt.Errorf("lobby bootstrap: %w", err)
		}
		serverTargetUID = uid
		c.emitPhase("lobby_done", fmt.Sprintf("server target uid=%d", uid))
		os.Setenv("VKCALLS_TARGET_REMOTE_ID", strconv.FormatInt(uid, 10))
		defer os.Unsetenv("VKCALLS_TARGET_REMOTE_ID")
	}

	c.emitPhase("auth", "VK auth ladder для target meeting'а")

	// Build VKCallsConnect spec и зовём Transport.Connect.
	spec := sfu.ConnectSpec{
		Kind:        sfu.KindVKCalls,
		DisplayName: displayName,
		Logger:      c.logger,
		VKCalls: &sfu.VKCallsConnect{
			MeetingURL:    target,
			Role:          "caller",
			Codec:         params.Codec,
			CaptchaSolver: captchaSolver,
		},
	}
	transport, err := sfu.Get(sfu.KindVKCalls)
	if err != nil {
		cancel()
		return ConnectResult{}, fmt.Errorf("vk-calls transport: %w", err)
	}

	c.emitPhase("target_connect", "VK SFU peer-join + SDP exchange")
	sess, err := transport.Connect(ctx, spec)
	if err != nil {
		cancel()
		return ConnectResult{}, fmt.Errorf("vk-calls connect: %w", err)
	}

	// Resolve external hosts that should bypass the VPN tunnel —
	// VK Calls SFU edges + auth hosts. Native side (Kotlin) добавит
	// в VpnService.Builder.addDisallowedRoute.
	var bypassIPs []net.IP
	if hp, ok := sess.(sfu.ICEHostsProvider); ok {
		for _, host := range hp.ICEHosts() {
			if ips, err := net.LookupIP(host); err == nil {
				bypassIPs = append(bypassIPs, ips...)
			}
		}
	}

	c.emitPhase("bridge_up", "WireGuard bridge listen "+listenAddr)
	dt := wgrelay.New(nil, nil, c.logger) // VK уже использует wgrelay внутри Session, joiner на нашем уровне
	_ = dt
	// Для VK путь uses sess.Send/sess.Frames напрямую через wgrelay.NewClientBridge.
	// Используем его вместо WGJoiner (joiner сам формирует frame channel).
	bridge := wgrelay.NewClientBridge(listenAddr, sess, c.logger)

	// Bridge.Run блокирует. Гоним в горутину и сообщаем о результате
	// через c.sessionDone — supervisor разрешит retry.
	done := make(chan error, 1)
	c.mu.Lock()
	prevDone := c.sessionDone
	c.sessionDone = done
	c.mu.Unlock()
	if prevDone != nil {
		select {
		case prevDone <- context.Canceled:
		default:
		}
	}
	go func() {
		bridgeErr := bridge.Run(ctx)
		sess.Close()
		cancel()
		select {
		case done <- bridgeErr:
		default:
		}
	}()

	res := ConnectResult{
		DisplayName: displayName,
		PeerID:      strconv.FormatInt(serverTargetUID, 10),
		ListenAddr:  listenAddr,
		WGEndpoint:  listenAddr,
		TelemostIPs: ipsToStrings(bypassIPs),
	}
	if params.HasWG() {
		params.WGEndpoint = listenAddr
		res.WGClientConfig = params.WGClientConfig()
		res.WGClientAddr = params.WGClientAddr
	}
	return res, nil
}

// lobbyDialMobile — мобильная адаптация pkg/wgclient/lobby_dial.go.
// Возвращает serverTargetUID или ошибку.
func (c *Client) lobbyDialMobile(parent context.Context, lobbyMeeting, bearer, targetMeeting, displayName string, solver sfu.VKCaptchaSolver) (int64, error) {
	if solver == nil {
		return 0, errors.New("lobby: captcha solver required (SetCaptchaSolver перед Connect)")
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()

	c.emitPhase("lobby_auth", "VK auth ladder для lobby")
	lobby, err := vkcalls.OpenLobbyPeer(ctx, c.logger, vkcalls.LobbyOptions{
		MeetingURL:    lobbyMeeting,
		DisplayName:   displayName,
		CaptchaSolver: solver,
	})
	if err != nil {
		return 0, fmt.Errorf("open lobby peer: %w", err)
	}
	defer lobby.Close()

	c.emitPhase("lobby_wait_server", "waiting for goloom server in roster")
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	var serverID int64
	for serverID == 0 {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("lobby: timed out waiting for server peer: %w", ctx.Err())
		case <-deadline.C:
			return 0, errors.New("lobby: server not in roster after 20s — is the inbound running?")
		case <-tick.C:
			serverID = lobby.RemotePeerID()
		}
	}

	c.emitPhase("lobby_dial", "sending goloom_ctrl DIAL")
	if err := lobby.SendCtrl(serverID, vkcalls.GoloomCtrl{
		Type: "DIAL", MeetingURL: targetMeeting, Bearer: bearer,
	}); err != nil {
		return 0, fmt.Errorf("lobby: send DIAL: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("lobby: timed out waiting DIAL response: %w", ctx.Err())
		case msg, ok := <-lobby.Incoming():
			if !ok {
				return 0, errors.New("lobby: incoming closed")
			}
			switch msg.Msg.Type {
			case "DIAL_OK":
				return msg.Msg.ServerTargetUserID, nil
			case "DIAL_FAIL":
				return 0, fmt.Errorf("server rejected DIAL: %s", msg.Msg.Reason)
			}
		}
	}
}

// buildVKCaptchaSolver возвращает captcha solver, который спавнит
// local reverse-proxy (vkcalls.AutoProxyCaptchaSolverWithOpener) и
// зовёт native [BrowserLauncher] открыть localhost URL в WebView.
// Token capture делает proxy через JS shim — native никаких
// токенов не парсит, просто рендерит UI.
func (c *Client) buildVKCaptchaSolver() sfu.VKCaptchaSolver {
	c.phaseMu.Lock()
	launcher := c.browserCB
	c.phaseMu.Unlock()
	if launcher == nil {
		return nil
	}
	opener := func(url string) {
		c.emitPhase("captcha", "open captcha in WebView")
		launcher.Open(url)
	}
	return vkcalls.AutoProxyCaptchaSolverWithOpener(2*time.Minute, c.logger, nil, opener)
}

// ensure json import for future ConnectResult expansion
var _ = json.Marshal
