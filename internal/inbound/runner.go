package inbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"

	// Side-effect imports — register Telemost / LiveKit / VK Calls
	// Transports with the sfu factory. Pulled in here so
	// cmd/goloom-wg-server doesn't have to know about every transport
	// package; the vkcalls non-blank import below also gives us access
	// to AutoProxyCaptchaSolver for runtime injection.
	_ "github.com/Pinnss/goloom-server/internal/sfu/livekit"
	_ "github.com/Pinnss/goloom-server/internal/sfu/telemost"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"

	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// isLikelyEmptyRoom recognises the handshake-timeout-with-no-peer error
// shape ("peerID=\"\" gotHello=false …") so the supervisor can treat it
// as "waiting" instead of a hard error in the admin panel. Telemost-
// specific signal but harmless to check on other transports (won't match).
func isLikelyEmptyRoom(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "handshake timeout") &&
		strings.Contains(s, `peerID=""`) &&
		strings.Contains(s, "gotHello=false")
}

// Runner owns the lifecycle of a single inbound: SFU session, wgrelay
// bridge, and the live-status surface used by the admin panel. Run
// blocks until the context is cancelled or an unrecoverable error
// occurs; the Manager retries with backoff between calls.
//
// Multi-transport: Runner is transport-agnostic; the actual SFU stack
// (Telemost vs LiveKit/WB-Stream) is hidden behind sfu.Transport, picked
// from Spec.Transport at Run time.
type Runner struct {
	Spec   Spec
	Logger *log.Logger

	mu        sync.Mutex
	phase     string
	lastError string
	startedAt time.Time

	bridge atomic.Pointer[wgrelay.SFUBridge]

	// captchaBroker is the admin-webview captcha solver bridge.
	// Populated by [Runner.SetCaptchaBroker], typically called by
	// the surrounding [Manager] right after NewRunner. nil disables
	// captcha_mode=admin-webview for this runner.
	captchaBroker vkcalls.AdminCaptchaBroker

	// vkProfileStore — пул FP для auto-replay (S1c). Если задан и
	// captcha_mode=admin-webview/auto, base solver оборачивается в
	// [vkcalls.WithReplaySolver]. nil → replay выключен.
	vkProfileStore *vkcalls.ProfileStore

	// VK client-meeting mode (S2/S3): runner идлит, ctrl-ws
	// триггерит сессию через VKDial. Каналы alloc'аются в NewRunner,
	// nil-safe для других режимов.
	vkDialCh        chan *vkDialReq
	vkHangupCh      chan struct{}
	activeSessionID atomic.Value // string; "" когда idle
}

// vkDialReq — запрос от ctrl-ws к runner'у на запуск сессии.
type vkDialReq struct {
	meeting   string
	onClose   func()
	sessionID string
	accepted  chan error // фиксируется когда Connect привёл к session или ошибке

	// preAuth — опциональный AuthResult от lobby flow (см.
	// vkcalls.PreAuthForTarget). Если задан, transport.Connect
	// реюзит его вместо повторного auth-ladder'а — иначе VK
	// выдаст другой peer slot и client'ский targetRemoteID
	// миснёт.
	preAuth *vkcalls.AuthResult
}

func NewRunner(spec Spec, lg *log.Logger) *Runner {
	tagged := log.New(lg.Writer(), fmt.Sprintf("[inbound:%s] ", spec.Tag), lg.Flags())
	r := &Runner{Spec: spec, Logger: tagged, phase: "stopped"}
	if spec.VKCalls != nil && spec.VKCalls.AcceptClientMeeting {
		r.vkDialCh = make(chan *vkDialReq, 1)
		r.vkHangupCh = make(chan struct{}, 1)
	}
	r.activeSessionID.Store("")
	return r
}

func (r *Runner) isVKClientMeetingMode() bool {
	return r.Spec.VKCalls != nil && r.Spec.VKCalls.AcceptClientMeeting
}

func newSessionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SetCaptchaBroker swaps in the admin captcha broker used when
// VKCalls.CaptchaMode=="admin-webview". nil clears it.
func (r *Runner) SetCaptchaBroker(b vkcalls.AdminCaptchaBroker) {
	r.captchaBroker = b
}

// SetVKProfileStore enables auto-replay для VK captcha (см. S1c).
// Pass nil чтобы отключить — runner вернётся к interactive-only.
func (r *Runner) SetVKProfileStore(s *vkcalls.ProfileStore) {
	r.vkProfileStore = s
}

func (r *Runner) setPhase(p string) {
	r.mu.Lock()
	r.phase = p
	r.mu.Unlock()
}

func (r *Runner) setError(err error) {
	r.mu.Lock()
	if err != nil {
		r.lastError = err.Error()
		r.phase = "error"
	} else {
		r.lastError = ""
	}
	r.mu.Unlock()
}

// Run executes one full attempt at standing up the inbound.
func (r *Runner) Run(ctx context.Context) error {
	r.setPhase("starting")
	r.mu.Lock()
	r.startedAt = time.Now()
	r.mu.Unlock()

	if r.isVKClientMeetingMode() {
		return r.runClientMeetingMode(ctx)
	}

	connectSpec, err := r.buildConnectSpec()
	if err != nil {
		r.setError(err)
		return fmt.Errorf("build connect spec: %w", err)
	}

	transport, err := sfu.Get(connectSpec.Kind)
	if err != nil {
		r.setError(err)
		return err
	}

	r.setPhase("waiting_for_client")
	r.Logger.Printf("connecting via transport=%s", connectSpec.Kind)
	sess, err := transport.Connect(ctx, connectSpec)
	if err != nil {
		// Empty-room handshake timeout from Telemost is normal until a
		// real client joins — surface as "waiting_for_client" rather
		// than red error in the admin panel.
		if isLikelyEmptyRoom(err) {
			r.mu.Lock()
			r.lastError = ""
			r.phase = "waiting_for_client"
			r.mu.Unlock()
			r.Logger.Printf("HANDSHAKE: no client connected yet — supervisor will retry shortly")
			return fmt.Errorf("connect: %w", err)
		}
		r.setError(err)
		return fmt.Errorf("connect: %w", err)
	}
	defer sess.Close()
	r.Logger.Printf("session ready")

	bridge := wgrelay.NewServerBridge(r.Spec.WGEndpoint, sess, r.Logger)
	r.bridge.Store(bridge)
	defer r.bridge.Store(nil)

	r.setPhase("relaying")
	r.setError(nil)
	r.Logger.Printf("✓ inbound %s relaying to %s", r.Spec.Tag, r.Spec.WGEndpoint)

	if err := bridge.Run(ctx); err != nil {
		if errors.Is(err, sfu.ErrPeerRehandshake) || errors.Is(err, wgrelay.ErrPeerRehandshake) {
			// Surface to the supervisor for fast retry without
			// recording it as an "error" state in the panel.
			r.setPhase("waiting_for_client")
			return err
		}
		if !errors.Is(err, wgrelay.ErrTunnelClosed) {
			r.setError(err)
			return fmt.Errorf("bridge: %w", err)
		}
	}
	r.setPhase("stopped")
	return nil
}

// runClientMeetingMode (S2/S3) — VK инбаунд в client-meeting режиме:
//  1. peer-join'ится в LobbyMeetingURL (стабильный VK звонок),
//  2. слушает goloom_ctrl DIAL от любого клиента в lobby,
//  3. на DIAL валидирует bearer, шлёт DIAL_OK, закрывает lobby,
//  4. поднимает target VK session с meeting'ом из DIAL,
//  5. после disconnect target — обратно в lobby.
//
// Один цикл runClientMeetingMode = одна полная фаза lobby+session.
// Supervisor (Manager) перезапускает Run() после каждого цикла.
func (r *Runner) runClientMeetingMode(ctx context.Context) error {
	if r.Spec.VKCalls == nil || r.Spec.VKCalls.LobbyMeetingURL == "" {
		err := fmt.Errorf("inbound %s: accept_client_meeting=true but no lobby_meeting_url configured", r.Spec.Tag)
		r.setError(err)
		return err
	}

	r.setPhase("lobby_joining")
	r.Logger.Printf("VK lobby: joining %s, waiting for goloom_ctrl DIAL", r.Spec.VKCalls.LobbyMeetingURL)

	// Captcha solver для lobby auth — тот же что и для target session.
	solver := r.buildVKCaptchaSolver()

	lobby, err := vkcalls.OpenLobbyPeer(ctx, r.Logger, vkcalls.LobbyOptions{
		MeetingURL:    r.Spec.VKCalls.LobbyMeetingURL,
		DisplayName:   r.Spec.DisplayName,
		CaptchaSolver: solver,
	})
	if err != nil {
		r.setError(err)
		return fmt.Errorf("lobby join: %w", err)
	}
	r.setPhase("lobby_idle")
	r.Logger.Printf("VK lobby: ✓ joined, listening")

	// Read lobby goloom_ctrl until DIAL arrives or ctx done.
	var dial vkcalls.IncomingCtrl
	select {
	case <-ctx.Done():
		lobby.Close()
		r.setPhase("stopped")
		return nil
	case <-lobby.Done():
		r.Logger.Printf("VK lobby: ws closed by remote, will retry")
		return errors.New("lobby ws closed")
	case dial = <-lobby.Incoming():
		// fall through
	}

	if dial.Msg.Type != "DIAL" {
		r.Logger.Printf("VK lobby: ignoring unexpected ctrl type=%s", dial.Msg.Type)
		// Не выходим — caller'у можем нагрешить случайным non-DIAL,
		// но для MVP проще закрыть lobby + перезапустить supervisor'ом.
		lobby.Close()
		return errors.New("unexpected ctrl in lobby")
	}

	// Validate bearer.
	if want := r.Spec.VKCalls.CtrlBearer; want != "" && want != dial.Msg.Bearer {
		_ = lobby.SendCtrl(dial.From, vkcalls.GoloomCtrl{Type: "DIAL_FAIL", Reason: "invalid bearer"})
		lobby.Close()
		r.Logger.Printf("VK lobby: rejected DIAL from %d (bad bearer)", dial.From)
		return errors.New("bearer mismatch")
	}
	if dial.Msg.MeetingURL == "" {
		_ = lobby.SendCtrl(dial.From, vkcalls.GoloomCtrl{Type: "DIAL_FAIL", Reason: "meeting_url required"})
		lobby.Close()
		return errors.New("DIAL.meeting_url empty")
	}

	sessionID := newSessionID()
	r.Logger.Printf("VK lobby: DIAL accepted from %d → session=%s meeting=%s",
		dial.From, sessionID, redactMeetingPrefix(dial.Msg.MeetingURL))

	// Pre-auth target meeting'а: пройти auth ladder и узнать
	// userID который мы получим в target call'е. Это значение летит
	// в DIAL_OK, чтобы клиент сразу знал кого pick'ать в roster'е
	// target meeting'а (а не выбирал стейлы реверс-итерацией).
	//
	// joinConversationByLink (внутри auth-ladder'а) УЖЕ резервирует
	// peer slot в target call'е — поэтому AuthResult надо реюзить в
	// последующем transport.Connect (иначе создастся другой peer slot,
	// другой userID, mismatch с тем что в DIAL_OK уехал клиенту).
	preAuthCtx, preAuthCancel := context.WithTimeout(ctx, 60*time.Second)
	preAuthResult, serverTargetUID, err := vkcalls.PreAuthForTarget(preAuthCtx, r.Logger, dial.Msg.MeetingURL, r.Spec.DisplayName, solver)
	preAuthCancel()
	if err != nil {
		_ = lobby.SendCtrl(dial.From, vkcalls.GoloomCtrl{Type: "DIAL_FAIL", Reason: "target pre-auth: " + err.Error()})
		lobby.Close()
		return fmt.Errorf("pre-auth target: %w", err)
	}
	r.Logger.Printf("VK lobby: target pre-auth ✓ server target userID=%d", serverTargetUID)

	if err := lobby.SendCtrl(dial.From, vkcalls.GoloomCtrl{
		Type:               "DIAL_OK",
		SessionID:          sessionID,
		ServerTargetUserID: serverTargetUID,
	}); err != nil {
		r.Logger.Printf("VK lobby: send DIAL_OK failed: %v", err)
		// Продолжаем всё равно — клиент может ретрайнуться.
	}

	// Lobby сделала своё дело — закрываем и идём в target.
	lobby.Close()

	// Build a synthetic vkDialReq так чтобы переиспользовать старую
	// runOneVKSession логику. accepted-канал тут «уже использован»
	// (DIAL_OK уже отправили в lobby) — runOneVKSession вызовет
	// req.accepted <- nil/err но мы это просто прочитаем.
	req := &vkDialReq{
		meeting:   dial.Msg.MeetingURL,
		onClose:   nil,
		sessionID: sessionID,
		accepted:  make(chan error, 1),
		preAuth:   preAuthResult,
	}
	go func() {
		// Read accepted чтобы не block'нуть runner'а.
		<-req.accepted
	}()
	return r.runOneVKSession(ctx, req)
}

// redactMeetingPrefix логит первые 12 символов id'шника, остальное
// маскируется. См. также admin/ctrlws.go::redactMeeting.
func redactMeetingPrefix(url string) string {
	if i := strings.LastIndex(url, "/"); i > 0 && i < len(url)-12 {
		return url[:i+13] + "***"
	}
	return "***"
}

// buildVKCaptchaSolver — копия логики из buildConnectSpec для VK
// (с auto-replay wrap'ом). Вынесен чтобы lobby и target делили
// одну и ту же captcha-стратегию.
func (r *Runner) buildVKCaptchaSolver() sfu.VKCaptchaSolver {
	if r.Spec.VKCalls == nil {
		return nil
	}
	mode := r.Spec.VKCalls.CaptchaMode
	if mode == "" {
		mode = "auto"
	}
	var solver sfu.VKCaptchaSolver
	switch mode {
	case "auto":
		solver = vkcalls.AutoProxyCaptchaSolver(2*time.Minute, r.Logger, nil)
	case "none":
		solver = nil
	case "admin-webview":
		if r.captchaBroker != nil {
			solver = vkcalls.AdminWebviewCaptchaSolver(r.captchaBroker, r.Spec.Tag, r.Logger)
		}
	}
	if solver != nil && r.vkProfileStore != nil {
		solver = vkcalls.WithReplaySolver(r.vkProfileStore, solver, r.Logger)
	}
	return solver
}

// runOneVKSession — драйвит ровно одну VK-сессию для уже триггеренного
// ctrl-ws DIAL'а. accepted-канал в req сигналит ctrl-ws-handler'у когда
// Connect либо стартовал session либо завершился ошибкой; после этого
// мы продолжаем держать сессию пока bridge или hangup не завершит её.
func (r *Runner) runOneVKSession(parent context.Context, req *vkDialReq) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	r.activeSessionID.Store(req.sessionID)
	defer r.activeSessionID.Store("")

	// Build ConnectSpec из текущего Spec'а с meeting'ом из DIAL'а.
	cs, err := r.buildConnectSpec()
	if err != nil {
		req.accepted <- err
		r.setError(err)
		return fmt.Errorf("build connect spec: %w", err)
	}
	if cs.VKCalls == nil {
		err := errors.New("client-meeting mode requires Kind=vk-calls")
		req.accepted <- err
		r.setError(err)
		return err
	}
	cs.VKCalls.MeetingURL = req.meeting
	if req.preAuth != nil {
		cs.VKCalls.PreAuthResult = req.preAuth
	}

	transport, err := sfu.Get(cs.Kind)
	if err != nil {
		req.accepted <- err
		r.setError(err)
		return err
	}

	r.setPhase("connecting")
	r.Logger.Printf("ctrl-ws DIAL accepted: session=%s connecting via vk-calls", req.sessionID)

	// КРИТИЧНО: сигналим DIAL_OK ПЕРЕД transport.Connect.
	// Server в роли receiver и Connect блокируется в waitConnected
	// до тех пор пока caller (клиент) не пришлёт SDP offer. А клиент
	// ждёт DIAL_OK прежде чем стартовать свой transport.Connect.
	// Если ждать Connect здесь — deadlock на 5 минут timeout'а.
	// Вместо этого: client получает DIAL_OK немедленно, начинает свой
	// SFU-dial; параллельно мы тоже идём в SFU; SDP exchange случается
	// когда оба в звонке.
	req.accepted <- nil

	// Hangup от ctrl-ws должен пробрасывать cancel в Connect — иначе
	// при отмене ctrl-ws сессии до того как peer подключится, мы
	// застрянем на 5 минут peerConnectTimeout.
	hangupDone := make(chan struct{})
	go func() {
		select {
		case <-r.vkHangupCh:
			r.Logger.Printf("ctrl-ws hangup received during connect, cancelling")
			cancel()
		case <-hangupDone:
		}
	}()
	defer close(hangupDone)

	sess, err := transport.Connect(ctx, cs)
	if err != nil {
		r.setError(err)
		return fmt.Errorf("connect: %w", err)
	}
	defer sess.Close()
	r.setError(nil)
	r.Logger.Printf("session ready ✓")

	bridge := wgrelay.NewServerBridge(r.Spec.WGEndpoint, sess, r.Logger)
	r.bridge.Store(bridge)
	defer r.bridge.Store(nil)
	r.setPhase("relaying")
	r.Logger.Printf("✓ inbound %s relaying to %s (session=%s)", r.Spec.Tag, r.Spec.WGEndpoint, req.sessionID)

	bridgeErr := make(chan error, 1)
	go func() { bridgeErr <- bridge.Run(ctx) }()

	select {
	case <-r.vkHangupCh:
		r.Logger.Printf("ctrl-ws hangup received, ending session=%s", req.sessionID)
	case err := <-bridgeErr:
		if err != nil && !errors.Is(err, wgrelay.ErrTunnelClosed) && !errors.Is(err, sfu.ErrPeerRehandshake) {
			r.setError(err)
			r.Logger.Printf("bridge ended with error: %v", err)
		} else {
			r.Logger.Printf("bridge ended cleanly")
		}
	case <-ctx.Done():
	}

	if req.onClose != nil {
		req.onClose()
	}
	r.setPhase("idle")
	return nil
}

// VKDial вызывается ctrl-ws handler'ом (через Manager). Триггерит
// runner на запуск сессии с указанным meeting URL'ом. Возвращает
// sessionID если Connect успел стартовать, или ошибку.
//
// Bearer проверяется здесь — runner владеет своим CtrlBearer'ом.
func (r *Runner) VKDial(meeting, bearer string, onClose func()) (string, error) {
	if !r.isVKClientMeetingMode() {
		return "", errors.New("inbound not in client-meeting mode")
	}
	expected := r.Spec.VKCalls.CtrlBearer
	if expected != "" && expected != bearer {
		return "", errors.New("invalid bearer token")
	}
	if cur, _ := r.activeSessionID.Load().(string); cur != "" {
		return "", errors.New("inbound already has active session")
	}
	sid := newSessionID()
	req := &vkDialReq{
		meeting:   meeting,
		onClose:   onClose,
		sessionID: sid,
		accepted:  make(chan error, 1),
	}
	select {
	case r.vkDialCh <- req:
	default:
		return "", errors.New("inbound not idle (dial channel full)")
	}
	if err := <-req.accepted; err != nil {
		return "", err
	}
	return sid, nil
}

// VKHangup корректно ломает текущую активную сессию для указанного
// sessionID. Idempotent: hangup на чужой/несуществующий session ID —
// no-op.
func (r *Runner) VKHangup(sessionID string) {
	if cur, _ := r.activeSessionID.Load().(string); cur != sessionID {
		return
	}
	select {
	case r.vkHangupCh <- struct{}{}:
	default:
	}
}

// Codec / IsBusy — для ctrl-ws WELCOME message.
func (r *Runner) VKInfo() (codec string, busy bool) {
	if r.Spec.VKCalls != nil {
		codec = r.Spec.VKCalls.Codec
	}
	cur, _ := r.activeSessionID.Load().(string)
	busy = cur != ""
	return
}

// buildConnectSpec maps the persisted Spec onto an sfu.ConnectSpec.
// Empty Spec.Transport defaults to Telemost for backward compatibility.
func (r *Runner) buildConnectSpec() (sfu.ConnectSpec, error) {
	kind := sfu.Kind(r.Spec.Transport)
	if kind == "" {
		kind = sfu.KindTelemost
	}

	cs := sfu.ConnectSpec{
		Kind:        kind,
		DisplayName: r.Spec.DisplayName,
		Logger:      r.Logger,
	}

	switch kind {
	case sfu.KindTelemost:
		cs.Telemost = &sfu.TelemostConnect{MeetingURL: r.Spec.Meeting}
	case sfu.KindLiveKitWBStream:
		if r.Spec.LiveKit == nil {
			return cs, fmt.Errorf("inbound %s: transport=livekit-wb-stream but Spec.LiveKit is nil", r.Spec.Tag)
		}
		cs.LiveKitWBStream = &sfu.LiveKitWBStreamConnect{
			RoomURL:     r.Spec.LiveKit.RoomURL,
			AccessToken: r.Spec.LiveKit.AccessToken,
			Cookies:     r.Spec.LiveKit.Cookies,
		}
	case sfu.KindVKCalls:
		// MeetingURL prefers Spec.VKCalls.MeetingURL but falls back
		// to the generic Spec.Meeting (same field used by Telemost).
		// That way the admin panel can ship a single "meeting/link"
		// input on the form and not require operators to learn two
		// fields with identical semantics.
		meetingURL := r.Spec.Meeting
		role := "receiver"
		captchaMode := "auto"
		if r.Spec.VKCalls != nil {
			if r.Spec.VKCalls.MeetingURL != "" {
				meetingURL = r.Spec.VKCalls.MeetingURL
			}
			if r.Spec.VKCalls.Role != "" {
				role = r.Spec.VKCalls.Role
			}
			if r.Spec.VKCalls.CaptchaMode != "" {
				captchaMode = r.Spec.VKCalls.CaptchaMode
			}
		}
		// В client-meeting mode (S2/S3) meeting приходит от клиента
		// через ctrl-ws DIAL после buildConnectSpec; здесь пусто
		// допускается, runOneVKSession сам пропишет cs.VKCalls.MeetingURL.
		clientMeeting := r.Spec.VKCalls != nil && r.Spec.VKCalls.AcceptClientMeeting
		if meetingURL == "" && !clientMeeting {
			return cs, fmt.Errorf("inbound %s: transport=vk-calls but no MeetingURL configured", r.Spec.Tag)
		}

		var solver sfu.VKCaptchaSolver
		switch captchaMode {
		case "auto":
			// S1b: AutoProxy на серверной стороне используется редко
			// (нужна desktop-сессия), pool профилей живёт под admin
			// captcha-broker. Передаём nil sink — захвата нет, но и
			// сценарий маргинальный.
			solver = vkcalls.AutoProxyCaptchaSolver(2*time.Minute, r.Logger, nil)
		case "none":
			solver = nil
		case "admin-webview":
			if r.captchaBroker == nil {
				return cs, fmt.Errorf("inbound %s: captcha_mode=admin-webview but no broker is wired (cmd binary forgot Manager.SetCaptchaBroker?)", r.Spec.Tag)
			}
			solver = vkcalls.AdminWebviewCaptchaSolver(r.captchaBroker, r.Spec.Tag, r.Logger)
		default:
			return cs, fmt.Errorf("inbound %s: unsupported vk_calls.captcha_mode %q (use auto|none|admin-webview)", r.Spec.Tag, captchaMode)
		}

		// S1c: оборачиваем base solver auto-replay логикой если пул
		// профилей задан. На пустой пул / fail replay'я / slider
		// challenge — фоллбэк на base (без замедления).
		if solver != nil && r.vkProfileStore != nil {
			solver = vkcalls.WithReplaySolver(r.vkProfileStore, solver, r.Logger)
		}

		codec := ""
		if r.Spec.VKCalls != nil {
			codec = r.Spec.VKCalls.Codec
		}
		cs.VKCalls = &sfu.VKCallsConnect{
			MeetingURL:    meetingURL,
			Role:          role,
			CaptchaSolver: solver,
			Codec:         codec,
		}
	default:
		return cs, fmt.Errorf("inbound %s: unknown transport %q", r.Spec.Tag, kind)
	}
	return cs, nil
}

// Status returns the current state for the admin panel.
func (r *Runner) Status() Status {
	r.mu.Lock()
	phase := r.phase
	lastErr := r.lastError
	startedAt := r.startedAt
	r.mu.Unlock()

	st := Status{
		ID:         r.Spec.ID,
		Tag:        r.Spec.Tag,
		Enabled:    r.Spec.Enabled,
		Running:    phase != "stopped" && phase != "error",
		Phase:      phase,
		LastError:  lastErr,
		Meeting:    r.Spec.Meeting,
		WGEndpoint: r.Spec.WGEndpoint,
		WGIface:    r.Spec.WGInterface,
		StartedAt:  startedAt,
	}
	if b := r.bridge.Load(); b != nil {
		st.TxPackets = b.TxPackets.Load()
		st.TxBytes = b.TxBytes.Load()
		st.RxPackets = b.RxPackets.Load()
		st.RxBytes = b.RxBytes.Load()
	}
	return st
}
