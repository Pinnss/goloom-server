package inbound

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay"
	"github.com/Pinnss/goloom-server/internal/sfu"

	// Side-effect imports — register Telemost / LiveKit / VK Calls
	// Transports with the sfu factory. Pulled in here so
	// cmd/goloom-wg-server doesn't have to know about every transport
	// package; the vkcalls non-blank import below also gives us access
	// to AutoProxyCaptchaSolver for runtime injection.
	_ "github.com/Pinnss/goloom-server/internal/sfu/livekit"
	_ "github.com/Pinnss/goloom-server/internal/sfu/telemost"
	"github.com/Pinnss/goloom-server/pkg/vkauth"

	// Non-blank import — pulls in vkturn.Options for runRelay() and
	// also fires the package init() that registers KindVKTurn with
	// the internal/relay factory. Separate registry from sfu (passive
	// listener vs active SFU client) so the two families stay clean.
	"github.com/Pinnss/goloom-server/internal/relay/vkturn"

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

	// relayHandle is set when Spec.Transport names a relay-family
	// transport (currently only vk-turn). nil for SFU-family
	// inbounds — they use [bridge] instead.
	relayHandle atomic.Pointer[relayHandleBox]

	// captchaBroker is the admin-webview captcha solver bridge.
	// Populated by [Runner.SetCaptchaBroker], typically called by
	// the surrounding [Manager] right after NewRunner. nil disables
	// captcha_mode=admin-webview for this runner.
	captchaBroker vkauth.AdminCaptchaBroker

	// vkProfileStore — пул FP для auto-replay (S1c). Если задан и
	// captcha_mode=admin-webview/auto, base solver оборачивается в
	// [vkauth.WithReplaySolver]. nil → replay выключен.
	vkProfileStore *vkauth.ProfileStore
}

func NewRunner(spec Spec, lg *log.Logger) *Runner {
	tagged := log.New(lg.Writer(), fmt.Sprintf("[inbound:%s] ", spec.Tag), lg.Flags())
	return &Runner{Spec: spec, Logger: tagged, phase: "stopped"}
}

// SetCaptchaBroker swaps in the admin captcha broker used when
// VKCalls.CaptchaMode=="admin-webview". nil clears it.
func (r *Runner) SetCaptchaBroker(b vkauth.AdminCaptchaBroker) {
	r.captchaBroker = b
}

// SetVKProfileStore enables auto-replay для VK captcha (см. S1c).
// Pass nil чтобы отключить — runner вернётся к interactive-only.
func (r *Runner) SetVKProfileStore(s *vkauth.ProfileStore) {
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

// relayHandleBox is a one-field struct so atomic.Pointer has something
// concrete to point at. relay.Handle is an interface; you can't take
// an atomic pointer to an interface value directly.
type relayHandleBox struct {
	h          relay.Handle
	listenAddr string
}

// Run executes one full attempt at standing up the inbound. Dispatch
// is by transport family:
//
//   - SFU family (telemost / vk-calls / livekit-wb-stream / "")
//     → [Runner.runSFU]: dial out via sfu.Transport, bridge through
//     wgrelay to WGEndpoint
//   - Relay family (vk-turn)
//     → [Runner.runRelay]: bind a listener via relay.Relay, forward
//     to WGEndpoint, supervise until ctx cancelled
//
// The two share Phase/Error/Status book-keeping but are otherwise
// completely independent — the SFU code path stays untouched.
func (r *Runner) Run(ctx context.Context) error {
	r.setPhase("starting")
	r.mu.Lock()
	r.startedAt = time.Now()
	r.mu.Unlock()

	if isRelayTransport(r.Spec.Transport) {
		return r.runRelay(ctx)
	}
	return r.runSFU(ctx)
}

// isRelayTransport returns true for transport kinds that belong to
// the listener-shaped [internal/relay] family. Kept as a single switch
// here so the SFU vs relay split is visible in one place.
func isRelayTransport(kind string) bool {
	switch relay.Kind(kind) {
	case relay.KindVKTurn:
		return true
	}
	return false
}

// runSFU is the original SFU-family code path. Unchanged behaviour;
// extracted into its own method so Run can dispatch between SFU and
// relay families without nested ifs.
func (r *Runner) runSFU(ctx context.Context) error {
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
		if meetingURL == "" {
			return cs, fmt.Errorf("inbound %s: transport=vk-calls but no MeetingURL configured", r.Spec.Tag)
		}

		var solver sfu.VKCaptchaSolver
		switch captchaMode {
		case "auto":
			// S1b: AutoProxy на серверной стороне используется редко
			// (нужна desktop-сессия), pool профилей живёт под admin
			// captcha-broker. Передаём nil sink — захвата нет, но и
			// сценарий маргинальный.
			solver = vkauth.AutoProxyCaptchaSolver(2*time.Minute, r.Logger, nil)
		case "none":
			solver = nil
		case "admin-webview":
			if r.captchaBroker == nil {
				return cs, fmt.Errorf("inbound %s: captcha_mode=admin-webview but no broker is wired (cmd binary forgot Manager.SetCaptchaBroker?)", r.Spec.Tag)
			}
			solver = vkauth.AdminWebviewCaptchaSolver(r.captchaBroker, r.Spec.Tag, r.Logger)
		default:
			return cs, fmt.Errorf("inbound %s: unsupported vk_calls.captcha_mode %q (use auto|none|admin-webview)", r.Spec.Tag, captchaMode)
		}

		// S1c: оборачиваем base solver auto-replay логикой если пул
		// профилей задан. На пустой пул / fail replay'я / slider
		// challenge — фоллбэк на base (без замедления).
		if solver != nil && r.vkProfileStore != nil {
			solver = vkauth.WithReplaySolver(r.vkProfileStore, solver, r.Logger)
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

// runRelay is the relay-family code path. Binds a listener via
// [relay.Relay.Start] and idles until ctx fires, then tears down the
// Handle. No SFU session, no wgrelay bridge — the kernel WG endpoint
// at WGEndpoint terminates WG handshakes on its own once the relay
// forwards traffic into it.
func (r *Runner) runRelay(ctx context.Context) error {
	relayCfg, err := r.buildRelayConfig()
	if err != nil {
		r.setError(err)
		return fmt.Errorf("build relay config: %w", err)
	}

	impl, err := relay.Get(relayCfg.kind)
	if err != nil {
		r.setError(err)
		return err
	}

	r.setPhase("starting_listener")
	r.Logger.Printf("starting relay: kind=%s listen=%s → %s", relayCfg.kind, relayCfg.cfg.ListenAddr, relayCfg.cfg.ConnectAddr)
	handle, err := impl.Start(ctx, relayCfg.cfg)
	if err != nil {
		r.setError(err)
		return fmt.Errorf("relay start: %w", err)
	}
	r.relayHandle.Store(&relayHandleBox{h: handle, listenAddr: relayCfg.cfg.ListenAddr})
	defer func() {
		r.relayHandle.Store(nil)
		if err := handle.Close(); err != nil {
			r.Logger.Printf("relay close: %v", err)
		}
	}()

	r.setPhase("relaying")
	r.setError(nil)
	r.Logger.Printf("✓ inbound %s relay listening on %s → %s", r.Spec.Tag, relayCfg.cfg.ListenAddr, r.Spec.WGEndpoint)

	<-ctx.Done()
	r.setPhase("stopped")
	return nil
}

// relayPlan bundles the resolved [relay.Kind] + [relay.Config] so
// runRelay doesn't have to peek at Spec internals.
type relayPlan struct {
	kind relay.Kind
	cfg  relay.Config
}

// buildRelayConfig translates the persisted Spec into a relay.Config
// based on Spec.Transport. Currently only vk-turn lands here.
func (r *Runner) buildRelayConfig() (relayPlan, error) {
	kind := relay.Kind(r.Spec.Transport)
	plan := relayPlan{kind: kind}

	switch kind {
	case relay.KindVKTurn:
		if r.Spec.VKTurn == nil {
			return plan, fmt.Errorf("inbound %s: transport=vk-turn but Spec.VKTurn is nil", r.Spec.Tag)
		}
		if r.Spec.VKTurn.ListenAddr == "" {
			return plan, fmt.Errorf("inbound %s: vk_turn.listen_addr is empty", r.Spec.Tag)
		}
		if r.Spec.WGEndpoint == "" {
			return plan, fmt.Errorf("inbound %s: WGEndpoint required for vk-turn relay (target of forwarded UDP)", r.Spec.Tag)
		}

		opts := vkturn.Options{
			UseWrap: r.Spec.VKTurn.UseWrap,
			Debug:   false,
		}
		if r.Spec.VKTurn.UseWrap {
			key, err := hex.DecodeString(r.Spec.VKTurn.WrapKeyHex)
			if err != nil {
				return plan, fmt.Errorf("inbound %s: vk_turn.wrap_key_hex decode: %w", r.Spec.Tag, err)
			}
			opts.WrapKey = key
		}

		plan.cfg = relay.Config{
			ListenAddr:  r.Spec.VKTurn.ListenAddr,
			ConnectAddr: r.Spec.WGEndpoint,
			Options:     opts,
			Logger:      r.Logger,
		}
		return plan, nil
	default:
		return plan, fmt.Errorf("inbound %s: unknown relay transport %q", r.Spec.Tag, kind)
	}
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
	if rh := r.relayHandle.Load(); rh != nil {
		rs := rh.h.Status()
		st.RelayActive = rs.ActiveConnections
		st.RelayAccepted = rs.TotalAccepted
		st.RelayListen = rs.ListenAddr
		if rs.LastErr != "" && st.LastError == "" {
			st.LastError = rs.LastErr
		}
	}
	return st
}
