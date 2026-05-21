package inbound

import (
	"context"
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
	"github.com/Pinnss/goloom-server/pkg/vkauth"

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

// Run executes one full attempt at standing up the inbound.
func (r *Runner) Run(ctx context.Context) error {
	r.setPhase("starting")
	r.mu.Lock()
	r.startedAt = time.Now()
	r.mu.Unlock()

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
