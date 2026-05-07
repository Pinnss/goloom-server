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

	// Side-effect imports — register Telemost and LiveKit Transports
	// with the sfu factory. Pulled in here so cmd/goloom-wg-server doesn't
	// have to know about every transport package.
	_ "github.com/Pinnss/goloom-server/internal/sfu/livekit"
	_ "github.com/Pinnss/goloom-server/internal/sfu/telemost"

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
}

func NewRunner(spec Spec, lg *log.Logger) *Runner {
	tagged := log.New(lg.Writer(), fmt.Sprintf("[inbound:%s] ", spec.Tag), lg.Flags())
	return &Runner{Spec: spec, Logger: tagged, phase: "stopped"}
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
