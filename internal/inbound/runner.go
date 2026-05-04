package inbound

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/identity"
	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/session"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// isLikelyEmptyRoom recognises the handshake-timeout-with-no-peer error
// shape ("peerID=\"\" gotHello=false …") so the supervisor can treat it
// as "waiting" instead of a hard error in the admin panel.
func isLikelyEmptyRoom(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "handshake timeout") &&
		strings.Contains(s, `peerID=""`) &&
		strings.Contains(s, "gotHello=false")
}

// Runner owns the lifecycle of a single inbound: Telemost session,
// tunnel sender/receivers, and the wgrelay creator. Run blocks until
// the context is cancelled or an unrecoverable error occurs.
type Runner struct {
	Spec   Spec
	Logger *log.Logger

	mu        sync.Mutex
	phase     string
	lastError string
	startedAt time.Time

	creator atomic.Pointer[wgrelay.WGCreator]
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

// Run executes one full attempt at standing up the inbound. Returns when
// ctx is cancelled or a fatal error occurs. The Manager retries with
// backoff on errors.
func (r *Runner) Run(ctx context.Context) error {
	r.setPhase("starting")
	r.mu.Lock()
	r.startedAt = time.Now()
	r.mu.Unlock()

	displayName := identity.NameOrGenerate(r.Spec.DisplayName)
	r.Logger.Printf("display name: %s", displayName)

	sess, err := session.SetupSession(ctx, r.Logger, r.Spec.Meeting, displayName)
	if err != nil {
		r.setError(err)
		return fmt.Errorf("session setup: %w", err)
	}
	defer sess.Close()

	go session.RunOpusSilenceLoop(ctx, r.Logger, sess.AudioTrack)
	go session.RunKeyframeRefresh(ctx, r.Logger, sess.VideoTrack)
	if err := session.SendInitialKeyframes(r.Logger, sess.VideoTrack, 10); err != nil {
		r.setError(err)
		return fmt.Errorf("camera keyframe warmup: %w", err)
	}

	merged := make(chan tunnel.ReceivedFrame, 512)
	go func() {
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
				rcv := tunnel.NewReceiver(256)
				go rcv.Run(ctx, tr, r.Logger)
				go func(recv *tunnel.Receiver) {
					for f := range recv.Frames() {
						select {
						case merged <- f:
						case <-ctx.Done():
							return
						}
					}
				}(rcv)
			}
		}
	}()

	r.setPhase("waiting_peer")
	r.Logger.Printf("WAIT waiting for client peer...")
	if _, err := sess.WaitForPeer(ctx, 5*time.Minute); err != nil {
		r.setError(err)
		return fmt.Errorf("wait for peer: %w", err)
	}

	// Until a real client completes the in-tunnel HELLO/ACK handshake,
	// surface the inbound as "waiting_for_client" — the SFU's empty-room
	// "ghost peer" doesn't reply, but that's not an error condition for
	// the operator to act on. The phase flips to "relaying" on success.
	r.setPhase("waiting_for_client")
	r.Logger.Printf("WAIT peer detected, starting handshake")

	cameraSender := tunnel.NewSender(sess.VideoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP8BlackKeyframe
	cameraSender.Start()
	defer cameraSender.Close()

	peerID, err := session.Handshake(ctx, r.Logger, sess, cameraSender, merged, 1)
	if err != nil {
		// Handshake timeouts before anyone connected aren't real
		// failures — the SFU just shows the empty meeting as having a
		// "ghost" peer (residual tracks, our own subscriber view, etc.)
		// and we wait for HELLO that never comes. Clear the error and
		// surface this as the dedicated "waiting_for_client" phase so
		// the panel doesn't scream red until a client actually joins.
		if isLikelyEmptyRoom(err) {
			r.mu.Lock()
			r.lastError = ""
			r.phase = "waiting_for_client"
			r.mu.Unlock()
			r.Logger.Printf("HANDSHAKE: no client connected yet — supervisor will retry shortly")
			return fmt.Errorf("handshake: %w", err)
		}
		r.setError(err)
		return fmt.Errorf("handshake: %w", err)
	}
	r.Logger.Printf("HANDSHAKE ✓ peer=%s", peerID)

	pushKeyframeOnPLI := session.MakeKeyframePusher(sess.VideoTrack, r.Logger, 100*time.Millisecond)
	session.StartRTCPLoop(ctx, r.Logger, "PUB-rtcp", sess.Pub.PC, pushKeyframeOnPLI)

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

	dt := wgrelay.New(cameraSender, merged, r.Logger)
	creator := wgrelay.NewCreator(r.Spec.WGEndpoint, dt, r.Logger)
	r.creator.Store(creator)

	go dt.Run(ctx)

	r.setPhase("relaying")
	r.setError(nil)
	r.Logger.Printf("✓ inbound %s relaying to %s", r.Spec.Tag, r.Spec.WGEndpoint)

	if err := creator.Run(ctx); err != nil && err != wgrelay.ErrTunnelClosed {
		r.setError(err)
		return fmt.Errorf("creator: %w", err)
	}
	r.setPhase("stopped")
	return nil
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
	if c := r.creator.Load(); c != nil {
		st.TxPackets = c.TxPackets.Load()
		st.TxBytes = c.TxBytes.Load()
		st.RxPackets = c.RxPackets.Load()
		st.RxBytes = c.RxBytes.Load()
	}
	return st
}
