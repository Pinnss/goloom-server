// Package telemost adapts the legacy Yandex Telemost transport to the
// generic sfu.Transport / sfu.Session interfaces.
//
// All the existing pion-based handshake / VP8-faked tunnel code lives
// under internal/session and internal/wgrelay; this package just wraps
// it so callers (runner.go) don't have to deal with Telemost-specific
// types. The wrapping cost is one extra goroutine that pumps frames
// from the existing wgrelay.DataTunnel onCalls into our outgoing
// channel — everything else is delegated.
package telemost

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/identity"
	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/session"
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// urlParse is a thin wrapper exposed so Session.ICEHosts can use it
// without dragging net/url into method-receiver scope. (Go doesn't let
// us use the std-lib name as a method dependency directly.)
var urlParse = url.Parse

// idleWaitForPeer is effectively "wait forever" for a peer to join. The real
// exit during idle is the session dying (Client.IsClosed, driven by the ping
// liveness watchdog), not this timer. We do NOT tear down and re-join the room
// on a short timer: each re-join churns the Telemost room and, over thousands
// of idle cycles, degrades the SFU until it stops forwarding our video to a
// new subscriber (the client then hangs in handshake). The year-long value is
// only a last-resort backstop against an unforeseen stuck state.
const idleWaitForPeer = 365 * 24 * time.Hour

// Compile-time interface assertion — fails the build if Session no
// longer implements ICEHostsProvider.
var _ sfu.ICEHostsProvider = (*Session)(nil)

// Transport implements [sfu.Transport] for Telemost.
type Transport struct{}

func init() {
	sfu.Register(Transport{})
}

func (Transport) Kind() sfu.Kind { return sfu.KindTelemost }

func (Transport) Connect(ctx context.Context, spec sfu.ConnectSpec) (sfu.Session, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.Kind != sfu.KindTelemost && spec.Kind != "" {
		return nil, fmt.Errorf("telemost: wrong Kind %q", spec.Kind)
	}
	if spec.Logger == nil {
		return nil, errors.New("telemost: ConnectSpec.Logger is required")
	}

	displayName := identity.NameOrGenerate(spec.DisplayName)
	lg := spec.Logger

	// Resolve side filtering for the pool architecture. "server" stamps
	// outbound frames with FlagFromServer and drops inbound frames bearing
	// it (same-side cross-talk). "client" inverts: stamps nothing on
	// outbound, drops inbound frames WITHOUT FlagFromServer set. "" (the
	// legacy single-instance default) disables filtering on both sides.
	var sendSideFlag, dropSideFlag tunnel.Flags
	switch spec.Side {
	case "server":
		sendSideFlag = tunnel.FlagFromServer
		dropSideFlag = tunnel.FlagFromServer
	case "client":
		sendSideFlag = 0
		// Client receivers drop frames that DON'T have FlagFromServer set;
		// we encode that as DropFlag=FlagFromServer with negation handled
		// at the Receiver layer via [Receiver.DropFlag] semantics. Since
		// our current Receiver does positive-match drop, the client side
		// uses 0 here — bot-to-bot cross-talk on the client side only
		// hurts if there are multiple client bots (out of scope for the
		// initial server-pool deployment).
		dropSideFlag = 0
	}

	sess, err := session.SetupSession(ctx, lg, spec.Telemost.MeetingURL, displayName)
	if err != nil {
		return nil, fmt.Errorf("telemost: SetupSession: %w", err)
	}

	// From this point on, we own teardown until either Connect returns
	// the wrapped Session (caller takes ownership) or we error out and
	// have to roll back.
	releaseOnError := sess.Close
	defer func() {
		if releaseOnError != nil {
			releaseOnError()
		}
	}()

	go session.RunOpusSilenceLoop(ctx, lg, sess.AudioTrack)
	go session.RunKeyframeRefresh(ctx, lg, sess.VideoTrack)
	if err := session.SendInitialKeyframes(lg, sess.VideoTrack, 10); err != nil {
		return nil, fmt.Errorf("telemost: keyframe warmup: %w", err)
	}

	merged := make(chan tunnel.ReceivedFrame, 512)
	go pumpVideoTracks(ctx, lg, sess, merged, dropSideFlag)

	// Wait for the remote peer to appear and complete the in-band
	// HELLO/HELLO_ACK exchange. Failures here propagate to the caller
	// before any goroutine ownership is transferred.
	if _, err := sess.WaitForPeer(ctx, idleWaitForPeer); err != nil {
		return nil, fmt.Errorf("telemost: wait for peer: %w", err)
	}

	cameraSender := tunnel.NewSender(sess.VideoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP9BlackKeyframe
	cameraSender.InterframePrefix = mediastubs.VP9InterframeHeader
	cameraSender.SideFlag = sendSideFlag
	cameraSender.Logger = lg // backpressure-drop diagnostics (2026-06-25)
	cameraSender.Start()

	peerID, err := session.Handshake(ctx, lg, sess, cameraSender, merged, 1)
	if err != nil {
		cameraSender.Close()
		return nil, fmt.Errorf("telemost: handshake: %w", err)
	}
	lg.Printf("telemost: handshake ✓ peer=%s", peerID)

	pushKeyframeOnPLI := session.MakeKeyframePusher(sess.VideoTrack, lg, 100*time.Millisecond)
	session.StartRTCPLoop(ctx, lg, "PUB-rtcp", sess.Pub.PC, pushKeyframeOnPLI)

	// Periodic slot rebinds — copied from the original runner.go: SFU
	// sometimes drops our subscription, this nudges it back. Independent
	// of session lifetime; the goroutine watches ctx.
	go func() {
		for i, delay := range []time.Duration{3 * time.Second, 8 * time.Second, 15 * time.Second} {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				_ = sess.RebindSlots(ctx, 4+i)
			}
		}
	}()

	dt := wgrelay.New(cameraSender, merged, lg)

	s := &Session{
		dt:           dt,
		cameraSender: cameraSender,
		sess:         sess,
		logger:       lg,
		meetingURL:   spec.Telemost.MeetingURL,
		incoming:     make(chan []byte, 512),
		done:         make(chan struct{}),
	}
	dt.SetOnData(s.onData)
	dt.SetOnClose(s.onTunnelClose)

	// Run the dt loop; it consumes merged and dispatches to onData.
	// When the underlying PC dies (or peer rehandshakes), dt.Run
	// returns, signalClose fires, we propagate to the consumer.
	go s.runTunnel(ctx)

	releaseOnError = nil // success — Session.Close now owns teardown.
	return s, nil
}

// pumpVideoTracks subscribes to every fresh remote video track and feeds
// its decoded frames into `merged`. Lifted verbatim from runner.go and
// the desktop client. dropSideFlag, if non-zero, makes each receiver
// silently drop frames stamped with that flag — used by SFU pool
// members to ignore other same-side pool members' broadcast frames.
func pumpVideoTracks(ctx context.Context, lg *log.Logger, sess *session.Session, merged chan<- tunnel.ReceivedFrame, dropSideFlag tunnel.Flags) {
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
			rcv.DropFlag = dropSideFlag
			go rcv.Run(ctx, tr, lg)
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
}

// Session implements [sfu.Session] over the legacy Telemost stack.
//
// Also implements [sfu.ICEHostsProvider] — clients use this to populate
// route-exclusion lists so their own WG default-route doesn't swallow
// the very pion sockets we're using to talk to Telemost.
type Session struct {
	dt           *wgrelay.DataTunnel
	cameraSender *tunnel.Sender
	sess         *session.Session
	logger       *log.Logger
	meetingURL   string

	incoming chan []byte

	doneOnce sync.Once
	done     chan struct{}

	errMu sync.Mutex
	err   error

	closed sync.Once
}

func (s *Session) Send(payload []byte) error {
	select {
	case <-s.done:
		return sfu.ErrSessionClosed
	default:
	}
	if err := s.dt.Send(payload); err != nil {
		// Map wgrelay's "tunnel closed" error to our public sentinel.
		return sfu.ErrSessionClosed
	}
	return nil
}

func (s *Session) Frames() <-chan []byte { return s.incoming }
func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

// ICEHosts returns the union of well-known Telemost service hosts and
// the dynamically-advertised ICE/TURN/STUN servers from serverHello.
//
// Implements [sfu.ICEHostsProvider]. Returns deduplicated hostnames
// without scheme/port.
func (s *Session) ICEHosts() []string {
	hosts := make(map[string]struct{})

	// Static hosts (always needed for the bootstrap HTTP /connection
	// + websocket dial, which happen before serverHello arrives).
	for _, h := range []string{
		"cloud-api.yandex.ru",
		"telemost.yandex.ru",
		"goloom.strm.yandex.net",
		"strm.yandex.net",
	} {
		hosts[h] = struct{}{}
	}

	// Meeting URL host (rarely differs from telemost.yandex.ru, but
	// staging links sometimes do).
	if u, err := urlParse(s.meetingURL); err == nil && u.Host != "" {
		hosts[u.Host] = struct{}{}
	}

	// Dynamically-discovered TURN/STUN — only available once
	// serverHello has been received during SetupSession.
	if hello := s.sess.ServerHello(); hello != nil {
		for _, ice := range hello.RtcConfiguration.ICEServers {
			for _, raw := range ice.URLs {
				if h := ExtractICEHost(raw); h != "" {
					hosts[h] = struct{}{}
				}
			}
		}
	}

	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out
}

func (s *Session) Close() error {
	s.closed.Do(func() {
		_ = s.dt.Close()
		s.cameraSender.Close()
		s.sess.Close()
		s.signalDone(nil)
	})
	return nil
}

// onData is wired into wgrelay.DataTunnel.SetOnData; it forwards each
// inbound payload (deep-copied — the dt buffer is reused) into our
// outgoing channel.
func (s *Session) onData(payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case s.incoming <- cp:
	case <-s.done:
	}
}

// onTunnelClose fires when wgrelay.DataTunnel.Run exits — either
// ctx-cancel, channel closure, or peer-rehandshake. It does NOT mean
// Session.Close has been called yet; the consumer may still want to
// drain incoming.
func (s *Session) onTunnelClose() {
	var err error
	if s.dt.NeedsRehandshake() {
		err = sfu.ErrPeerRehandshake
	}
	s.signalDone(err)
}

func (s *Session) runTunnel(ctx context.Context) {
	s.dt.Run(ctx)
	// signalDone already invoked via onTunnelClose; nothing else to
	// do here. Don't close incoming yet — let Close handle it so a
	// graceful drain is possible.
}

func (s *Session) signalDone(err error) {
	s.doneOnce.Do(func() {
		s.errMu.Lock()
		if s.err == nil {
			s.err = err
		}
		s.errMu.Unlock()
		close(s.done)
		// Drain into incoming-close happens in Close().
		go func() {
			// Only close incoming once we know no more onData calls
			// can land — safest is after a small grace period since
			// onData may race with Run's exit.
			time.Sleep(50 * time.Millisecond)
			defer func() { _ = recover() }()
			close(s.incoming)
		}()
	})
}
