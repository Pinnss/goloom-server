// Session adapts the videocode tunnel + peer signaling stack to the
// generic [sfu.Session] interface, so wgrelay/runner can drive a VK
// Calls inbound exactly like Telemost or LiveKit. Externally we expose
// `Send(payload)` + `Frames() <-chan []byte` + lifecycle plumbing;
// internally we own:
//
//   - the [peer] (WS + PC + signaling)
//   - the videocode Sender (encodes app payloads into H.264 frames
//     written to the local video track)
//   - the videocode Receiver (decodes inbound H.264 from the remote
//     video track back into bundle payloads)
//   - a Fragmenter / Defragmenter pair that preserves WG-datagram
//     boundaries across the videocode bundle layer
//
// Goroutine map at steady state:
//
//	peer.run         — WS read loop (notification dispatch)
//	Sender.Run       — paces encoded frames at videocode.EncodeFPS
//	Receiver.HandleTrack — RTP read loop on the remote video track
//	pumpFrames       — Defragmenter loop turning Receiver.RecvCh into
//	                   complete-datagram emissions on Session.incoming
//
// All goroutines watch the session ctx; Close() cancels it, then
// closes the WS / PC, then waits for goroutines to exit before
// closing the incoming channel.

package vkcalls

import (
	"context"
	"errors"
	"log"
	"net/url"
	"sync"

	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls/videocode"
)

// Session implements [sfu.Session] over a connected VK Calls peer.
//
// Also implements [sfu.ICEHostsProvider] — clients use the host list
// to set up route exclusions so the WG default-route doesn't capture
// the very pion sockets we use to talk to the SFU.
type Session struct {
	logger *log.Logger
	auth   *AuthResult
	peer   *peer

	sender   *videocode.Sender
	receiver *videocode.Receiver

	fragmenter   *videocode.Fragmenter
	defragmenter *videocode.Defragmenter

	ctx    context.Context
	cancel context.CancelFunc

	incoming chan []byte

	doneOnce sync.Once
	done     chan struct{}
	errMu    sync.Mutex
	errSlot  error

	closed sync.Once
}

// newSession wires a connected peer + freshly-created videocode pumps
// together and starts the data-plane goroutines. The peer must already
// be in PeerConnectionStateConnected.
func newSession(parentCtx context.Context, lg *log.Logger, auth *AuthResult, p *peer, sender *videocode.Sender, receiver *videocode.Receiver) *Session {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &Session{
		logger:       lg,
		auth:         auth,
		peer:         p,
		sender:       sender,
		receiver:     receiver,
		fragmenter:   videocode.NewFragmenter(),
		defragmenter: videocode.NewDefragmenter(),
		ctx:          ctx,
		cancel:       cancel,
		incoming:     make(chan []byte, 512),
		done:         make(chan struct{}),
	}

	// Sender pump — paces encoded frames at videocode's internal FPS.
	go s.sender.Run(ctx)

	// Receiver-side defragmenter: drain Receiver.RecvCh, feed bytes
	// into Defragmenter, emit complete WG datagrams on Session.incoming.
	go s.pumpFrames(ctx)

	// Watch the underlying peer's lifecycle — when its WS dies, our
	// Session is dead too.
	go func() {
		select {
		case <-p.Done():
			s.signalDone(p.Err())
		case <-ctx.Done():
		}
	}()

	return s
}

// Send fragments the payload, queues each fragment on the videocode
// Sender. Returns immediately — the Sender pump pulls bytes off the
// queue at frame-pace.
func (s *Session) Send(payload []byte) error {
	select {
	case <-s.done:
		return sfu.ErrSessionClosed
	default:
	}
	frags := s.fragmenter.Fragment(payload)
	for _, frag := range frags {
		if err := s.sender.Send(s.ctx, frag); err != nil {
			return sfu.ErrSessionClosed
		}
	}
	return nil
}

func (s *Session) Frames() <-chan []byte { return s.incoming }
func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.errSlot
}

// Close tears down the videocode pumps + the peer. Idempotent.
func (s *Session) Close() error {
	s.closed.Do(func() {
		s.cancel()
		if s.peer != nil {
			s.peer.Close()
		}
		s.signalDone(nil)
	})
	return nil
}

// ICEHosts returns the dynamically-discovered TURN/STUN endpoints
// from the join response, plus the hostname of the call's WS
// endpoint. Implements [sfu.ICEHostsProvider].
func (s *Session) ICEHosts() []string {
	if s.auth == nil {
		return nil
	}
	hosts := make(map[string]struct{})
	add := func(raw string) {
		if h := extractURLHost(raw); h != "" {
			hosts[h] = struct{}{}
		}
	}
	for _, u := range s.auth.TurnURLs {
		add(u)
	}
	for _, u := range s.auth.StunURLs {
		add(u)
	}
	add(s.auth.WSEndpoint)

	// Static helpers — auth + signaling endpoints we hit before the
	// dynamic TURN/STUN list is known. Hard-coded so VPN clients can
	// pre-exclude them at default-route capture time.
	for _, h := range []string{
		"vk.com",
		"id.vk.com",
		"id.vk.ru",
		"login.vk.ru",
		"api.vk.com",
		"calls.okcdn.ru",
		"videowebrtc.okcdn.ru",
	} {
		hosts[h] = struct{}{}
	}

	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out
}

// pumpFrames drains the videocode Receiver's frame channel, feeds raw
// payloads into the Defragmenter, and emits complete datagrams on
// s.incoming. Runs until ctx is cancelled or Receiver shuts down.
func (s *Session) pumpFrames(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-s.receiver.RecvCh():
			if !ok {
				return
			}
			if len(frame.Payload) == 0 {
				continue
			}
			if complete := s.defragmenter.Feed(frame.Payload); complete != nil {
				select {
				case s.incoming <- complete:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Session) signalDone(err error) {
	s.doneOnce.Do(func() {
		s.errMu.Lock()
		if s.errSlot == nil && err != nil {
			s.errSlot = err
		}
		s.errMu.Unlock()
		close(s.done)
		// Defer incoming-close so any in-flight pumpFrames
		// emissions don't write to a closed channel.
		go func() {
			defer func() { _ = recover() }()
			close(s.incoming)
		}()
	})
}

// extractURLHost pulls hostname out of a stun:/turn:/wss: URL.
func extractURLHost(raw string) string {
	// stun:host:port and turn:host:port are NOT valid URLs to net/url
	// (no // — they're URI not URL). Manual parse for those.
	for _, prefix := range []string{"stun:", "turn:", "turns:"} {
		if len(raw) > len(prefix) && raw[:len(prefix)] == prefix {
			rest := raw[len(prefix):]
			// Strip params after `?`.
			if i := indexAny(rest, "?#"); i >= 0 {
				rest = rest[:i]
			}
			if i := indexAny(rest, ":"); i >= 0 {
				return rest[:i]
			}
			return rest
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func indexAny(s, chars string) int {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}

// Compile-time interface assertions.
var _ sfu.Session = (*Session)(nil)
var _ sfu.ICEHostsProvider = (*Session)(nil)
var _ = errors.New // future use
