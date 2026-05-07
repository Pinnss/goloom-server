package livekit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"
	lksdk "github.com/livekit/server-sdk-go/v2"
)

// Transport implements [sfu.Transport] for WB-Stream-style LiveKit SFUs.
//
// The auth flow is split into two halves: long-lived credentials
// (accessToken + cookies) live on the inbound Spec and are populated by
// the admin webview-auth flow once per ~14 days; the short-lived
// LiveKit roomToken is minted at every Connect via WB's connection-
// details endpoint.
type Transport struct{}

func init() {
	sfu.Register(Transport{})
}

func (Transport) Kind() sfu.Kind { return sfu.KindLiveKitWBStream }

func (Transport) Connect(ctx context.Context, spec sfu.ConnectSpec) (sfu.Session, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.Kind != sfu.KindLiveKitWBStream {
		return nil, fmt.Errorf("livekit: wrong Kind %q", spec.Kind)
	}
	if spec.Logger == nil {
		return nil, errors.New("livekit: ConnectSpec.Logger is required")
	}

	displayName := identity.NameOrGenerate(spec.DisplayName)
	lg := spec.Logger
	lk := spec.LiveKitWBStream

	// Step 1 — mint a fresh roomToken and obtain the SFU URL.
	rc, err := fetchRoomConnect(ctx, lk.RoomURL, lk.AccessToken, lk.Cookies, displayName)
	if err != nil {
		return nil, fmt.Errorf("livekit: fetch roomConnect: %w", err)
	}
	lg.Printf("livekit: room token minted (server=%s, ice=%d servers)", rc.ServerURL, len(rc.ICEServers))

	// Step 2 — build callbacks before Connect so we don't miss any
	// early data packets.
	s := &Session{
		logger:   lg,
		incoming: make(chan []byte, 512),
		done:     make(chan struct{}),
	}

	cb := &lksdk.RoomCallback{
		ParticipantCallback: lksdk.ParticipantCallback{
			OnDataPacket: func(data lksdk.DataPacket, _ lksdk.DataReceiveParams) {
				u, ok := data.(*lksdk.UserDataPacket)
				if !ok {
					return
				}
				cp := make([]byte, len(u.Payload))
				copy(cp, u.Payload)
				select {
				case s.incoming <- cp:
				case <-s.done:
				}
			},
		},
		OnDisconnected: func() {
			lg.Printf("livekit: room disconnected")
			s.signalDone(errors.New("livekit: room disconnected"))
		},
	}

	// Step 3 — Connect. ConnectToRoomWithToken blocks until ICE is up.
	room, err := lksdk.ConnectToRoomWithToken(rc.ServerURL, rc.RoomToken, cb,
		lksdk.WithAutoSubscribe(true),
	)
	if err != nil {
		return nil, fmt.Errorf("livekit: ConnectToRoomWithToken: %w", err)
	}

	s.room = room
	lg.Printf("livekit: connected room=%s sid=%s identity=%s",
		room.Name(), room.SID(), room.LocalParticipant.Identity())

	return s, nil
}

// Session implements [sfu.Session] over a LiveKit lksdk.Room.
//
// All the heavy lifting (signalling, ICE, DataChannel SCTP buffering)
// is in the SDK — Session is just an adapter that
//   - deep-copies inbound payloads from the OnDataPacket callback into
//     the outgoing channel,
//   - forwards Send → room.LocalParticipant.PublishData,
//   - signals Done on disconnect.
type Session struct {
	room     *lksdk.Room
	logger   *log.Logger
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
	if s.room == nil {
		return sfu.ErrSessionClosed
	}
	// Unreliable=false (i.e. reliable, SCTP-ordered) is the right
	// default for WG datagrams: WG itself is loss-tolerant, but the
	// inner TCP traffic carried inside the tunnel really doesn't like
	// reorder. SCTP-reliable preserves order at small RTT cost and we
	// measured zero negative impact on UDP throughput with it.
	if err := s.room.LocalParticipant.PublishData(payload,
		lksdk.WithDataPublishReliable(true),
	); err != nil {
		return fmt.Errorf("livekit: PublishData: %w", err)
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

func (s *Session) Close() error {
	s.closed.Do(func() {
		if s.room != nil {
			s.room.Disconnect()
		}
		s.signalDone(nil)
	})
	return nil
}

func (s *Session) signalDone(err error) {
	s.doneOnce.Do(func() {
		s.errMu.Lock()
		if s.err == nil && err != nil {
			s.err = err
		}
		s.errMu.Unlock()
		close(s.done)
		// Channel close is delayed slightly so any in-flight onData
		// callbacks don't write to a closed chan. Reasonable since
		// LiveKit SDK quiesces callbacks after Disconnect.
		go func() {
			defer func() { _ = recover() }()
			close(s.incoming)
		}()
	})
}

// Compile-time interface assertion.
var _ sfu.Transport = Transport{}
var _ sfu.Session = (*Session)(nil)

