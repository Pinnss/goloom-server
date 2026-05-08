// Transport orchestrator for VK Calls. Wires the auth chain, the WS
// signalling channel, the pion PeerConnection, and the videocode
// tunnel into a [sfu.Session] that wgrelay can drive.
//
// Connect() is the heavy lift:
//
//	1. validate spec
//	2. DoAuth — 4-step ladder, surfaces the captcha to spec.CaptchaSolver
//	3. dialPeer — open the OK Calls SDK WS
//	4. allocate videocode.Receiver (connected to the future remote
//	   video track via the OnTrack callback registered in buildPC)
//	5. buildPC — pion PC + Opus/H264 tracks + ICE callbacks
//	6. start peer.run() — drives the signaling loop
//	7. waitConnected — block until PeerConnectionStateConnected
//	8. allocate videocode.Sender on the local track
//	9. wrap the lot in a Session and hand it back
//
// Caller is "join second"; Receiver is "join first". For goloom's
// standard topology the server inbound runs as receiver (waits for
// clients), and clients run as caller. This is configurable via
// sfu.VKCallsConnect.Role; empty defaults to "receiver".
package vkcalls

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls/videocode"
)

// Transport implements [sfu.Transport] for VK Calls.
type Transport struct{}

func init() {
	sfu.Register(Transport{})
}

func (Transport) Kind() sfu.Kind { return sfu.KindVKCalls }

func (Transport) Connect(ctx context.Context, spec sfu.ConnectSpec) (sfu.Session, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.Kind != sfu.KindVKCalls {
		return nil, fmt.Errorf("vkcalls: wrong Kind %q", spec.Kind)
	}
	if spec.Logger == nil {
		return nil, errors.New("vkcalls: ConnectSpec.Logger is required")
	}

	vk := spec.VKCalls
	role := vk.Role
	if role == "" {
		role = "receiver"
	}
	displayName := identity.NameOrGenerate(spec.DisplayName)
	lg := spec.Logger

	// 1. auth.
	shortID := extractShortID(vk.MeetingURL)
	if shortID == "" {
		return nil, fmt.Errorf("vkcalls: could not extract short id from MeetingURL %q (expected …/call/join/<id> or bare id)", vk.MeetingURL)
	}
	authSpec := AuthSpec{
		ShortID:  shortID,
		Name:     displayName,
		DeviceID: uuid.NewString(),
		Solver:   vk.CaptchaSolver,
	}
	auth, err := DoAuth(ctx, lg, authSpec)
	if err != nil {
		return nil, fmt.Errorf("vkcalls: auth: %w", err)
	}
	lg.Printf("vkcalls: auth ✓ peerId=%s userId=%s", auth.PeerID, auth.UserID)

	// 2. dial WS, build the peer envelope.
	p, err := dialPeer(ctx, lg, auth, role)
	if err != nil {
		return nil, err
	}

	// We own the peer until either Connect succeeds (Session takes
	// over) or fails (we have to clean up).
	releaseOnError := p.Close
	defer func() {
		if releaseOnError != nil {
			releaseOnError()
		}
	}()

	// 3. allocate the videocode receive pipeline. The receiver gets
	// wired into buildPC's OnTrack callback so RTP starts flowing the
	// instant the SFU subscribes us to the remote track.
	receiver := videocode.NewReceiver()
	receiver.SetTag("vkcalls-rx")

	// 4. build PC + register OnTrack.
	if err := p.buildPC(ctx, receiver); err != nil {
		return nil, fmt.Errorf("vkcalls: buildPC: %w", err)
	}

	// 5. start the signaling loop. peer.run() owns ws teardown after
	// this point.
	go p.run(ctx)

	// 6. block until PC is connected, then snap up the local video
	// track for the outbound videocode Sender.
	if err := p.waitConnected(ctx, peerConnectTimeout); err != nil {
		return nil, fmt.Errorf("vkcalls: %w", err)
	}
	lg.Printf("vkcalls: peer connected (role=%s)", role)

	if p.videoTrack == nil {
		return nil, errors.New("vkcalls: peer connected but local video track is nil (buildPC bug)")
	}
	sender := videocode.NewSender(p.videoTrack)
	sender.SetTag("vkcalls-tx")

	// 7. wrap and ship.
	sess := newSession(ctx, lg, auth, p, sender, receiver)
	releaseOnError = nil // success — sess.Close now owns teardown.
	return sess, nil
}

// peerConnectTimeout caps how long we'll wait between WS-up and PC=
// Connected. Generous — VK auth can be slow when the captcha solver
// is interactive (web browser pop-up etc.) but the connect itself is
// usually well under 10 s once both peers are present.
const peerConnectTimeout = 5 * time.Minute
