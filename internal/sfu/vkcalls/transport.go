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
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"

	"github.com/Pinnss/goloom-server/internal/identity"
	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls/videocode"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
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

	codec := vk.Codec
	if codec == "" {
		codec = "h264"
	}
	lg.Printf("vkcalls: video codec=%s", codec)

	// 2. dial WS, build the peer envelope.
	p, err := dialPeer(ctx, lg, auth, role, codec)
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

	switch codec {
	case "vp8":
		sess, err := connectVP8(ctx, lg, auth, p, role)
		if err != nil {
			return nil, err
		}
		releaseOnError = nil
		return sess, nil
	default:
		sess, err := connectH264(ctx, lg, auth, p, role)
		if err != nil {
			return nil, err
		}
		releaseOnError = nil
		return sess, nil
	}
}

// connectH264 — оригинальный путь на videocode (RS I_PCM grid).
// Сохраняем как fallback пока VP8 не подтверждён в проде.
func connectH264(ctx context.Context, lg *log.Logger, auth *AuthResult, p *peer, role string) (sfu.Session, error) {
	receiver := videocode.NewReceiver()
	receiver.SetTag("vkcalls-rx")

	if err := p.buildPC(ctx, receiver); err != nil {
		return nil, fmt.Errorf("vkcalls: buildPC: %w", err)
	}
	go p.run(ctx)
	if err := p.waitConnected(ctx, peerConnectTimeout); err != nil {
		return nil, fmt.Errorf("vkcalls: %w", err)
	}
	lg.Printf("vkcalls: peer connected (role=%s)", role)
	if p.videoTrack == nil {
		return nil, errors.New("vkcalls: peer connected but local video track is nil (buildPC bug)")
	}
	sender := videocode.NewSender(p.videoTrack)
	sender.SetTag("vkcalls-tx")
	return newSession(ctx, lg, auth, p, sender, receiver), nil
}

// connectVP8 — VP8-faked frames через [internal/tunnel] + wgrelay,
// тот же стек что Telemost. Целевая throughput выше H.264 (по PoC
// findings) за счёт отсутствия RS-overhead и менее агрессивного
// shaping'а на VP8 video tracks у VK SFU.
func connectVP8(ctx context.Context, lg *log.Logger, auth *AuthResult, p *peer, role string) (sfu.Session, error) {
	if err := p.buildPC(ctx, nil); err != nil {
		return nil, fmt.Errorf("vkcalls: buildPC vp8: %w", err)
	}
	go p.run(ctx)
	if err := p.waitConnected(ctx, peerConnectTimeout); err != nil {
		return nil, fmt.Errorf("vkcalls: %w", err)
	}
	lg.Printf("vkcalls: peer connected (role=%s)", role)
	if p.videoTrack == nil {
		return nil, errors.New("vkcalls: peer connected but local video track is nil (buildPC bug)")
	}

	cameraSender := tunnel.NewSender(p.videoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP8BlackKeyframe
	cameraSender.Start()

	merged := make(chan tunnel.ReceivedFrame, 512)
	go pumpRemoteVP8Tracks(ctx, lg, p.remoteTracks, merged)

	dt := wgrelay.New(cameraSender, merged, lg)
	return newVP8Session(ctx, lg, auth, p, cameraSender, dt), nil
}

// pumpRemoteVP8Tracks подписывается на каждый новый remote video
// track из buildPC OnTrack и оборачивает в tunnel.Receiver. Все
// receiver'ы сливают frames в `merged` для wgrelay.DataTunnel.
func pumpRemoteVP8Tracks(ctx context.Context, lg *log.Logger, tracks <-chan *webrtc.TrackRemote, merged chan<- tunnel.ReceivedFrame) {
	idx := 0
	for {
		select {
		case <-ctx.Done():
			return
		case tr, ok := <-tracks:
			if !ok {
				return
			}
			idx++
			rcv := tunnel.NewReceiver(256)
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

// peerConnectTimeout caps how long we'll wait between WS-up and PC=
// Connected. Generous — VK auth can be slow when the captcha solver
// is interactive (web browser pop-up etc.) but the connect itself is
// usually well under 10 s once both peers are present.
const peerConnectTimeout = 5 * time.Minute
