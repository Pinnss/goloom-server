// Stages 1-6 wiring shared with PoC #1. Gathers everything into a Session
// the rest of poc2a can pull from (signal client, both peer wrappers, the
// publisher tracks, the goloom IDs we negotiated).
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"

	"github.com/Pinnss/goloom-server/internal/api"
	"github.com/Pinnss/goloom-server/internal/goloom"
	"github.com/Pinnss/goloom-server/internal/peer"
)

// Session holds everything the test phases need after connect.
type Session struct {
	Logger            *log.Logger
	Conn              *api.ConnectionResponse
	Client            *goloom.Client
	Pub               *peer.Wrapper
	Sub               *peer.Wrapper
	AudioTrack        *webrtc.TrackLocalStaticSample
	VideoTrack        *webrtc.TrackLocalStaticSample
	DisplayAudioTrack *webrtc.TrackLocalStaticSample // populated by SetupScreenShare
	DisplayVideoTrack *webrtc.TrackLocalStaticSample // populated by SetupScreenShare

	mu            sync.Mutex
	knownPeers    map[string]string        // participantId -> name (from updateDescription/upsertDescription)
	newVideoTrack chan *webrtc.TrackRemote // every fresh remote video track is pushed here
	dcDefault     *webrtc.DataChannel

	// Persistent channels — handler always pushes; consumers (SetupSession,
	// SetupScreenShare) drain when needed.
	srvHelloCh  chan *goloom.ServerHello
	pubAnswerCh chan *goloom.PublisherSdpAnswer
	subOfferCh  chan *goloom.SubscriberSdpOffer
	slotsCh     chan ParsedSlotsConfig

	// subRenegoDone is closed after the first successful subscriber
	// renegotiation (new subscriberSdpOffer processed). Used by
	// WaitForSubRenegotiation to detect when the SFU pushed new tracks.
	subRenegoDone     chan struct{}
	subRenegoDoneOnce sync.Once

	srvHello *goloom.ServerHello

	closeOnce sync.Once
}

// Close tears the Telemost session down properly: closes both
// PeerConnections (so DTLS sends a close_notify and ICE goes "failed"
// fast on the SFU side) AND closes the signalling WebSocket with a
// "bye" reason. The SFU drops the participant from the room as soon as
// the WebSocket goes away — without this step our restart cycles leave
// "zombie" peers that linger for ~30s on ICE timeout.
//
// Safe to call multiple times. Best-effort: errors are logged, never
// returned, since at this point the caller is already tearing down.
//
// Close order matters for "no zombie peer" behaviour:
//
//  1. Close the WebSocket first — that's the signalling channel the SFU
//     uses to track participant presence. Once we send a normal-closure
//     close frame, the SFU drops us from the room immediately, BEFORE
//     waiting for ICE/DTLS timeouts on the media side.
//  2. Then close PeerConnections (DTLS close_notify). ICE state will
//     converge to "closed" on its own; without WS bye first the SFU
//     would keep our peer slot warm for the full ICE timeout (~30s).
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.Logger.Printf("SESSION-CLOSE: ws bye → PCs (this order avoids SFU zombie peer)")

		if s.Client != nil {
			if err := s.Client.Close(); err != nil {
				s.Logger.Printf("SESSION-CLOSE: ws: %v", err)
			}
		}
		if s.Pub != nil {
			if err := s.Pub.Close(); err != nil {
				s.Logger.Printf("SESSION-CLOSE: pub: %v", err)
			}
		}
		if s.Sub != nil {
			if err := s.Sub.Close(); err != nil {
				s.Logger.Printf("SESSION-CLOSE: sub: %v", err)
			}
		}
	})
}

// ParsedSlotsConfig is what SetupScreenShare waits on — it carries the full
// snapshot so the consumer can pick out the peer's screen-share mid binding.
type ParsedSlotsConfig struct {
	Key   int
	Slots []ParsedSlot
}

type ParsedSlot struct {
	Index                       int
	Type                        string // "selfView" / "participant" / "participantVideoByMid" / "participantScreenSharingByMid" / "empty"
	ParticipantID               string
	Mid                         string // populated for *ByMid types
}

// SetupSession runs Stage 1-4 + creates both PCs, exchanges SDP, waits for
// connected, sends initial sized setSlots. After it returns the caller can
// use Session to drive tunnel sender / receiver.
func SetupSession(ctx context.Context, lg *log.Logger, meeting, displayName string) (*Session, error) {
	s := &Session{
		Logger:        lg,
		knownPeers:    make(map[string]string),
		newVideoTrack: make(chan *webrtc.TrackRemote, 8),
		srvHelloCh:    make(chan *goloom.ServerHello, 1),
		pubAnswerCh:   make(chan *goloom.PublisherSdpAnswer, 4),
		subOfferCh:    make(chan *goloom.SubscriberSdpOffer, 4),
		slotsCh:       make(chan ParsedSlotsConfig, 16),
		subRenegoDone: make(chan struct{}),
	}

	// Stage 1
	ids := api.NewClientIDs()
	lg.Printf("client ids: instance=%s idempotency=%s", ids.ClientInstanceID, ids.IdempotencyKey)
	hc := api.DefaultHTTPClient()
	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := api.FetchConnection(httpCtx, hc, meeting, displayName, ids)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("stage1: %w", err)
	}
	s.Conn = conn
	lg.Printf("STAGE1 ✓ room=%s peer=%s media=%s ws=%s",
		conn.RoomID, conn.PeerID, conn.MediaPlatform, conn.ClientConfiguration.MediaServerURL)

	// Stage 2
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	wsConn, err := goloom.Dial(dialCtx, conn.ClientConfiguration.MediaServerURL, goloom.DialOptions{
		UserAgent: api.UserAgent,
		Origin:    api.Origin,
	})
	dialCancel()
	if err != nil {
		return nil, fmt.Errorf("stage2: %w", err)
	}
	s.Client = goloom.NewClient(wsConn, lg)
	lg.Printf("STAGE2 ✓ WSS connected")

	s.Client.OnIncoming(func(typeName string, env *goloom.RecvEnvelope, payload json.RawMessage) {
		s.handleIncoming(typeName, env, payload)
	})
	s.Client.Start(ctx)

	// Stage 3 — hello
	hello := goloom.Hello{
		ParticipantMeta: goloom.ParticipantMeta{
			Name: displayName, Role: "SPEAKER", Description: "",
			SendAudio: true, SendVideo: true,
		},
		ParticipantAttributes: goloom.ParticipantAttr{
			Name: displayName, Role: "SPEAKER", Description: "",
		},
		SendAudio:              true,
		SendVideo:              true,
		SendSharing:            false,
		ParticipantID:          conn.PeerID,
		RoomID:                 conn.RoomID,
		ServiceName:            "telemost",
		Credentials:            conn.Credentials,
		CapabilitiesOffer:      goloom.DefaultCapabilitiesOffer,
		SDKInfo:                goloom.ChromeSDKInfo,
		SDKInitializationID:    uuid.NewString(),
		DisablePublisher:       false,
		DisableSubscriber:      false,
		DisableSubscriberAudio: false,
	}
	if err := s.Client.Send(goloom.Envelope{Hello: &hello}); err != nil {
		return nil, fmt.Errorf("stage3: %w", err)
	}
	lg.Printf("STAGE3 ✓ hello sent (peer=%s)", conn.PeerID)

	// Stage 4 — wait serverHello
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s.srvHello = <-s.srvHelloCh:
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("stage4 timeout")
	}
	lg.Printf("STAGE4 ✓ serverHello received; ICE=%d ping=%dms telem=%dms",
		len(s.srvHello.RtcConfiguration.ICEServers),
		s.srvHello.PingPongConfiguration.PingInterval,
		s.srvHello.TelemetryConfiguration.SendingInterval)
	s.Client.ConfigurePeriodicTasks(ctx, s.srvHello.PingPongConfiguration, s.srvHello.TelemetryConfiguration)

	// Stage 5 — build PCs, publisher offer
	pionAPI, err := peer.BuildAPI()
	if err != nil {
		return nil, fmt.Errorf("stage5 api: %w", err)
	}
	rtcCfg := peer.ToConfig(s.srvHello.RtcConfiguration.ICEServers)

	s.Pub, err = peer.New("PUB", pionAPI, rtcCfg, lg)
	if err != nil {
		return nil, fmt.Errorf("stage5 PUB: %w", err)
	}
	s.Sub, err = peer.New("SUB", pionAPI, rtcCfg, lg)
	if err != nil {
		return nil, fmt.Errorf("stage5 SUB: %w", err)
	}

	s.Pub.PC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			lg.Printf("PUB ICE gathering complete")
			return
		}
		sendICE(lg, s.Client, c, "PUBLISHER", 1)
	})

	s.AudioTrack, err = webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio0", "fake-stream",
	)
	if err != nil {
		return nil, fmt.Errorf("audio track: %w", err)
	}
	if _, err := s.Pub.PC.AddTransceiverFromTrack(s.AudioTrack, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendonly,
	}); err != nil {
		return nil, fmt.Errorf("audio xcvr: %w", err)
	}

	s.VideoTrack, err = webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video0", "fake-stream",
	)
	if err != nil {
		return nil, fmt.Errorf("video track: %w", err)
	}
	if _, err := s.Pub.PC.AddTransceiverFromTrack(s.VideoTrack, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendonly,
	}); err != nil {
		return nil, fmt.Errorf("video xcvr: %w", err)
	}

	offer, err := s.Pub.PC.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	if err := s.Pub.PC.SetLocalDescription(offer); err != nil {
		return nil, fmt.Errorf("set local pub: %w", err)
	}
	pubTracks := buildPublisherTracks(s.Pub.PC)
	if err := s.Client.Send(goloom.Envelope{
		PublisherSdpOffer: &goloom.PublisherSdpOffer{PcSeq: 1, SDP: offer.SDP, Tracks: pubTracks},
	}); err != nil {
		return nil, fmt.Errorf("send pub offer: %w", err)
	}
	lg.Printf("STAGE5 ✓ PUB offer sent (sdp=%d tracks=%d)", len(offer.SDP), len(pubTracks))

	// SUB handlers
	s.Sub.PC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			lg.Printf("SUB ICE gathering complete")
			return
		}
		sendICE(lg, s.Client, c, "SUBSCRIBER", 1)
	})
	s.Sub.PC.OnTrack(func(track *webrtc.TrackRemote, recv *webrtc.RTPReceiver) {
		// Find which transceiver this remote track belongs to so we can log
		// the mid (e.g. "video_AA"). The mid is what slotsConfig binds
		// participantId to via participantVideoByMid.
		mid := "?"
		for _, tr := range s.Sub.PC.GetTransceivers() {
			if tr.Receiver() == recv {
				mid = tr.Mid()
				break
			}
		}
		lg.Printf("SUB OnTrack: kind=%s id=%s codec=%s ssrc=%d mid=%s streamID=%s",
			track.Kind(), track.ID(), track.Codec().MimeType, track.SSRC(), mid, track.StreamID())
		// Surface RTCP feedback Pion sends/receives for this remote track so
		// we can spot PLI / FIR / REMB / SR coming from the SFU.
		startRTPRecvRTCPLoop(ctx, lg, fmt.Sprintf("SUB-rtcp[%s]", shortID(track.ID())), recv)
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			select {
			case s.newVideoTrack <- track:
			default:
				lg.Printf("WARN newVideoTrack channel full, dropping track %s", track.ID())
			}
		} else {
			// drain non-video tracks (host audio etc)
			go func() {
				for {
					if _, _, err := track.ReadRTP(); err != nil {
						return
					}
				}
			}()
		}
	})
	s.Sub.PC.OnDataChannel(func(dc *webrtc.DataChannel) {
		idStr := "?"
		if dc.ID() != nil {
			idStr = fmt.Sprintf("%d", *dc.ID())
		}
		lg.Printf("SUB OnDataChannel: label=%q id=%s", dc.Label(), idStr)
		if dc.Label() == "default" {
			s.mu.Lock()
			s.dcDefault = dc
			s.mu.Unlock()
			dc.OnOpen(func() {
				lg.Printf("DC default opened (readyState=%s)", dc.ReadyState())
			})
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				lg.Printf("DC-PROBE ← default msg (%d bytes, isString=%v)", len(msg.Data), msg.IsString)
			})
			dc.OnClose(func() {
				lg.Printf("DC default closed")
			})
		}
	})

	// wait pub answer + sub offer
	pubAns, err := waitOrTimeout(ctx, s.pubAnswerCh, 15*time.Second, "publisherSdpAnswer")
	if err != nil {
		return nil, err
	}
	if err := s.Pub.SetRemoteDescriptionAndFlush(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: pubAns.SDP,
	}); err != nil {
		return nil, fmt.Errorf("apply pub answer: %w", err)
	}
	lg.Printf("STAGE5 ✓ PUB answer applied (sdp=%d) — full SDP follows:\n----- BEGIN PUB ANSWER SDP -----\n%s----- END PUB ANSWER SDP -----",
		len(pubAns.SDP), pubAns.SDP)

	subOff, err := waitOrTimeout(ctx, s.subOfferCh, 15*time.Second, "subscriberSdpOffer")
	if err != nil {
		return nil, err
	}
	if err := s.Sub.SetRemoteDescriptionAndFlush(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: subOff.SDP,
	}); err != nil {
		return nil, fmt.Errorf("apply sub offer: %w", err)
	}
	subAnswer, err := s.Sub.PC.CreateAnswer(nil)
	if err != nil {
		return nil, fmt.Errorf("create sub answer: %w", err)
	}
	if err := s.Sub.PC.SetLocalDescription(subAnswer); err != nil {
		return nil, fmt.Errorf("set local sub: %w", err)
	}
	if err := s.Client.Send(goloom.Envelope{
		SubscriberSdpAnswer: &goloom.SubscriberSdpAnswer{PcSeq: subOff.PcSeq, SDP: subAnswer.SDP},
	}); err != nil {
		return nil, fmt.Errorf("send sub answer: %w", err)
	}
	lg.Printf("STAGE6 ✓ SUB answer sent (sdp=%d)", len(subAnswer.SDP))

	// Wait both connected.
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	defer connectCancel()
	if err := waitConnected(connectCtx, s.Pub.PC, s.Sub.PC); err != nil {
		return nil, fmt.Errorf("wait connected: %w", err)
	}
	lg.Printf("STAGE6 ✓ both PCs connected")

	// Initial setSlots: ask SFU to actually push us peer video.
	slots := make([]goloom.SlotSize, 12)
	slots[0] = goloom.SlotSize{Width: 640, Height: 480}
	slots[1] = goloom.SlotSize{Width: 320, Height: 240}
	if err := s.Client.Send(goloom.Envelope{
		SetSlots: &goloom.SetSlots{
			Slots:              slots,
			AudioSlotsCount:    0,
			Key:                2,
			ShutdownAllVideo:   nil,
			WithSelfView:       true,
			SelfViewVisibility: "ON_LOADING_THEN_SHOW",
		},
	}); err != nil {
		return nil, fmt.Errorf("setSlots: %w", err)
	}
	lg.Printf("STAGE6.7 ✓ setSlots sent (slot[0]=640x480 slot[1]=320x240, key=2)")

	go s.runSubRenegotiationLoop(ctx)
	lg.Printf("SUB-RENEGO loop started — will process subsequent subscriberSdpOffers")

	return s, nil
}

// runSubRenegotiationLoop drains subOfferCh after the initial setup. When the
// peer adds new publisher tracks (e.g. screen-share), the SFU sends us a new
// subscriberSdpOffer. Without this loop, that offer is dropped and we never
// receive the peer's new tracks — this was the root cause of the one-directional
// binding asymmetry observed in PoC #2A.
func (s *Session) runSubRenegotiationLoop(ctx context.Context) {
	slotKey := 10
	for {
		select {
		case <-ctx.Done():
			return
		case offer := <-s.subOfferCh:
			s.Logger.Printf("SUB-RENEGO ← subscriberSdpOffer pcSeq=%d (sdp=%d bytes)", offer.PcSeq, len(offer.SDP))
			if err := s.Sub.PC.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeOffer, SDP: offer.SDP,
			}); err != nil {
				s.Logger.Printf("SUB-RENEGO SetRemoteDescription err: %v", err)
				continue
			}
			answer, err := s.Sub.PC.CreateAnswer(nil)
			if err != nil {
				s.Logger.Printf("SUB-RENEGO CreateAnswer err: %v", err)
				continue
			}
			if err := s.Sub.PC.SetLocalDescription(answer); err != nil {
				s.Logger.Printf("SUB-RENEGO SetLocalDescription err: %v", err)
				continue
			}
			if err := s.Client.Send(goloom.Envelope{
				SubscriberSdpAnswer: &goloom.SubscriberSdpAnswer{PcSeq: offer.PcSeq, SDP: answer.SDP},
			}); err != nil {
				s.Logger.Printf("SUB-RENEGO send answer err: %v", err)
				continue
			}

			for _, tr := range s.Sub.PC.GetTransceivers() {
				mid := tr.Mid()
				dir := tr.Direction()
				recv := tr.Receiver()
				trackInfo := "no-track"
				if recv != nil && recv.Track() != nil {
					t := recv.Track()
					trackInfo = fmt.Sprintf("kind=%s id=%s ssrc=%d", t.Kind(), t.ID(), t.SSRC())
				}
				s.Logger.Printf("SUB-RENEGO   transceiver mid=%s dir=%s %s", mid, dir, trackInfo)
			}

			s.Logger.Printf("SUB-RENEGO ✓ answer sent (pcSeq=%d, sdp=%d bytes)", offer.PcSeq, len(answer.SDP))
			s.subRenegoDoneOnce.Do(func() { close(s.subRenegoDone) })

			slotKey++
			slots := make([]goloom.SlotSize, 12)
			slots[0] = goloom.SlotSize{Width: 1280, Height: 720}
			slots[1] = goloom.SlotSize{Width: 320, Height: 240}
			if err := s.Client.Send(goloom.Envelope{
				SetSlots: &goloom.SetSlots{
					Slots:              slots,
					AudioSlotsCount:    0,
					Key:                slotKey,
					ShutdownAllVideo:   nil,
					WithSelfView:       false,
					SelfViewVisibility: "ON_LOADING_THEN_SHOW",
				},
			}); err != nil {
				s.Logger.Printf("SUB-RENEGO setSlots err: %v", err)
			} else {
				s.Logger.Printf("SUB-RENEGO ✓ setSlots re-sent (key=%d) to refresh binding", slotKey)
			}
		}
	}
}

// ResetHandshakeState is a no-op placeholder — handshake() is stateless and
// reads from the merged channel. Any leftover frames from the camera handshake
// are HELLO/HELLO_ACK frames which will be re-processed correctly (idempotent).
func (s *Session) ResetHandshakeState() {}

// NewVideoTracks returns a channel that yields every remote video track as
// it arrives via OnTrack. The channel is buffered (size 8) — under normal
// conditions the consumer drains immediately so it never blocks the SUB PC
// callback thread.
func (s *Session) NewVideoTracks() <-chan *webrtc.TrackRemote { return s.newVideoTrack }

func (s *Session) DefaultDataChannel() *webrtc.DataChannel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dcDefault
}

func (s *Session) ServerHello() *goloom.ServerHello {
	return s.srvHello
}

// KnownPeers returns participantId -> name for everyone the SFU has told us
// about (us + others). Caller filters out self.
func (s *Session) KnownPeers() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.knownPeers))
	for k, v := range s.knownPeers {
		out[k] = v
	}
	return out
}

func (s *Session) handleIncoming(
	typeName string, env *goloom.RecvEnvelope, payload json.RawMessage,
) {
	switch typeName {
	case "serverHello":
		var sh goloom.ServerHello
		if err := json.Unmarshal(payload, &sh); err == nil {
			select {
			case s.srvHelloCh <- &sh:
			default:
			}
		}
	case "publisherSdpAnswer":
		var a goloom.PublisherSdpAnswer
		if err := json.Unmarshal(payload, &a); err == nil {
			select {
			case s.pubAnswerCh <- &a:
			default:
				s.Logger.Printf("WARN pubAnswerCh full, dropping pcSeq=%d", a.PcSeq)
			}
		}
	case "subscriberSdpOffer":
		var o goloom.SubscriberSdpOffer
		if err := json.Unmarshal(payload, &o); err == nil {
			select {
			case s.subOfferCh <- &o:
			default:
				s.Logger.Printf("WARN subOfferCh full, dropping pcSeq=%d", o.PcSeq)
			}
		}
	case "webrtcIceCandidate":
		var ic goloom.WebrtcIceCandidate
		if err := json.Unmarshal(payload, &ic); err == nil {
			s.routeICE(ic)
		}
	case "updateDescription", "upsertDescription":
		s.absorbDescription(payload)
	case "slotsConfig":
		s.dumpSlotsConfig(payload) // logs and pushes to slotsCh
	case "ack":
		// already cleared
	default:
		// ignore (vadActivity, notification, ...)
	}
}

// dumpSlotsConfig prints the parsed slot bindings AND pushes a parsed
// snapshot onto slotsCh so SetupScreenShare can wait for the binding it needs.
func (s *Session) dumpSlotsConfig(payload json.RawMessage) {
	var sc struct {
		Key   int               `json:"key"`
		Slots []json.RawMessage `json:"slots"`
	}
	if err := json.Unmarshal(payload, &sc); err != nil {
		s.Logger.Printf("SLOTSCONFIG decode err: %v", err)
		return
	}
	parsed := ParsedSlotsConfig{Key: sc.Key}
	s.Logger.Printf("SLOTSCONFIG key=%d slots=%d:", sc.Key, len(sc.Slots))
	for i, raw := range sc.Slots {
		var slot struct {
			SelfView    *json.RawMessage `json:"selfView,omitempty"`
			Participant *struct {
				ParticipantID string `json:"participantId"`
			} `json:"participant,omitempty"`
			ParticipantVideoByMid *struct {
				ParticipantID string `json:"participantId"`
				Mid           string `json:"mid"`
			} `json:"participantVideoByMid,omitempty"`
			ParticipantScreenSharingByMid *struct {
				ParticipantID string `json:"participantId"`
				Mid           string `json:"mid"`
			} `json:"participantScreenSharingByMid,omitempty"`
			Pinned bool   `json:"pinned"`
			Vad    bool   `json:"vad"`
			Label  string `json:"label"`
		}
		_ = json.Unmarshal(raw, &slot)
		ps := ParsedSlot{Index: i}
		switch {
		case slot.SelfView != nil:
			ps.Type = "selfView"
			s.Logger.Printf("  slot[%d] selfView pinned=%v vad=%v label=%q", i, slot.Pinned, slot.Vad, slot.Label)
		case slot.Participant != nil:
			ps.Type = "participant"
			ps.ParticipantID = slot.Participant.ParticipantID
			s.Logger.Printf("  slot[%d] participant=%s pinned=%v vad=%v", i, slot.Participant.ParticipantID, slot.Pinned, slot.Vad)
		case slot.ParticipantVideoByMid != nil:
			ps.Type = "participantVideoByMid"
			ps.ParticipantID = slot.ParticipantVideoByMid.ParticipantID
			ps.Mid = slot.ParticipantVideoByMid.Mid
			s.Logger.Printf("  slot[%d] participantVideoByMid=%s mid=%s", i, slot.ParticipantVideoByMid.ParticipantID, slot.ParticipantVideoByMid.Mid)
		case slot.ParticipantScreenSharingByMid != nil:
			ps.Type = "participantScreenSharingByMid"
			ps.ParticipantID = slot.ParticipantScreenSharingByMid.ParticipantID
			ps.Mid = slot.ParticipantScreenSharingByMid.Mid
			s.Logger.Printf("  slot[%d] screenShareByMid=%s mid=%s", i, slot.ParticipantScreenSharingByMid.ParticipantID, slot.ParticipantScreenSharingByMid.Mid)
		default:
			ps.Type = "empty"
			s.Logger.Printf("  slot[%d] empty/other raw=%s", i, truncateRaw(raw, 120))
		}
		parsed.Slots = append(parsed.Slots, ps)
	}
	select {
	case s.slotsCh <- parsed:
	default:
		// drop oldest if queue full
		select {
		case <-s.slotsCh:
		default:
		}
		select {
		case s.slotsCh <- parsed:
		default:
		}
	}
}

func truncateRaw(raw json.RawMessage, n int) string {
	s := string(raw)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (s *Session) absorbDescription(payload json.RawMessage) {
	var x struct {
		Description []struct {
			ID   string `json:"id"`
			Meta struct {
				Name string `json:"name"`
				Role string `json:"role"`
			} `json:"meta"`
		} `json:"description"`
	}
	if err := json.Unmarshal(payload, &x); err != nil {
		return
	}
	s.mu.Lock()
	for _, d := range x.Description {
		if d.ID == "" {
			continue
		}
		s.knownPeers[d.ID] = d.Meta.Name
	}
	s.mu.Unlock()
}

func (s *Session) routeICE(ic goloom.WebrtcIceCandidate) {
	if s.Pub == nil || s.Sub == nil {
		return
	}
	init := webrtc.ICECandidateInit{Candidate: ic.Candidate}
	if ic.SdpMid != "" {
		mid := ic.SdpMid
		init.SDPMid = &mid
	}
	mlineIdx := uint16(ic.SdpMlineIndex)
	init.SDPMLineIndex = &mlineIdx
	if ic.UsernameFragment != "" {
		uf := ic.UsernameFragment
		init.UsernameFragment = &uf
	}
	var w *peer.Wrapper
	switch ic.Target {
	case "PUBLISHER":
		w = s.Pub
	case "SUBSCRIBER":
		w = s.Sub
	default:
		return
	}
	if err := w.AddICECandidate(init); err != nil {
		s.Logger.Printf("ICE %s add err: %v", ic.Target, err)
	}
}

func sendICE(lg *log.Logger, c *goloom.Client, ic *webrtc.ICECandidate, target string, pcSeq int) {
	init := ic.ToJSON()
	sdpMid := ""
	if init.SDPMid != nil {
		sdpMid = *init.SDPMid
	}
	mlineIdx := 0
	if init.SDPMLineIndex != nil {
		mlineIdx = int(*init.SDPMLineIndex)
	}
	uf := ""
	if init.UsernameFragment != nil {
		uf = *init.UsernameFragment
	}
	if err := c.Send(goloom.Envelope{
		WebrtcIceCandidate: &goloom.WebrtcIceCandidate{
			PcSeq:            pcSeq,
			Target:           target,
			Candidate:        init.Candidate,
			SdpMid:           sdpMid,
			SdpMlineIndex:    mlineIdx,
			UsernameFragment: uf,
		},
	}); err != nil {
		lg.Printf("ICE %s send err: %v", target, err)
	}
}

func buildPublisherTracks(pc *webrtc.PeerConnection) []goloom.Track {
	var out []goloom.Track
	for _, tr := range pc.GetTransceivers() {
		s := tr.Sender()
		if s == nil {
			continue
		}
		t := s.Track()
		if t == nil {
			continue
		}
		var kind, label string
		switch t.Kind() {
		case webrtc.RTPCodecTypeAudio:
			kind, label = "AUDIO", "Fake Default Audio Input"
		case webrtc.RTPCodecTypeVideo:
			kind, label = "VIDEO", "fake_device_0"
		default:
			continue
		}
		out = append(out, goloom.Track{
			MID: tr.Mid(), TransceiverMID: tr.Mid(),
			Kind: kind, Priority: 0, Label: label,
			Codecs: map[string]interface{}{}, GroupID: 1, Description: "",
		})
	}
	return out
}

func waitConnected(ctx context.Context, pcs ...*webrtc.PeerConnection) error {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			ok := true
			for _, pc := range pcs {
				if pc.ConnectionState() != webrtc.PeerConnectionStateConnected {
					ok = false
					break
				}
			}
			if ok {
				return nil
			}
		}
	}
}

// SetupScreenShare adds DISPLAY_AUDIO + DISPLAY_VIDEO transceivers, drives a
// renegotiation round (publisherSdpOffer pcSeq=1 with all 4 tracks ->
// publisherSdpAnswer -> SetRemoteDescription), pushes
// updatePublisherTrackDescription, and finally sends an updated setSlots
// asking the SFU to forward peer's screen-share. Returns when both transceivers
// are wired up and the answer is applied. Caller is responsible for waiting
// on Session.slotsCh for the actual peer-binding (peer may not have
// renegotiated yet at this point).
//
// pcSeq stays at 1 — same PeerConnection instance, just renegotiation.
func (s *Session) SetupScreenShare(ctx context.Context) error {
	var err error
	s.DisplayAudioTrack, err = webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"display-audio0", "screen-stream",
	)
	if err != nil {
		return fmt.Errorf("display-audio track: %w", err)
	}
	if _, err := s.Pub.PC.AddTransceiverFromTrack(s.DisplayAudioTrack, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendonly,
	}); err != nil {
		return fmt.Errorf("display-audio xcvr: %w", err)
	}
	s.DisplayVideoTrack, err = webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"display-video0", "screen-stream",
	)
	if err != nil {
		return fmt.Errorf("display-video track: %w", err)
	}
	if _, err := s.Pub.PC.AddTransceiverFromTrack(s.DisplayVideoTrack, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendonly,
	}); err != nil {
		return fmt.Errorf("display-video xcvr: %w", err)
	}

	offer, err := s.Pub.PC.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("renego CreateOffer: %w", err)
	}
	if err := s.Pub.PC.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("renego SetLocalDescription: %w", err)
	}
	tracks := buildPublisherTracksWithDisplay(s.Pub.PC)
	s.Logger.Printf("STAGE7 → renegotiation offer: %d tracks", len(tracks))
	for _, t := range tracks {
		s.Logger.Printf("        track mid=%s kind=%s label=%q groupId=%d", t.MID, t.Kind, t.Label, t.GroupID)
	}
	if err := s.Client.Send(goloom.Envelope{
		PublisherSdpOffer: &goloom.PublisherSdpOffer{PcSeq: 1, SDP: offer.SDP, Tracks: tracks},
	}); err != nil {
		return fmt.Errorf("renego send offer: %w", err)
	}

	// Drain any stale answer from the initial setup that the handler may
	// have re-pushed, then await the renegotiation answer specifically.
	answer, err := waitOrTimeout(ctx, s.pubAnswerCh, 15*time.Second, "renegotiation publisherSdpAnswer")
	if err != nil {
		return err
	}
	if err := s.Pub.PC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: answer.SDP,
	}); err != nil {
		return fmt.Errorf("renego SetRemoteDescription: %w", err)
	}
	s.Logger.Printf("STAGE7 ✓ renegotiation answer applied (sdp=%d) — full SDP follows:\n----- BEGIN RENEGO ANSWER SDP -----\n%s----- END RENEGO ANSWER SDP -----",
		len(answer.SDP), answer.SDP)

	if err := s.Client.Send(goloom.Envelope{
		UpdatePublisherTrackDescription: &goloom.UpdatePublisherTrackDescription{
			PublisherTrackDescriptions: tracks,
		},
	}); err != nil {
		return fmt.Errorf("send updatePublisherTrackDescription: %w", err)
	}
	s.Logger.Printf("STAGE7 ✓ updatePublisherTrackDescription sent (4 tracks)")

	// Updated setSlots — WithSelfView=false so SFU doesn't reserve slot[0]
	// for our own self-view; we want it free for peer's screen-share. The
	// big size in slot[0] hints SFU to forward at hi-res (we want bandwidth
	// for tunnel data).
	slots := make([]goloom.SlotSize, 12)
	slots[0] = goloom.SlotSize{Width: 1280, Height: 720}
	slots[1] = goloom.SlotSize{Width: 320, Height: 240}
	if err := s.Client.Send(goloom.Envelope{
		SetSlots: &goloom.SetSlots{
			Slots:              slots,
			AudioSlotsCount:    0,
			Key:                3,
			ShutdownAllVideo:   nil,
			WithSelfView:       false,
			SelfViewVisibility: "ON_LOADING_THEN_SHOW",
		},
	}); err != nil {
		return fmt.Errorf("send setSlots key=3: %w", err)
	}
	s.Logger.Printf("STAGE7 ✓ setSlots sent (key=3, slot[0]=1280x720 slot[1]=320x240, WithSelfView=false)")

	return nil
}

// RebindSlots re-sends setSlots to force SFU to re-evaluate participant
// bindings. Called after both peers have completed SetupScreenShare so the
// later-renegotiated peer gets proper screen-share binding (not just
// participant binding to whoever was active when its setSlots first arrived).
func (s *Session) RebindSlots(ctx context.Context, key int) error {
	slots := make([]goloom.SlotSize, 12)
	slots[0] = goloom.SlotSize{Width: 1280, Height: 720}
	slots[1] = goloom.SlotSize{Width: 320, Height: 240}
	if err := s.Client.Send(goloom.Envelope{
		SetSlots: &goloom.SetSlots{
			Slots:              slots,
			AudioSlotsCount:    0,
			Key:                key,
			ShutdownAllVideo:   nil,
			WithSelfView:       false,
			SelfViewVisibility: "ON_LOADING_THEN_SHOW",
		},
	}); err != nil {
		return fmt.Errorf("rebind setSlots: %w", err)
	}
	s.Logger.Printf("STAGE7b ✓ setSlots resent (key=%d) to refresh slot binding", key)
	return nil
}

// WaitForPeerScreenShareBinding consumes slotsCh until it sees a slot with
// participantScreenSharingByMid for peerID. Returns the bound mid (e.g.
// "video_AA"). Times out after timeout.
func (s *Session) WaitForPeerScreenShareBinding(ctx context.Context, peerID string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-cctx.Done():
			return "", fmt.Errorf("timeout waiting screen-share binding for peer %s", peerID)
		case sc := <-s.slotsCh:
			for _, sl := range sc.Slots {
				if sl.Type == "participantScreenSharingByMid" && sl.ParticipantID == peerID {
					return sl.Mid, nil
				}
			}
		}
	}
}

// WaitForPeer blocks until we discover another participant (via updateDescription
// / upsertDescription). Returns the first non-self participantId. Times out
// after timeout.
func (s *Session) WaitForPeer(ctx context.Context, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-cctx.Done():
			return "", fmt.Errorf("timeout waiting for peer to join")
		case <-tk.C:
			s.mu.Lock()
			for id := range s.knownPeers {
				if id != s.Conn.PeerID {
					s.mu.Unlock()
					return id, nil
				}
			}
			s.mu.Unlock()
		}
	}
}

// WaitForSubRenegotiation blocks until the subscriber renegotiation loop
// processes at least one new subscriberSdpOffer. This is the signal that the
// SFU pushed us new tracks (e.g. the peer's screen-share). Returns true if
// a renegotiation happened, false on timeout.
func (s *Session) WaitForSubRenegotiation(ctx context.Context, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-cctx.Done():
		return false
	case <-s.subRenegoDone:
		return true
	}
}

// buildPublisherTracksWithDisplay returns the full 4-track inventory after
// SetupScreenShare. Track labels and groupIds match what Chrome sends in the
// Phase 1 dump (groupId=1 for camera, groupId=2 for display).
func buildPublisherTracksWithDisplay(pc *webrtc.PeerConnection) []goloom.Track {
	var out []goloom.Track
	for i, tr := range pc.GetTransceivers() {
		s := tr.Sender()
		if s == nil {
			continue
		}
		t := s.Track()
		if t == nil {
			continue
		}
		mid := tr.Mid()
		var kind, label string
		var groupID int
		switch i {
		case 0:
			kind, label, groupID = "AUDIO", "Fake Default Audio Input", 1
		case 1:
			kind, label, groupID = "VIDEO", "fake_device_0", 1
		case 2:
			kind, label, groupID = "DISPLAY_AUDIO", "Fake audio", 2
		case 3:
			kind, label, groupID = "DISPLAY_VIDEO", "screen:-3:0", 2
		default:
			// Future-proofing: treat extras as generic camera tracks
			switch t.Kind() {
			case webrtc.RTPCodecTypeAudio:
				kind, label, groupID = "AUDIO", "extra-audio", 1
			case webrtc.RTPCodecTypeVideo:
				kind, label, groupID = "VIDEO", "extra-video", 1
			}
		}
		out = append(out, goloom.Track{
			MID: mid, TransceiverMID: mid,
			Kind: kind, Priority: 0, Label: label,
			Codecs: map[string]interface{}{}, GroupID: groupID, Description: "",
		})
	}
	return out
}

func waitOrTimeout[T any](ctx context.Context, ch <-chan T, d time.Duration, what string) (T, error) {
	var zero T
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	select {
	case <-cctx.Done():
		return zero, fmt.Errorf("timeout waiting %s: %w", what, cctx.Err())
	case v := <-ch:
		return v, nil
	}
}
