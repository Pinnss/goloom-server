// PeerConnection driver for VK Calls' SFU.
//
// After [DoAuth] hands us a WSS endpoint we open the OK Calls SDK
// signalling channel, build a pion PeerConnection with the strict
// Opus+H264 codec set the SFU expects, and react to two streams of
// events:
//
//  1. WS notifications (the OK Calls protocol) — wrapped in
//     `transmit-data` envelopes that ferry SDP offers/answers and ICE
//     candidates between participants.
//  2. PC callbacks (OnICECandidate, OnConnectionStateChange) — mirrored
//     outbound through the same `transmit-data` envelope so the remote
//     peer can reach us.
//
// Role:
//
//	receiver — joins first, never creates an offer; answers the
//	           first offer it receives.
//	caller   — joins second, generates an offer once a
//	           participant-joined notification names the remote peer.
//
// Lifecycle:
//
//	dialPeer  — opens WS, allocates the peer struct
//	buildPC   — creates the pion PC, registers OnTrack/OnICECandidate
//	run(ctx)  — runs the WS read loop until ctx is cancelled or the
//	            socket closes; surfaces errors via [peer.err]
//
// SFU acceptance gotchas (lifted from the PoC's hard-won lessons):
//
//   - Default pion codec set blows the SDP up to ~5.5 KB and trips
//     `Invalid message format` on transmit-data of the offer. Only
//     register Opus PT=109 + H264 PT=126 with the exact SDPFmtpLine
//     values the OK SDK pins.
//   - End-of-trickle: when pion's OnICECandidate fires with nil, we
//     have to send an empty candidate per m-line (mid="0"/"1") so the
//     SFU marks gathering complete.
//   - Trickle SDPMid + UsernameFragment must be present; backfill from
//     SDPMLineIndex / local SDP if pion drops them.
//   - Append `b=AS:3000` after `a=mid:1` in offers (the SFU ignores
//     it, but the web client always sends it — keeps us indistinguishable
//     from the canonical web client traffic).
package vkcalls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"

	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls/videocode"
)

// peer is the runtime state for one VK call participation. Lives for
// the lifetime of the [Session] that wraps it.
type peer struct {
	lg    *log.Logger
	role  string // "receiver" | "caller"
	codec string // "h264" | "vp8" — video codec stack
	auth  *AuthResult

	conn   *websocket.Conn
	sendMu sync.Mutex
	seq    int64

	pc         *webrtc.PeerConnection
	videoTrack *webrtc.TrackLocalStaticSample
	remoteID   int64

	// targetRemoteID — diagnostic override. Если != 0,
	// adoptParticipants игнорирует roster и сразу адоптит этот UID.
	// Решает проблему засранного roster'а в тестовых VK-звонках:
	// зомби-peer'ы от убитых смок-сессий висят в SFU 10-30 минут,
	// и без override caller'а уносит на них offer.
	targetRemoteID int64

	// videocode receive pipeline (h264 mode only) — owned by Session
	// but referenced here so OnTrack can hand the remote track to the
	// Receiver before Session takes over. nil for vp8 mode.
	videoReceiver *videocode.Receiver

	// remoteTracks (vp8 mode only) — каждый remote video track из
	// OnTrack улетает сюда. Transport.Connect читает их и оборачивает
	// в [tunnel.Receiver]'ы. nil для h264 mode.
	remoteTracks chan *webrtc.TrackRemote

	// controlListener (lobby mode only) — callback на goloom_ctrl
	// сообщения внутри transmit-data. Когда задан, peer работает в
	// lobby-режиме: НЕТ buildPC, НЕТ SDP/ICE обработки, role="lobby".
	// Используется для in-band DIAL bootstrap'а.
	controlListener func(from int64, ctrl GoloomCtrl)

	// pending ICE candidates received before the remote SDP is set.
	pendingMu  sync.Mutex
	pendingICE []webrtc.ICECandidateInit

	// connected fires once when the PeerConnection reaches
	// PeerConnectionStateConnected. Closed at most once.
	connectOnce sync.Once
	connected   chan struct{}

	// done is closed when run() exits. errSlot is set before close.
	doneOnce sync.Once
	done     chan struct{}
	errMu    sync.Mutex
	errSlot  error
}

// dialPeer opens the OK Calls SDK WS to the call's signalling endpoint
// and returns an initialised peer. The peer is not yet ready for I/O —
// the caller must call buildPC and then run() to start the lifecycle.
func dialPeer(ctx context.Context, lg *log.Logger, auth *AuthResult, role, codec string) (*peer, error) {
	endpoint, err := augmentWSEndpoint(auth.WSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("vkcalls: augment ws endpoint: %w", err)
	}

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	hdr := http.Header{}
	// WS-заголовки для videowebrtc.okcdn.ru — оставляем pre-S1a
	// значения (vk.com origin + UA). Эмпирически: смена origin на
	// vk.ru ломает SFU-signaling (handshake проходит, "connection"
	// notification приходит, дальше тишина — SFU перестаёт пушить
	// participant-joined / transmit-data). Auth-ладдер ходит на
	// api.vk.ru с vk.ru origin'ом — это OK; SFU WS другой стек.
	hdr.Set("Origin", "https://vk.com")
	hdr.Set("Referer", "https://vk.com/")
	hdr.Set("User-Agent", auth.Profile.UserAgent)

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lg.Printf("vkcalls: dialing %s", redactURL(endpoint))

	conn, resp, err := dialer.DialContext(dctx, endpoint, hdr)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("vkcalls: ws dial: %w (status=%d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("vkcalls: ws dial: %w", err)
	}
	lg.Printf("vkcalls: ws connected (role=%s)", role)

	if codec == "" {
		codec = "h264"
	}
	pp := &peer{
		lg:        lg,
		role:      role,
		codec:     codec,
		auth:      auth,
		conn:      conn,
		connected: make(chan struct{}),
		done:      make(chan struct{}),
	}
	if codec == "vp8" {
		pp.remoteTracks = make(chan *webrtc.TrackRemote, 8)
	}
	// VKCALLS_TARGET_REMOTE_ID — диагностический env var: forces
	// adoptParticipants принять конкретный peer userID. Помогает
	// в multi-peer тестах когда roster засран зомби-сессиями.
	if v := os.Getenv("VKCALLS_TARGET_REMOTE_ID"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id != 0 {
			pp.targetRemoteID = id
			lg.Printf("vkcalls: targetRemoteID=%d (env override)", id)
		}
	}
	return pp, nil
}

// buildPC creates the pion PeerConnection with audio (Opus) + video
// (H264) tracks matching what the SFU expects, and registers all the
// callbacks. videoReceiver is wired into OnTrack so frames flow into
// the videocode decoder the moment the remote side starts publishing.
//
// The local video track is exposed via p.videoTrack after this returns
// — the caller (Transport.Connect) builds the videocode.Sender on top
// of it once buildPC succeeds.
func (p *peer) buildPC(ctx context.Context, videoReceiver *videocode.Receiver) error {
	p.videoReceiver = videoReceiver

	iceServers := []webrtc.ICEServer{}
	if len(p.auth.StunURLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{URLs: p.auth.StunURLs})
	}
	if len(p.auth.TurnURLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:       p.auth.TurnURLs,
			Username:   p.auth.TurnUser,
			Credential: p.auth.TurnPass,
		})
	}

	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeOpus,
			ClockRate:   48000,
			Channels:    2,
			SDPFmtpLine: "maxplaybackrate=48000;stereo=1;useinbandfec=1",
		},
		PayloadType: 109,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return fmt.Errorf("vkcalls: register opus: %w", err)
	}
	switch p.codec {
	case "vp8":
		// VK SFU offer'ит VP8/VP9/H264 (vk-poc1 README:70). PT=96
		// — стандартный default, видеоплатформа Pion'а матчит по
		// MimeType+SDPFmtpLine, не по PT, так что mismatch SFU
		// answer'ом он перенумерует. Без SDPFmtpLine — VP8 не имеет
		// fmtp параметров обязательных для negotiation.
		if err := me.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:  webrtc.MimeTypeVP8,
				ClockRate: 90000,
			},
			PayloadType: 96,
		}, webrtc.RTPCodecTypeVideo); err != nil {
			return fmt.Errorf("vkcalls: register vp8: %w", err)
		}
	default:
		if err := me.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:    webrtc.MimeTypeH264,
				ClockRate:   90000,
				SDPFmtpLine: "profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1",
			},
			PayloadType: 126,
		}, webrtc.RTPCodecTypeVideo); err != nil {
			return fmt.Errorf("vkcalls: register h264: %w", err)
		}
	}

	api := webrtc.NewAPI(webrtc.WithMediaEngine(me))

	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		return fmt.Errorf("vkcalls: NewPeerConnection: %w", err)
	}
	p.pc = pc

	audio, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "vkcalls-audio",
	)
	if err != nil {
		return fmt.Errorf("vkcalls: audio track: %w", err)
	}
	if _, err := pc.AddTrack(audio); err != nil {
		return fmt.Errorf("vkcalls: add audio: %w", err)
	}

	videoMime := webrtc.MimeTypeH264
	if p.codec == "vp8" {
		videoMime = webrtc.MimeTypeVP8
	}
	video, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: videoMime}, "video", "vkcalls-video",
	)
	if err != nil {
		return fmt.Errorf("vkcalls: video track (%s): %w", videoMime, err)
	}
	if _, err := pc.AddTrack(video); err != nil {
		return fmt.Errorf("vkcalls: add video: %w", err)
	}
	p.videoTrack = video

	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		p.lg.Printf("vkcalls: PC state → %s", st)
		if st == webrtc.PeerConnectionStateConnected {
			p.connectOnce.Do(func() { close(p.connected) })
		}
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			p.signalDone(fmt.Errorf("vkcalls: PC entered state %s", st))
		}
	})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			// End-of-trickle: VK SFU expects an empty candidate per
			// m-line (audio mid="0", video mid="1") so it can mark
			// gathering complete and finish the connectivity check.
			if p.remoteID == 0 {
				return
			}
			for _, mid := range []string{"0", "1"} {
				midCopy := mid
				mline := uint16(mid[0] - '0')
				_ = p.sendCommand(map[string]any{
					"command":         "transmit-data",
					"participantId":   p.remoteID,
					"participantType": "USER",
					"data": map[string]any{
						"candidate": webrtc.ICECandidateInit{
							Candidate:     "",
							SDPMid:        &midCopy,
							SDPMLineIndex: &mline,
						},
					},
				})
			}
			return
		}
		if p.remoteID == 0 {
			return
		}

		ji := c.ToJSON()

		// SFU validates SDPMid against the m-line mid. pion sometimes
		// emits candidates with empty SDPMid but populated SDPMLineIndex
		// — VK rejects those. Backfill from index ("0" / "1").
		if ji.SDPMid == nil || *ji.SDPMid == "" {
			if ji.SDPMLineIndex != nil {
				mid := fmt.Sprintf("%d", *ji.SDPMLineIndex)
				ji.SDPMid = &mid
			}
		}

		// SFU also needs the ICE ufrag echoed. pion's ToJSON omits it
		// for host candidates; lift it from the local SDP we just set.
		if ji.UsernameFragment == nil || *ji.UsernameFragment == "" {
			if ld := p.pc.LocalDescription(); ld != nil {
				if ufrag := extractICEUfrag(ld.SDP); ufrag != "" {
					ji.UsernameFragment = &ufrag
				}
			}
		}

		_ = p.sendCommand(map[string]any{
			"command":         "transmit-data",
			"participantId":   p.remoteID,
			"participantType": "USER",
			"data":            map[string]any{"candidate": ji},
		})
	})

	pc.OnTrack(func(tr *webrtc.TrackRemote, rcv *webrtc.RTPReceiver) {
		p.lg.Printf("vkcalls: remote track kind=%s codec=%s ssrc=%d",
			tr.Kind(), tr.Codec().MimeType, tr.SSRC())
		if tr.Kind() != webrtc.RTPCodecTypeVideo {
			return // audio = silence, ignore
		}
		switch p.codec {
		case "vp8":
			// VP8 mode: каждый remote video track пробрасываем в
			// transport.go который оборачивает в tunnel.NewReceiver.
			if p.remoteTracks != nil {
				select {
				case p.remoteTracks <- tr:
				default:
					p.lg.Printf("vkcalls: remoteTracks chan full, dropping track")
				}
			}
		default:
			// H264 mode: видео сразу в videocode (RS + I_PCM decoder).
			if p.videoReceiver != nil {
				go p.videoReceiver.HandleTrack(ctx, tr, rcv)
			}
		}
	})

	return nil
}

// run is the WS read-loop with notification dispatch. Returns when the
// socket closes, ctx is cancelled, or a transport error occurs. Closes
// p.done before returning.
func (p *peer) run(ctx context.Context) {
	defer p.signalDone(nil)

	msgCh := make(chan []byte, 16)
	errCh := make(chan error, 1)
	go func() {
		for {
			_, raw, err := p.conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- raw
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = p.sendCommand(map[string]any{"command": "hangup", "reason": "HUNGUP"})
			_ = p.conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, ""),
				time.Now().Add(2*time.Second))
			return
		case err := <-errCh:
			p.signalDone(fmt.Errorf("vkcalls: ws read: %w", err))
			return
		case raw := <-msgCh:
			p.dispatch(raw)
		}
	}
}

// waitConnected blocks until the PC reaches Connected state, ctx is
// cancelled, or the deadline expires.
func (p *peer) waitConnected(ctx context.Context, deadline time.Duration) error {
	tctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	select {
	case <-p.connected:
		return nil
	case <-p.done:
		return fmt.Errorf("vkcalls: peer closed before connecting: %w", p.Err())
	case <-tctx.Done():
		return fmt.Errorf("vkcalls: timed out waiting for PeerConnectionStateConnected: %w", tctx.Err())
	}
}

// Done returns a channel that closes when the peer's run loop exits.
func (p *peer) Done() <-chan struct{} { return p.done }

// Err returns the terminal error of the peer's lifecycle, or nil if
// it shut down cleanly.
func (p *peer) Err() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.errSlot
}

// Close tears down the WS + PC. Idempotent.
func (p *peer) Close() {
	if p.pc != nil {
		_ = p.pc.Close()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.signalDone(nil)
}

func (p *peer) signalDone(err error) {
	p.doneOnce.Do(func() {
		p.errMu.Lock()
		if p.errSlot == nil && err != nil {
			p.errSlot = err
		}
		p.errMu.Unlock()
		close(p.done)
	})
}

// ─── notification dispatch ───────────────────────────────────────────

func (p *peer) dispatch(raw []byte) {
	str := string(raw)
	if str == "ping" {
		_ = p.sendText("pong")
		return
	}
	if str == "pong" {
		return
	}

	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		p.lg.Printf("vkcalls: ← unparseable: %s", preview(raw))
		return
	}

	notif, _ := msg["notification"].(string)
	switch notif {
	case "":
		// Server response/ack to our command (or an error).
		if errStr, _ := msg["error"].(string); errStr != "" {
			p.lg.Printf("vkcalls: ← server error: %s", preview(raw))
		}

	case "connection":
		// First substantial frame — server hands us the conversation
		// roster + sends an empty serverHello-equivalent.
		_ = p.sendCommand(map[string]any{
			"command": "change-media-settings",
			"mediaSettings": map[string]bool{
				"isAudioEnabled": true, "isVideoEnabled": true,
				"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
				"isAudioSharingEnabled":  false, "isAnimojiEnabled": false,
			},
		})
		// Roster may already include the peer if we joined second.
		if conv, ok := msg["conversation"].(map[string]any); ok {
			p.adoptParticipants(conv["participants"], "connection")
		}

	case "participant-joined":
		if pid, ok := msg["participantId"].(float64); ok {
			p.remoteID = int64(pid)
			p.lg.Printf("vkcalls: participant-joined remoteID=%d", p.remoteID)
		}
		if p.role == "caller" {
			p.sendOffer("participant-joined")
		}

	case "registered-peer", "media-settings-changed":
		// Informational — no-op.

	case "transmitted-data":
		p.handleTransmittedData(msg)

	default:
		// Ignore unknown notifications (forward-compat).
	}
}

// adoptParticipants picks a non-self participant from the conversation
// roster as our remote peer. Если задан targetRemoteID — адоптит его
// без сканирования roster'а (диагностический override).
//
// Дефолтная стратегия: итерация с КОНЦА (last in roster) — VK SFU
// обычно ordering по времени ascending, последний = самый свежий.
// В реальном 2-peer сценарии (1 server + 1 client) разницы нет.
func (p *peer) adoptParticipants(raw any, source string) {
	if p.targetRemoteID != 0 {
		p.remoteID = p.targetRemoteID
		p.lg.Printf("vkcalls: remote peer (%s): %d [forced via targetRemoteID]", source, p.remoteID)
		if p.role == "caller" {
			p.sendOffer(source)
		}
		return
	}
	parts, ok := raw.([]any)
	if !ok {
		return
	}
	myUID := parseWSUserID(p.auth.WSEndpoint)
	rosterIDs := make([]int64, 0, len(parts))
	for _, m := range parts {
		entry, ok := m.(map[string]any)
		if !ok {
			continue
		}
		if f, ok := entry["id"].(float64); ok {
			rosterIDs = append(rosterIDs, int64(f))
		}
	}
	p.lg.Printf("vkcalls: roster (%s) self=%d others=%v", source, myUID, rosterIDs)
	for i := len(parts) - 1; i >= 0; i-- {
		entry, ok := parts[i].(map[string]any)
		if !ok {
			continue
		}
		var id int64
		if f, ok := entry["id"].(float64); ok {
			id = int64(f)
		}
		if id != 0 && id != myUID {
			p.remoteID = id
			p.lg.Printf("vkcalls: remote peer (%s): %d (picked from roster size=%d)", source, id, len(parts))
			if p.role == "caller" {
				p.sendOffer(source)
			}
			return
		}
	}
}

func (p *peer) handleTransmittedData(msg map[string]any) {
	data, _ := msg["data"].(map[string]any)
	if data == nil {
		return
	}
	from := int64(0)
	if pid, ok := msg["participantId"].(float64); ok {
		from = int64(pid)
	}
	if p.remoteID == 0 {
		p.remoteID = from
	}

	// In-band ctrl envelope: { "goloom_ctrl": "DIAL", ... }.
	// Передаётся через тот же transmit-data что и SDP, отличается
	// наличием поля goloom_ctrl. Lobby peer ничего не делает с
	// SDP/ICE — только маршрутизирует ctrl listener'у.
	if ctrlType, ok := data["goloom_ctrl"].(string); ok && ctrlType != "" {
		ctrl := GoloomCtrl{
			Type:       ctrlType,
			MeetingURL: stringField(data, "meeting_url"),
			Bearer:     stringField(data, "bearer"),
			SessionID:  stringField(data, "session_id"),
			Phase:      stringField(data, "phase"),
			Detail:     stringField(data, "detail"),
			Reason:     stringField(data, "reason"),
		}
		if v, ok := data["server_target_user_id"].(float64); ok {
			ctrl.ServerTargetUserID = int64(v)
		} else if s, ok := data["server_target_user_id"].(string); ok {
			// JSON может прислать как строку если userID > 2^53.
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				ctrl.ServerTargetUserID = n
			}
		}
		if p.controlListener != nil {
			p.controlListener(from, ctrl)
		}
		return
	}

	if sdpWrap, ok := data["sdp"].(map[string]any); ok {
		typ, _ := sdpWrap["type"].(string)
		sdp, _ := sdpWrap["sdp"].(string)
		switch typ {
		case "offer":
			p.handleOffer(sdp, msg)
		case "answer":
			p.handleAnswer(sdp)
		}
	}

	if candWrap, ok := data["candidate"].(map[string]any); ok {
		p.handleCandidate(candWrap)
	}
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func (p *peer) handleOffer(sdp string, msg map[string]any) {
	if pid, ok := msg["participantId"].(float64); ok && p.remoteID != int64(pid) {
		p.remoteID = int64(pid)
	}
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: sdp,
	}); err != nil {
		p.lg.Printf("vkcalls: setRemote(offer): %v", err)
		return
	}
	p.flushPendingICE()

	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		p.lg.Printf("vkcalls: CreateAnswer: %v", err)
		return
	}
	if err := p.pc.SetLocalDescription(answer); err != nil {
		p.lg.Printf("vkcalls: setLocal(answer): %v", err)
		return
	}
	_ = p.sendCommand(map[string]any{
		"command":         "transmit-data",
		"participantId":   p.remoteID,
		"participantType": "USER",
		"data": map[string]any{
			"sdp": map[string]any{"type": "answer", "sdp": answer.SDP},
		},
	})
}

func (p *peer) handleAnswer(sdp string) {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: sdp,
	}); err != nil {
		p.lg.Printf("vkcalls: setRemote(answer): %v", err)
		return
	}
	p.flushPendingICE()
}

func (p *peer) handleCandidate(candWrap map[string]any) {
	cand, ok := parseICECandidate(candWrap)
	if !ok {
		return
	}
	if p.pc.RemoteDescription() == nil {
		p.pendingMu.Lock()
		p.pendingICE = append(p.pendingICE, cand)
		p.pendingMu.Unlock()
		return
	}
	if err := p.pc.AddICECandidate(cand); err != nil {
		p.lg.Printf("vkcalls: addICE: %v", err)
	}
}

func (p *peer) flushPendingICE() {
	p.pendingMu.Lock()
	pending := p.pendingICE
	p.pendingICE = nil
	p.pendingMu.Unlock()
	for _, c := range pending {
		if err := p.pc.AddICECandidate(c); err != nil {
			p.lg.Printf("vkcalls: addICE (buffered): %v", err)
		}
	}
}

func (p *peer) sendOffer(reason string) {
	if p.remoteID == 0 {
		return
	}
	if p.pc.SignalingState() != webrtc.SignalingStateStable {
		return
	}
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		p.lg.Printf("vkcalls: CreateOffer: %v", err)
		return
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		p.lg.Printf("vkcalls: setLocal(offer): %v", err)
		return
	}
	sdp := mungeOfferBitrate(offer.SDP)
	_ = p.sendCommand(map[string]any{
		"command":         "transmit-data",
		"participantId":   p.remoteID,
		"participantType": "USER",
		"data": map[string]any{
			"sdp":            map[string]any{"type": "offer", "sdp": sdp},
			"animojiVersion": 2,
		},
	})
	p.lg.Printf("vkcalls: → offer (reason=%s sdp=%dB)", reason, len(sdp))
}

// mungeOfferBitrate inserts `b=AS:3000` after the video m-line so the
// SFU allocates ~3 Mbps for our camera track. The SFU ignores our
// suggestion in practice (we measured 28 Mbps), but the web client
// always sends it — keeping us indistinguishable.
func mungeOfferBitrate(sdp string) string {
	lines := strings.Split(sdp, "\r\n")
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		out = append(out, line)
		if strings.HasPrefix(line, "a=mid:1") {
			out = append(out, "b=AS:3000")
		}
	}
	return strings.Join(out, "\r\n")
}

// ─── WS write helpers ─────────────────────────────────────────────────

func (p *peer) sendCommand(payload map[string]any) error {
	if _, ok := payload["sequence"]; !ok {
		payload["sequence"] = atomic.AddInt64(&p.seq, 1) - 1
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.conn.WriteMessage(websocket.TextMessage, raw)
}

func (p *peer) sendText(t string) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.conn.WriteMessage(websocket.TextMessage, []byte(t))
}

// ─── helpers ──────────────────────────────────────────────────────────

// parseWSUserID extracts the userId query param from the WSS URL —
// it's our own participant id, used to filter the conversation
// roster down to the remote peer.
func parseWSUserID(raw string) int64 {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	id := u.Query().Get("userId")
	var n int64
	_, _ = fmt.Sscanf(id, "%d", &n)
	return n
}

// parseICECandidate accepts the loose JSON shape the SFU sends and
// returns a typed ICECandidateInit. Returns false on a payload that
// can't be normalized (empty candidate strings during end-of-trickle
// signalling have a special meaning we ignore here for the PoC).
func parseICECandidate(m map[string]any) (webrtc.ICECandidateInit, bool) {
	cand, _ := m["candidate"].(string)
	if cand == "" {
		// End-of-trickle: empty candidate. pion can't accept this
		// directly; ignore.
		return webrtc.ICECandidateInit{}, false
	}
	out := webrtc.ICECandidateInit{Candidate: cand}
	switch v := m["sdpMid"].(type) {
	case string:
		if v != "" {
			out.SDPMid = &v
		}
	case float64:
		s := fmt.Sprintf("%.0f", v)
		out.SDPMid = &s
	}
	if idx, ok := m["sdpMLineIndex"].(float64); ok {
		mi := uint16(idx)
		out.SDPMLineIndex = &mi
	}
	if u, ok := m["usernameFragment"].(string); ok && u != "" {
		out.UsernameFragment = &u
	}
	return out, true
}

// extractICEUfrag pulls the ICE ufrag out of a freshly built SDP. The
// VK SFU validates that outbound trickle candidates carry the same
// ufrag that's pinned in the offer/answer, otherwise they're silently
// dropped.
func extractICEUfrag(sdp string) string {
	const needle = "a=ice-ufrag:"
	idx := strings.Index(sdp, needle)
	if idx == -1 {
		return ""
	}
	rest := sdp[idx+len(needle):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\r' || rest[i] == '\n' {
			return rest[:i]
		}
	}
	return rest
}

var _ = errors.New // keep "errors" import live for future use
