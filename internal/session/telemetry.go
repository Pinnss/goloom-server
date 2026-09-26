package session

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/goloom"
	"github.com/Pinnss/goloom-server/internal/tunnel"
)

// Reported video geometry. Our VP9 SS descriptor declares 16x16 on the wire,
// but the SFU reads the telemetry resolution to judge whether a real camera
// encoder is behind the track. A 16x16 report reads as obviously synthetic, so
// we report a common webcam resolution. If the SFU cross-checks telemetry
// resolution against the RTP frame, this is where to revisit. Captured schema
// (2026-07-22) confirmed the field set of outbound-rtp/video.
const (
	reportWidth  = 1280
	reportHeight = 720
)

// PublisherIdent names the publisher's own tracks the way the SFU sees them in
// the publisherSdpOffer, so telemetry can be attributed to the right m-lines.
type PublisherIdent struct {
	VideoSSRC uint32
	VideoMid  string
	AudioMid  string
}

// Publisher returns the SSRC and mids of our published tracks. The mids must be
// read from the live transceivers rather than assumed: SetupSession adds audio
// before video, so pion assigns mid "0" to AUDIO and "1" to VIDEO, and swapping
// them in telemetry would report a video encoder behind the audio m-line. Zero
// values mean the local description has not been set yet.
func (s *Session) Publisher() PublisherIdent {
	var id PublisherIdent
	for _, tr := range s.Pub.PC.GetTransceivers() {
		snd := tr.Sender()
		if snd == nil {
			continue
		}
		switch snd.Track() {
		case s.VideoTrack:
			id.VideoMid = tr.Mid()
			if p := snd.GetParameters(); len(p.Encodings) > 0 {
				id.VideoSSRC = uint32(p.Encodings[0].SSRC)
			}
		case s.AudioTrack:
			id.AudioMid = tr.Mid()
		}
	}
	return id
}

// NewPublisherStatsProvider returns a telemetry callback that mirrors what a
// real Telemost web client emits every ~20 s: a getStats() dump proving a live
// encoder sits behind our published video track. It is driven by the Sender's
// real wire counters (TxSamples → framesEncoded, TxBytes → bytesSent) so the
// numbers stay consistent with the RTP the SFU actually receives, plus a
// framesPerSecond computed from the delta between calls.
//
// This is a SIGNALLING-layer message only; it never touches the fake-VP9 media
// pipeline that carries the HELLO/HELLO_ACK handshake, so it cannot break
// pairing. id names our tracks as the SFU knows them (see Session.Publisher);
// a zero VideoSSRC omits the ssrc field.
func NewPublisherStatsProvider(sender *tunnel.Sender, id PublisherIdent) func() *goloom.Telemetry {
	var (
		mu         sync.Mutex
		prevFrames uint64
		prevAt     time.Time
	)
	return func() *goloom.Telemetry {
		mu.Lock()
		now := time.Now()
		frames := sender.TxSamples.Load()
		bytes := sender.TxBytes.Load()
		var fps float64
		if !prevAt.IsZero() {
			if dt := now.Sub(prevAt).Seconds(); dt > 0 {
				fps = float64(frames-prevFrames) / dt
			}
		}
		prevFrames, prevAt = frames, now
		mu.Unlock()

		return &goloom.Telemetry{
			PublisherRawStatsReport:  buildPublisherReport(now, frames, bytes, fps, id),
			SubscriberRawStatsReport: []string{},
			RoomAgentRawStatsReport:  []string{},
			EventsReport:             []string{},
			CustomStats:              []string{},
		}
	}
}

// buildPublisherReport renders the getStats entries a live video publisher
// produces, one JSON-encoded RTCStats object per []string element, matching the
// browser-captured schema.
func buildPublisherReport(now time.Time, frames, bytes uint64, fps float64, id PublisherIdent) []string {
	tsMs := float64(now.UnixNano()) / 1e6

	// Approximate packet-level counters from the byte counter: our batched
	// samples fragment into ~1150-byte RTP payloads. Keep packets ≥ frames.
	packets := bytes/1150 + frames
	headerBytes := packets * 12 // RTP fixed header per packet
	keyFrames := frames/50 + 1  // RunKeyframeRefresh cadence ≈ 1 per ~2 s
	encodeTime := float64(frames) * 0.008
	sendDelay := float64(packets) * 0.0005

	outVideo := map[string]any{
		"id": "OTV0", "timestamp": tsMs, "type": "outbound-rtp",
		"kind": "video", "mediaType": "video", "transportId": "T01",
		"codecId": "COV0", "mediaSourceId": "SV0", "remoteId": "RIV0",
		"mid": id.VideoMid, "active": true, "encodingIndex": 0,
		"bytesSent": bytes, "packetsSent": packets, "headerBytesSent": headerBytes,
		"framesEncoded": frames, "framesSent": frames, "keyFramesEncoded": keyFrames,
		"hugeFramesSent": 0, "frameWidth": reportWidth, "frameHeight": reportHeight,
		"framesPerSecond":         fps,
		"qualityLimitationReason": "none", "qualityLimitationResolutionChanges": 0,
		"nackCount": 0, "pliCount": 0, "firCount": 0,
		"retransmittedBytesSent": 0, "retransmittedPacketsSent": 0,
		"totalEncodeTime": encodeTime, "totalEncodedBytesTarget": 0,
		"totalPacketSendDelay": sendDelay,
	}
	if id.VideoSSRC != 0 {
		outVideo["ssrc"] = id.VideoSSRC
	}

	entries := []map[string]any{
		{
			"id": "COV0", "timestamp": tsMs, "type": "codec", "transportId": "T01",
			"payloadType": 98, "mimeType": "video/VP9", "clockRate": 90000,
		},
		{
			"id": "SV0", "timestamp": tsMs, "type": "media-source", "kind": "video",
			"trackIdentifier": "goloom-video", "width": reportWidth, "height": reportHeight,
			"frames": frames, "framesPerSecond": fps,
		},
		outVideo,
		{
			"id": "OTA0", "timestamp": tsMs, "type": "outbound-rtp", "kind": "audio",
			"mediaType": "audio", "transportId": "T01", "mid": id.AudioMid, "active": true,
			"bytesSent": bytes / 40, "packetsSent": frames, "headerBytesSent": frames * 12,
		},
		{
			"id": "PC", "timestamp": tsMs, "type": "peer-connection",
			"dataChannelsOpened": 1, "dataChannelsClosed": 0,
		},
		{
			"id": "T01", "timestamp": tsMs, "type": "transport",
			"bytesSent": bytes, "bytesReceived": bytes / 8,
			"dtlsState": "connected", "selectedCandidatePairId": "CP",
		},
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		out = append(out, string(b))
	}
	return out
}
