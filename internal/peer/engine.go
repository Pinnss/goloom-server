package peer

import (
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"

	"github.com/Pinnss/goloom-server/internal/goloom"
)

// BuildAPI constructs a Pion webrtc.API with a minimal MediaEngine matching
// the codecs Telemost's web client offers in its publisher SDP:
//   - audio/opus PT=111 with minptime=10;useinbandfec=1, transport-cc + nack
//   - video/VP8  PT=96  with goog-remb, transport-cc, ccm fir, nack, nack pli
//
// VP9 / H264 / AV1 / RED are intentionally not registered for PoC #1 — one
// codec per kind keeps SDP and renegotiation simple. The SFU has VP8 in its
// subscriber answer offerings, so this is enough to receive too.
func BuildAPI() (*webrtc.API, error) {
	me := &webrtc.MediaEngine{}

	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeOpus,
			ClockRate:   48000,
			Channels:    2,
			SDPFmtpLine: "minptime=10;useinbandfec=1",
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "transport-cc"},
				{Type: "nack"},
			},
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}

	// VP9 with profile-id=0 (8-bit 4:2:0). 2026-05-27 — migrated from
	// VP8 PT 96 to fight Yandex Telemost shaping that classifies plain
	// VP8 publishers as low-end webcams (~3 Mbps cap). VP9 is the modern
	// codec the SFU prefers; declaring it may grant higher bitrate budget.
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeVP9,
			ClockRate:   90000,
			SDPFmtpLine: "profile-id=0",
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "goog-remb"},
				{Type: "transport-cc"},
				{Type: "ccm", Parameter: "fir"},
				{Type: "nack"},
				{Type: "nack", Parameter: "pli"},
			},
		},
		PayloadType: 98,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, err
	}

	// 2026-05-28 — register the transport-cc (TWCC) header-extension sender.
	// Real WebRTC clients stamp every RTP packet with a transport-wide
	// sequence number so the remote can generate TWCC feedback. Without it
	// our packets lack the extension that the SFU's answer advertises
	// (a=extmap:N transport-cc) — a strong "not a real WebRTC source" DPI
	// signal. ConfigureTWCCHeaderExtensionSender registers the extmap on
	// both audio + video and adds an interceptor that injects monotonic
	// sequence numbers on egress. Pairs with the keyframe-ratio fix to make
	// the flow indistinguishable from a genuine Yandex SDK publisher.
	ir := &interceptor.Registry{}
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(me, ir); err != nil {
		return nil, err
	}

	// 2026-07-23 — TRIED a receiver-side transport-cc FEEDBACK generator here
	// (twcc.NewSenderInterceptor) to fix the "barely loads" throughput on
	// server→phone. It PASSED the clean-path bench-stand canary but REGRESSED the
	// real MOBILE path: with the phone now reporting its (lossy mobile) receive
	// stats, the SFU's send-side BWE for SFU→phone throttled DOWN toward zero, so
	// even the tiny in-band HELLO stopped arriving and pairing failed
	// (gotHello=false). Reverted. Receiver-side BWE feedback is the WRONG lever
	// on a lossy last mile — it tells the SFU to send LESS, not more.

	// 2026-07-22 — TRIED webrtc.ConfigureRTCPReports(ir) here (synthesize RTCP
	// Sender Reports, which a real libwebrtc publisher sends ~1/s and we never
	// did). It made things WORSE on the stand: delivery collapsed to ~1% and the
	// handshake slowed to ~5.7s — pion's report interceptor evidently chokes on
	// our very high packet rate. Reverted. RTCP-SR is not the fix (and not
	// installable cheaply here).

	return webrtc.NewAPI(
		webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(ir),
	), nil
}

// ToConfig converts the goloom-supplied ice_servers list into a Pion
// webrtc.Configuration with BUNDLE max-bundle (Telemost requires it — its
// publisher offer always uses a=group:BUNDLE 0 1).
func ToConfig(servers []goloom.ServerICEEntry) webrtc.Configuration {
	out := make([]webrtc.ICEServer, 0, len(servers))
	for _, s := range servers {
		out = append(out, webrtc.ICEServer{
			URLs:       s.URLs,
			Username:   s.Username,
			Credential: s.Credential,
		})
	}
	return webrtc.Configuration{
		ICEServers:    out,
		BundlePolicy:  webrtc.BundlePolicyMaxBundle,
		RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
	}
}
