package peer

import (
	"github.com/pion/webrtc/v4"

	"github.com/Sv9toslavPinigin/goloom-server/internal/goloom"
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

	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "goog-remb"},
				{Type: "transport-cc"},
				{Type: "ccm", Parameter: "fir"},
				{Type: "nack"},
				{Type: "nack", Parameter: "pli"},
			},
		},
		PayloadType: 96,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, err
	}

	return webrtc.NewAPI(webrtc.WithMediaEngine(me)), nil
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
