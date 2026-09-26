package peer

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/nack"
	"github.com/pion/interceptor/pkg/report"
	"github.com/pion/interceptor/pkg/twcc"
	"github.com/pion/rtp"
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

	// 2026-09-26 — RTCP interceptors. With ONLY the TWCC header-extension sender
	// registered, neither PC ever emits RTCP (no SR from the publisher, no RR /
	// NACK from the subscriber) and never answers the SFU's NACKs. Three sibling
	// Telemost tunnels hit our exact "SFU stops forwarding after 30-60 s"
	// symptom and each fixed it by registering pion's default interceptors
	// (olcrtc b20554b, kulikov0/whitelist-bypass, and one more sibling). The
	// 2026-07-22 ConfigureRTCPReports-only attempt below was measured on the
	// bench stand, later judged a misleading proxy, and without NACK — it does
	// not refute this. RTCPMode keeps the old behaviour one env var away.
	//
	// The interceptors are built individually rather than through
	// RegisterDefaultInterceptors: our codecs above already declare nack /
	// transport-cc feedback, and the Configure* helpers would append duplicate
	// a=rtcp-fb lines to the SDP.
	//
	// History kept for context:
	// 2026-07-23 — a receiver-side TWCC feedback generator alone regressed the
	// real mobile path (SFU BWE for SFU→phone throttled toward zero). With the
	// FrameAssembler of that time a single lost packet discarded a whole 64 KB
	// frame, so any SFU-side pacing looked like a dead link; RTCPModeNoFeedback
	// isolates that generator if it still hurts with the reorder buffer.
	// 2026-07-22 — ConfigureRTCPReports alone "collapsed delivery to ~1%" on the
	// stand.
	if err := addRTCPInterceptors(ir, RTCPMode); err != nil {
		return nil, err
	}

	return webrtc.NewAPI(
		webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(ir),
		webrtc.WithSettingEngine(newSettingEngine()),
	), nil
}

// RTCP interceptor sets selectable through RTCPMode.
const (
	// RTCPModeFull: NACK generator + responder, RTCP sender/receiver reports,
	// receiver-side TWCC feedback. What a real WebRTC client does.
	RTCPModeFull = "full"
	// RTCPModeNoFeedback: RTCPModeFull without receiver-side TWCC feedback.
	RTCPModeNoFeedback = "nofb"
	// RTCPModeLegacy: no RTCP interceptors (behaviour before 2026-09).
	RTCPModeLegacy = "legacy"
)

// RTCPMode is read by BuildAPI for every new session. It defaults to
// $GOLOOM_RTCP_MODE, or RTCPModeNoFeedback when that is unset or unknown.
//
// The default deliberately omits the receiver-side TWCC feedback generator.
// Measured 2026-07-23: with the phone reporting its (lossy mobile) receive
// stats, the SFU's send-side estimate for SFU→phone fell toward zero and even
// the single-packet HELLO stopped arriving. Reports and NACK — the parts the
// sibling projects identified as load-bearing — are on. Set the env var to
// "full" to re-test the feedback generator, or on Android call
// Client.SetRTCPMode before Connect.
var RTCPMode = rtcpModeFromEnv()

// ValidRTCPMode reports whether m names an RTCP interceptor set.
func ValidRTCPMode(m string) bool {
	switch m {
	case RTCPModeFull, RTCPModeNoFeedback, RTCPModeLegacy:
		return true
	}
	return false
}

func rtcpModeFromEnv() string {
	if m := strings.ToLower(strings.TrimSpace(os.Getenv("GOLOOM_RTCP_MODE"))); ValidRTCPMode(m) {
		return m
	}
	return RTCPModeNoFeedback
}

// NACK sizing. The tunnel runs ~50 frames/s of up to ~64 KB, i.e. ~2700
// RTP packets/s at full rate. The responder keeps the last 4096 sent packets
// (~1.5 s, ~5 MB) so the SFU's NACKs can still be answered after one RTT;
// the generator watches a 2048-packet window and asks for each hole at most
// three times so a dead leg cannot turn into a NACK storm of our own.
const (
	nackResponderSize    = 4096
	nackGeneratorSize    = 2048
	nackMaxPerPacket     = 3
	nackGeneratorEveryMs = 50
)

func addRTCPInterceptors(ir *interceptor.Registry, mode string) error {
	if mode == RTCPModeLegacy {
		return nil
	}
	// Sits between the TWCC header-extension sender (registered above, so it
	// is closer to the transport) and the NACK responder: pion wraps writers
	// in registration order, making a later interceptor the outer one. The
	// responder resends straight from its buffer, handing the SAME *rtp.Header
	// to the writer chain from one goroutine per NACK; the TWCC sender then
	// stamps a sequence number into that shared header in place. Two resends of
	// one packet would race and could burn the same transport-wide sequence
	// number twice, which the SFU reports back as phantom loss. Cloning here
	// gives every write its own header.
	ir.Add(&cloneHeaderFactory{})

	responder, err := nack.NewResponderInterceptor(nack.ResponderSize(nackResponderSize))
	if err != nil {
		return err
	}
	generator, err := nack.NewGeneratorInterceptor(
		nack.GeneratorSize(nackGeneratorSize),
		nack.GeneratorMaxNacksPerPacket(nackMaxPerPacket),
		nack.GeneratorInterval(nackGeneratorEveryMs*time.Millisecond),
	)
	if err != nil {
		return err
	}
	ir.Add(responder)
	ir.Add(generator)

	rr, err := report.NewReceiverInterceptor()
	if err != nil {
		return err
	}
	sr, err := report.NewSenderInterceptor()
	if err != nil {
		return err
	}
	ir.Add(rr)
	ir.Add(sr)

	if mode == RTCPModeNoFeedback {
		return nil
	}
	fb, err := twcc.NewSenderInterceptor()
	if err != nil {
		return err
	}
	ir.Add(fb)
	return nil
}

// newSettingEngine restricts ICE to IPv4/UDP on real uplink interfaces.
// Host candidates on WireGuard / VPN / container interfaces can never reach
// the SFU; the dead pairs they create starve ICE consent checks on the
// working pair and end in a media teardown after ~30-60 s (olcrtc b20554b,
// PR #136). Our own servers host wg* interfaces, and on a reconnect the phone
// already has its VPN tun up.
//
// The filter is NOT only about host candidates: with one set, pion gathers
// srflx and relay candidates from one socket per kept address instead of a
// single wildcard socket, and gathers none at all if no address survives. So
// it is installed only when it leaves a usable uplink — otherwise a host whose
// only uplink sits on a filtered name (a Hyper-V external switch, say) would
// gather nothing and fail ICE outright.
func newSettingEngine() webrtc.SettingEngine {
	var se webrtc.SettingEngine
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if haveKeptICEInterface() {
		se.SetInterfaceFilter(KeepICEInterface)
	}
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return se
}

// haveKeptICEInterface reports whether at least one up, non-loopback
// interface with an IPv4 address survives KeepICEInterface. On any
// enumeration error it returns false, i.e. it errs towards not filtering.
func haveKeptICEInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !KeepICEInterface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// ignoredICEInterfacePrefixes are matched case-insensitively against the
// start of an interface name. "goloom" is our own wintun adapter on Windows.
// The Hyper-V names are the internal switches only: an EXTERNAL switch is
// named "vEthernet (<switch>)" too but carries the host's real uplink, so a
// bare "vethernet" prefix would filter away the only usable interface.
var ignoredICEInterfacePrefixes = []string{
	"wg", "awg", "tun", "utun", "tap", "goloom", "docker", "veth", "br-",
	"virbr", "vethernet (wsl", "vethernet (default switch",
	"zt", "tailscale", "dummy",
}

// cloneHeaderFactory gives every outgoing RTP write its own header copy, so an
// interceptor closer to the transport that stamps the header in place (the TWCC
// header-extension sender) cannot mutate a header another goroutine is
// resending from. Stateless, so one instance serves every stream.
type cloneHeaderFactory struct{ interceptor.NoOp }

func (f *cloneHeaderFactory) NewInterceptor(string) (interceptor.Interceptor, error) { return f, nil }

func (f *cloneHeaderFactory) BindLocalStream(_ *interceptor.StreamInfo, w interceptor.RTPWriter) interceptor.RTPWriter {
	return interceptor.RTPWriterFunc(func(h *rtp.Header, payload []byte, a interceptor.Attributes) (int, error) {
		c := h.Clone()
		return w.Write(&c, payload, a)
	})
}

// KeepICEInterface reports whether ICE may gather host candidates on the
// named network interface.
func KeepICEInterface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range ignoredICEInterfacePrefixes {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	return true
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
