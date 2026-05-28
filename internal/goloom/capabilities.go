package goloom

// DefaultCapabilitiesOffer is a verbatim copy of the capabilitiesOffer block
// sent by the production Telemost web client (Chrome 5.27.1 SDK build) on
// hello. Order and string casing matter — the server compares values literally.
//
// Reverse-engineered from C:\Users\pcex\VPSUTILS\telemost-dump\guest2-capture.json
// (first WS send frame, hello.capabilitiesOffer).
//
// Several fields use ["TRUE"] / ["FALSE"] string singletons rather than booleans
// — that is intentional protobuf-style enum encoding. Do not "normalize" them.
var DefaultCapabilitiesOffer = map[string][]string{
	"offerAnswerMode":                       {"SEPARATE"},
	"initialSubscriberOffer":                {"ON_HELLO"},
	"slotsMode":                             {"FROM_CONTROLLER"},
	// Force DISABLED — when we removed VP9/SVC, SFU defaulted to STATIC
	// here. STATIC simulcast expects 3 layered tracks; we publish 1.
	// Mismatch likely worsens forwarding decisions.
	"simulcastMode":                         {"DISABLED"},
	"selfVadStatus":                         {"FROM_SERVER", "FROM_CLIENT"},
	"dataChannelSharing":                    {"TO_RTP"},
	"videoEncoderConfig":                    {"NO_CONFIG", "ONLY_INIT_CONFIG", "RUNTIME_CONFIG"},
	// We now publish VP9 (PT 98) — see [internal/peer/engine.go] BuildAPI.
	"dataChannelVideoCodec":                 {"VP9", "UNIQUE_CODEC_FROM_TRACK_DESCRIPTION"},
	// Single-value offer forces SFU to pick "DISABLED" — i.e. don't engage
	// per-participant bandwidth limitation logic. Original offer included
	// "BANDWIDTH_REASON_ENABLED"; SFU chose ENABLED and capped us at ~3
	// Mbps. 2026-05-27 — see [internal/session/session.go] STAGE4 log.
	"bandwidthLimitationReason":             {"BANDWIDTH_REASON_DISABLED"},
	"sdkDefaultDeviceManagement":            {"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED", "SDK_DEFAULT_DEVICE_MANAGEMENT_ENABLED"},
	"joinOrderLayout":                       {"JOIN_ORDER_LAYOUT_DISABLED", "JOIN_ORDER_LAYOUT_ENABLED"},
	"pinLayout":                             {"PIN_LAYOUT_DISABLED"},
	"sendSelfViewVideoSlot":                 {"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED", "SEND_SELF_VIEW_VIDEO_SLOT_ENABLED"},
	"serverLayoutTransition":                {"SERVER_LAYOUT_TRANSITION_DISABLED"},
	// Single-value offer forces "DISABLED" — i.e. ask the SDK not to
	// auto-optimize (read: reduce) the publisher bitrate based on
	// REMB/TWCC. SFU previously chose FULL on the multi-option offer,
	// which is the strongest possible bitrate-clamping mode.
	"sdkPublisherOptimizeBitrate":           {"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
	"sdkNetworkLostDetection":               {"SDK_NETWORK_LOST_DETECTION_DISABLED"},
	"sdkNetworkPathMonitor":                 {"SDK_NETWORK_PATH_MONITOR_DISABLED"},
	// We publish plain VP9 (no SVC layers). Force ENABLED for publisherVp9
	// to truthfully signal the codec, but keep svcMode at DISABLED so the
	// SFU doesn't try to slice us into spatial/temporal layers it won't
	// find (we publish one flat VP9 stream).
	"publisherVp9":                          {"PUBLISH_VP9_ENABLED"},
	"svcMode":                               {"SVC_MODE_DISABLED"},
	"subscriberOfferAsyncAck":               {"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED", "SUBSCRIBER_OFFER_ASYNC_ACK_ENABLED"},
	"androidBluetoothRoutingFix":            {"ANDROID_BLUETOOTH_ROUTING_FIX_DISABLED"},
	"fixedIceCandidatesPoolSize":            {"FIXED_ICE_CANDIDATES_POOL_SIZE_DISABLED"},
	"sdkAndroidTelecomIntegration":          {"SDK_ANDROID_TELECOM_INTEGRATION_DISABLED"},
	"setActiveCodecsMode":                   {"SET_ACTIVE_CODECS_MODE_DISABLED", "SET_ACTIVE_CODECS_MODE_VIDEO_ONLY"},
	"subscriberDtlsPassiveMode":             {"SUBSCRIBER_DTLS_PASSIVE_MODE_DISABLED", "SUBSCRIBER_DTLS_PASSIVE_MODE_ENABLED"},
	"publisherOpusDred":                     {"PUBLISHER_OPUS_DRED_DISABLED"},
	"publisherOpusLowBitrate":               {"PUBLISHER_OPUS_LOW_BITRATE_DISABLED"},
	"sdkAndroidDestroySessionOnTaskRemoved": {"SDK_ANDROID_DESTROY_SESSION_ON_TASK_REMOVED_DISABLED"},
	"svcModes":                              {"FALSE"},
	"reportTelemetryModes":                  {"TRUE"},
	"keepDefaultDevicesModes":               {"FALSE"},
}

// ChromeSDKInfo mirrors the sdkInfo block sent by the web client. Used as
// hello.sdkInfo verbatim — the server may gate features on implementation/
// version so we identify as the production browser SDK.
var ChromeSDKInfo = SDKInfo{
	Implementation: "browser",
	Version:        "5.27.1",
	UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	HwConcurrency:  8,
}
