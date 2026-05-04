// Package goloom defines the wire types and the WebSocket signalling client
// for Yandex Telemost's "goloom" SFU. Field tags mirror the JSON shape
// observed in C:\Users\pcex\VPSUTILS\telemost-dump\guest{1,2}-capture.json.
//
// Each frame on the wire is a JSON object with:
//   - a single "uid" UUID (request id, also echoed back in ack)
//   - exactly one content key naming the message type
package goloom

import "encoding/json"

// Envelope is what we send. For receive we keep the raw bytes plus the type
// key so unknown/optional message types pass through without decode failures.
//
// On send we build an Envelope per message type (Hello, PublisherSdpOffer,
// Ack, ...). On receive we parse just the UID and the message-type key, then
// decode the inner payload only if a handler asks for it.
type Envelope struct {
	UID                             string                           `json:"uid"`
	Hello                           *Hello                           `json:"hello,omitempty"`
	Ack                             *Ack                             `json:"ack,omitempty"`
	PublisherSdpOffer               *PublisherSdpOffer               `json:"publisherSdpOffer,omitempty"`
	SubscriberSdpAnswer             *SubscriberSdpAnswer             `json:"subscriberSdpAnswer,omitempty"`
	WebrtcIceCandidate              *WebrtcIceCandidate              `json:"webrtcIceCandidate,omitempty"`
	SetSlots                        *SetSlots                        `json:"setSlots,omitempty"`
	SdkCodecsInfo                   *SdkCodecsInfo                   `json:"sdkCodecsInfo,omitempty"`
	Telemetry                       *Telemetry                       `json:"telemetry,omitempty"`
	Ping                            *Ping                            `json:"ping,omitempty"`
	UpdatePublisherTrackDescription *UpdatePublisherTrackDescription `json:"updatePublisherTrackDescription,omitempty"`
	UpdateMe                        *UpdateMe                        `json:"updateMe,omitempty"`
}

// ParticipantMeta is the active state portion of a participant identity.
// Echoed by the server back to other peers so they can render us correctly.
type ParticipantMeta struct {
	Name        string `json:"name"`
	Role        string `json:"role"` // observed: "SPEAKER" for guests
	Description string `json:"description"`
	SendAudio   bool   `json:"sendAudio"`
	SendVideo   bool   `json:"sendVideo"`
}

// ParticipantAttr is the static identity portion (no media flags).
type ParticipantAttr struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Description string `json:"description"`
}

// SDKInfo is sent inside Hello so the SFU can do per-client feature gating.
// We mimic Chrome 5.27.1 verbatim.
type SDKInfo struct {
	Implementation string `json:"implementation"`
	Version        string `json:"version"`
	UserAgent      string `json:"userAgent"`
	HwConcurrency  int    `json:"hwConcurrency"`
}

// Hello is the first send frame after WS open. credentials and participantId
// come from the /connection HTTP response.
type Hello struct {
	ParticipantMeta         ParticipantMeta     `json:"participantMeta"`
	ParticipantAttributes   ParticipantAttr     `json:"participantAttributes"`
	SendAudio               bool                `json:"sendAudio"`
	SendVideo               bool                `json:"sendVideo"`
	SendSharing             bool                `json:"sendSharing"`
	ParticipantID           string              `json:"participantId"`
	RoomID                  string              `json:"roomId"`
	ServiceName             string              `json:"serviceName"` // "telemost"
	Credentials             string              `json:"credentials"`
	CapabilitiesOffer       map[string][]string `json:"capabilitiesOffer"`
	SDKInfo                 SDKInfo             `json:"sdkInfo"`
	SDKInitializationID     string              `json:"sdkInitializationId"`
	DisablePublisher        bool                `json:"disablePublisher"`
	DisableSubscriber       bool                `json:"disableSubscriber"`
	DisableSubscriberAudio  bool                `json:"disableSubscriberAudio"`
}

// AckStatus is the embedded status object inside Ack.
type AckStatus struct {
	Code        string `json:"code"` // "OK" on success
	Description string `json:"description"`
}

// Ack acknowledges receipt of a previous frame. The Envelope.UID of an Ack
// MUST equal the UID of the message being acknowledged (NOT a fresh UUID).
type Ack struct {
	Status AckStatus `json:"status"`
}

// ServerHello mirrors the response after our hello. We decode only the
// fields we actually act on; everything else is preserved by leaving extra
// keys in the raw payload.
type ServerHello struct {
	CapabilitiesAnswer    map[string]string         `json:"capabilitiesAnswer"`
	RtcConfiguration      RtcConfiguration          `json:"rtcConfiguration"`
	PingPongConfiguration PingPongConfiguration     `json:"pingPongConfiguration"`
	TelemetryConfiguration TelemetryConfiguration   `json:"telemetryConfiguration"`
	SdkFeatureFlags       map[string]json.RawMessage `json:"sdkFeatureFlags"`
}

// RtcConfiguration carries the ice_servers list (with TURN credentials)
// that becomes webrtc.Configuration.ICEServers on both PeerConnections.
type RtcConfiguration struct {
	ICEServers []ServerICEEntry `json:"iceServers"`
}

// ServerICEEntry mirrors RTCIceServer JSON. Empty username/credential are
// permitted (STUN entries have them blank).
type ServerICEEntry struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

// PingPongConfiguration controls how often we ping and how long we wait for
// the matching ack. Falls back to {ping=5000, ackTimeout=9000} if the server
// omits the block.
type PingPongConfiguration struct {
	PingInterval int `json:"pingInterval"` // milliseconds
	AckTimeout   int `json:"ackTimeout"`   // milliseconds
}

// TelemetryConfiguration controls how often we emit publisherRawStatsReport.
type TelemetryConfiguration struct {
	SendingInterval int `json:"sendingInterval"` // milliseconds
}

// PublisherSdpOffer is sent right after we ack the serverHello, with the
// offer SDP from Pion's CreateOffer + a one-entry-per-m-line tracks list
// describing what each transceiver carries.
type PublisherSdpOffer struct {
	PcSeq  int     `json:"pcSeq"` // 1 for the initial publisher offer
	SDP    string  `json:"sdp"`
	Tracks []Track `json:"tracks"`
}

// PublisherSdpAnswer is the SFU's answer to PublisherSdpOffer. No client ack
// is required — the answer itself acknowledges the offer.
type PublisherSdpAnswer struct {
	PcSeq int    `json:"pcSeq"`
	SDP   string `json:"sdp"`
}

// SubscriberSdpOffer arrives unprompted soon after our publisherSdpOffer
// (the SFU's "ON_HELLO" initial subscriber offer behaviour). We answer it
// with SubscriberSdpAnswer.
type SubscriberSdpOffer struct {
	PcSeq int    `json:"pcSeq"`
	SDP   string `json:"sdp"`
}

// SubscriberSdpAnswer carries Pion's CreateAnswer SDP back to the SFU.
type SubscriberSdpAnswer struct {
	PcSeq int    `json:"pcSeq"`
	SDP   string `json:"sdp"`
}

// Track describes one m-line in our publisherSdpOffer. mid and transceiverMid
// must match the values Pion baked into the SDP (typically "0", "1", ...).
type Track struct {
	MID            string                 `json:"mid"`
	TransceiverMID string                 `json:"transceiverMid"`
	Kind           string                 `json:"kind"` // "AUDIO" | "VIDEO"
	Priority       int                    `json:"priority"`
	Label          string                 `json:"label"`
	Codecs         map[string]interface{} `json:"codecs"`      // {} on initial offer
	GroupID        int                    `json:"groupId"`     // 1
	Description    string                 `json:"description"` // ""
}

// WebrtcIceCandidate carries one ICE candidate either way. Target tells the
// other side which PeerConnection it belongs to. UsernameFragment is set on
// the client-to-server direction (Pion exposes c.SDPMid + ufrag inferred from
// candidate string).
type WebrtcIceCandidate struct {
	PcSeq            int    `json:"pcSeq"`
	Target           string `json:"target"` // "PUBLISHER" | "SUBSCRIBER"
	Candidate        string `json:"candidate"`
	SdpMid           string `json:"sdpMid"`
	SdpMlineIndex    int    `json:"sdpMlineIndex"`
	UsernameFragment string `json:"usernameFragment,omitempty"`
}

// SetSlots is the client-side layout request. For PoC #1 we send 12 zero-
// sized slots once and never touch it again.
type SetSlots struct {
	Slots              []SlotSize `json:"slots"`
	AudioSlotsCount    int        `json:"audioSlotsCount"`
	Key                int        `json:"key"`
	ShutdownAllVideo   *bool      `json:"shutdownAllVideo"`
	WithSelfView       bool       `json:"withSelfView"`
	SelfViewVisibility string     `json:"selfViewVisibility"` // "ON_LOADING_THEN_SHOW"
	GridConfig         struct{}   `json:"gridConfig"`
}

// SlotSize sets the requested resolution for one slot. {0,0} means we don't
// need any pixels for that slot.
type SlotSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// SdkCodecsInfo is sent once during setup; for PoC #1 we omit it.
type SdkCodecsInfo struct {
	Codecs []json.RawMessage `json:"codecs"`
}

// Telemetry carries periodic stats reports. We send a minimal stub every
// telemetryConfiguration.sendingInterval to keep the SFU's liveness counter
// happy.
type Telemetry struct {
	PublisherRawStatsReport []string `json:"publisherRawStatsReport"`
}

// Ping carries no payload but the wrapper exists for type safety.
type Ping struct{}

// UpdatePublisherTrackDescription is sent after a successful renegotiation
// to declare the full track inventory (camera + display tracks). The JSON
// field is publisherTrackDescriptions per Phase 1 dump.
type UpdatePublisherTrackDescription struct {
	PublisherTrackDescriptions []Track `json:"publisherTrackDescriptions"`
}

// UpdateMe lets us mutate our participant flags after hello (mute/unmute,
// camera off, etc). Not used in PoC #1 directly.
type UpdateMe struct {
	ParticipantMeta       ParticipantMeta `json:"participantMeta"`
	ParticipantAttributes ParticipantAttr `json:"participantAttributes"`
	SendAudio             bool            `json:"sendAudio"`
	SendVideo             bool            `json:"sendVideo"`
	SendSharing           bool            `json:"sendSharing"`
}
