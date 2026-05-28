// Package inbound represents a single configured "tunnel into a Telemost
// meeting" on the goloom-wg-server. Each Inbound owns:
//
//   - one Telemost session (its own peer in the call)
//   - one Sender for outbound VP8 frames + receivers for incoming
//   - one wgrelay.WGCreator that bridges the tunnel to a local WG endpoint
//
// Multiple Inbounds run independently in goroutines; the Manager (manager.go)
// supervises them so a failure in one doesn't take down the others.
package inbound

import "time"

// Spec is the persistent description of an inbound — what gets serialised
// to the server's YAML / JSON state.
type Spec struct {
	ID          string `yaml:"id" json:"id"`
	Tag         string `yaml:"tag" json:"tag"`
	Meeting     string `yaml:"meeting" json:"meeting"`
	DisplayName string `yaml:"display_name" json:"display_name"`

	// Transport selects the SFU/transport implementation to use.
	// Empty string is treated as "telemost" for backward compatibility
	// with pre-multi-transport configs. Valid values come from
	// [github.com/Pinnss/goloom-server/internal/sfu].Kind.
	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	// PoolSize, when >1, runs the SFU session inside an N-member pool —
	// N parallel Telemost room participants share one logical inbound,
	// each publishing on their own track. Yandex Telemost caps each
	// publisher at ~3 Mbps, so N pool members give an ~N×3 Mbps download
	// budget on the subscriber side. Only meaningful for SFU-family
	// transports that tunnel through the SFU's media plane (currently
	// only Telemost). 0 and 1 both fall back to legacy single-instance
	// behaviour. Client side must match (encoded in the connection
	// string as p=N).
	PoolSize int `yaml:"pool_size,omitempty" json:"pool_size,omitempty"`

	// LiveKit holds extra credentials for transport=livekit-wb-stream.
	// Populated by the admin webview-auth flow; ignored otherwise.
	LiveKit *LiveKitSpec `yaml:"livekit,omitempty" json:"livekit,omitempty"`

	// VKCalls holds extra knobs for transport=vk-calls. Ignored
	// otherwise.
	VKCalls *VKCallsSpec `yaml:"vk_calls,omitempty" json:"vk_calls,omitempty"`

	// VKTurn holds extra knobs for transport=vk-turn. Ignored
	// otherwise. This transport is a listener (not an SFU client) —
	// see [github.com/Pinnss/goloom-server/internal/relay/vkturn].
	VKTurn *VKTurnSpec `yaml:"vk_turn,omitempty" json:"vk_turn,omitempty"`

	// WGEndpoint is the local UDP address the relay forwards decrypted
	// tunnel frames to (typically 127.0.0.1:51820 for wg0, +1 for wg1, etc.).
	WGEndpoint string `yaml:"wg_endpoint" json:"wg_endpoint"`

	// WGInterface is the wireguard interface name this inbound is bound to.
	// Empty if the operator manages WG out-of-band; populated when the admin
	// panel provisioned the interface itself.
	WGInterface string `yaml:"wg_iface,omitempty" json:"wg_iface,omitempty"`

	// WGSubnet is the /24 the WG interface owns (e.g. "10.66.66.0/24").
	// Stored so the Manager can free it when the inbound is removed.
	WGSubnet string `yaml:"wg_subnet,omitempty" json:"wg_subnet,omitempty"`

	// ClientWGPrivateKey is the client-side WG private key, kept here so
	// the panel can re-render the client config / QR on demand without
	// asking the operator to upload it again. Server pubkey is derived.
	ClientWGPrivateKey string `yaml:"client_wg_private_key,omitempty" json:"-"`
	ClientWGPublicKey  string `yaml:"client_wg_public_key,omitempty" json:"client_wg_public_key,omitempty"`
	ServerWGPrivateKey string `yaml:"server_wg_private_key,omitempty" json:"-"`
	ServerWGPublicKey  string `yaml:"server_wg_public_key,omitempty" json:"server_wg_public_key,omitempty"`

	Enabled bool `yaml:"enabled" json:"enabled"`

	CreatedAt time.Time `yaml:"created_at" json:"created_at"`
}

// LiveKitSpec stores the long-lived credentials needed to mint
// short-lived LiveKit roomTokens at Connect time. Captured by the
// admin webview-auth flow; cookies expire roughly every 14 days at
// which point the operator must re-auth in the admin UI.
//
// Mirror of [github.com/Pinnss/goloom-server/internal/sfu].LiveKitWBStreamConnect
// with persistence-friendly tags.
type LiveKitSpec struct {
	// RoomURL — public room link, e.g. https://stream.wb.ru/room/<id>.
	RoomURL string `yaml:"room_url" json:"room_url"`

	// AccessToken — guest user's long-lived JWT extracted from
	// localStorage.wb_auth_auth_slice.accessToken in the webview.
	// Persisted because re-issuing it requires another webview pass
	// through Cloudflare.
	AccessToken string `yaml:"access_token" json:"-"`

	// Cookies — joined Cookie header containing _wbafp / x_wbaas_token
	// / _wbauid. These are what Cloudflare actually checks; expiry is
	// about 14 days for x_wbaas_token, 1 year for _wbauid.
	Cookies string `yaml:"cookies" json:"-"`

	// CookiesExpireAt — earliest expiry among the captured cookies.
	// Admin UI surfaces this so operators can re-auth before runs go
	// dark. RFC3339-formatted in JSON.
	CookiesExpireAt time.Time `yaml:"cookies_expire_at,omitempty" json:"cookies_expire_at,omitempty"`
}

// VKCallsSpec persists the VK-Calls-specific knobs for one inbound.
//
// Mirror of [github.com/Pinnss/goloom-server/internal/sfu].VKCallsConnect
// minus the CaptchaSolver — the solver is wired at runtime by the
// runner (different deploy modes need different solvers; see the
// "captcha_mode" field).
//
// MeetingURL parallels Spec.Meeting (same URL slot, just kept here
// too for symmetry with LiveKitSpec.RoomURL). When both Spec.Meeting
// and Spec.VKCalls.MeetingURL are set, MeetingURL wins.
type VKCallsSpec struct {
	// MeetingURL — full https://vk.com/call/join/<id> link or just
	// the bare <id> short string.
	MeetingURL string `yaml:"meeting_url,omitempty" json:"meeting_url,omitempty"`

	// Role — "receiver" (default; server joins first, waits) or
	// "caller" (server joins second, drives the offer). Should
	// almost always be "receiver" for an inbound.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`

	// CaptchaMode picks the runtime captcha solver:
	//
	//   - "auto"          (default) — open the operator's default
	//                                 browser via a local reverse-
	//                                 proxy. Needs a desktop session
	//                                 on the server box; fine for
	//                                 dev/laptop deploys.
	//   - "none"          — no solver; the inbound fails fast on a
	//                       captcha challenge. Useful when you
	//                       expect the call link to bypass captcha
	//                       (e.g. cached IP-bound exemptions).
	//   - "admin-webview" — admin panel proxies the captcha to a
	//                       connected admin browser via the
	//                       CaptchaBroker (default for headless VPS).
	//
	// Empty defaults to "auto".
	CaptchaMode string `yaml:"captcha_mode,omitempty" json:"captcha_mode,omitempty"`

	// Codec выбирает video transport stack — см. VKCallsConnect.Codec.
	// Допустимые значения: "h264" / "" (default, RS I_PCM grid) или
	// "vp8" (Telemost-стек). Эксперимент S5: VP8 даёт целевую
	// throughput ~30+ Mbit/s vs ~600 Kbit/s на H.264.
	Codec string `yaml:"codec,omitempty" json:"codec,omitempty"`
}

// VKTurnSpec persists the VK TURN relay-specific knobs for one inbound.
//
// Unlike SFU transports, this is purely server-side: the relay listens
// on ListenAddr and forwards decrypted UDP payload to Spec.WGEndpoint.
// VKLink is not consumed by the server — it's stored only so the admin
// panel can render an end-user connection link/QR for third-party
// clients (anton48/Moroka8) that still need a VK call URL to anchor
// their TURN credential request.
type VKTurnSpec struct {
	// ListenAddr — public UDP endpoint the relay binds, e.g.
	// "0.0.0.0:56001". Must be unique across vk-turn inbounds on the
	// same host (otherwise the second Start fails with EADDRINUSE).
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	// VKLink — VK call URL the client side references when registering
	// VK TURN credentials via captcha (https://vk.com/call/join/<id>).
	// Not used by the listener itself — surfaced in the admin's client
	// connection-link generator only.
	VKLink string `yaml:"vk_link,omitempty" json:"vk_link,omitempty"`

	// UseWrap toggles the ChaCha20-XOR obfuscation layer (symmetric to
	// the client's `-wrap` flag). When true, WrapKeyHex must be 64 hex
	// characters (32 bytes).
	UseWrap bool `yaml:"use_wrap,omitempty" json:"use_wrap,omitempty"`

	// WrapKeyHex — 64-char hex-encoded 32-byte shared key for WRAP.
	// Auto-rolled at create-time by the admin form when UseWrap is on.
	WrapKeyHex string `yaml:"wrap_key_hex,omitempty" json:"-"`

	// PresharedKey — 32-byte base64 WG preshared key that the
	// auto-provisioned WG interface uses for this inbound's peer.
	// anton48 / Moroka8 client validates that the connection-link
	// includes a non-empty presharedKey, so vk-turn inbounds always
	// generate one. Server side bakes it into the peer section of
	// /etc/wireguard/<iface>.conf via wgprovision.
	PresharedKey string `yaml:"preshared_key,omitempty" json:"-"`
}

// Status is the live snapshot the admin panel renders. Not persisted.
type Status struct {
	ID         string    `json:"id"`
	Tag        string    `json:"tag"`
	Enabled    bool      `json:"enabled"`
	Running    bool      `json:"running"`
	Phase      string    `json:"phase"` // "starting" | "waiting_peer" | "handshaking" | "relaying" | "stopped" | "error"
	LastError  string    `json:"last_error,omitempty"`
	Meeting    string    `json:"meeting"`
	WGEndpoint string    `json:"wg_endpoint"`
	WGIface    string    `json:"wg_iface,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`

	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`

	// Relay-specific counters — non-zero only when Spec.Transport
	// addresses the [github.com/Pinnss/goloom-server/internal/relay]
	// family (currently just vk-turn). SFU transports leave these at 0.
	RelayActive   uint64 `json:"relay_active,omitempty"`
	RelayAccepted uint64 `json:"relay_accepted,omitempty"`
	RelayListen   string `json:"relay_listen,omitempty"`
}
