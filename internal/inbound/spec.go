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

	// LiveKit holds extra credentials for transport=livekit-wb-stream.
	// Populated by the admin webview-auth flow; ignored otherwise.
	LiveKit *LiveKitSpec `yaml:"livekit,omitempty" json:"livekit,omitempty"`

	// VKCalls holds extra knobs for transport=vk-calls. Ignored
	// otherwise.
	VKCalls *VKCallsSpec `yaml:"vk_calls,omitempty" json:"vk_calls,omitempty"`

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
	//   - "admin-webview" — TODO; the admin panel proxies the
	//                       captcha to a connected admin browser.
	//
	// Empty defaults to "auto".
	CaptchaMode string `yaml:"captcha_mode,omitempty" json:"captcha_mode,omitempty"`

	// Codec выбирает video transport stack — см. VKCallsConnect.Codec.
	// Допустимые значения: "h264" / "" (default, RS I_PCM grid) или
	// "vp8" (Telemost-стек). Эксперимент S5: VP8 даёт целевую
	// throughput ~30+ Mbit/s vs ~600 Kbit/s на H.264.
	Codec string `yaml:"codec,omitempty" json:"codec,omitempty"`

	// AcceptClientMeeting (S3): meeting URL приходит от клиента
	// через ctrl-ws DIAL вместо того чтобы быть забит в yaml.
	// Server inbound в этом режиме идле'т (ws на admin :9443) и
	// триггерит Transport.Connect только когда клиент DIAL'нул.
	// Совместимость: false (default) → старое поведение, MeetingURL
	// в yaml обязателен. true → MeetingURL игнорируется в yaml,
	// должен прилететь от клиента.
	AcceptClientMeeting bool `yaml:"accept_client_meeting,omitempty" json:"accept_client_meeting,omitempty"`

	// CtrlBearer (S2) — shared secret для авторизации клиентского
	// ctrl-ws подключения. Если пусто и AcceptClientMeeting=true,
	// генерируется автоматически при первом старте и зашивается в
	// yaml (для воспроизводимости между рестартами). Клиент получает
	// его в connstr.
	CtrlBearer string `yaml:"ctrl_bearer,omitempty" json:"ctrl_bearer,omitempty"`
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
}
