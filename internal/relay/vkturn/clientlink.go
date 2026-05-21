// Client-link generator for third-party vk-turn-proxy clients.
//
// Goloom hasn't shipped its own vk-turn client yet, so until we do
// the admin panel emits a `vkturnproxy://import?data=<base64>` link
// that anton48/vk-turn-proxy-ios (and the Moroka8 fork it's based on)
// can consume out of the box. Wire format is reverse-engineered from
// the iOS app's BackupManager: a versioned envelope { version, type,
// settings } base64'd into the URL.
//
// Once goloom has a native client, the same Spec.VKTurn data will be
// served via a connstr:// link instead — but the wire format here
// stays as a public compatibility surface for the upstream clients.

package vkturn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// LinkSettings is the JSON payload anton48's BackupManager.importLink
// decodes. Field names match anton48 *exactly* — don't rename.
type LinkSettings struct {
	PrivateKey     string `json:"privateKey"`
	PeerPublicKey  string `json:"peerPublicKey"`
	PresharedKey   string `json:"presharedKey"`
	TunnelAddress  string `json:"tunnelAddress"` // e.g. "10.66.1.2/24"
	AllowedIPs     string `json:"allowedIPs"`    // e.g. "0.0.0.0/0"
	VKLink         string `json:"vkLink"`        // "https://vk.com/call/join/<id>"
	PeerAddress    string `json:"peerAddress"`   // "1.2.3.4:56001" — the vk-turn listener
	UseDTLS        bool   `json:"useDTLS"`
	UseWrap        bool   `json:"useWrap"`
	WrapKeyHex     string `json:"wrapKeyHex"` // 64 hex chars; 64 zeroes when UseWrap=false (anton48 validator)
	UseSrtp        bool   `json:"useSrtp,omitempty"` // anton48 v1.0-build125+: enables SRTP-framed transport
	DNSServers     string `json:"dnsServers,omitempty"`
	NumConnections int    `json:"numConnections,omitempty"`
	MTU            int    `json:"mtu,omitempty"` // see defaultMTU
}

// LinkParams gathers the inputs BuildAnton48Link needs. The caller
// (admin handler) collects these from inbound.Spec + provisioned
// allocation.
type LinkParams struct {
	// Client-side WG identity from auto-provision.
	ClientPrivateKey string
	ServerPublicKey  string
	PresharedKey     string

	// Client WG interface address with CIDR mask (e.g. "10.66.1.2/24").
	TunnelAddress string

	// VK call URL (https://vk.com/call/join/<id>).
	VKLink string

	// Public vk-turn endpoint (e.g. "1.2.3.4:56001").
	PeerAddress string

	// WRAP layer toggle + key.
	UseWrap    bool
	WrapKeyHex string

	// Optional knobs (omitted from payload when zero).
	DNSServers     string
	NumConnections int

	// MTU for the client's WG interface. Zero → defaultMTU (1280).
	// Rationale: vk-turn double-encapsulates (WG inside DTLS inside
	// TURN ChannelData over UDP). Each layer adds overhead; on a 1500-
	// byte path MTU the client's WG MTU has to drop to ~1280 to avoid
	// IP fragmentation of the outer DTLS packets, which TURN relays
	// don't reassemble. The upstream Moroka8 quick_link.py hard-coded
	// 1280 for the same reason.
	MTU int

	// UseSrtp toggles the SRTP-framed transport on the iOS client side
	// (anton48 build125+). Server-side requires a vk-turn-srtp inbound
	// listening for DTLS-SRTP — set this true *only* when the link
	// targets a vkturnsrtp.Transport listener; leaving it false keeps
	// the legacy DTLS+WG path.
	UseSrtp bool
}

// link envelope schema version. Must match anton48
// BackupManager.supportedConfigVersion.
const linkSchemaVersion = 1

// defaultMTU is the WG-interface MTU baked into the link when caller
// doesn't override. 1280 = path MTU 1500 − 20 (IPv4) − 8 (UDP) − ~56
// (DTLS+TURN ChannelData framing) − 80 (WG header) ≈ 1336, rounded
// down with safety margin. Matches upstream Moroka8 quick_link.py.
const defaultMTU = 1280

// BuildAnton48Link returns a `vkturnproxy://import?data=<base64>`
// URL ready to share. The base64 encoding is URL-safe-no-padding
// (anton48 parser accepts either variant).
func BuildAnton48Link(p LinkParams) (string, error) {
	if p.ClientPrivateKey == "" {
		return "", fmt.Errorf("vkturn: clientlink ClientPrivateKey is empty")
	}
	if p.ServerPublicKey == "" {
		return "", fmt.Errorf("vkturn: clientlink ServerPublicKey is empty")
	}
	if p.PresharedKey == "" {
		return "", fmt.Errorf("vkturn: clientlink PresharedKey is empty (anton48 validator rejects empty PSK)")
	}
	if p.TunnelAddress == "" {
		return "", fmt.Errorf("vkturn: clientlink TunnelAddress is empty")
	}
	if p.VKLink == "" {
		return "", fmt.Errorf("vkturn: clientlink VKLink is empty")
	}
	if p.PeerAddress == "" {
		return "", fmt.Errorf("vkturn: clientlink PeerAddress is empty")
	}

	// anton48 BackupManager validates wrapKeyHex is exactly 64 hex chars
	// even when useWrap=false (it only skips the *content* check). Pad
	// with zeros when WRAP is off so the client-side validator accepts.
	wrapKey := p.WrapKeyHex
	if !p.UseWrap {
		wrapKey = strings.Repeat("0", 64)
	}

	mtu := p.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	settings := LinkSettings{
		PrivateKey:     p.ClientPrivateKey,
		PeerPublicKey:  p.ServerPublicKey,
		PresharedKey:   p.PresharedKey,
		TunnelAddress:  p.TunnelAddress,
		AllowedIPs:     "0.0.0.0/0",
		VKLink:         p.VKLink,
		PeerAddress:    p.PeerAddress,
		UseDTLS:        true,
		UseWrap:        p.UseWrap,
		WrapKeyHex:     wrapKey,
		UseSrtp:        p.UseSrtp,
		DNSServers:     p.DNSServers,
		NumConnections: p.NumConnections,
		MTU:            mtu,
	}

	envelope := struct {
		Version  int          `json:"version"`
		Type     string       `json:"type"`
		Settings LinkSettings `json:"settings"`
	}{
		Version:  linkSchemaVersion,
		Type:     "connection",
		Settings: settings,
	}

	raw, err := marshalCanonical(envelope)
	if err != nil {
		return "", fmt.Errorf("vkturn: clientlink json: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	return "vkturnproxy://import?data=" + b64, nil
}

// marshalCanonical encodes with sorted keys + no extra whitespace — the
// same canonical form Python's `json.dumps(..., sort_keys=True,
// separators=(",", ":"))` produces, which is what anton48 quick_link.py
// emits. Bit-for-bit identical output makes debugging easier when an
// operator manually decodes a link.
func marshalCanonical(v any) ([]byte, error) {
	// Two-pass: encoding/json sorts struct fields by declared order,
	// not name. To get sorted-by-key output we round-trip through a
	// map and use sortMapJSON below. For our small envelope this is
	// fine — payload is < 1 KiB.
	tmp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var asMap any
	if err := json.Unmarshal(tmp, &asMap); err != nil {
		return nil, err
	}
	return sortMapJSON(asMap), nil
}

// sortMapJSON walks a json-decoded value and re-emits it with map keys
// in lexicographic order. Returns canonical bytes.
func sortMapJSON(v any) []byte {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf []byte
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, _ := json.Marshal(k)
			buf = append(buf, kb...)
			buf = append(buf, ':')
			buf = append(buf, sortMapJSON(x[k])...)
		}
		buf = append(buf, '}')
		return buf
	case []any:
		var buf []byte
		buf = append(buf, '[')
		for i, e := range x {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, sortMapJSON(e)...)
		}
		buf = append(buf, ']')
		return buf
	default:
		b, _ := json.Marshal(v)
		return b
	}
}

