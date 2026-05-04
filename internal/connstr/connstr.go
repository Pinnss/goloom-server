package connstr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const Scheme = "goloom://"

type Params struct {
	Meeting     string `json:"m"`
	DisplayName string `json:"n,omitempty"`
	KCPMTU      int    `json:"km,omitempty"`
	KCPSndWnd   int    `json:"ks,omitempty"`
	KCPRcvWnd   int    `json:"kr,omitempty"`
	PSK         string `json:"psk,omitempty"`
	Tag         string `json:"tag,omitempty"`

	// WG-related fields. Populated by the admin panel when an inbound
	// has been auto-provisioned, so the client can build its WG config
	// from a single connection string instead of having the user copy a
	// .conf file separately. Field names kept short to fit a QR.
	WGClientPrivate string `json:"wgcp,omitempty"` // client private key (base64)
	WGServerPublic  string `json:"wgsp,omitempty"` // server public key (base64)
	WGClientAddr    string `json:"wga,omitempty"`  // client tunnel address with prefix, e.g. "10.66.1.2/24"
	WGEndpoint      string `json:"wge,omitempty"`  // endpoint to dial, e.g. "127.0.0.1:51820"
	WGDNS           string `json:"wgd,omitempty"`  // comma-separated DNS list, e.g. "1.1.1.1,8.8.8.8"
}

// HasWG reports whether the connection string carries a usable embedded
// WireGuard client config (no manual .conf import needed on the client).
func (p *Params) HasWG() bool {
	return p.WGClientPrivate != "" && p.WGServerPublic != "" && p.WGClientAddr != "" && p.WGEndpoint != ""
}

// WGClientConfig renders the embedded WG fields as a wg-quick-compatible
// config text. Returns "" if HasWG() is false.
func (p *Params) WGClientConfig() string {
	if !p.HasWG() {
		return ""
	}
	dns := p.WGDNS
	if dns == "" {
		dns = "1.1.1.1, 8.8.8.8"
	}
	return "[Interface]\n" +
		"PrivateKey = " + p.WGClientPrivate + "\n" +
		"Address = " + p.WGClientAddr + "\n" +
		"DNS = " + dns + "\n" +
		"\n" +
		"[Peer]\n" +
		"PublicKey = " + p.WGServerPublic + "\n" +
		"Endpoint = " + p.WGEndpoint + "\n" +
		"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n" +
		"PersistentKeepalive = 25\n"
}

func Encode(p *Params) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return Scheme + base64.RawURLEncoding.EncodeToString(data), nil
}

func Decode(s string) (*Params, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Scheme) {
		return nil, fmt.Errorf("invalid scheme: expected %s prefix", Scheme)
	}
	raw := s[len(Scheme):]
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	var p Params
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	if p.Meeting == "" {
		return nil, fmt.Errorf("meeting URL is required")
	}
	return &p, nil
}
