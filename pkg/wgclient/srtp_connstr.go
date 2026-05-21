// vkturnproxy:// connection-link parser for the client side.
//
// The admin panel emits these links via
// [internal/relay/vkturn.BuildAnton48Link] for the iOS anton48 client.
// goloom's desktop GUI consumes the same format so operators don't
// have to track two link schemas (vkturnproxy:// for iOS,
// goloom:// for desktop). When a vkturnproxy:// link comes in with
// useSrtp=true, [Service.Start] dispatches to the SRTP code path;
// useSrtp=false keeps the legacy DTLS+WG path.

package wgclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// vkTurnProxyLinkSettings is the JSON envelope anton48's BackupManager
// encodes. Field names must match the iOS-side schema exactly — see
// the upstream comment in [internal/relay/vkturn].LinkSettings.
type vkTurnProxyLinkSettings struct {
	PrivateKey     string `json:"privateKey"`
	PeerPublicKey  string `json:"peerPublicKey"`
	PresharedKey   string `json:"presharedKey"`
	TunnelAddress  string `json:"tunnelAddress"`
	AllowedIPs     string `json:"allowedIPs"`
	VKLink         string `json:"vkLink"`
	PeerAddress    string `json:"peerAddress"`
	UseDTLS        bool   `json:"useDTLS"`
	UseWrap        bool   `json:"useWrap"`
	WrapKeyHex     string `json:"wrapKeyHex"`
	UseSrtp        bool   `json:"useSrtp"`
	DNSServers     string `json:"dnsServers"`
	NumConnections int    `json:"numConnections"`
	MTU            int    `json:"mtu"`
}

type vkTurnProxyLinkEnvelope struct {
	Version  int                     `json:"version"`
	Type     string                  `json:"type"`
	Settings vkTurnProxyLinkSettings `json:"settings"`
}

const vkTurnProxyLinkPrefix = "vkturnproxy://import?data="

// IsVKTurnProxyLink reports whether s looks like a vkturnproxy://
// connection link the caller can pass to [FromVKTurnProxyLink].
// Cheap prefix check — full parsing happens in From… below.
func IsVKTurnProxyLink(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), vkTurnProxyLinkPrefix)
}

// FromVKTurnProxyLink decodes a vkturnproxy://import?data=<base64> URL
// into a wgclient.Config. Sets Transport to "vk-turn-srtp" when the
// payload's useSrtp is true; otherwise "vk-turn" (the legacy DTLS+WG
// path).
//
// Validation: only fields strictly required by the chosen transport are
// checked here; the rest is deferred to [Config.Validate]. Errors are
// shaped to be useful to the operator (mentions which JSON field).
func FromVKTurnProxyLink(s string) (Config, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, vkTurnProxyLinkPrefix) {
		return Config{}, fmt.Errorf("not a vkturnproxy:// link (want prefix %q)", vkTurnProxyLinkPrefix)
	}
	b64 := s[len(vkTurnProxyLinkPrefix):]
	// anton48 emits url-safe-no-padding; accept either standard or
	// url-safe encoding for paranoia.
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
	}
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(b64)
	}
	if err != nil {
		return Config{}, fmt.Errorf("base64 decode: %w", err)
	}

	var env vkTurnProxyLinkEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Config{}, fmt.Errorf("json: %w", err)
	}
	if env.Type != "" && env.Type != "connection" {
		return Config{}, fmt.Errorf("unsupported envelope type %q (want \"connection\")", env.Type)
	}
	if env.Version != 0 && env.Version != 1 {
		return Config{}, fmt.Errorf("unsupported schema version %d (this build understands v1)", env.Version)
	}
	st := env.Settings

	// Per-transport required fields.
	transport := "vk-turn"
	if st.UseSrtp {
		transport = "vk-turn-srtp"
	}
	if st.PeerAddress == "" {
		return Config{}, fmt.Errorf("missing peerAddress (server's vk-turn(-srtp) listener host:port)")
	}
	if st.PrivateKey == "" || st.PeerPublicKey == "" || st.TunnelAddress == "" {
		return Config{}, fmt.Errorf("missing WG identity (privateKey / peerPublicKey / tunnelAddress)")
	}

	cfg := Config{
		Transport:  transport,
		Meeting:    st.VKLink,
		ListenAddr: "127.0.0.1:51820",
		AutoWG:     true,
		WG: WGParams{
			ClientPrivateKey: st.PrivateKey,
			ServerPublicKey:  st.PeerPublicKey,
			ClientAddr:       st.TunnelAddress,
			PresharedKey:     st.PresharedKey,
			Endpoint:         "127.0.0.1:51820", // wg→our local SRTP-bind socket
		},
		VKTurnSRTP: VKTurnSRTPParams{
			PeerAddress:    st.PeerAddress,
			UseWrap:        st.UseWrap,
			WrapKeyHex:     st.WrapKeyHex,
			NumConnections: st.NumConnections,
			MTU:            st.MTU,
		},
	}
	if dns := strings.TrimSpace(st.DNSServers); dns != "" {
		for _, s := range strings.Split(dns, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.WG.DNS = append(cfg.WG.DNS, s)
			}
		}
	}
	return cfg, nil
}
