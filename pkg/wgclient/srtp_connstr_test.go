package wgclient

import (
	"strings"
	"testing"

	"github.com/Pinnss/goloom-server/internal/relay/vkturn"
)

// Build a vkturnproxy:// link via the server-side generator, then
// decode it via the client-side parser, then verify the resulting
// wgclient.Config carries the same identity. End-to-end check that
// the two sides agree on the wire format.
func TestFromVKTurnProxyLink_RoundTrip(t *testing.T) {
	params := vkturn.LinkParams{
		ClientPrivateKey: "cENyBCcexdGDW0GqvW2GVRDbSo/8T7WQfRRblI3ZjX8=",
		ServerPublicKey:  "kMDrzuiS8mAU/JssntSnyPrvEzgN2DXVYHvE7J1Wtys=",
		PresharedKey:     "5TzS4OQPulRyEZKB5QNacJ+/eGrkmIsY5B4pPg+RPTg=",
		TunnelAddress:    "10.66.66.3/24",
		VKLink:           "https://vk.com/call/join/AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU",
		PeerAddress:      "vps.example.com:56001",
		UseSrtp:          true,
		DNSServers:       "8.8.8.8,1.1.1.1",
		NumConnections:   10,
		MTU:              1280,
	}
	link, err := vkturn.BuildAnton48Link(params)
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	if !IsVKTurnProxyLink(link) {
		t.Fatalf("IsVKTurnProxyLink rejected its own link: %q", link[:64])
	}

	cfg, err := FromVKTurnProxyLink(link)
	if err != nil {
		t.Fatalf("FromVKTurnProxyLink: %v", err)
	}
	if cfg.Transport != "vk-turn-srtp" {
		t.Errorf("Transport: got %q, want %q (UseSrtp=true should select SRTP path)", cfg.Transport, "vk-turn-srtp")
	}
	if cfg.WG.ClientPrivateKey != params.ClientPrivateKey {
		t.Errorf("ClientPrivateKey: got %q, want %q", cfg.WG.ClientPrivateKey, params.ClientPrivateKey)
	}
	if cfg.WG.PresharedKey != params.PresharedKey {
		t.Errorf("PresharedKey: got %q, want %q", cfg.WG.PresharedKey, params.PresharedKey)
	}
	if cfg.WG.ClientAddr != params.TunnelAddress {
		t.Errorf("ClientAddr: got %q, want %q", cfg.WG.ClientAddr, params.TunnelAddress)
	}
	if cfg.VKTurnSRTP.PeerAddress != params.PeerAddress {
		t.Errorf("PeerAddress: got %q, want %q", cfg.VKTurnSRTP.PeerAddress, params.PeerAddress)
	}
	if cfg.VKTurnSRTP.MTU != params.MTU {
		t.Errorf("MTU: got %d, want %d", cfg.VKTurnSRTP.MTU, params.MTU)
	}
	if cfg.VKTurnSRTP.NumConnections != params.NumConnections {
		t.Errorf("NumConnections: got %d, want %d", cfg.VKTurnSRTP.NumConnections, params.NumConnections)
	}
	if cfg.Meeting != params.VKLink {
		t.Errorf("Meeting: got %q, want %q", cfg.Meeting, params.VKLink)
	}
	if want := []string{"8.8.8.8", "1.1.1.1"}; len(cfg.WG.DNS) != len(want) {
		t.Errorf("DNS count: got %d, want %d (%v)", len(cfg.WG.DNS), len(want), cfg.WG.DNS)
	} else {
		for i, v := range want {
			if cfg.WG.DNS[i] != v {
				t.Errorf("DNS[%d]: got %q, want %q", i, cfg.WG.DNS[i], v)
			}
		}
	}
	// And the resulting config must pass Validate.
	if err := cfg.Validate(); err != nil {
		t.Errorf("parsed config failed Validate: %v", err)
	}
}

func TestFromVKTurnProxyLink_LegacyDTLS(t *testing.T) {
	params := vkturn.LinkParams{
		ClientPrivateKey: "cENyBCcexdGDW0GqvW2GVRDbSo/8T7WQfRRblI3ZjX8=",
		ServerPublicKey:  "kMDrzuiS8mAU/JssntSnyPrvEzgN2DXVYHvE7J1Wtys=",
		PresharedKey:     "5TzS4OQPulRyEZKB5QNacJ+/eGrkmIsY5B4pPg+RPTg=",
		TunnelAddress:    "10.66.66.3/24",
		VKLink:           "https://vk.com/call/join/AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU",
		PeerAddress:      "1.2.3.4:56001",
		UseSrtp:          false, // legacy DTLS+WG
	}
	link, err := vkturn.BuildAnton48Link(params)
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	cfg, err := FromVKTurnProxyLink(link)
	if err != nil {
		t.Fatalf("FromVKTurnProxyLink: %v", err)
	}
	if cfg.Transport != "vk-turn" {
		t.Errorf("Transport: got %q, want %q (UseSrtp=false should select legacy path)", cfg.Transport, "vk-turn")
	}
}

func TestFromVKTurnProxyLink_Errors(t *testing.T) {
	type tc struct {
		name string
		link string
		want string // substring that must appear in error
	}
	cases := []tc{
		{"empty", "", "not a vkturnproxy"},
		{"wrong scheme", "https://example.com", "not a vkturnproxy"},
		{"bad base64", vkTurnProxyLinkPrefix + "!!!not_base64!!!", "base64 decode"},
		{"bad json", vkTurnProxyLinkPrefix + "bm90LWpzb24=", "json"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := FromVKTurnProxyLink(c.link)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q should contain %q", err, c.want)
			}
		})
	}
}
