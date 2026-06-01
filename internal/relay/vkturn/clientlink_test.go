package vkturn

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// validParams returns a LinkParams populated with values that pass
// every validation in BuildAnton48Link. Each test then mutates one
// field to drive a specific code path.
func validParams() LinkParams {
	return LinkParams{
		ClientPrivateKey: "cENyBCcexdGDW0GqvW2GVRDbSo/8T7WQfRRblI3ZjX8=",
		ServerPublicKey:  "kMDrzuiS8mAU/JssntSnyPrvEzgN2DXVYHvE7J1Wtys=",
		PresharedKey:     "5TzS4OQPulRyEZKB5QNacJ+/eGrkmIsY5B4pPg+RPTg=",
		TunnelAddress:    "10.66.66.3/24",
		VKLink:           "https://vk.com/call/join/AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU",
		PeerAddress:      "203.0.113.10:56000",
		UseWrap:          false,
	}
}

// decodeLink reverses BuildAnton48Link's URL → struct so tests can
// inspect the inner payload directly instead of brittle substring
// matches on the base64.
func decodeLink(t *testing.T, link string) struct {
	Version  int          `json:"version"`
	Type     string       `json:"type"`
	Settings LinkSettings `json:"settings"`
} {
	t.Helper()
	const prefix = "vkturnproxy://import?data="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link does not start with %q: %q", prefix, link)
	}
	raw, err := base64.RawURLEncoding.DecodeString(link[len(prefix):])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var out struct {
		Version  int          `json:"version"`
		Type     string       `json:"type"`
		Settings LinkSettings `json:"settings"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json decode: %v\nraw: %s", err, raw)
	}
	return out
}

func TestBuildAnton48Link_Success(t *testing.T) {
	link, err := BuildAnton48Link(validParams())
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	got := decodeLink(t, link)

	if got.Version != linkSchemaVersion {
		t.Errorf("version: got %d, want %d", got.Version, linkSchemaVersion)
	}
	if got.Type != "connection" {
		t.Errorf("type: got %q, want %q", got.Type, "connection")
	}
	if !got.Settings.UseDTLS {
		t.Error("useDTLS should default to true (we never run without)")
	}
	if got.Settings.AllowedIPs != "0.0.0.0/0" {
		t.Errorf("allowedIPs: got %q, want %q", got.Settings.AllowedIPs, "0.0.0.0/0")
	}
	if got.Settings.MTU != defaultMTU {
		t.Errorf("MTU: got %d, want %d (default)", got.Settings.MTU, defaultMTU)
	}
	// useWrap=false ⇒ wrapKeyHex must still be 64 chars or anton48 rejects.
	if len(got.Settings.WrapKeyHex) != 64 {
		t.Errorf("wrapKeyHex padding length: got %d, want 64", len(got.Settings.WrapKeyHex))
	}
}

func TestBuildAnton48Link_WrapOnUsesProvidedKey(t *testing.T) {
	p := validParams()
	p.UseWrap = true
	p.WrapKeyHex = strings.Repeat("ab", 32) // 64 hex chars
	link, err := BuildAnton48Link(p)
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	got := decodeLink(t, link)
	if !got.Settings.UseWrap {
		t.Error("useWrap should be true")
	}
	if got.Settings.WrapKeyHex != p.WrapKeyHex {
		t.Errorf("wrapKeyHex: got %q, want %q", got.Settings.WrapKeyHex, p.WrapKeyHex)
	}
}

func TestBuildAnton48Link_UseSrtpFlows(t *testing.T) {
	// Default: UseSrtp=false → field omitted from JSON output (omitempty).
	link, err := BuildAnton48Link(validParams())
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	const prefix = "vkturnproxy://import?data="
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, prefix))
	if strings.Contains(string(raw), `"useSrtp"`) {
		t.Errorf("default UseSrtp=false should be omitted (omitempty), but JSON contains it: %s", raw)
	}

	// Explicit true: must surface as useSrtp: true.
	p := validParams()
	p.UseSrtp = true
	link, err = BuildAnton48Link(p)
	if err != nil {
		t.Fatalf("BuildAnton48Link UseSrtp=true: %v", err)
	}
	got := decodeLink(t, link)
	if !got.Settings.UseSrtp {
		t.Error("useSrtp should be true in payload")
	}
}

func TestBuildAnton48Link_MTUOverride(t *testing.T) {
	p := validParams()
	p.MTU = 1400
	link, err := BuildAnton48Link(p)
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	got := decodeLink(t, link)
	if got.Settings.MTU != 1400 {
		t.Errorf("MTU override ignored: got %d, want 1400", got.Settings.MTU)
	}
}

func TestBuildAnton48Link_ValidationErrors(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*LinkParams)
	}
	cases := []tc{
		{"missing ClientPrivateKey", func(p *LinkParams) { p.ClientPrivateKey = "" }},
		{"missing ServerPublicKey", func(p *LinkParams) { p.ServerPublicKey = "" }},
		{"missing PresharedKey", func(p *LinkParams) { p.PresharedKey = "" }},
		{"missing TunnelAddress", func(p *LinkParams) { p.TunnelAddress = "" }},
		{"missing VKLink", func(p *LinkParams) { p.VKLink = "" }},
		{"missing PeerAddress", func(p *LinkParams) { p.PeerAddress = "" }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			p := validParams()
			c.mutate(&p)
			if _, err := BuildAnton48Link(p); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestBuildAnton48Link_DeterministicEncoding pins the canonical JSON
// form: same input must always produce byte-identical output regardless
// of map-iteration order. anton48's importLink doesn't care about
// ordering, but operators comparing two links by eye (or by sha256)
// expect stability.
func TestBuildAnton48Link_DeterministicEncoding(t *testing.T) {
	p := validParams()
	first, err := BuildAnton48Link(p)
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := BuildAnton48Link(p)
		if err != nil {
			t.Fatalf("BuildAnton48Link iteration %d: %v", i, err)
		}
		if got != first {
			t.Fatalf("encoding not deterministic at iteration %d:\n  first: %s\n  got:   %s", i, first, got)
		}
	}
}

// TestBuildAnton48Link_KeysSortedLexicographically asserts the JSON
// inside the base64 has its map keys in lexicographic order — the
// same canonical form the upstream Python quick_link.py emits. Keeps
// links bit-identical between Go server and the original Python tool
// when fed the same inputs (handy for debugging operator-supplied
// payloads).
func TestBuildAnton48Link_KeysSortedLexicographically(t *testing.T) {
	link, err := BuildAnton48Link(validParams())
	if err != nil {
		t.Fatalf("BuildAnton48Link: %v", err)
	}
	const prefix = "vkturnproxy://import?data="
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, prefix))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	// Quick sanity: the top-level envelope must be `settings`, `type`,
	// `version` in that order (alphabetical).
	body := string(raw)
	settingsAt := strings.Index(body, `"settings"`)
	typeAt := strings.Index(body, `"type"`)
	versionAt := strings.Index(body, `"version"`)
	if !(settingsAt < typeAt && typeAt < versionAt) {
		t.Errorf("top-level keys not lexicographically ordered: settings=%d type=%d version=%d in %s",
			settingsAt, typeAt, versionAt, body)
	}

	// And one ordering check inside settings to catch a regression in
	// sortMapJSON: allowedIPs must come before peerAddress (a < p).
	allowedAt := strings.Index(body, `"allowedIPs"`)
	peerAt := strings.Index(body, `"peerAddress"`)
	if allowedAt < 0 || peerAt < 0 || allowedAt > peerAt {
		t.Errorf("settings keys not lexicographically ordered: allowedIPs=%d peerAddress=%d in %s",
			allowedAt, peerAt, body)
	}
}
