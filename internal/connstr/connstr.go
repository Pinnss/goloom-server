package connstr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const Scheme = "goloom://"

type Params struct {
	Meeting     string `json:"m,omitempty"`
	DisplayName string `json:"n,omitempty"`
	KCPMTU      int    `json:"km,omitempty"`
	KCPSndWnd   int    `json:"ks,omitempty"`
	KCPRcvWnd   int    `json:"kr,omitempty"`
	PSK         string `json:"psk,omitempty"`
	Tag         string `json:"tag,omitempty"`

	// Transport names the SFU/transport implementation to use.
	// Empty == "telemost" for backward compatibility with connstrs
	// generated before multi-transport. Mirrors
	// [github.com/Pinnss/goloom-server/internal/sfu].Kind values.
	Transport string `json:"t,omitempty"`

	// Codec — для VK transport: "vp8" / "h264" / "" (h264 default).
	// Клиент должен совпадать с серверным codec'ом инбаунда.
	Codec string `json:"c,omitempty"`

	// LobbyMeetingURL + Bearer (S2/S3 in-band): rendezvous-канал
	// внутри VK SFU. Клиент peer-join'ится в LobbyMeetingURL
	// (стабильный VK звонок), находит сервер в roster'е, шлёт
	// goloom_ctrl DIAL{meeting,bearer} через transmit-data envelope.
	// Сервер на DIAL поднимает session'ную сторону и идёт в target
	// meeting. Клиент тоже идёт в target и они peer-connect'ятся.
	//
	// Bootstrap полностью через videowebrtc.okcdn.ru — никакого
	// прямого WSS клиента к нашему VPS.
	//
	// Пусто → клиент использует Meeting из этой структуры (legacy).
	LobbyMeetingURL string `json:"lm,omitempty"`
	Bearer          string `json:"b,omitempty"`

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

// HasLobby сообщает, есть ли в connstr данные для in-band lobby
// bootstrap'а (S2/S3 client-meeting mode).
func (p *Params) HasLobby() bool {
	return p.LobbyMeetingURL != "" && p.Bearer != ""
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
	// Meeting URL обязателен ИЛИ должен быть lobby bootstrap. В
	// client-meeting mode (S2/S3) клиент сам подставляет meeting
	// из локальной формы, а в connstr остаются только lobby fields.
	if p.Meeting == "" && !p.HasLobby() {
		return nil, fmt.Errorf("meeting URL or lobby bootstrap required")
	}
	return &p, nil
}
