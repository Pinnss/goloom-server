// Profile-link codec for the structured Android editor.
//
// The Android UI lets the operator edit individual transport fields
// (meeting URL, peer address, num_connections, etc.) without
// touching the base64+JSON encoding of the link. To do that we
// expose a single JSON shape that covers every link kind goloom
// supports today (goloom:// + vkturnproxy://) and round-trip
// through the existing Go-side codecs.
//
// Flow on the Kotlin side:
//
//   1. mobile.DecodeProfileLink(rawLink) → JSON string with every
//      field the link carries (per the union schema below).
//   2. UI shows fields scoped to the JSON's transport value.
//   3. On save: mobile.EncodeProfileLink(modifiedJson) → new rawLink
//      string, stored back into Profile.connStr.
//
// Both halves go through gomobile's standard string-in/string-out
// convention to avoid wrapping JSON in a gomobile-incompatible
// struct.

package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/relay/vkturn"
	wgclient "github.com/Pinnss/goloom-server/pkg/wgclient"
)

// profileLinkShape is the union JSON the Kotlin editor reads/writes.
// `transport` decides which scheme.Encode is selected on encode and
// drives which fields the UI surfaces.
//
// Field names match the Kotlin Profile editor 1:1; rename here only
// in lock-step with the Kotlin side.
type profileLinkShape struct {
	// Scheme is filled by Decode for caller's information; ignored on
	// encode (transport drives that).
	Scheme string `json:"scheme"`

	// Transport drives both UI field visibility and the encode scheme:
	//   "telemost" / ""     → goloom://
	//   "vk-calls"          → goloom://
	//   "livekit-wb-stream" → goloom://
	//   "vk-turn"           → vkturnproxy:// (UseSrtp=false)
	//   "vk-turn-srtp"      → vkturnproxy:// (UseSrtp=true)
	Transport string `json:"transport"`

	// Common across most transports.
	Meeting     string `json:"meeting"`
	DisplayName string `json:"display_name"`
	Tag         string `json:"tag"`

	// WG identity (admin-auto-provisioned inbounds).
	WGClientPrivate string `json:"wg_client_private"`
	WGServerPublic  string `json:"wg_server_public"`
	WGClientAddr    string `json:"wg_client_addr"`
	WGEndpoint      string `json:"wg_endpoint"`
	WGDNS           string `json:"wg_dns"`
	WGPresharedKey  string `json:"wg_preshared_key"`

	// goloom:// only.
	KCPMTU    int    `json:"kcp_mtu"`
	KCPSndWnd int    `json:"kcp_snd_wnd"`
	KCPRcvWnd int    `json:"kcp_rcv_wnd"`
	PSK       string `json:"psk"`
	VKCodec   string `json:"vk_codec"`

	// vkturnproxy:// only.
	VKTurnPeerAddress    string `json:"vk_turn_peer_address"`
	VKTurnUseWrap        bool   `json:"vk_turn_use_wrap"`
	VKTurnWrapKeyHex     string `json:"vk_turn_wrap_key_hex"`
	VKTurnNumConnections int    `json:"vk_turn_num_connections"`
	VKTurnMTU            int    `json:"vk_turn_mtu"`
}

// DecodeProfileLink parses any supported link scheme (goloom:// or
// vkturnproxy://) into the union JSON shape the structured editor
// uses. Returns a typed MobileError on parse failure.
func (c *Client) DecodeProfileLink(rawLink string) (string, error) {
	s := strings.TrimSpace(rawLink)
	shape := profileLinkShape{}

	switch {
	case strings.HasPrefix(s, "goloom://"):
		p, err := connstr.Decode(s)
		if err != nil {
			return "", mobileErr(ErrInvalidConnString, err)
		}
		shape.Scheme = "goloom"
		shape.Transport = p.Transport
		if shape.Transport == "" {
			shape.Transport = "telemost"
		}
		shape.Meeting = p.Meeting
		shape.DisplayName = p.DisplayName
		shape.Tag = p.Tag
		shape.WGClientPrivate = p.WGClientPrivate
		shape.WGServerPublic = p.WGServerPublic
		shape.WGClientAddr = p.WGClientAddr
		shape.WGEndpoint = p.WGEndpoint
		shape.WGDNS = p.WGDNS
		shape.KCPMTU = p.KCPMTU
		shape.KCPSndWnd = p.KCPSndWnd
		shape.KCPRcvWnd = p.KCPRcvWnd
		shape.PSK = p.PSK
		shape.VKCodec = p.Codec

	case strings.HasPrefix(s, "vkturnproxy://"):
		cfg, err := wgclient.FromVKTurnProxyLink(s)
		if err != nil {
			return "", mobileErr(ErrInvalidConnString, err)
		}
		shape.Scheme = "vkturnproxy"
		shape.Transport = cfg.Transport
		shape.Meeting = cfg.Meeting
		shape.WGClientPrivate = cfg.WG.ClientPrivateKey
		shape.WGServerPublic = cfg.WG.ServerPublicKey
		shape.WGClientAddr = cfg.WG.ClientAddr
		shape.WGEndpoint = cfg.WG.Endpoint
		shape.WGDNS = strings.Join(cfg.WG.DNS, ",")
		shape.WGPresharedKey = cfg.WG.PresharedKey
		shape.VKTurnPeerAddress = cfg.VKTurnSRTP.PeerAddress
		shape.VKTurnUseWrap = cfg.VKTurnSRTP.UseWrap
		shape.VKTurnWrapKeyHex = cfg.VKTurnSRTP.WrapKeyHex
		shape.VKTurnNumConnections = cfg.VKTurnSRTP.NumConnections
		shape.VKTurnMTU = cfg.VKTurnSRTP.MTU

	default:
		return "", mobileErr(ErrInvalidConnString, errors.New("unknown link scheme (expected goloom:// or vkturnproxy://)"))
	}

	out, err := json.Marshal(shape)
	if err != nil {
		return "", mobileErr(ErrUnknown, err)
	}
	return string(out), nil
}

// EncodeProfileLink takes the structured JSON the editor wrote and
// returns a fresh link string. Selects the scheme by Transport:
// vk-turn* → vkturnproxy://, everything else → goloom://.
func (c *Client) EncodeProfileLink(jsonStr string) (string, error) {
	var shape profileLinkShape
	if err := json.Unmarshal([]byte(jsonStr), &shape); err != nil {
		return "", mobileErr(ErrInvalidConnString, fmt.Errorf("invalid JSON: %w", err))
	}

	switch shape.Transport {
	case "vk-turn", "vk-turn-srtp":
		dns := ""
		if shape.WGDNS != "" {
			dns = shape.WGDNS
		}
		params := vkturn.LinkParams{
			ClientPrivateKey: shape.WGClientPrivate,
			ServerPublicKey:  shape.WGServerPublic,
			PresharedKey:     shape.WGPresharedKey,
			TunnelAddress:    shape.WGClientAddr,
			VKLink:           shape.Meeting,
			PeerAddress:      shape.VKTurnPeerAddress,
			UseWrap:          shape.VKTurnUseWrap,
			WrapKeyHex:       shape.VKTurnWrapKeyHex,
			UseSrtp:          shape.Transport == "vk-turn-srtp",
			DNSServers:       dns,
			NumConnections:   shape.VKTurnNumConnections,
			MTU:              shape.VKTurnMTU,
		}
		// vkturn.BuildAnton48Link requires non-empty WG identity +
		// PSK + VKLink — surface a typed error so the editor can
		// pinpoint the missing field.
		link, err := vkturn.BuildAnton48Link(params)
		if err != nil {
			return "", mobileErr(ErrInvalidConnString, err)
		}
		return link, nil

	default:
		// goloom:// — telemost / vk-calls / livekit-wb-stream / "".
		// Map "telemost" → "" since connstr.Decode normalises both
		// to KindTelemost; keeping it empty in the encoded form
		// stays compatible with pre-multi-transport readers.
		transport := shape.Transport
		if transport == "telemost" {
			transport = ""
		}
		p := &connstr.Params{
			Meeting:         shape.Meeting,
			DisplayName:     shape.DisplayName,
			Tag:             shape.Tag,
			Transport:       transport,
			Codec:           shape.VKCodec,
			KCPMTU:          shape.KCPMTU,
			KCPSndWnd:       shape.KCPSndWnd,
			KCPRcvWnd:       shape.KCPRcvWnd,
			PSK:             shape.PSK,
			WGClientPrivate: shape.WGClientPrivate,
			WGServerPublic:  shape.WGServerPublic,
			WGClientAddr:    shape.WGClientAddr,
			WGEndpoint:      shape.WGEndpoint,
			WGDNS:           shape.WGDNS,
		}
		link, err := connstr.Encode(p)
		if err != nil {
			return "", mobileErr(ErrUnknown, err)
		}
		return link, nil
	}
}
