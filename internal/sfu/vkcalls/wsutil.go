// WS utility helpers shared between the signaling code in peer.go
// and any future protocol-debug tooling. The big WSDump function
// (frame-level dumper used during reverse-engineering) lives in the
// reverse-engineering tooling, not here — production has no need to dump every
// frame to stdout.

package vkcalls

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

// Default OK Calls SDK identification — VK's web client pins these
// values, so we replay them verbatim. From the mipselqq/vk-calls-tun
// reference's config.toml.
const (
	wsPlatform     = "WEB"
	wsAppVersion   = "1.1"
	wsVersion      = "5"
	wsDevice       = "browser"
	wsCapabilities = "2F7F"
	wsClientType   = "VK"
)

func wsTypeName(t int) string {
	switch t {
	case websocket.TextMessage:
		return "text"
	case websocket.BinaryMessage:
		return "binary"
	case websocket.PingMessage:
		return "ping"
	case websocket.PongMessage:
		return "pong"
	case websocket.CloseMessage:
		return "close"
	default:
		return fmt.Sprintf("type=%d", t)
	}
}

// preview truncates raw frame bytes for log lines.
func preview(data []byte) string {
	const max = 800
	if len(data) <= max {
		return string(data)
	}
	return string(data[:max]) + fmt.Sprintf(" …(+%dB truncated)", len(data)-max)
}

// augmentWSEndpoint adds the OK Calls SDK identification query
// params the server requires before it'll start signalling. The
// initial endpoint from joinConversationByLink only has auth params
// (userId, peerId, conversationId, token, entityType); without
// platform/appVersion/device/capabilities/clientType the server
// answers with `{"error":"invalid-request","message":"Parameter
// appVersion is required"}` and disconnects.
func augmentWSEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("platform", wsPlatform)
	q.Set("appVersion", wsAppVersion)
	q.Set("version", wsVersion)
	q.Set("device", wsDevice)
	q.Set("capabilities", wsCapabilities)
	q.Set("clientType", wsClientType)
	q.Set("tgt", "join")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// redactURL keeps the URL recognisable while hiding the bearer-style
// `token=` query parameter (which is per-call short-lived but still
// avoids accidentally pasting it in screenshots/logs).
func redactURL(u string) string {
	if i := strings.Index(u, "token="); i >= 0 {
		end := strings.IndexAny(u[i:], "&")
		if end < 0 {
			return u[:i] + "token=…"
		}
		return u[:i] + "token=…" + u[i+end:]
	}
	return u
}

// extractShortID accepts either a full https://vk.com/call/join/<id>
// URL or just the bare <id> string and returns the id portion.
func extractShortID(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "/call/join/"); i >= 0 {
		s = s[i+len("/call/join/"):]
	}
	if i := strings.IndexAny(s, "?&#/"); i >= 0 {
		s = s[:i]
	}
	return s
}
