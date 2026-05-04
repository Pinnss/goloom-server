// Package api implements the HTTP handshake against Telemost's
// cloud-api endpoint to obtain a goloom signalling session.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

const (
	BaseHost      = "https://cloud-api.yandex.ru"
	UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
	Origin        = "https://telemost.yandex.ru"
	Referer       = "https://telemost.yandex.ru/"
	ClientVersion = "191.0.0"
	SecChUA       = `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`
)

// ICEServer mirrors the entries returned by Telemost in
// client_configuration.ice_servers AND in serverHello.rtcConfiguration.iceServers.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// ClientConfiguration is a subset of the conference's client_configuration
// block. Only the fields PoC #1 actually consumes are unmarshalled.
type ClientConfiguration struct {
	MediaServerURL string      `json:"media_server_url"`
	ICEServers     []ICEServer `json:"ice_servers"`
}

// ConnectionResponse holds the parsed payload of GET /connection. Telemost
// returns many additional fields (chat_path, conference_state, etc) — we
// ignore them.
type ConnectionResponse struct {
	ConnectionType      string              `json:"connection_type"`
	URI                 string              `json:"uri"`
	RoomID              string              `json:"room_id"`
	SafeRoomID          string              `json:"safe_room_id"`
	PeerID              string              `json:"peer_id"`
	SessionID           string              `json:"session_id"`
	PeerSessionID       string              `json:"peer_session_id"`
	Credentials         string              `json:"credentials"`
	MediaPlatform       string              `json:"media_platform"`
	ExpirationTime      int64               `json:"expiration_time"`
	ConferenceLimit     int                 `json:"conference_limit"`
	ClientConfiguration ClientConfiguration `json:"client_configuration"`
}

// ClientIDs holds the per-process random identifiers reused across the HTTP
// handshake and (later) the WS subprotocol headers.
type ClientIDs struct {
	ClientInstanceID string
	IdempotencyKey   string
}

// NewClientIDs returns a fresh pair of UUID v4 values.
func NewClientIDs() ClientIDs {
	return ClientIDs{
		ClientInstanceID: uuid.NewString(),
		IdempotencyKey:   uuid.NewString(),
	}
}

// FetchConnection performs the GET /connection handshake. meetingURL must be
// the full https://telemost.yandex.ru/j/<id> URL (we URL-encode it for the
// path segment). displayName is the guest's display label, e.g. "Гость" or
// "PoC1".
func FetchConnection(ctx context.Context, hc *http.Client, meetingURL, displayName string, ids ClientIDs) (*ConnectionResponse, error) {
	encodedMeeting := url.QueryEscape(meetingURL)
	endpoint := fmt.Sprintf(
		"%s/telemost_front/v2/telemost/conferences/%s/connection?next_gen_media_platform_allowed=true&display_name=%s&waiting_room_supported=true",
		BaseHost, encodedMeeting, url.QueryEscape(displayName),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	// Headers — order is preserved by http.Header for inspection but irrelevant
	// over the wire. Captured via web-client dump (4 user headers) plus the
	// browser-default trio (UA, Origin, Referer) and sec-ch-ua hints.
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Origin", Origin)
	req.Header.Set("Referer", Referer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Telemost-Client-Version", ClientVersion)
	req.Header.Set("Client-Instance-Id", ids.ClientInstanceID)
	req.Header.Set("idempotency-key", ids.IdempotencyKey)
	req.Header.Set("sec-ch-ua", SecChUA)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var out ConnectionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode body: %w (body=%s)", err, truncate(string(body), 400))
	}
	if out.Credentials == "" || out.RoomID == "" || out.PeerID == "" || out.ClientConfiguration.MediaServerURL == "" {
		return nil, fmt.Errorf("incomplete response: %s", truncate(string(body), 400))
	}
	return &out, nil
}

// DefaultHTTPClient builds an http.Client tuned for short-lived handshake
// calls (no connection pooling needed, fail-fast timeout).
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
