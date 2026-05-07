// Package livekit adapts the LiveKit-based WB Stream transport to
// sfu.Transport / sfu.Session.
//
// Auth flow (see docs/wb-stream-poc.md for the full reverse-engineering
// notes):
//
//  1. The operator authenticates ONCE via an admin webview that walks
//     through Cloudflare's antibot challenge and the WB guest-register
//     flow. The webview captures `accessToken` and the cookie set
//     ({_wbafp, x_wbaas_token, _wbauid}) and persists them in
//     inbound.Spec.LiveKit.
//  2. At Connect time we POST those credentials to WB's connection-
//     details endpoint to mint a fresh, short-lived (~2 min) LiveKit
//     roomToken plus the SFU server URL and ICE configuration.
//  3. The server-sdk-go client connects to the LiveKit SFU via that
//     roomToken — once established, the WS stays open as long as the
//     SFU allows it (no token rotation needed mid-session).
//  4. When cookies expire (~14 days) the operator must re-auth in the
//     admin UI; until then the same accessToken+cookies pair mints
//     unlimited fresh roomTokens.
//
// All HTTP goes to https://stream.wb.ru — there's no separate dev-mode
// or alternate URL. If WB ever moves the API or rotates the API key
// (`APIefx2BJbD3hvw` baked into JWTs), this file is the only place
// that has to change.
package livekit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// connectionDetailsResponse is the shape of GET .../connection-details
// — fields are stable between WB Stream releases as of 2026-05.
type connectionDetailsResponse struct {
	RoomToken string `json:"roomToken"`
	ServerURL string `json:"serverUrl"`
	RTCConfig struct {
		ICEServers []struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username,omitempty"`
			Credential string   `json:"credential,omitempty"`
		} `json:"iceServers"`
	} `json:"rtcConfig"`
}

// roomConnect holds the result of a successful auth round-trip — what
// the LiveKit SDK needs to dial in.
type roomConnect struct {
	ServerURL  string
	RoomToken  string
	ICEServers []struct {
		URLs       []string
		Username   string
		Credential string
	}
}

// fetchRoomConnect mints a fresh LiveKit roomToken via WB's
// connection-details endpoint. Blocking; respects ctx for timeouts.
func fetchRoomConnect(ctx context.Context, roomURL, accessToken, cookies, displayName string) (*roomConnect, error) {
	if accessToken == "" {
		return nil, errors.New("livekit: missing accessToken — operator needs to re-auth via admin webview")
	}

	roomID, err := parseRoomID(roomURL)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("deviceType", "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP")
	if displayName != "" {
		q.Set("displayName", displayName)
	}
	endpoint := "https://stream.wb.ru/api-room-manager/v2/room/" + url.PathEscape(roomID) +
		"/connection-details?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("livekit: build conn-details request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) goloom/wb-stream")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("livekit: conn-details: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		// JWT typically just has expired claims at this point; the
		// caller should treat this as "operator needs to re-auth via
		// admin webview".
		return nil, fmt.Errorf("livekit: 401 from conn-details (expired auth): %s",
			truncate(string(body), 200))
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("livekit: conn-details %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	var parsed connectionDetailsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("livekit: parse conn-details JSON: %w (body=%s)",
			err, truncate(string(body), 200))
	}
	if parsed.RoomToken == "" || parsed.ServerURL == "" {
		return nil, fmt.Errorf("livekit: conn-details missing required fields (roomToken/serverURL): %s",
			truncate(string(body), 200))
	}

	rc := &roomConnect{
		ServerURL: parsed.ServerURL,
		RoomToken: parsed.RoomToken,
	}
	for _, ice := range parsed.RTCConfig.ICEServers {
		rc.ICEServers = append(rc.ICEServers, struct {
			URLs       []string
			Username   string
			Credential string
		}{ice.URLs, ice.Username, ice.Credential})
	}
	return rc, nil
}

// parseRoomID extracts the room id from a WB Stream URL.
//
//	https://stream.wb.ru/room/asd_q2h76ipz  →  "asd_q2h76ipz"
//	https://stream.wb.ru/room/abc/foo       →  error (extra segment)
func parseRoomID(roomURL string) (string, error) {
	u, err := url.Parse(roomURL)
	if err != nil {
		return "", fmt.Errorf("livekit: parse RoomURL %q: %w", roomURL, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "room" || parts[1] == "" {
		return "", fmt.Errorf("livekit: RoomURL %q doesn't match expected /room/<id> shape", roomURL)
	}
	return parts[1], nil
}

// EnsureGuestAuth performs a guest-register against WB's auth service
// using the supplied display name. Returns the access token (long-lived,
// valid until cookies expire ~14 days) plus the response cookies as a
// joined Cookie-header value.
//
// This is intended for the admin webview-auth flow: the webview
// finishes Cloudflare challenge, captures the resulting cookies, and
// then calls this to upgrade them into a usable access token. On the
// server side it's only invoked once per inbound (or every ~14 days
// when the operator re-auths).
func EnsureGuestAuth(ctx context.Context, cookies, displayName string) (accessToken, cookiesOut string, err error) {
	if displayName == "" {
		return "", "", errors.New("livekit: guest-register requires non-empty displayName")
	}

	body, _ := json.Marshal(map[string]string{"displayName": displayName})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://stream.wb.ru/auth/api/v1/auth/user/guest-register", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("livekit: build guest-register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) goloom/wb-stream")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("livekit: guest-register: %w", err)
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("livekit: guest-register %d: %s",
			resp.StatusCode, truncate(string(rb), 300))
	}

	var parsed struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return "", "", fmt.Errorf("livekit: parse guest-register: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", "", fmt.Errorf("livekit: guest-register returned no accessToken: %s",
			truncate(string(rb), 200))
	}

	// Aggregate Set-Cookie back into a single Cookie header for next
	// round-trips.
	var sb strings.Builder
	for _, c := range resp.Cookies() {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(c.Name)
		sb.WriteByte('=')
		sb.WriteString(c.Value)
	}
	if sb.Len() == 0 && cookies != "" {
		// No fresh Set-Cookie — keep the ones we already had.
		return parsed.AccessToken, cookies, nil
	}
	return parsed.AccessToken, sb.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
