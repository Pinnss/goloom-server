// VK Calls anonymous auth chain — 4 HTTP calls that produce a WSS
// endpoint we can dial as a peer. Adapted from
// vk-turn-proxy/client/main.go ~lines 850-1090; the retry orchestrator
// here is a single-shot loop that re-queries getAnonymousToken with the
// captcha success_token once the [sfu.VKCaptchaSolver] has resolved.

package vkcalls

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/pkg/vkauth"
)

const (
	// Hardcoded constants from VK's web client. The web app pins
	// these values so we replay them verbatim — VK's API gates by
	// them and isn't picky about who's requesting.
	//
	// The (client_id, client_secret) pair is the VK_WEB_APP_ID
	// credentials that VK ships in vk.com's bundle. They're not
	// secret in any meaningful sense (every browser session sees
	// them) — vk-turn-proxy lists 5 alternative pairs in case one
	// gets rate-limited.
	vkClientID     = "6287487"
	vkClientSecret = "QbYic1K3lEV5kTGiqlq2"
	// vkAPIVersion соответствует тому что шлёт vk.com web SDK
	// на момент vk-turn-proxy PR #162. Реальные браузеры посылают
	// именно эту версию — отклонение на minor — bot-сигнал.
	vkAPIVersion = "5.275"

	okApplicationKey = "CGMMEJLGDIHBABABA"
)

// AuthSpec is the input bundle for [DoAuth].
type AuthSpec struct {
	ShortID  string // "AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU"
	Name     string // anonymous display name
	DeviceID string // uuid

	// Solver is invoked when step 1 receives a captcha challenge.
	// Implementation drives the user through the I-am-not-a-robot
	// flow (open URL in browser, capture success_token from
	// captchaNotRobot.check response) and returns the value the
	// retry needs. Leave nil to fail-fast on captcha.
	Solver sfu.VKCaptchaSolver
}

// AuthResult captures everything we need from the 3-call ladder.
type AuthResult struct {
	AnonymToken string // from getAnonymousToken; needed for further VK API calls
	SessionKey  string // OK SDK session_key from auth.anonymLogin

	// From vchat.joinConversationByLink:
	WSEndpoint  string   // wss://videowebrtc.okcdn.ru/ws2?…
	WTEndpoint  string   // https://videowebrtc.okcdn.ru:23456/wt?… (alt path)
	CallToken   string   // opaque call token
	CallID      string   // conversation_id GUID
	UserID      string   // anonymous-user numeric id
	PeerID      string   // peer numeric id
	TurnURLs    []string
	TurnUser    string
	TurnPass    string
	StunURLs    []string
	P2PForbidden bool

	// Profile — браузерный fingerprint, использованный во всём
	// auth-ладдере. peer.go должен предъявить тот же UA на WS-dial,
	// иначе VK увидит «другое устройство присоединилось к сессии».
	Profile vkauth.BrowserProfile
}

// DoAuth runs the 4-step ladder. Returns enough state to open the
// peer-join WSS.
func DoAuth(ctx context.Context, lg *log.Logger, spec AuthSpec) (*AuthResult, error) {
	client := &http.Client{}
	res := &AuthResult{}

	// Один профиль (UA + sec-ch-ua-*) на всю сессию — смена
	// fingerprint между шагами сама по себе bot-сигнал.
	profile := vkauth.PickProfile()
	res.Profile = profile
	lg.Printf("auth identity: %s", shortUA(profile.UserAgent))

	// Step 0 (seed): login.vk.ru/?act=get_anonym_token
	// VK requires a signed anonym JWT before calls.getAnonymousToken
	// will accept an "anonymous" request — the warmup converts the
	// (client_id, client_secret) pair into a session-bound token.
	seed, err := vkSeedAnonymToken(ctx, client, lg, profile)
	if err != nil {
		return nil, fmt.Errorf("seed anonym token: %w", err)
	}
	lg.Printf("step 0 ✓ seed token: %s…", seed[:min(len(seed), 16)])

	vkDelayRandom(ctx, 100, 150)

	// Step 0.5 (warmup): calls.getCallPreview — реальный браузер
	// перед getAnonymousToken запрашивает preview звонка (миниатюра,
	// число участников). Пропуск — bot-сигнал; ошибки игнорируем,
	// preview не критичен.
	if err := vkGetCallPreview(ctx, client, lg, profile, spec.ShortID, seed); err != nil {
		lg.Printf("step 0.5 warning: getCallPreview failed: %v (non-fatal)", err)
	} else {
		lg.Printf("step 0.5 ✓ preview warmup")
	}

	vkDelayRandom(ctx, 200, 400)

	// Step 1: api.vk.ru/method/calls.getAnonymousToken
	tok, err := vkGetAnonymousToken(ctx, client, lg, profile, spec, seed)
	if err != nil {
		return nil, fmt.Errorf("getAnonymousToken: %w", err)
	}
	res.AnonymToken = tok
	lg.Printf("step 1 ✓ anonym token: %s…", tok[:min(len(tok), 16)])

	vkDelayRandom(ctx, 100, 200)

	// Step 2: calls.okcdn.ru/fb.do — auth.anonymLogin → session_key
	sk, err := okAnonymLogin(ctx, client, lg, profile, spec.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("anonymLogin: %w", err)
	}
	res.SessionKey = sk
	lg.Printf("step 2 ✓ session_key: %s…", sk[:min(len(sk), 16)])

	vkDelayRandom(ctx, 100, 200)

	// Step 3: calls.okcdn.ru/fb.do — vchat.joinConversationByLink
	join, err := okJoinByLink(ctx, client, lg, profile, spec.ShortID, tok, sk)
	if err != nil {
		return nil, fmt.Errorf("joinConversationByLink: %w", err)
	}
	res.WSEndpoint = join.Endpoint
	res.WTEndpoint = join.WTEndpoint
	res.CallToken = join.Token
	res.CallID = join.ID
	res.TurnURLs = join.TurnServer.URLs
	res.TurnUser = join.TurnServer.Username
	res.TurnPass = join.TurnServer.Credential
	res.StunURLs = join.StunServer.URLs
	res.P2PForbidden = join.P2PForbidden

	// Pull userId / peerId from the wss URL query (server doesn't
	// echo them in the JSON body but bakes them into the URL).
	if u, err := url.Parse(join.Endpoint); err == nil {
		q := u.Query()
		res.UserID = q.Get("userId")
		res.PeerID = q.Get("peerId")
	}
	lg.Printf("step 3 ✓ call %s peer=%s wss=%s", res.CallID, res.PeerID, res.WSEndpoint)
	return res, nil
}

// ─── step 0: warmup, get seed anonym JWT ───────────────────────────

func vkSeedAnonymToken(ctx context.Context, c *http.Client, lg *log.Logger, profile vkauth.BrowserProfile) (string, error) {
	form := url.Values{}
	form.Set("client_id", vkClientID)
	form.Set("token_type", "messages")
	form.Set("client_secret", vkClientSecret)
	form.Set("version", "1")
	form.Set("app_id", vkClientID)

	body, err := postForm(ctx, c, "https://login.vk.ru/?act=get_anonym_token", form, profile, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Data *struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("json: %w (body=%s)", err, snippet(body))
	}
	if resp.Error != "" {
		return "", fmt.Errorf("vk seed: %s", resp.Error)
	}
	if resp.Data == nil || resp.Data.AccessToken == "" {
		return "", fmt.Errorf("missing access_token: %s", snippet(body))
	}
	return resp.Data.AccessToken, nil
}

// ─── step 0.5: warmup — getCallPreview ─────────────────────────────

// vkGetCallPreview бьёт api.vk.ru/method/calls.getCallPreview перед
// getAnonymousToken. Реальный web-клиент VK всегда делает этот шаг
// (миниатюра/имя организатора в pre-join экране); пропуск — bot-сигнал.
// Ответ нам не нужен, важен только сам факт запроса.
func vkGetCallPreview(ctx context.Context, c *http.Client, lg *log.Logger, profile vkauth.BrowserProfile, shortID, seedToken string) error {
	endpoint := "https://api.vk.ru/method/calls.getCallPreview?v=" + vkAPIVersion + "&client_id=" + vkClientID
	form := url.Values{}
	form.Set("vk_join_link", "https://vk.com/call/join/"+shortID)
	form.Set("fields", "photo_200")
	form.Set("access_token", seedToken)
	_, err := postForm(ctx, c, endpoint, form, profile, nil)
	return err
}

// ─── step 1: VK API ────────────────────────────────────────────────

func vkGetAnonymousToken(ctx context.Context, c *http.Client, lg *log.Logger, profile vkauth.BrowserProfile, spec AuthSpec, seedToken string) (string, error) {
	endpoint := "https://api.vk.ru/method/calls.getAnonymousToken?v=" + vkAPIVersion + "&client_id=" + vkClientID

	doRequest := func(extra url.Values) ([]byte, error) {
		form := url.Values{}
		form.Set("vk_join_link", "https://vk.com/call/join/"+spec.ShortID)
		form.Set("name", spec.Name)
		form.Set("access_token", seedToken)
		for k, v := range extra {
			form[k] = v
		}
		return postForm(ctx, c, endpoint, form, profile, nil)
	}

	parse := func(body []byte) (string, *vkError, error) {
		var resp struct {
			Response *struct {
				Token      string `json:"token"`
				APIBaseURL string `json:"api_base_url"`
			} `json:"response"`
			Error *vkError `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", nil, fmt.Errorf("json: %w (body=%s)", err, snippet(body))
		}
		if resp.Error != nil {
			return "", resp.Error, nil
		}
		if resp.Response == nil {
			return "", nil, fmt.Errorf("missing response: %s", snippet(body))
		}
		return resp.Response.Token, nil, nil
	}

	body, err := doRequest(nil)
	if err != nil {
		return "", err
	}
	tok, vkErr, err := parse(body)
	if err != nil {
		return "", err
	}
	if vkErr == nil {
		return tok, nil
	}

	// Captcha required (error_code 14). Surface to solver if we have one.
	if vkErr.ErrorCode != 14 {
		return "", fmt.Errorf("vk error %d: %s", vkErr.ErrorCode, vkErr.ErrorMsg)
	}
	if spec.Solver == nil {
		return "", fmt.Errorf("captcha required (sid=%s) but no Solver configured — open %s in a browser, replay -mode=auth with -captcha-success-token … or set Solver",
			vkErr.CaptchaSid, vkErr.RedirectURI)
	}

	ts := captchaTsAsFloat(vkErr.CaptchaTs)
	attempt := captchaAttemptAsString(vkErr.CaptchaAttempt)
	if attempt == "" {
		attempt = "1"
	}

	sessionToken := extractSessionToken(vkErr.RedirectURI)
	if sessionToken == "" {
		sessionToken = vkErr.SessionToken
	}

	lg.Printf("captcha challenge — sid=%s ts=%v attempt=%s", vkErr.CaptchaSid, ts, attempt)
	sol, err := spec.Solver(ctx, sfu.VKCaptchaChallenge{
		Sid:          vkErr.CaptchaSid,
		Ts:           ts,
		Attempt:      attempt,
		RedirectURI:  vkErr.RedirectURI,
		SessionToken: sessionToken,
	})
	if err != nil {
		return "", fmt.Errorf("captcha solver: %w", err)
	}

	// Retry with the captured success_token. (sfu.VKCaptchaSolution
	// only carries SuccessToken — image/audio captcha branches are
	// not part of the public solver API; if VK rolls those out, we'll
	// extend the solver type.)
	retry := url.Values{}
	retry.Set("captcha_key", "")
	retry.Set("captcha_sid", vkErr.CaptchaSid)
	retry.Set("is_sound_captcha", "0")
	retry.Set("success_token", sol.SuccessToken)
	retry.Set("captcha_ts", fmt.Sprintf("%v", ts))
	retry.Set("captcha_attempt", attempt)

	body, err = doRequest(retry)
	if err != nil {
		return "", err
	}
	tok, vkErr, err = parse(body)
	if err != nil {
		return "", err
	}
	if vkErr != nil {
		return "", fmt.Errorf("captcha replay still failed: vk %d %s", vkErr.ErrorCode, vkErr.ErrorMsg)
	}
	return tok, nil
}

func captchaTsAsFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		var f float64
		_, _ = fmt.Sscanf(t, "%f", &f)
		return f
	}
	return 0
}

func captchaAttemptAsString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%d", int(t))
	}
	return ""
}

// extractSessionToken pulls ?session_token= out of a captcha redirect URI.
func extractSessionToken(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return u.Query().Get("session_token")
}

type vkError struct {
	ErrorCode      int    `json:"error_code"`
	ErrorMsg       string `json:"error_msg"`
	RedirectURI    string `json:"redirect_uri,omitempty"`
	CaptchaSid     string `json:"captcha_sid,omitempty"`
	CaptchaImg     string `json:"captcha_img,omitempty"`
	CaptchaTs      any    `json:"captcha_ts,omitempty"`
	CaptchaAttempt any    `json:"captcha_attempt,omitempty"`
	SessionToken   string `json:"session_token,omitempty"`
}

// ─── step 2: OK SDK auth.anonymLogin ───────────────────────────────

func okAnonymLogin(ctx context.Context, c *http.Client, lg *log.Logger, profile vkauth.BrowserProfile, deviceID string) (string, error) {
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, deviceID)

	form := url.Values{}
	form.Set("session_data", sessionData)
	form.Set("method", "auth.anonymLogin")
	form.Set("format", "JSON")
	form.Set("application_key", okApplicationKey)

	body, err := postForm(ctx, c, "https://calls.okcdn.ru/fb.do", form, profile, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		SessionKey       string `json:"session_key"`
		SessionSecretKey string `json:"session_secret_key"`
		APIServer        string `json:"api_server"`
		ErrorCode        int    `json:"error_code,omitempty"`
		ErrorMsg         string `json:"error_msg,omitempty"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("json: %w (body=%s)", err, snippet(body))
	}
	if resp.ErrorCode != 0 {
		return "", fmt.Errorf("ok error %d: %s", resp.ErrorCode, resp.ErrorMsg)
	}
	if resp.SessionKey == "" {
		return "", fmt.Errorf("missing session_key: %s", snippet(body))
	}
	return resp.SessionKey, nil
}

// ─── step 3: OK SDK vchat.joinConversationByLink ───────────────────

type okJoinResponse struct {
	Token        string `json:"token"`
	Endpoint     string `json:"endpoint"`
	WTEndpoint   string `json:"wt_endpoint"`
	ClientType   string `json:"client_type"`
	DeviceIdx    int    `json:"device_idx"`
	ID           string `json:"id"`
	P2PForbidden bool   `json:"p2p_forbidden"`
	TurnServer   struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"turn_server"`
	StunServer struct {
		URLs []string `json:"urls"`
	} `json:"stun_server"`
	ErrorCode int    `json:"error_code,omitempty"`
	ErrorMsg  string `json:"error_msg,omitempty"`
}

func okJoinByLink(ctx context.Context, c *http.Client, lg *log.Logger, profile vkauth.BrowserProfile, shortID, anonymToken, sessionKey string) (*okJoinResponse, error) {
	form := url.Values{}
	form.Set("joinLink", shortID)
	form.Set("isVideo", "false")
	form.Set("protocolVersion", "5")
	form.Set("capabilities", "2F7F")
	form.Set("anonymToken", anonymToken)
	form.Set("method", "vchat.joinConversationByLink")
	form.Set("format", "JSON")
	form.Set("application_key", okApplicationKey)
	form.Set("session_key", sessionKey)

	body, err := postForm(ctx, c, "https://calls.okcdn.ru/fb.do", form, profile, nil)
	if err != nil {
		return nil, err
	}
	var resp okJoinResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("json: %w (body=%s)", err, snippet(body))
	}
	if resp.ErrorCode != 0 {
		return nil, fmt.Errorf("ok error %d: %s", resp.ErrorCode, resp.ErrorMsg)
	}
	if resp.Endpoint == "" {
		return nil, fmt.Errorf("missing endpoint: %s", snippet(body))
	}
	return &resp, nil
}

// ─── shared helpers ────────────────────────────────────────────────

// postForm шлёт POST с set-of-headers, имитирующим реальный VK
// web-клиент: paired UA + sec-ch-ua-* + Sec-Fetch-* + Priority +
// Origin/Referer на vk.ru. Лишние заголовки или их рассогласование —
// bot-сигнал; набор и значения зеркалят vk-turn-proxy PR #162
// client/main.go::doRequest.
//
// extraHeaders переопределяют дефолты — нужно крайне редко
// (например, для /not_robot_captcha с другим Origin).
func postForm(ctx context.Context, c *http.Client, url string, form url.Values, profile vkauth.BrowserProfile, extraHeaders map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, snippet(body))
	}
	return body, nil
}

// vkDelayRandom вставляет джиттер между HTTP-шагами auth-ладдера.
// Реальный браузер не лупит запросы один за другим: между
// get_anonym_token и getAnonymousToken проходит ~100-150мс на JS,
// между getAnonymousToken и anonymLogin — 200-400мс на UI-handoff.
// Возвращает раньше, если ctx отменён.
func vkDelayRandom(ctx context.Context, minMs, maxMs int) {
	if maxMs <= minMs {
		maxMs = minMs + 1
	}
	d := time.Duration(minMs+mathrand.Intn(maxMs-minMs)) * time.Millisecond
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// shortUA отрезает префикс UA для лога: «Mozilla/5.0 ... Chrome/146...»
// → «Chrome/146 (Windows)» — достаточно чтобы понять какой профиль
// сработал/не сработал, без замусоренных логов.
func shortUA(ua string) string {
	chrome := ""
	if i := strings.Index(ua, "Chrome/"); i >= 0 {
		end := i + 7
		for end < len(ua) && (ua[end] == '.' || (ua[end] >= '0' && ua[end] <= '9')) {
			end++
		}
		chrome = ua[i:end]
	}
	plat := "?"
	switch {
	case strings.Contains(ua, "Windows"):
		plat = "Windows"
	case strings.Contains(ua, "Macintosh"):
		plat = "macOS"
	case strings.Contains(ua, "Linux"):
		plat = "Linux"
	}
	if chrome == "" {
		return plat
	}
	return chrome + " (" + plat + ")"
}

func snippet(b []byte) string {
	if len(b) > 240 {
		return string(b[:240]) + "…"
	}
	return string(b)
}

func min(a, b int) int { if a < b { return a }; return b }
