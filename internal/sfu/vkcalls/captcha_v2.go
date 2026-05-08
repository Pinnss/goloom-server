// Серверный auto-replay captcha-solver. Работает в сессионной паре с
// [ProfileStore]: при появлении challenge'а берёт самый свежий
// captured-profile из пула, реплеит его (UA + sec-ch-ua + device +
// browser_fp) к VK captcha API и проходит за ~1-3 секунды без UI.
//
// Лифтнут из cacggghp/vk-turn-proxy PR #162 client/captcha_v2.go,
// адаптирован под нашу архитектуру:
//   - вместо их `Profile + SavedProfile` используем
//     [browserProfile] (текущая попытка) + [CapturedProfile] (из пула)
//   - tls-client + fhttp обязательны: VK WAF матчит JA3 и порядок
//     заголовков, на stdlib net/http запросы реджектятся
//   - slider не поддержан в этой слайсе (S1c-checkbox-only) —
//     при show_type=slider возвращаем [ErrSliderUnsupported] чтобы
//     caller фоллбэкнулся на ручной solver
//
// Последовательность для checkbox path:
//
//   1. GET redirectURI                        → captcha HTML
//   2. parse window.init JSON + script URL    → PoW input/difficulty
//   3. GET scriptURL                          → debug_info SHA-256
//   4. POST captchaNotRobot.settings          → init session
//   5. PoW: sha256(input+nonce) с N нулями
//   6. POST captchaNotRobot.componentDone     → device + browser_fp
//   7. (delay 400-650ms — имитация UI)
//   8. POST captchaNotRobot.check             → success_token
//   9. POST captchaNotRobot.endSession        → cleanup (fail-soft)

package vkcalls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

const (
	captchaV2APIVersion    = "5.131"
	captchaV2ScriptVersion = "1.1.1324"
	captchaV2DefaultDevice = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1080,"innerWidth":1920,"innerHeight":951,"devicePixelRatio":1,"language":"en-US","languages":["en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"denied"}`
	captchaV2MaxAttempts   = 2
)

var (
	reCaptchaV2PowInput   = regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	reCaptchaV2Difficulty = regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`)
	reCaptchaV2WindowInit = regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?})\s*;`)
	reCaptchaV2ScriptSrc  = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)
	reCaptchaV2DebugInfo  = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)
	reCaptchaV2Version    = regexp.MustCompile(`vkid/([0-9.]*)/not_robot_captcha\.js`)

	captchaV2DebugCache sync.Map // scriptURL → string (debug_info)

	// captchaV2HeaderOrder зеркалит порядок Chrome'а — VK WAF
	// сравнивает с эталоном и ловит «Go runtime отдаёт заголовки в
	// alphabetical order» как bot-сигнал.
	captchaV2HeaderOrder = []string{
		"host",
		"content-length",
		"sec-ch-ua-platform",
		"accept-language",
		"sec-ch-ua",
		"content-type",
		"sec-ch-ua-mobile",
		"user-agent",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	captchaV2PHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
)

// ErrSliderUnsupported возвращается из [SolveCaptchaV2] когда VK
// отдал show_type=slider. S1c-checkbox-only; caller должен fallback'нуть
// на интерактивный solver.
var ErrSliderUnsupported = errors.New("vkcalls: captcha v2: slider show_type not supported (S1c-checkbox)")

// ErrCaptchaV2RateLimit — VK сообщил error_limit; смысла ретраить нет.
var ErrCaptchaV2RateLimit = errors.New("vkcalls: captcha v2: rate limit reached")

// ErrCaptchaV2Bot — VK увидел bot-сигнал на checkbox-попытке. С
// данным профилем не пройдёт; caller должен MarkFail и пробовать
// другой профиль или фоллбэкнуться.
var ErrCaptchaV2Bot = errors.New("vkcalls: captcha v2: bot challenge")

// SolveCaptchaV2 пытается пройти captcha автоматически по
// captured-profile из пула. Возвращает success_token при успехе.
//
// challenge — то что прилетело из getAnonymousToken (sid, redirect_uri,
// session_token).
// profile — текущий браузерный профиль для UA + sec-ch-ua-* (тот же
// что и у auth-ладдера; брать из AuthResult.Profile).
// saved — captured-profile из ProfileStore.Pick(); определяет device +
// browser_fp + UA для replay'я (если не nil — replay; если nil —
// генерируется свежий browser_fp но device берётся из default'а,
// шансов меньше).
func SolveCaptchaV2(ctx context.Context, challenge sfu.VKCaptchaChallenge, profile browserProfile, saved *CapturedProfile, lg *log.Logger) (string, error) {
	if challenge.SessionToken == "" {
		return "", fmt.Errorf("vkcalls: captcha v2: empty session_token (challenge: %+v)", challenge)
	}

	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
	)
	if err != nil {
		return "", fmt.Errorf("vkcalls: captcha v2: tls-client init: %w", err)
	}

	// Если saved-profile есть — синхронизируем UA c ним (профиль из
	// ProfileStore был успешен в прошлом с конкретным UA, ломать пару
	// нельзя). Иначе используем переданный profile (тот же что в
	// auth-ладдере).
	effectiveProfile := profile
	if saved != nil && saved.UserAgent != "" {
		effectiveProfile = browserProfile{
			UserAgent:       saved.UserAgent,
			SecChUa:         profile.SecChUa,
			SecChUaMobile:   profile.SecChUaMobile,
			SecChUaPlatform: profile.SecChUaPlatform,
		}
	}

	s := &captchaV2Session{
		ctx:            ctx,
		client:         client,
		profile:        effectiveProfile,
		saved:          saved,
		lg:             lg,
		sessionToken:   challenge.SessionToken,
		redirectURI:    challenge.RedirectURI,
	}

	for attempt := 1; attempt <= captchaV2MaxAttempts; attempt++ {
		token, err := s.solveOnce()
		if err == nil {
			return token, nil
		}
		s.logf("attempt %d failed: %v", attempt, err)
		// На rate-limit / slider — ретраить не имеет смысла,
		// возвращаем как есть.
		if errors.Is(err, ErrCaptchaV2RateLimit) || errors.Is(err, ErrSliderUnsupported) {
			return "", err
		}
		// Backoff перед следующей попыткой.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("vkcalls: captcha v2: %d attempts exhausted", captchaV2MaxAttempts)
}

type captchaV2Session struct {
	ctx          context.Context
	client       tlsclient.HttpClient
	profile      browserProfile
	saved        *CapturedProfile
	lg           *log.Logger
	sessionToken string
	redirectURI  string
}

type captchaV2Page struct {
	PowInput      string
	PowDifficulty int
	ScriptURL     string
	ShowType      string
}

type captchaV2Check struct {
	Status       string
	SuccessToken string
	ShowType     string
}

func (s *captchaV2Session) solveOnce() (string, error) {
	html, err := s.fetchCaptchaHTML()
	if err != nil {
		return "", fmt.Errorf("fetch captcha html: %w", err)
	}
	page, err := parseCaptchaV2Page(html)
	if err != nil {
		return "", fmt.Errorf("parse page: %w", err)
	}
	if page.PowInput == "" {
		return "", errors.New("PoW settings not found on page")
	}

	s.logf("page: showType=%q pow.diff=%d script=%s", page.ShowType, page.PowDifficulty, page.ScriptURL)

	debugInfo, err := s.fetchDebugInfo(page.ScriptURL)
	if err != nil {
		return "", fmt.Errorf("fetch debug_info: %w (script_version=%s)", err, captchaV2ScriptVersion)
	}

	hash := solveCaptchaPoWV2(s.ctx, page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("PoW computation cancelled or exhausted")
	}
	s.logf("PoW solved")

	base := captchaV2BaseValues(s.sessionToken)
	if _, err := s.captchaRequest("captchaNotRobot.settings", base); err != nil {
		return "", fmt.Errorf("settings: %w", err)
	}

	browserFP, err := captchaV2RandomBrowserFP()
	if err != nil {
		return "", err
	}
	if s.saved != nil && strings.TrimSpace(s.saved.BrowserFP) != "" {
		browserFP = s.saved.BrowserFP
	}

	if m := reCaptchaV2Version.FindStringSubmatch(page.ScriptURL); len(m) > 1 && m[1] != captchaV2ScriptVersion {
		s.logf("script version drift: known=%s seen=%s (captcha_v2 may need update)", captchaV2ScriptVersion, m[1])
	}

	switch page.ShowType {
	case "slider":
		return "", ErrSliderUnsupported
	case "checkbox", "":
		token, err := s.solveCheckboxCaptcha(browserFP, hash, debugInfo)
		// endSession — best-effort cleanup.
		if _, e := s.captchaRequest("captchaNotRobot.endSession", base); e != nil {
			s.logf("endSession failed (non-fatal): %v", e)
		}
		return token, err
	default:
		return "", fmt.Errorf("unsupported show_type: %s", page.ShowType)
	}
}

func (s *captchaV2Session) solveCheckboxCaptcha(browserFP, hash, debugInfo string) (string, error) {
	deviceJSON := captchaV2DefaultDevice
	if s.saved != nil && strings.TrimSpace(s.saved.DeviceJSON) != "" {
		deviceJSON = s.saved.DeviceJSON
	}
	if _, err := s.captchaRequest("captchaNotRobot.componentDone", [][2]string{
		{"session_token", s.sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"browser_fp", browserFP},
		{"device", deviceJSON},
		{"access_token", ""},
	}); err != nil {
		return "", fmt.Errorf("componentDone: %w", err)
	}

	// Имитация задержки на UI-клик. Без неё VK моментально отдаёт BOT.
	select {
	case <-s.ctx.Done():
		return "", s.ctx.Err()
	case <-time.After(time.Duration(400+mathrand.Intn(250)) * time.Millisecond):
	}

	check, err := s.performCaptchaCheck(browserFP, hash, "{}", "[]", debugInfo)
	if err != nil {
		return "", err
	}
	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		// VK переключился на slider посередине — нужен fallback.
		return "", ErrSliderUnsupported
	}
	if strings.EqualFold(check.Status, "error_limit") {
		return "", ErrCaptchaV2RateLimit
	}
	if strings.EqualFold(check.Status, "bot") {
		return "", fmt.Errorf("%w: status=%s", ErrCaptchaV2Bot, check.Status)
	}
	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("checkbox rejected: status=%s", check.Status)
	}
	if check.SuccessToken == "" {
		return "", errors.New("missing success_token in OK response")
	}
	return check.SuccessToken, nil
}

func (s *captchaV2Session) performCaptchaCheck(browserFP, hash, answerJSON, cursor, debugInfo string) (*captchaV2Check, error) {
	resp, err := s.captchaRequest("captchaNotRobot.check", [][2]string{
		{"session_token", s.sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"accelerometer", "[]"},
		{"gyroscope", "[]"},
		{"motion", "[]"},
		{"cursor", cursor},
		{"taps", "[]"},
		{"connectionRtt", "[]"},
		{"connectionDownlink", "[]"},
		{"browser_fp", browserFP},
		{"hash", hash},
		{"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON))},
		{"debug_info", debugInfo},
		{"access_token", ""},
	})
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	return parseCaptchaV2Check(resp)
}

func (s *captchaV2Session) fetchCaptchaHTML() (string, error) {
	body, err := s.doRaw(fhttp.MethodGet, s.redirectURI, nil, map[string]string{
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "cross-site",
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *captchaV2Session) fetchDebugInfo(scriptURL string) (string, error) {
	if cached, ok := captchaV2DebugCache.Load(scriptURL); ok {
		if v, ok := cached.(string); ok {
			return v, nil
		}
		captchaV2DebugCache.Delete(scriptURL)
	}
	body, err := s.doRaw(fhttp.MethodGet, scriptURL, nil, map[string]string{
		"Accept":  "text/javascript,*/*",
		"Referer": "https://id.vk.com/",
	})
	if err != nil {
		return "", err
	}
	m := reCaptchaV2DebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", errors.New("debug_info regex did not match")
	}
	v := string(m[1])
	captchaV2DebugCache.Store(scriptURL, v)
	return v, nil
}

func (s *captchaV2Session) captchaRequest(method string, form [][2]string) (map[string]any, error) {
	endpoint := "https://api.vk.ru/method/" + method + "?v=" + captchaV2APIVersion
	body, err := s.doRaw(fhttp.MethodPost, endpoint, form, map[string]string{
		"Origin":   "https://id.vk.com",
		"Referer":  "https://id.vk.com/",
		"Priority": "u=1, i",
	})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", method, err)
	}
	return out, nil
}

func (s *captchaV2Session) doRaw(method, endpoint string, form [][2]string, extraHeaders map[string]string) ([]byte, error) {
	var body []byte
	if form != nil {
		body = []byte(captchaV2EncodeForm(form))
	}
	req, err := fhttp.NewRequestWithContext(s.ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyBrowserProfileFhttp(req, s.profile)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	req.Header[fhttp.HeaderOrderKey] = captchaV2HeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaV2PHeaderOrder

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

func (s *captchaV2Session) logf(format string, args ...interface{}) {
	if s.lg == nil {
		return
	}
	s.lg.Printf("vkcalls/captcha-v2: "+format, args...)
}

// ─── helpers ────────────────────────────────────────────────────────

func parseCaptchaV2Page(html string) (*captchaV2Page, error) {
	page := &captchaV2Page{}

	if m := reCaptchaV2WindowInit.FindStringSubmatch(html); len(m) >= 2 {
		var init struct {
			Data struct {
				ShowCaptchaType string `json:"show_captcha_type"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(m[1]), &init); err == nil {
			page.ShowType = init.Data.ShowCaptchaType
		}
	}

	if m := reCaptchaV2ScriptSrc.FindStringSubmatch(html); len(m) >= 2 {
		page.ScriptURL = m[1]
	} else {
		return nil, errors.New("captcha script URL not found")
	}

	if m := reCaptchaV2PowInput.FindStringSubmatch(html); len(m) >= 2 {
		page.PowInput = m[1]
	}
	if page.PowInput == "" {
		// PoW бывает не на каждой странице — значит другая разновидность
		// captcha; вернём что есть.
		return page, nil
	}

	m := reCaptchaV2Difficulty.FindStringSubmatch(html)
	if len(m) < 2 {
		return nil, errors.New("difficulty const not found")
	}
	d, err := strconv.Atoi(m[1])
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("invalid difficulty %q", m[1])
	}
	page.PowDifficulty = d
	return page, nil
}

func parseCaptchaV2Check(raw map[string]any) (*captchaV2Check, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid check response: %v", raw)
	}
	out := &captchaV2Check{
		Status:       captchaV2StringifyAny(resp["status"]),
		SuccessToken: captchaV2StringifyAny(resp["success_token"]),
		ShowType:     captchaV2StringifyAny(resp["show_captcha_type"]),
	}
	if out.Status == "" {
		return nil, fmt.Errorf("missing status in check response: %v", raw)
	}
	return out, nil
}

func captchaV2StringifyAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// solveCaptchaPoWV2 — sha256(input + nonce) until префикс из difficulty
// нулей. Pure CPU, ~10ms на difficulty=4, ~200ms на 5.
func solveCaptchaPoWV2(ctx context.Context, input string, difficulty int) string {
	if input == "" || difficulty <= 0 {
		return ""
	}
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10_000_000; nonce++ {
		if nonce%4096 == 0 {
			select {
			case <-ctx.Done():
				return ""
			default:
			}
		}
		sum := sha256.Sum256([]byte(input + strconv.Itoa(nonce)))
		hashHex := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hashHex, target) {
			return hashHex
		}
	}
	return ""
}

func captchaV2RandomBrowserFP() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random browser_fp: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func captchaV2BaseValues(sessionToken string) [][2]string {
	return [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"access_token", ""},
	}
}

// captchaV2EncodeForm — порядок полей сохраняется (важно для VK WAF).
// stdlib url.Values.Encode сортирует ключи алфавитно — это лишний
// bot-сигнал.
func captchaV2EncodeForm(form [][2]string) string {
	var b strings.Builder
	for i, kv := range form {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(kv[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(kv[1]))
	}
	return b.String()
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile browserProfile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
}
