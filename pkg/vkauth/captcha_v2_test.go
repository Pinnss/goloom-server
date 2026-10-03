package vkauth

import (
	"encoding/json"
	"testing"
	"time"
)

// Slider-настройки VK кладёт в window.init на СТРАНИЦЕ, а не в ответ
// captchaNotRobot.settings. Без них getContent отвечает ERROR — ровно так
// упал первый живой прогон слайдера 2026-07-20. Проверяем, что парсер
// страницы их сохраняет и что extractSliderSettings их оттуда достаёт.
func TestParseCaptchaV2PageExtractsSliderSettings(t *testing.T) {
	html := `<html><head>` +
		`<script src="https://static.vk.ru/vkid/1.1.1382/not_robot_captcha.js"></script>` +
		`<script>window.init = {"data":{"show_captcha_type":"slider",` +
		`"captcha_settings":[{"type":"slider","settings":"SLIDER-CFG"}]}};` +
		`const powInput = "abc123";` +
		`const difficulty = 2;` +
		`</script></head><body></body></html>`

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatalf("parseCaptchaV2Page: %v", err)
	}
	if page.ShowType != "slider" {
		t.Errorf("ShowType = %q, want slider", page.ShowType)
	}
	if page.PowInput != "abc123" || page.PowDifficulty != 2 {
		t.Errorf("PoW parsed as input=%q diff=%d", page.PowInput, page.PowDifficulty)
	}
	if page.Settings == nil {
		t.Fatal("Settings not captured from window.init")
	}
	// Настройки должны доехать в форме ответа API — {"response": data} —
	// чтобы их можно было отдать разборщику slider-настроек как есть.
	resp, ok := page.Settings["response"].(map[string]any)
	if !ok {
		t.Fatalf("Settings not wrapped as {\"response\": …}: %v", page.Settings)
	}
	entries, ok := resp["captcha_settings"].([]any)
	if !ok || len(entries) == 0 {
		t.Fatalf("captcha_settings missing from parsed page: %v", resp)
	}
	first, _ := entries[0].(map[string]any)
	if first["type"] != "slider" || first["settings"] != "SLIDER-CFG" {
		t.Fatalf("captcha_settings entry = %v, want slider/SLIDER-CFG", first)
	}
}

// Страница без window.init не должна ронять парсер — Settings просто nil,
// и solveOnce откатится на ответ API.
func TestParseCaptchaV2PageWithoutWindowInit(t *testing.T) {
	html := `<html><head>` +
		`<script src="https://static.vk.ru/vkid/1.1.1382/not_robot_captcha.js"></script>` +
		`<script>const powInput = "xyz"; const difficulty = 3;</script>` +
		`</head></html>`

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatalf("parseCaptchaV2Page: %v", err)
	}
	if page.Settings != nil {
		t.Errorf("Settings = %v, want nil", page.Settings)
	}
	if page.ShowType != "" {
		t.Errorf("ShowType = %q, want empty", page.ShowType)
	}
}

func TestSameSite(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"id.vk.ru", "api.vk.ru", true},     // captcha -> API: same-site
		{"id.vk.ru", "static.vk.ru", true},  // captcha -> JS-бандл
		{"id.vk.com", "api.vk.com", true},   // legacy-домен
		{"id.vk.ru", "ad.mail.ru", false},   // adFp-загрузчик: cross-site
		{"id.vk.ru", "api.vk.com", false},   // .ru и .com — разные сайты
		{"id.vk.ru:443", "api.vk.ru", true}, // порт не мешает
		{"localhost", "api.vk.ru", false},   // без точки — не путаем
		{"ID.VK.RU", "api.vk.ru", true},     // регистр не важен
	}
	for _, c := range cases {
		if got := sameSite(c.a, c.b); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCaptchaV2DomainOrigin(t *testing.T) {
	cases := []struct {
		name        string
		redirectURI string
		wantDomain  string
		wantOrigin  string
	}{
		{
			// Что VK реально отдаёт на 2026-07-20: страница уже переехала на
			// id.vk.ru, а domain= всё ещё vk.com. Обе половины берём как есть.
			"live vk.ru page still carrying domain=vk.com",
			"https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=abc",
			"vk.com", "https://id.vk.ru",
		},
		{
			// После того как VK докрутит миграцию — подхватываем без правок кода.
			"fully migrated",
			"https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=abc",
			"vk.ru", "https://id.vk.ru",
		},
		{
			"legacy vk.com page",
			"https://id.vk.com/not_robot_captcha?domain=vk.com&session_token=abc",
			"vk.com", "https://id.vk.com",
		},
		{
			"missing domain param falls back",
			"https://id.vk.ru/not_robot_captcha?session_token=abc",
			"vk.com", "https://id.vk.ru",
		},
		{
			"garbage uri falls back to both defaults",
			"://not-a-url",
			"vk.com", "https://id.vk.ru",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			domain, origin := captchaV2DomainOrigin(c.redirectURI)
			if domain != c.wantDomain || origin != c.wantOrigin {
				t.Fatalf("captchaV2DomainOrigin(%q) = (%q, %q), want (%q, %q)",
					c.redirectURI, domain, origin, c.wantDomain, c.wantOrigin)
			}
		})
	}
}

func TestPickBrowserFP(t *testing.T) {
	const fresh = "FRESHRANDOMFP"
	healthy := &CapturedProfile{BrowserFP: "SAVEDFP", ConsecutiveFails: 0}
	failing := &CapturedProfile{BrowserFP: "SAVEDFP", ConsecutiveFails: 1}

	cases := []struct {
		name        string
		saved       *CapturedProfile
		attempt     int
		wantFP      string
		wantRotated bool
	}{
		{"healthy attempt1 keeps saved fp", healthy, 1, "SAVEDFP", false},
		{"healthy retry rotates to fresh", healthy, 2, fresh, true},
		{"failing profile rotates from attempt1", failing, 1, fresh, true},
		{"no saved profile uses fresh", nil, 1, fresh, false},
		{"saved with blank fp uses fresh", &CapturedProfile{BrowserFP: "  "}, 1, fresh, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp, rotated := pickBrowserFP(c.saved, c.attempt, fresh)
			if fp != c.wantFP || rotated != c.wantRotated {
				t.Fatalf("pickBrowserFP = (%q, %v), want (%q, %v)", fp, rotated, c.wantFP, c.wantRotated)
			}
		})
	}
}

// VK stopped serving a <script src=…not_robot_captcha…> tag. The parser used to
// bail out on that BEFORE reading the PoW input a few lines below, so a
// perfectly solvable challenge was discarded and every connect fell back to a
// manual WebView — which is unusable once we need one identity per allocation.
func TestParseCaptchaV2PageWithoutScriptTag(t *testing.T) {
	html := `<html><head>` +
		`<script>window.init = {"data":{"show_captcha_type":"checkbox"}};</script>` +
		`<script>const powInput = "deadbeef"; const difficulty = 4;</script>` +
		`</head><body></body></html>`

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatalf("parse failed without a script tag: %v", err)
	}
	if page.PowInput != "deadbeef" {
		t.Errorf("PowInput = %q, want deadbeef", page.PowInput)
	}
	if page.PowDifficulty != 4 {
		t.Errorf("PowDifficulty = %d, want 4", page.PowDifficulty)
	}
	if page.ShowType != "checkbox" {
		t.Errorf("ShowType = %q, want checkbox", page.ShowType)
	}
	if page.ScriptURL != "" {
		t.Errorf("ScriptURL = %q, want empty", page.ScriptURL)
	}
}

// A page with neither a script tag nor PoW input is genuinely unsolvable, and
// the caller must still be told so rather than proceeding with empty input.
func TestParseCaptchaV2PageWithoutPowIsStillUsable(t *testing.T) {
	page, err := parseCaptchaV2Page(`<html><body>nothing here</body></html>`)
	if err != nil {
		t.Fatalf("parse should not error on a bare page: %v", err)
	}
	if page.PowInput != "" {
		t.Errorf("PowInput = %q, want empty so solveOnce rejects it", page.PowInput)
	}
}

// debug_info has to be accepted by VK without reading the captcha bundle, and
// the value the reference client uses is the SHA-256 of the empty string.
func TestCaptchaV2DebugInfoFallback(t *testing.T) {
	const wantEmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if captchaV2DebugInfoFallback != wantEmptySHA256 {
		t.Errorf("fallback = %q, want the SHA-256 of the empty string %q",
			captchaV2DebugInfoFallback, wantEmptySHA256)
	}
}

// The fingerprint, the cursor trail and the downlink series are cross-checked
// by VK, so they have to describe the same browser.
func TestCaptchaV2DeviceIsSelfConsistent(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev := captchaV2NewDevice()

		var fp map[string]any
		if err := json.Unmarshal([]byte(dev.json), &fp); err != nil {
			t.Fatalf("fingerprint is not valid JSON: %v", err)
		}
		if got := fp["screenWidth"].(float64); int(got) != dev.width {
			t.Fatalf("screenWidth %v disagrees with the device width %d", got, dev.width)
		}
		if fp["webdriver"] != false {
			t.Error("webdriver must be false")
		}
		if _, ok := fp["connectionDownlink"]; !ok {
			t.Error("fingerprint claims a connection but carries no downlink")
		}

		var pts []struct {
			X int   `json:"x"`
			Y int   `json:"y"`
			T int64 `json:"t"`
		}
		if err := json.Unmarshal([]byte(dev.cursorTrail()), &pts); err != nil {
			t.Fatalf("cursor trail is not valid JSON: %v", err)
		}
		if len(pts) < 4 {
			t.Fatalf("cursor trail has %d points; an empty-ish trail is a bot signal", len(pts))
		}
		for j := 1; j < len(pts); j++ {
			if pts[j].T < pts[j-1].T {
				t.Fatalf("cursor timestamps go backwards at %d", j)
			}
			if dx := pts[j].X - pts[j-1].X; dx > 15 || dx < -15 {
				t.Fatalf("cursor jumped %d px in one sample", dx)
			}
		}

		var series []float64
		if err := json.Unmarshal([]byte(dev.downlinkSeries()), &series); err != nil {
			t.Fatalf("downlink series is not valid JSON: %v", err)
		}
		if len(series) == 0 {
			t.Fatal("downlink series is empty")
		}
		for _, v := range series {
			if v != dev.downlink {
				t.Fatalf("downlink series %v contradicts the fingerprint's %v", v, dev.downlink)
			}
		}
	}
}

// VK scores the pause before the click: 400 ms was answered with BOT.
func TestCaptchaV2ClickDelayIsHumanScale(t *testing.T) {
	for i := 0; i < 100; i++ {
		d := captchaV2ClickDelay()
		if d < 1500*time.Millisecond || d > 2500*time.Millisecond {
			t.Fatalf("click delay %v is outside the 1.5-2.5 s a human takes", d)
		}
	}
}
