package vkauth

import "testing"

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
		{"id.vk.ru", "api.vk.ru", true},        // captcha -> API: same-site
		{"id.vk.ru", "static.vk.ru", true},     // captcha -> JS-бандл
		{"id.vk.com", "api.vk.com", true},      // legacy-домен
		{"id.vk.ru", "ad.mail.ru", false},      // adFp-загрузчик: cross-site
		{"id.vk.ru", "api.vk.com", false},      // .ru и .com — разные сайты
		{"id.vk.ru:443", "api.vk.ru", true},    // порт не мешает
		{"localhost", "api.vk.ru", false},      // без точки — не путаем
		{"ID.VK.RU", "api.vk.ru", true},        // регистр не важен
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
