// loggingTransport — http.RoundTripper-обёртка для captcha-proxy,
// перехватывает тела `captchaNotRobot.componentDone` и
// `captchaNotRobot.check` POST-запросов от браузера к id.vk.com,
// извлекает поля `device` (JSON-описание устройства) и `browser_fp`
// (hex-строка) и кормит их в [ProfileStore] для будущего auto-replay.
//
// Тело запроса нужно прочитать ДО того как оно уйдёт на upstream
// (httputil.ReverseProxy уже оптимизировал req.Body для streaming),
// поэтому делаем clone-and-restore через bytes.NewReader.
//
// Срабатывает только на POST с Content-Type form-encoded — другие
// запросы (HTML, JS, картинки) пролетают без накладных. На сами
// fingerprint-поля парсер тоже валится тихо: если VK завтра поменяет
// формат — мы не будем падать, просто временно перестанем копить
// пул, до момента пока кто-то не починит парсер.
//
// См. также cacggghp/vk-turn-proxy PR #162 client/manual_captcha.go
// (~line 600) — там же эта идея, но с прямой записью в SavedProfile
// и поиском success_token в response.

package vkcalls

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// CaptureSink — куда сбрасываются перехваченные fingerprint'ы.
// Реализуется [ProfileStore.Capture]; абстракция нужна чтобы
// loggingTransport не зависел от ProfileStore напрямую (легче
// тестировать + AutoProxy путь может писать в другое место).
type CaptureSink interface {
	Capture(p CapturedProfile)
}

// loggingTransport оборачивает базовый RoundTripper. Если sink == nil —
// поведение прозрачное (no-op обёртка).
type loggingTransport struct {
	base http.RoundTripper
	sink CaptureSink
	lg   *log.Logger
}

// NewLoggingTransport возвращает обёртку. base = http транспорт,
// который реально шлёт запросы (обычно [defaultTransport]).
func NewLoggingTransport(base http.RoundTripper, sink CaptureSink, lg *log.Logger) http.RoundTripper {
	if sink == nil {
		return base
	}
	return &loggingTransport{base: base, sink: sink, lg: lg}
}

// RoundTrip — основной хук. Пытается распарсить body для нужных
// captchaNotRobot.* запросов, потом восстанавливает body и делегирует
// base'у.
func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.shouldSniff(req) {
		t.sniffRequest(req)
	}
	return t.base.RoundTrip(req)
}

// shouldSniff — true если это POST на путь с captchaNotRobot.componentDone
// или captchaNotRobot.check. Учитываем оба варианта эндпоинта:
// `/method/captchaNotRobot.componentDone` и `/method/captchaNotRobot.check`
// (полное имя метода в URL — VK API style).
func (t *loggingTransport) shouldSniff(req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	if req.URL == nil {
		return false
	}
	p := req.URL.Path
	return strings.Contains(p, "captchaNotRobot.componentDone") ||
		strings.Contains(p, "captchaNotRobot.check")
}

// sniffRequest читает body, парсит form-параметры device + browser_fp,
// потом восстанавливает body для дальнейшего forwarding'а.
func (t *loggingTransport) sniffRequest(req *http.Request) {
	if req.Body == nil {
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.logf("read captcha body: %v", err)
		return
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.logf("parse captcha form: %v", err)
		return
	}
	device := form.Get("device")
	bfp := form.Get("browser_fp")
	if device == "" && bfp == "" {
		return
	}
	ua := req.Header.Get("User-Agent")

	t.logf("captured fingerprint via %s (device=%dB browser_fp=%dB ua=%s)",
		captchaPathTag(req.URL.Path), len(device), len(bfp), shortUA(ua))

	t.sink.Capture(CapturedProfile{
		UserAgent:  ua,
		DeviceJSON: device,
		BrowserFP:  bfp,
	})
}

func (t *loggingTransport) logf(format string, args ...interface{}) {
	if t.lg == nil {
		return
	}
	t.lg.Printf("vkcalls/captcha-sniff: "+format, args...)
}

// captchaPathTag — короткая метка для логов, чтобы видеть какой из
// двух методов сработал.
func captchaPathTag(p string) string {
	switch {
	case strings.Contains(p, "captchaNotRobot.componentDone"):
		return "componentDone"
	case strings.Contains(p, "captchaNotRobot.check"):
		return "check"
	default:
		return p
	}
}
