package vkauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
}

type recordingSink struct{ captured []CapturedProfile }

func (s *recordingSink) Capture(p CapturedProfile) { s.captured = append(s.captured, p) }

func postCaptcha(t *testing.T, rt http.RoundTripper, method, body, ua string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost,
		"https://api.vk.ru/method/"+method+"?v=5.131", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("User-Agent", ua)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
}

// Регрессионный тест на давний баг: VK шлёт `device` в componentDone, а
// `browser_fp` — в check, тогда как ProfileStore.Capture молча отбрасывает
// профиль с любым пустым полем. Поштучные Capture поэтому были no-op'ами и
// пул не наполнялся никогда. Транспорт обязан собрать половинки и отдать
// профиль ОДИН раз, когда обе на руках.
func TestLoggingTransportMergesFingerprintHalves(t *testing.T) {
	const (
		ua     = "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/146.0.0.0 Mobile Safari/537.36"
		device = `{"screenWidth":360,"screenHeight":820}`
		bfp    = "deadbeefdeadbeefdeadbeefdeadbeef"
	)
	sink := &recordingSink{}
	rt := NewLoggingTransport(stubRoundTripper{}, sink, nil)

	// componentDone несёт только device — сохранять ещё нечего.
	postCaptcha(t, rt, "captchaNotRobot.componentDone",
		"session_token=x&domain=vk.com&browser_fp=&device="+url.QueryEscape(device), ua)
	if len(sink.captured) != 0 {
		t.Fatalf("captured %d profiles after componentDone alone, want 0", len(sink.captured))
	}

	// check доносит browser_fp — теперь профиль полный.
	postCaptcha(t, rt, "captchaNotRobot.check",
		"session_token=x&domain=vk.com&browser_fp="+bfp+"&hash=abc", ua)
	if len(sink.captured) != 1 {
		t.Fatalf("captured %d profiles after check, want exactly 1", len(sink.captured))
	}

	got := sink.captured[0]
	if got.DeviceJSON != device {
		t.Errorf("DeviceJSON = %q, want %q", got.DeviceJSON, device)
	}
	if got.BrowserFP != bfp {
		t.Errorf("BrowserFP = %q, want %q", got.BrowserFP, bfp)
	}
	if got.UserAgent != ua {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, ua)
	}
}

// Запросы не из captcha-потока трогать нельзя.
func TestLoggingTransportIgnoresUnrelatedRequests(t *testing.T) {
	sink := &recordingSink{}
	rt := NewLoggingTransport(stubRoundTripper{}, sink, nil)

	postCaptcha(t, rt, "calls.getAnonymousToken",
		"device="+url.QueryEscape(`{"screenWidth":360}`)+"&browser_fp=abc", "UA")

	if len(sink.captured) != 0 {
		t.Fatalf("captured %d profiles from a non-captcha request, want 0", len(sink.captured))
	}
}

// nil sink → прозрачная обёртка, без паник.
func TestLoggingTransportNilSinkIsTransparent(t *testing.T) {
	rt := NewLoggingTransport(stubRoundTripper{}, nil, nil)
	postCaptcha(t, rt, "captchaNotRobot.check", "browser_fp=abc", "UA")
}
