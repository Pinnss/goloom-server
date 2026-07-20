package vkauth

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"testing"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

func storeWithProfile(t *testing.T) *ProfileStore {
	t.Helper()
	s, err := NewProfileStore(ProfileStoreOptions{Path: filepath.Join(t.TempDir(), "p.json")})
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	s.Capture(CapturedProfile{UserAgent: "ua", DeviceJSON: "{}", BrowserFP: "fp"})
	return s
}

// When auto-replay fails on a non-empty pool, the interactive fallback
// must receive a FRESH challenge (Refresh result), never the spent one
// — and the returned solution must carry the refreshed sid/ts/attempt
// so the auth ladder replays against the right session.
func TestWithReplaySolver_RefreshesChallengeOnFallback(t *testing.T) {
	s := storeWithProfile(t)

	orig := autoSolve
	autoSolve = func(context.Context, sfu.VKCaptchaChallenge, BrowserProfile, *CapturedProfile, *log.Logger) (string, error) {
		return "", errors.New("forced auto-replay failure")
	}
	defer func() { autoSolve = orig }()

	refreshed := sfu.VKCaptchaChallenge{
		Sid: "fresh-sid", Ts: 222, Attempt: "2",
		SessionToken: "fresh-st", RedirectURI: "https://id.vk.ru/not_robot_captcha?session_token=fresh-st",
	}
	var baseGot sfu.VKCaptchaChallenge
	base := func(_ context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		baseGot = ch
		return sfu.VKCaptchaSolution{SuccessToken: "TOK"}, nil
	}

	origCh := sfu.VKCaptchaChallenge{
		Sid: "orig-sid", Ts: 111, Attempt: "1", SessionToken: "orig-st",
		Refresh: func(context.Context) (sfu.VKCaptchaChallenge, error) { return refreshed, nil },
	}

	sol, err := WithReplaySolver(s, base, nil)(context.Background(), origCh)
	if err != nil {
		t.Fatalf("solver error: %v", err)
	}
	if baseGot.SessionToken != "fresh-st" || baseGot.Sid != "fresh-sid" {
		t.Fatalf("interactive fallback got spent challenge, want fresh: %+v", baseGot)
	}
	if sol.SuccessToken != "TOK" {
		t.Fatalf("token = %q", sol.SuccessToken)
	}
	if sol.Sid != "fresh-sid" || sol.Ts != 222 || sol.Attempt != "2" {
		t.Fatalf("solution not stamped with refreshed challenge: %+v", sol)
	}
}

// Пустой пул больше не пропускает авто-солвер: SolveCaptchaV2 умеет работать
// с saved == nil и ходит через tls-client с корректным JA3, тогда как
// интерактивный WebView проксируется stdlib net/http и получает от VK BOT.
// Проверяем, что авто-попытка ДЕЛАЕТСЯ и что saved при этом nil.
func TestWithReplaySolver_EmptyPoolStillTriesAutoSolve(t *testing.T) {
	s, err := NewProfileStore(ProfileStoreOptions{Path: filepath.Join(t.TempDir(), "p.json")})
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}

	autoCalled := false
	orig := autoSolve
	autoSolve = func(_ context.Context, _ sfu.VKCaptchaChallenge, _ BrowserProfile, saved *CapturedProfile, _ *log.Logger) (string, error) {
		autoCalled = true
		if saved != nil {
			t.Errorf("empty pool must pass saved=nil, got %+v", saved)
		}
		return "AUTOTOK", nil
	}
	defer func() { autoSolve = orig }()

	baseCalled := false
	base := func(context.Context, sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		baseCalled = true
		return sfu.VKCaptchaSolution{SuccessToken: "TOK"}, nil
	}
	ch := sfu.VKCaptchaChallenge{Sid: "orig-sid", SessionToken: "orig-st"}

	sol, err := WithReplaySolver(s, base, nil)(context.Background(), ch)
	if err != nil {
		t.Fatalf("solver error: %v", err)
	}
	if !autoCalled {
		t.Fatal("auto-solve must be attempted even with an empty pool")
	}
	if baseCalled {
		t.Fatal("interactive fallback must not run when auto-solve succeeds")
	}
	if sol.SuccessToken != "AUTOTOK" {
		t.Fatalf("token = %q, want AUTOTOK", sol.SuccessToken)
	}
}

// Когда авто-попытка на пустом пуле проваливается, она уже сожгла
// session_token, поэтому интерактивный fallback ОБЯЗАН получить свежий
// challenge — иначе WebView покажет пустую страницу.
func TestWithReplaySolver_EmptyPoolRefreshesAfterAutoSolveFailure(t *testing.T) {
	s, err := NewProfileStore(ProfileStoreOptions{Path: filepath.Join(t.TempDir(), "p.json")})
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}

	orig := autoSolve
	autoSolve = func(context.Context, sfu.VKCaptchaChallenge, BrowserProfile, *CapturedProfile, *log.Logger) (string, error) {
		return "", errors.New("bot")
	}
	defer func() { autoSolve = orig }()

	var baseGot sfu.VKCaptchaChallenge
	base := func(_ context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		baseGot = ch
		return sfu.VKCaptchaSolution{SuccessToken: "TOK"}, nil
	}
	refreshCalled := false
	ch := sfu.VKCaptchaChallenge{
		Sid: "orig-sid", SessionToken: "orig-st",
		Refresh: func(context.Context) (sfu.VKCaptchaChallenge, error) {
			refreshCalled = true
			return sfu.VKCaptchaChallenge{Sid: "fresh-sid", SessionToken: "fresh-st", Ts: 222, Attempt: "2"}, nil
		},
	}

	sol, err := WithReplaySolver(s, base, nil)(context.Background(), ch)
	if err != nil {
		t.Fatalf("solver error: %v", err)
	}
	if !refreshCalled {
		t.Fatal("spent session must be refreshed before the interactive fallback")
	}
	if baseGot.SessionToken != "fresh-st" {
		t.Fatalf("base got %+v, want the refreshed challenge", baseGot)
	}
	if sol.SuccessToken != "TOK" {
		t.Fatalf("token = %q", sol.SuccessToken)
	}
}
