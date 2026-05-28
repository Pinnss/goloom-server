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

// With an empty pool there is no auto attempt, so the original session
// is still fresh — the solver must hand it straight to base and must
// NOT burn a refresh.
func TestWithReplaySolver_EmptyPoolUsesOriginalChallenge(t *testing.T) {
	s, err := NewProfileStore(ProfileStoreOptions{Path: filepath.Join(t.TempDir(), "p.json")})
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}

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
			return sfu.VKCaptchaChallenge{}, nil
		},
	}

	sol, err := WithReplaySolver(s, base, nil)(context.Background(), ch)
	if err != nil {
		t.Fatalf("solver error: %v", err)
	}
	if refreshCalled {
		t.Fatal("empty pool must not refresh — original session is unspent")
	}
	if baseGot.SessionToken != "orig-st" {
		t.Fatalf("base got %+v, want original", baseGot)
	}
	if sol.SuccessToken != "TOK" {
		t.Fatalf("token = %q", sol.SuccessToken)
	}
}
