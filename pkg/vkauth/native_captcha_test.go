package vkauth

import (
	"context"
	"testing"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

func captchaURL(sessionToken string) string {
	return "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=" + sessionToken + "&variant=popup"
}

func TestNativeCaptchaSolverAcceptsTokenForCurrentPage(t *testing.T) {
	var opened string
	s := NewNativeCaptchaSolver(2*time.Second, nil, func(u string) { opened = u })

	go func() {
		// Даём Solve зарегистрировать канал, затем присылаем токен с той же страницы.
		time.Sleep(20 * time.Millisecond)
		s.Submit("TOK", captchaURL("session-A"))
	}()

	sol, err := s.Solve(context.Background(), sfu.VKCaptchaChallenge{RedirectURI: captchaURL("session-A")})
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if sol.SuccessToken != "TOK" {
		t.Fatalf("token = %q, want TOK", sol.SuccessToken)
	}
	if opened != captchaURL("session-A") {
		t.Fatalf("opened %q, want VK's URL verbatim", opened)
	}
}

// Ключевой сценарий: пользователь возится дольше таймаута, попытка #1 умирает,
// стартует попытка #2 с новым session_token, и пользователь дорешивает СТАРОЕ,
// ещё открытое окно. Токен от протухшей страницы не должен «решить» новую
// попытку — иначе VK ответит «captcha replay still failed», а настоящее
// решение из второго окна пропадёт.
func TestNativeCaptchaSolverRejectsTokenFromStalePage(t *testing.T) {
	s := NewNativeCaptchaSolver(300*time.Millisecond, nil, func(string) {})

	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Submit("STALE", captchaURL("session-OLD"))
	}()

	_, err := s.Solve(context.Background(), sfu.VKCaptchaChallenge{RedirectURI: captchaURL("session-NEW")})
	if err == nil {
		t.Fatal("stale token was accepted as the solution for a fresh challenge")
	}
	if !isDeadline(err) {
		t.Fatalf("err = %v, want a timeout (stale token ignored)", err)
	}
}

// Нераспознаваемый URL не должен блокировать рабочий сценарий: сверять нечего —
// пропускаем.
func TestNativeCaptchaSolverAcceptsTokenWhenPageURLUnparseable(t *testing.T) {
	s := NewNativeCaptchaSolver(2*time.Second, nil, func(string) {})

	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Submit("TOK", "")
	}()

	sol, err := s.Solve(context.Background(), sfu.VKCaptchaChallenge{RedirectURI: captchaURL("session-A")})
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if sol.SuccessToken != "TOK" {
		t.Fatalf("token = %q, want TOK", sol.SuccessToken)
	}
}

func TestNativeCaptchaSolverRequiresRedirectURI(t *testing.T) {
	s := NewNativeCaptchaSolver(time.Second, nil, func(string) {})
	if _, err := s.Solve(context.Background(), sfu.VKCaptchaChallenge{}); err != ErrNoRedirectURI {
		t.Fatalf("err = %v, want ErrNoRedirectURI", err)
	}
}

// Submit без ждущего Solve не должен паниковать или блокироваться.
func TestNativeCaptchaSolverSubmitWithNoWaiter(t *testing.T) {
	s := NewNativeCaptchaSolver(time.Second, nil, func(string) {})
	s.Submit("TOK", captchaURL("session-A")) // просто не должно упасть
}

func TestSessionTokenFromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{captchaURL("abc123"), "abc123"},
		{"https://id.vk.ru/not_robot_captcha?domain=vk.com", ""},
		{"", ""},
		{"://broken", ""},
	}
	for _, c := range cases {
		if got := sessionTokenFromURL(c.in); got != c.want {
			t.Errorf("sessionTokenFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func isDeadline(err error) bool {
	return err == context.DeadlineExceeded
}
