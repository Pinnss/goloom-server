// Captcha solver для нативного WebView БЕЗ локального reverse-proxy.
//
// Почему не [AutoProxyCaptchaSolverWithOpener]: тот отдаёт VK'шную страницу
// с http://localhost:<port>, и это ломает капчу двумя способами (замерено
// 2026-07-20 на живом VK через CDP):
//
//  1. Страница шлёт отпечаток на privacy-cs.mail.ru; с localhost-origin
//     CORS-preflight не проходит, запрос падает с ERR_ABORTED, и VK
//     получает adFp, который mail.ru никогда не подтверждал.
//  2. Прокси ходит к VK через stdlib net/http, а VK WAF матчит JA3 и
//     порядок заголовков (та же причина, по которой [SolveCaptchaV2]
//     обязан использовать tls-client).
//
// Итог обоих: captchaNotRobot.check возвращает status=BOT — даже на
// настоящий человеческий тап в живом Chrome WebView.
//
// Здесь мы отдаём WebView НАСТОЯЩИЙ VK'шный redirect_uri (id.vk.ru/…),
// поэтому origin, CORS, cookies и TLS-отпечаток — подлинные. Взамен
// теряется серверный перехват success_token, и его присылает native
// через [NativeCaptchaSolver.Submit].
package vkauth

import (
	"context"
	"errors"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

// ErrNoRedirectURI — challenge без redirect_uri: открывать в WebView нечего.
// ErrCaptchaDismissed reports that the user closed the captcha without solving
// it. Distinct from a timeout so a caller can tell "not now" from "no answer" —
// for an optional identity the first is an instant, deliberate no.
var ErrCaptchaDismissed = errors.New("captcha dismissed by the user")

var ErrNoRedirectURI = errors.New("vkcalls: native captcha: challenge has no redirect_uri")

// NativeCaptchaSolver открывает VK'шный captcha URL в нативном WebView и
// ждёт success_token, который клиент присылает обратно через [Submit].
type NativeCaptchaSolver struct {
	timeout time.Duration
	lg      *log.Logger
	open    func(string)

	mu sync.Mutex
	ch chan string // не nil только пока Solve ждёт токен

	// cancelCh закрывается, когда native сообщает, что WebView закрыли без
	// решения. Без него Solve досиживал до своего таймаута — две минуты, в
	// течение которых подключение просто стояло, хотя пользователь уже ответил
	// «не сейчас». Отдельный канал, а не закрытие ch: токен может прийти в тот
	// же момент, и закрывать канал, в который кто-то пишет, нельзя.
	cancelCh chan struct{}
	// sessionToken — session_token активной попытки; по нему [Submit]
	// отсекает токены, снятые с уже протухшей страницы captcha.
	sessionToken string
}

// NewNativeCaptchaSolver. open вызывается с VK'шным URL как есть; timeout —
// сколько ждём, пока пользователь решит капчу.
func NewNativeCaptchaSolver(timeout time.Duration, lg *log.Logger, open func(string)) *NativeCaptchaSolver {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &NativeCaptchaSolver{timeout: timeout, lg: lg, open: open}
}

// Submit принимает success_token от native-стороны. pageURL — адрес страницы
// captcha, с которой токен снят; по нему токен сверяется с активной попыткой.
//
// Безопасно звать когда никто не ждёт (пользователь дорешал капчу после
// таймаута) и повторно — лишние вызовы отбрасываются.
func (s *NativeCaptchaSolver) Submit(token, pageURL string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	ch, want := s.ch, s.sessionToken
	s.mu.Unlock()
	if ch == nil {
		s.logf("captcha-native: token submitted with no solver waiting — ignored")
		return
	}

	// Токен обязан принадлежать ТЕКУЩЕЙ попытке. Иначе: пользователь возится
	// дольше таймаута, Solve #1 отваливается, супервизор поднимает Solve #2 с
	// НОВЫМ session_token и открывает второе окно — а пользователь дорешивает
	// первое, ещё открытое. Без сверки протухший токен уехал бы в Solve #2 и
	// вернулся как решение свежего challenge'а: VK ответил бы «captcha replay
	// still failed», а настоящее решение из второго окна пропало.
	if got := sessionTokenFromURL(pageURL); want != "" && got != "" && got != want {
		s.logf("captcha-native: token from a stale captcha page — ignored (page session_token differs)")
		return
	}

	select {
	case ch <- token:
	default: // уже получили токен
	}
}

// sessionTokenFromURL достаёт query-параметр session_token. Пустая строка —
// «не удалось определить»; вызывающий тогда не блокирует токен, чтобы кривой
// URL не ломал рабочий сценарий.
func sessionTokenFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get("session_token")
}

// Solve — точка входа в виде [sfu.VKCaptchaSolver].
func (s *NativeCaptchaSolver) Solve(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
	if ch.RedirectURI == "" {
		return sfu.VKCaptchaSolution{}, ErrNoRedirectURI
	}

	tokens := make(chan string, 1)
	cancelled := make(chan struct{})
	s.mu.Lock()
	s.ch = tokens
	s.cancelCh = cancelled
	s.sessionToken = sessionTokenFromURL(ch.RedirectURI)
	s.mu.Unlock()
	defer func() {
		// Compare-and-clear: если эта попытка отвалилась по таймауту, а вызывающий
		// уже начал следующую, s.ch принадлежит ЕЙ — затирать его нельзя, иначе
		// новый Solve навсегда останется без канала и прождёт впустую до своего
		// таймаута.
		s.mu.Lock()
		if s.ch == tokens {
			s.ch = nil
		}
		if s.cancelCh == cancelled {
			s.cancelCh = nil
		}
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	s.logf("captcha-native: opening VK URL directly (no local proxy)")
	s.open(ch.RedirectURI)

	select {
	case tok := <-tokens:
		s.logf("captcha-native: success_token received (%d bytes)", len(tok))
		return sfu.VKCaptchaSolution{SuccessToken: tok}, nil
	case <-cancelled:
		s.logf("captcha-native: dismissed by the user")
		return sfu.VKCaptchaSolution{}, ErrCaptchaDismissed
	case <-ctx.Done():
		s.logf("captcha-native: %v", ctx.Err())
		return sfu.VKCaptchaSolution{}, ctx.Err()
	}
}

// Cancel unblocks a Solve that is still waiting, because the WebView was closed
// without a solution. It is safe to call when nothing is waiting — the token may
// have arrived microseconds earlier and that attempt has already finished.
func (s *NativeCaptchaSolver) Cancel() {
	s.mu.Lock()
	cancelled := s.cancelCh
	s.cancelCh = nil
	s.mu.Unlock()
	if cancelled != nil {
		close(cancelled)
	}
}

func (s *NativeCaptchaSolver) logf(format string, args ...any) {
	if s.lg != nil {
		s.lg.Printf(format, args...)
	}
}
