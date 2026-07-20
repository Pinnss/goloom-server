package vkauth

import (
	neturl "net/url"
	"strings"
	"testing"
)

// Регрессионный тест на блокер: инжектируемый шим переписывал URL'ы
// неидемпотентно, когда selfBase — это МОНТИРОВАННЫЙ ПУТЬ, а не origin.
//
// В AutoProxy-режиме selfBase = "http://localhost:<port>" (абсолютный origin),
// и всё сходится. В admin-режиме selfBase = "/captcha-proxy/<id>", и безусловное
// префиксование дописывало монтировку на каждом проходе:
//
//	/captcha-proxy/abc/static/x.js
//	→ /captcha-proxy/abc/captcha-proxy/abc/static/x.js → …
//
// А поскольку MutationObserver в шиме слушает src/href, каждая запись атрибута
// возвращалась в rewriteAttr — бесконечный цикл в микрозадачах и повешенная
// вкладка оператора.
//
// Полноценно исполнить JS тут нечем, поэтому проверяем инвариант на уровне
// сгенерированного шима: (1) guard на уже-примонтированный путь присутствует,
// (2) rewriteAttr отказывается писать неидемпотентный результат. Плюс отдельно
// проверяем саму логику префиксования на Go-модели.
func TestCaptchaShimGuardsAgainstNonIdempotentRewrite(t *testing.T) {
	mnt := &proxyMount{
		target:           mustParseURL(t, "https://id.vk.ru/not_robot_captcha?domain=vk.com"),
		selfBase:         "/captcha-proxy/abc123",
		selfHostMatchers: nil,
	}
	shim := rewriteCaptchaHTML("<html><head></head><body></body></html>", mnt, "/captcha-proxy/abc123/")

	if !strings.Contains(shim, "selfBase.charAt(0) === '/'") {
		t.Error("shim lost the mount-path guard — admin mode will re-prefix forever")
	}
	if !strings.Contains(shim, "rewriteUrl(r) !== r") {
		t.Error("shim lost the idempotence check in rewriteAttr — a regression would hang the tab")
	}
}

// Модель того, что делает rewriteUrl для «нашего» хоста: с монтированным путём
// повторный прогон обязан быть неподвижной точкой.
func TestMountPrefixIsIdempotent(t *testing.T) {
	// Зеркалит rewriteUrl: сперва из строки достаётся pathname (как это делает
	// new URL(s, location.href) в шиме), и только потом решается вопрос префикса.
	apply := func(selfBase, rawURL string) string {
		u, err := neturl.Parse(rawURL)
		if err != nil {
			return rawURL
		}
		path := u.Path
		if strings.HasPrefix(selfBase, "/") &&
			(path == selfBase || strings.HasPrefix(path, selfBase+"/")) {
			return rawURL // уже примонтирован
		}
		return selfBase + path
	}

	cases := []struct {
		name     string
		selfBase string
		path     string
		want     string
	}{
		{"admin mount, fresh path", "/captcha-proxy/abc", "/static/x.js", "/captcha-proxy/abc/static/x.js"},
		{"admin mount, already prefixed", "/captcha-proxy/abc", "/captcha-proxy/abc/static/x.js", "/captcha-proxy/abc/static/x.js"},
		{"admin mount, exactly the mount", "/captcha-proxy/abc", "/captcha-proxy/abc", "/captcha-proxy/abc"},
		// Ложное срабатывание недопустимо: похожий, но другой префикс.
		{"similar but different mount", "/captcha-proxy/abc", "/captcha-proxy/abcdef/x.js", "/captcha-proxy/abc/captcha-proxy/abcdef/x.js"},
		{"absolute origin base", "http://localhost:44099", "/static/x.js", "http://localhost:44099/static/x.js"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := apply(c.selfBase, c.path)
			if got != c.want {
				t.Fatalf("apply(%q, %q) = %q, want %q", c.selfBase, c.path, got, c.want)
			}
			// Ключевое свойство: второй проход ничего не меняет.
			if again := apply(c.selfBase, got); again != got {
				t.Fatalf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func mustParseURL(t *testing.T, raw string) *neturl.URL {
	t.Helper()
	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
