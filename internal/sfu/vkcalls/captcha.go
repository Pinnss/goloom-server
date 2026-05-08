// Local-HTTP-proxy captcha solver. Adapted from
// vk-turn-proxy/client/manual_captcha.go, stripped of the DNS-hijack
// path (we use a plain localhost URL and reverse-proxy to id.vk.com
// server-side).
//
// How it works:
//
//  1. The auth chain hits a captcha challenge with a redirect_uri
//     pointing at https://id.vk.com/not_robot_captcha?session_token=…
//  2. We start a local HTTP server on 127.0.0.1:<port> that:
//     - reverse-proxies every request to id.vk.com (forwarding
//       cookies, rewriting Origin/Referer headers)
//     - rewrites HTML responses so absolute id.vk.com URLs become
//       localhost URLs, and injects a tiny JS shim that re-rewrites
//       runtime-built URLs (XHR/fetch).
//     - inspects responses for /method/captchaNotRobot.check — when
//       one comes through with a non-empty success_token, we send
//       it on a channel.
//  3. We open the user's default browser at the local URL. They
//     click "Я не робот"; the proxy sees the resulting fetch and
//     captures the token.
//  4. Server shuts down, solver returns the token.
//
// Useful for CLI clients running on a workstation with a browser. For
// headless servers, the operator captures the token via the admin
// webview-auth flow and stuffs it into a [PreSolvedSolver]; for the
// Wails GUI, the captcha is rendered inside an embedded webview that
// pipes the success_token straight to the solver.

package vkcalls

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

// AutoProxyCaptchaSolver returns a [sfu.VKCaptchaSolver] that opens
// a local reverse-proxy + the user's default browser, then waits for
// the success_token to flow back through the proxy. Default for CLI
// tooling on a workstation.
func AutoProxyCaptchaSolver(timeout time.Duration, lg *log.Logger) sfu.VKCaptchaSolver {
	return func(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		tok, err := solveCaptchaViaProxy(ctx, ch.RedirectURI, timeout, lg)
		if err != nil {
			return sfu.VKCaptchaSolution{}, err
		}
		return sfu.VKCaptchaSolution{SuccessToken: tok}, nil
	}
}

// PreSolvedCaptchaSolver returns a one-shot solver that hands back a
// pre-captured success_token. Useful when an external orchestrator
// (admin webview, mobile app) has already solved the captcha and the
// caller just needs to feed the token into the auth chain.
//
// Returns an error on the second invocation — tokens are single-use.
func PreSolvedCaptchaSolver(token string) sfu.VKCaptchaSolver {
	var used bool
	return func(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		if used {
			return sfu.VKCaptchaSolution{}, errors.New("vkcalls: PreSolvedCaptchaSolver invoked twice (tokens are single-use)")
		}
		used = true
		return sfu.VKCaptchaSolution{SuccessToken: token}, nil
	}
}

func solveCaptchaViaProxy(ctx context.Context, redirectURI string, timeout time.Duration, lg *log.Logger) (string, error) {
	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}

	// Pick a random free localhost port (avoid collisions when several
	// PoCs run in parallel).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	tokCh := make(chan string, 1)
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	notifyTok := func(s string) {
		if s == "" {
			return
		}
		select {
		case tokCh <- s:
		default:
		}
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			rewriteProxyRequest(req.Out, targetURL, port)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			lg.Printf("captcha-proxy: error %s %s: %v", r.Method, r.URL.String(), err)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "captcha proxy error: %v", err)
		},
		ModifyResponse: func(res *http.Response) error {
			rewriteProxyCookies(res.Header)

			// Redirects: rewrite same-origin redirects so they stay
			// inside our local proxy.
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					if rewritten, ok := rewriteProxyRedirectLocation(loc, targetURL, port); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			ct := res.Header.Get("Content-Type")
			isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
			isToken := strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")
			if !isHTML && !isToken {
				return nil
			}

			body := res.Body
			if res.Header.Get("Content-Encoding") == "gzip" {
				if gz, err := gzip.NewReader(res.Body); err == nil {
					defer gz.Close()
					body = gz
				}
			}
			raw, err := io.ReadAll(body)
			if err != nil {
				return err
			}
			_ = res.Body.Close()

			if isToken {
				notifyTok(extractSuccessToken(raw))
			}

			if isHTML {
				// CSP/Frame headers would block our injected script.
				for _, h := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
				} {
					res.Header.Del(h)
				}
				raw = []byte(rewriteCaptchaHTML(string(raw), targetURL, port))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(raw))
			res.ContentLength = int64(len(raw))
			res.Header.Set("Content-Length", fmt.Sprint(len(raw)))
			return nil
		},
	}

	mux := http.NewServeMux()

	// JS-side fallback: shim posts here when it sees success_token in
	// a runtime-XHR. Server-side ModifyResponse usually catches it
	// first, but cover the asynchronous case.
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		notifyTok(r.FormValue("token"))
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "ok")
	})

	// Generic-proxy escape hatch for nested cross-origin assets the
	// SPA may load (e.g. gtm, errlogger). The shim rewrites those
	// URLs through this endpoint.
	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("proxy_url")
		parsed, err := neturl.Parse(raw)
		if err != nil || parsed.Host == "" {
			http.Error(w, "bad proxy_url", http.StatusBadRequest)
			return
		}
		(&httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = parsed.Path
				req.Out.URL.RawQuery = parsed.RawQuery
				rewriteProxyRequest(req.Out, parsed, port)
			},
		}).ServeHTTP(w, r)
	})

	mux.HandleFunc("/", proxy.ServeHTTP)

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("captcha-proxy: server: %v", err)
		}
	}()

	localURL := localCaptchaURLForTarget(targetURL, port)
	lg.Printf("captcha-proxy: opening %s in browser", localURL)
	openBrowser(localURL)

	// Wait for token, ctx cancel, or timeout.
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var token string
	select {
	case token = <-tokCh:
	case <-dctx.Done():
		_ = srv.Shutdown(context.Background())
		return "", fmt.Errorf("captcha-proxy: timeout/cancelled: %w", dctx.Err())
	}

	shCtx, shCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shCancel()
	_ = srv.Shutdown(shCtx)
	lg.Printf("captcha-proxy: success_token captured (%d chars)", len(token))
	return token, nil
}

// ─── helpers (lifted ~verbatim from vk-turn-proxy/manual_captcha.go) ─

func localCaptchaOrigin(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

func localCaptchaHosts(port int) []string {
	p := fmt.Sprintf(":%d", port)
	return []string{"localhost" + p, "127.0.0.1" + p, "[::1]" + p}
}

func isLocalCaptchaHost(host string, port int) bool {
	for _, h := range localCaptchaHosts(port) {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

func localCaptchaURLForTarget(t *neturl.URL, port int) string {
	u := &neturl.URL{
		Scheme:   "http",
		Host:     fmt.Sprintf("localhost:%d", port),
		Path:     t.Path,
		RawPath:  t.RawPath,
		RawQuery: t.RawQuery,
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func targetOrigin(t *neturl.URL) string { return t.Scheme + "://" + t.Host }

func rewriteProxyRequest(req *http.Request, t *neturl.URL, port int) {
	req.URL.Scheme = t.Scheme
	req.URL.Host = t.Host
	if req.URL.Path == "" {
		req.URL.Path = t.Path
	}
	req.Host = t.Host
	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")
	for _, n := range []string{"Origin", "Referer"} {
		if rw := rewriteProxyHeaderURL(req.Header.Get(n), t, port); rw != "" {
			req.Header.Set(n, rw)
		} else {
			req.Header.Del(n)
		}
	}
}

func rewriteProxyHeaderURL(raw string, t *neturl.URL, port int) string {
	if raw == "" {
		return raw
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Scheme != "http" || !isLocalCaptchaHost(parsed.Host, port) {
		return raw
	}
	parsed.Scheme = t.Scheme
	parsed.Host = t.Host
	return parsed.String()
}

func isSafeLocalRedirectPath(raw string) bool {
	if raw == "" || raw[0] != '/' {
		return false
	}
	if len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\') {
		return false
	}
	return true
}

func rewriteProxyRedirectLocation(raw string, t *neturl.URL, port int) (string, bool) {
	if isSafeLocalRedirectPath(raw) {
		return raw, true
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, t.Scheme) || !strings.EqualFold(parsed.Host, t.Host) {
		return "", false
	}
	return localCaptchaURLForTarget(parsed, port), true
}

func rewriteProxyCookies(header http.Header) {
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Domain = ""
		c.Secure = false
		c.Partitioned = false
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteStrictMode {
			c.SameSite = http.SameSiteLaxMode
		}
		header.Add("Set-Cookie", c.String())
	}
}

func extractSuccessToken(body []byte) string {
	var p struct {
		Response struct {
			SuccessToken string `json:"success_token"`
			Status       string `json:"status"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return ""
	}
	if p.Response.Status != "OK" {
		return ""
	}
	return p.Response.SuccessToken
}

// rewriteCaptchaHTML rewrites absolute id.vk.com URLs to local
// proxy URLs and injects a runtime-rewriter script.
func rewriteCaptchaHTML(html string, t *neturl.URL, port int) string {
	localOrigin := localCaptchaOrigin(port)
	upstreamOrigin := targetOrigin(t)
	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)

	script := fmt.Sprintf(`
<script>
(function() {
    var localOrigin = %q;
    var upstreamOrigin = %q;

    function rewriteUrl(s) {
        if (!s || typeof s !== 'string') return s;
        if (s.indexOf(localOrigin) === 0) return s;
        if (s.indexOf(upstreamOrigin) === 0) return localOrigin + s.slice(upstreamOrigin.length);
        if (s.indexOf('//') === 0) return '/generic_proxy?proxy_url=' + encodeURIComponent(window.location.protocol + s);
        if (s.indexOf('http://') === 0 || s.indexOf('https://') === 0) return '/generic_proxy?proxy_url=' + encodeURIComponent(s);
        return s;
    }
    function rewriteAttr(el, a) {
        if (!el || !el.getAttribute) return;
        var v = el.getAttribute(a);
        if (!v) return;
        var r = rewriteUrl(v);
        if (r !== v) el.setAttribute(a, r);
    }
    function rewriteDoc(root) {
        if (!root || !root.querySelectorAll) return;
        root.querySelectorAll('[href]').forEach(function(e){rewriteAttr(e,'href')});
        root.querySelectorAll('[src]').forEach(function(e){rewriteAttr(e,'src')});
        root.querySelectorAll('form[action]').forEach(function(e){rewriteAttr(e,'action')});
    }
    function postToken(t) {
        if (!t) return;
        fetch('/local-captcha-result', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'token='+encodeURIComponent(t)})
          .then(function(){ document.body.innerHTML='<h2 style="text-align:center;margin-top:20vh;font-family:sans-serif">Готово! Можно закрывать вкладку.</h2>'; setTimeout(function(){window.close()},400); })
          .catch(function(){});
    }
    var ox = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        if (arguments[1] && typeof arguments[1] === 'string') {
            this._u = arguments[1];
            arguments[1] = rewriteUrl(arguments[1]);
        }
        return ox.apply(this, arguments);
    };
    var os = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        var x = this;
        if (this._u && this._u.indexOf('captchaNotRobot.check') !== -1) {
            x.addEventListener('load', function() {
                try {
                    var d = JSON.parse(x.responseText);
                    if (d.response && d.response.success_token) postToken(d.response.success_token);
                } catch(e){}
            });
        }
        return os.apply(this, arguments);
    };
    var of = window.fetch;
    if (of) {
        window.fetch = function() {
            var u = arguments[0];
            var isObj = (typeof u === 'object' && u && u.url);
            var ustr = isObj ? u.url : u;
            var orig = ustr;
            if (typeof ustr === 'string') {
                ustr = rewriteUrl(ustr);
                arguments[0] = ustr;
            }
            var p = of.apply(this, arguments);
            if (typeof orig === 'string' && orig.indexOf('captchaNotRobot.check') !== -1) {
                p.then(function(r){ try { r.clone().json().then(function(d){ if(d.response && d.response.success_token) postToken(d.response.success_token); }) } catch(e){} });
            }
            return p;
        };
    }
    rewriteDoc(document);
    if (document.documentElement && window.MutationObserver) {
        new MutationObserver(function(ms) {
            ms.forEach(function(m) {
                if (m.type === 'attributes' && m.target) { rewriteAttr(m.target, m.attributeName); return; }
                m.addedNodes.forEach(function(n){ if (n.nodeType===1) rewriteDoc(n); });
            });
        }).observe(document.documentElement, {subtree:true, childList:true, attributes:true, attributeFilter:['href','src','action']});
    }
})();
</script>
`, localOrigin, upstreamOrigin)

	switch {
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", script+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", script+"</body>", 1)
	default:
		return html + script
	}
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		// `cmd /c start <url>` mangles URLs containing & (cmd parses
		// it as a command separator). Use rundll32 url.dll's
		// FileProtocolHandler instead — direct ShellExecute, no
		// shell-parsing in the path.
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "linux":
		if exec.Command("xdg-open", url).Start() != nil {
			_ = exec.Command("gio", "open", url).Start()
		}
	}
}
