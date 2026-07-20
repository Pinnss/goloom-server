// Captcha solvers for the VK anonymous-login flow.
//
// Three flavours, picked at runtime:
//
//   - [AutoProxyCaptchaSolver] — spins up a local 127.0.0.1:<port>
//     reverse-proxy + auto-launches the operator's default browser.
//     Default for CLI/GUI clients running on a workstation.
//
//   - [PreSolvedCaptchaSolver] — replays a token captured out-of-band.
//     One-shot.
//
//   - [AdminWebviewCaptchaSolver] — delegates to an [AdminCaptchaBroker]
//     hosted by the goloom admin panel. The operator opens the broker's
//     proxy URL in their browser, solves the captcha, and the token
//     flows back through the same channel. Fits headless production
//     servers where there's no desktop session for AutoProxy.
//
// All three converge on the same internal handler tree (reverse-proxy
// + JS shim + token capture); the only differences are where the
// handlers are mounted (own ephemeral HTTP server vs. an existing one)
// and how the URL is delivered to the operator (auto-open browser vs.
// admin-panel badge).
package vkauth

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
//
// sink — опциональный [CaptureSink] (обычно [*ProfileStore]); если
// задан, перехваченные device/browser_fp/UA отправятся туда для
// будущего auto-replay. Передавай nil если не используешь стор.
func AutoProxyCaptchaSolver(timeout time.Duration, lg *log.Logger, sink CaptureSink) sfu.VKCaptchaSolver {
	return AutoProxyCaptchaSolverWithOpener(timeout, lg, sink, openBrowser)
}

// AutoProxyCaptchaSolverWithOpener — то же что [AutoProxyCaptchaSolver],
// но использует custom URL opener. Мобильные клиенты передают сюда
// функцию которая шлёт URL в native WebView (см. mobile/api.go);
// desktop-вариант идёт через [openBrowser] (system browser).
func AutoProxyCaptchaSolverWithOpener(timeout time.Duration, lg *log.Logger, sink CaptureSink, openURL func(string)) sfu.VKCaptchaSolver {
	return func(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		tok, err := solveCaptchaViaProxy(ctx, ch.RedirectURI, timeout, lg, sink, openURL)
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

// AdminCaptchaBroker is the admin-side surface that
// [AdminWebviewCaptchaSolver] delegates to. The admin package
// implements this with a registry of pending challenges + HTTP
// routes mounted on the existing admin server.
type AdminCaptchaBroker interface {
	// Register adds a pending challenge to the broker's queue and
	// returns the URL the operator should open in their browser to
	// solve it, plus a channel that fires once with the captured
	// success_token (empty string on timeout/cancel).
	//
	// `tag` is a human-readable label (typically the inbound tag) so
	// the admin UI can show "captcha needed for <tag>" instead of
	// an opaque hex id.
	//
	// Implementations must respect ctx — when ctx is cancelled, the
	// channel must be closed so the solver doesn't hang.
	Register(ctx context.Context, ch sfu.VKCaptchaChallenge, tag string) (proxyURL string, done <-chan string)
}

// AdminWebviewCaptchaSolver returns a [sfu.VKCaptchaSolver] that
// delegates to the goloom admin panel via the supplied broker. Use
// this for inbounds running on headless servers where AutoProxy
// can't open a browser.
//
// `tag` is a human-readable label (e.g. the inbound's tag) shown in
// the admin UI's pending-captcha badge.
//
// The solver blocks until the operator solves the challenge or ctx
// is cancelled — under normal conditions the admin's pending-captcha
// badge surfaces the request within a second of the inbound asking.
func AdminWebviewCaptchaSolver(broker AdminCaptchaBroker, tag string, lg *log.Logger) sfu.VKCaptchaSolver {
	return func(ctx context.Context, ch sfu.VKCaptchaChallenge) (sfu.VKCaptchaSolution, error) {
		proxyURL, done := broker.Register(ctx, ch, tag)
		if lg != nil {
			lg.Printf("captcha-broker: pending [%s] — operator should open %s", tag, proxyURL)
		}
		select {
		case tok, ok := <-done:
			if !ok || tok == "" {
				return sfu.VKCaptchaSolution{}, errors.New("vkcalls: admin captcha challenge expired or cancelled")
			}
			return sfu.VKCaptchaSolution{SuccessToken: tok}, nil
		case <-ctx.Done():
			return sfu.VKCaptchaSolution{}, ctx.Err()
		}
	}
}

// ─── proxy core (used by both AutoProxy and Admin paths) ──────────────

// proxyMount captures everything the captcha proxy + JS shim need to
// rewrite URLs. selfBase is the URL prefix the browser uses to reach
// our proxy:
//
//	"http://localhost:1234"           — local-mode (AutoProxy)
//	"/captcha-proxy/<id>"             — admin-mode (relative path)
//
// selfHostMatchers is the list of host strings that count as "us" for
// header-rewrite purposes. For local mode it's the various forms of
// the loopback host:port; for admin mode it's empty (the browser's
// Host: header is always the admin host, not us).
type proxyMount struct {
	target           *neturl.URL  // upstream id.vk.com URL
	selfBase         string       // proxy base URL the browser sees
	selfHostMatchers []string     // proxy hosts to recognise in headers
	onToken          func(string) // success_token captured callback
	transport        http.RoundTripper
}

// MountAdminCaptchaProxyOptions конфигурирует [MountAdminCaptchaProxy].
//
// FingerprintSink — опциональный сборщик device/browser_fp/UA,
// перехватывает тела `captchaNotRobot.componentDone` и `.check` пока
// они проходят через reverse-proxy. Передаётся обычно как
// `*ProfileStore`; nil → перехвата нет (legacy-поведение).
//
// Logger — лог для loggingTransport diagnostics; nil → silent.
type MountAdminCaptchaProxyOptions struct {
	FingerprintSink CaptureSink
	Logger          *log.Logger
}

// MountAdminCaptchaProxy installs the captcha proxy + JS shim
// handlers under urlPrefix on mux. urlPrefix must start with "/" and
// not end with "/" (e.g. "/captcha-proxy/abc123"). target is the
// upstream URL (id.vk.com/not_robot_captcha?session_token=…). onToken
// fires when a success_token is captured (server-side or via the JS
// shim's POST fallback).
//
// Если opts.FingerprintSink задан — поверх defaultTransport
// натягивается [loggingTransport], который параллельно с обычным
// proxying извлекает device/browser_fp/UA и кормит их в sink (для
// будущего auto-replay, см. [ProfileStore]).
//
// Used by [internal/admin].CaptchaBroker; sites without an admin
// server should use [AutoProxyCaptchaSolver] instead.
func MountAdminCaptchaProxy(mux *http.ServeMux, urlPrefix string, target *neturl.URL, onToken func(string), opts MountAdminCaptchaProxyOptions) error {
	if mux == nil {
		return errors.New("vkcalls: MountAdminCaptchaProxy: mux is nil")
	}
	if target == nil {
		return errors.New("vkcalls: MountAdminCaptchaProxy: target is nil")
	}
	if !strings.HasPrefix(urlPrefix, "/") || strings.HasSuffix(urlPrefix, "/") {
		return fmt.Errorf("vkcalls: MountAdminCaptchaProxy: urlPrefix %q must start with / and not end with /", urlPrefix)
	}
	transport := http.RoundTripper(defaultTransport())
	if opts.FingerprintSink != nil {
		transport = NewLoggingTransport(transport, opts.FingerprintSink, opts.Logger)
	}
	mnt := &proxyMount{
		target:    target,
		selfBase:  urlPrefix,
		onToken:   onToken,
		transport: transport,
	}
	mountHandlers(mux, urlPrefix+"/", mnt)
	return nil
}

// AdminCaptchaProxyURL returns the relative URL where a freshly-
// registered challenge will live, given the broker's URL prefix
// scheme ("/captcha-proxy/<id>"). Convenience for callers that build
// challenge IDs externally.
func AdminCaptchaProxyURL(urlPrefix string, target *neturl.URL) string {
	u := &neturl.URL{
		Path:     urlPrefix + target.Path,
		RawPath:  urlPrefix + target.EscapedPath(),
		RawQuery: target.RawQuery,
	}
	if u.Path == "" {
		u.Path = urlPrefix + "/"
	}
	return u.String()
}

func solveCaptchaViaProxy(ctx context.Context, redirectURI string, timeout time.Duration, lg *log.Logger, sink CaptureSink, openURL func(string)) (string, error) {
	if openURL == nil {
		openURL = openBrowser
	}
	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	tokCh := make(chan string, 1)
	notifyTok := func(s string) {
		if s == "" {
			return
		}
		select {
		case tokCh <- s:
		default:
		}
	}

	transport := http.RoundTripper(defaultTransport())
	if sink != nil {
		transport = NewLoggingTransport(transport, sink, lg)
	}
	mnt := &proxyMount{
		target:           targetURL,
		selfBase:         localCaptchaOrigin(port),
		selfHostMatchers: localCaptchaHosts(port),
		onToken:          notifyTok,
		transport:        transport,
	}

	mux := http.NewServeMux()
	mountHandlers(mux, "/", mnt)

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("captcha-proxy: server: %v", err)
		}
	}()

	localURL := localCaptchaURLForTarget(targetURL, port)
	lg.Printf("captcha-proxy: opening %s", localURL)
	openURL(localURL)

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

// mountHandlers attaches the three captcha-proxy routes to mux at
// urlBase (which must end with "/"). Routes:
//
//	<urlBase>local-captcha-result   POST endpoint the JS shim hits
//	                                 with the captured success_token
//	<urlBase>generic_proxy          escape hatch for runtime-rewritten
//	                                 cross-origin asset loads
//	<urlBase>                       catch-all reverse-proxy with
//	                                 HTML/cookie/redirect rewrites
func mountHandlers(mux *http.ServeMux, urlBase string, mnt *proxyMount) {
	if !strings.HasSuffix(urlBase, "/") {
		panic("vkcalls.mountHandlers: urlBase must end with /")
	}

	proxy := &httputil.ReverseProxy{
		Transport: mnt.transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			rewriteProxyRequest(req.Out, mnt, urlBase)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "captcha proxy error: %v", err)
		},
		ModifyResponse: func(res *http.Response) error {
			rewriteProxyCookies(res.Header)

			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					if rewritten, ok := rewriteProxyRedirectLocation(loc, mnt); ok {
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
				if mnt.onToken != nil {
					mnt.onToken(extractSuccessToken(raw))
				}
			}

			if isHTML {
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
				raw = []byte(rewriteCaptchaHTML(string(raw), mnt, urlBase))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(raw))
			res.ContentLength = int64(len(raw))
			res.Header.Set("Content-Length", fmt.Sprint(len(raw)))
			return nil
		},
	}

	mux.HandleFunc(urlBase+"local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		if mnt.onToken != nil {
			mnt.onToken(r.FormValue("token"))
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "ok")
	})

	mux.HandleFunc(urlBase+"generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("proxy_url")
		parsed, err := neturl.Parse(raw)
		if err != nil || parsed.Host == "" {
			http.Error(w, "bad proxy_url", http.StatusBadRequest)
			return
		}
		(&httputil.ReverseProxy{
			Transport: mnt.transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = parsed.Path
				req.Out.URL.RawQuery = parsed.RawQuery
				rewriteGenericProxy(req.Out, parsed, mnt)
			},
		}).ServeHTTP(w, r)
	})

	mux.Handle(urlBase, http.StripPrefix(strings.TrimSuffix(urlBase, "/"), proxy))
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ─── helpers (lifted ~verbatim from vk-turn-proxy/manual_captcha.go) ─

func localCaptchaOrigin(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

func localCaptchaHosts(port int) []string {
	p := fmt.Sprintf(":%d", port)
	return []string{"localhost" + p, "127.0.0.1" + p, "[::1]" + p}
}

func isOurHost(host string, mnt *proxyMount) bool {
	for _, h := range mnt.selfHostMatchers {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// localCaptchaURLForTarget returns the localhost URL the browser
// should open. Used only by the AutoProxy path — admin path builds
// its own URL via [AdminCaptchaProxyURL].
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

func rewriteProxyRequest(req *http.Request, mnt *proxyMount, urlBase string) {
	req.URL.Scheme = mnt.target.Scheme
	req.URL.Host = mnt.target.Host
	if req.URL.Path == "" {
		req.URL.Path = mnt.target.Path
	}
	req.Host = mnt.target.Host
	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")
	for _, n := range []string{"Origin", "Referer"} {
		if rw := rewriteProxyHeaderURL(req.Header.Get(n), mnt); rw != "" {
			req.Header.Set(n, rw)
		} else {
			req.Header.Del(n)
		}
	}
}

func rewriteGenericProxy(req *http.Request, target *neturl.URL, mnt *proxyMount) {
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host
	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")

	// The WebView believes it is on http://localhost:<port>, so it labels these
	// requests with OUR origin — captured live on 2026-07-20 hitting api.vk.ru
	// with `Referer: http://localhost:39169/not_robot_captcha?…session_token=…`.
	// Handing VK's antifraud a localhost referer (and leaking the session token
	// into it) is a plain bot signal. Present the captcha's real upstream origin
	// instead, derived from the target so this tracks VK's vk.com -> vk.ru
	// migration on its own.
	//
	// Origin-only, no path: id.vk.* -> api.vk.* is cross-origin, where a browser
	// under the default referrer policy sends the bare origin. The catch-all
	// proxy path does the equivalent via [rewriteProxyHeaderURL]; generic_proxy
	// forwarded these verbatim until now.
	captchaOrigin := targetOrigin(mnt.target)
	req.Header.Set("Referer", captchaOrigin+"/")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		req.Header.Set("Origin", captchaOrigin)
	} else {
		req.Header.Del("Origin")
	}

	// Sec-Fetch-Site должен согласовываться с подставленным выше Origin.
	// WebView считает себя на localhost и шлёт same-origin — вместе с
	// Origin: id.vk.ru это самопротиворечие (origin id.vk.ru, хост api.vk.ru,
	// а заголовок говорит «тот же origin»). Настоящий браузер прислал бы
	// same-site для vk.ru -> vk.ru и cross-site для ad.mail.ru.
	if sameSite(mnt.target.Host, target.Host) {
		req.Header.Set("Sec-Fetch-Site", "same-site")
	} else {
		req.Header.Set("Sec-Fetch-Site", "cross-site")
	}
}

// sameSite сравнивает хосты по двум последним меткам (id.vk.ru vs api.vk.ru →
// true; id.vk.ru vs ad.mail.ru → false). Публичного суффикс-листа тут не надо:
// все хосты этого флоу — обычные домены второго уровня.
func sameSite(a, b string) bool {
	reg := func(h string) string {
		if i := strings.IndexByte(h, ':'); i >= 0 {
			h = h[:i] // отрезаем порт
		}
		parts := strings.Split(strings.ToLower(h), ".")
		if len(parts) < 2 {
			return h
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return reg(a) == reg(b)
}

func rewriteProxyHeaderURL(raw string, mnt *proxyMount) string {
	if raw == "" {
		return raw
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	// Only rewrite headers that look like they came from our local
	// proxy (e.g. Referer Origin). For admin mode selfHostMatchers is
	// typically empty so we fall through and return raw unchanged —
	// the browser is already sending headers relative to the admin
	// host, which is fine for upstream.
	if !isOurHost(parsed.Host, mnt) {
		return raw
	}
	parsed.Scheme = mnt.target.Scheme
	parsed.Host = mnt.target.Host
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

func rewriteProxyRedirectLocation(raw string, mnt *proxyMount) (string, bool) {
	if isSafeLocalRedirectPath(raw) {
		return mnt.selfBase + raw, true
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, mnt.target.Scheme) || !strings.EqualFold(parsed.Host, mnt.target.Host) {
		return "", false
	}
	rewritten := &neturl.URL{
		Scheme:   "",
		Host:     "",
		Path:     mnt.selfBase + parsed.Path,
		RawQuery: parsed.RawQuery,
	}
	return rewritten.String(), true
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
// proxy URLs and injects a runtime-rewriter script. urlBase is the
// captcha-proxy mount path with trailing "/" (used to build the
// /local-captcha-result and /generic_proxy paths inside the shim).
func rewriteCaptchaHTML(html string, mnt *proxyMount, urlBase string) string {
	upstreamOrigin := targetOrigin(mnt.target)
	html = strings.ReplaceAll(html, upstreamOrigin, mnt.selfBase)

	tokenPath := urlBase + "local-captcha-result"
	genericPath := urlBase + "generic_proxy"

	script := fmt.Sprintf(`
<script>
(function() {
    var selfBase = %q;          // "http://localhost:1234" or "/captcha-proxy/<id>"
    var upstreamOrigin = %q;    // captcha origin, derived: "https://id.vk.ru"
    var tokenPath = %q;         // POST endpoint for captured success_token
    var genericPath = %q;       // generic-proxy escape hatch

    function isOurHost(s) {
        try { return new URL(s, window.location.href).host === window.location.host; }
        catch (e) { return false; }
    }
    function rewriteUrl(s) {
        if (!s || typeof s !== 'string') return s;
        // Match on HOST, not on the selfBase prefix: VK handed back its FAQ link
        // as https://localhost:<port>/about/faq/… (https, while selfBase is http),
        // so a prefix test missed it, the URL got wrapped in generic_proxy a
        // second time, the proxy fetched itself and returned 502.
        if (isOurHost(s)) {
            try {
                var u = new URL(s, window.location.href);
                return selfBase + u.pathname + u.search + u.hash;
            } catch (e) { return s; }
        }
        if (s.indexOf(upstreamOrigin) === 0) return selfBase + s.slice(upstreamOrigin.length);
        if (s.indexOf('//') === 0) return genericPath + '?proxy_url=' + encodeURIComponent(window.location.protocol + s);
        if (s.indexOf('http://') === 0 || s.indexOf('https://') === 0) return genericPath + '?proxy_url=' + encodeURIComponent(s);
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
        fetch(tokenPath, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'token='+encodeURIComponent(t)})
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
`, mnt.selfBase, upstreamOrigin, tokenPath, genericPath)

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
		// `cmd /c start <url>` mangles URLs that contain `&` (the
		// shell treats them as command separators). rundll32 takes
		// the raw URL through the file-protocol-handler shim.
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
