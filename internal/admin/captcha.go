// CaptchaBroker mediates VK Calls captcha challenges between the
// inbound runners (the "asker") and the operator's browser (the
// "solver"). When an inbound's auth chain hits a captcha:
//
//  1. The vkcalls AdminWebviewCaptchaSolver calls Broker.Register,
//     gets back a proxy URL + a wait channel
//  2. Broker mounts a per-challenge reverse-proxy at
//     /captcha-proxy/<id>/ using vkcalls.MountAdminCaptchaProxy, so
//     the operator's browser can navigate to the challenge with the
//     same JS-shim experience as AutoProxy.
//  3. Admin UI surfaces a pending-captcha badge with the proxy URL.
//  4. Operator opens it, solves the I-am-not-a-robot click, the JS
//     shim posts the captured success_token to
//     /captcha-proxy/<id>/local-captcha-result. The proxy's onToken
//     callback fires the wait channel; the solver returns; auth
//     retries.
//  5. Tokens expire fast (~1 min) — Broker.expireOldChallenges()
//     sweeps stale entries and closes their channels so nobody
//     hangs.
//
// Concurrent challenges are isolated by a per-id URL path
// (/captcha-proxy/{id}). Multiple inbounds can be solving captchas
// at once — they get their own entries in Pending() and their own
// open-in-browser links.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
)

// captchaURLPrefix is the URL space the broker owns. Per-challenge
// proxies live under /captcha-proxy/<id>/.
const captchaURLPrefix = "/captcha-proxy"

// captchaChallengeTTL caps how long a single challenge can stay in
// the pending queue before the broker gives up and closes the wait
// channel. Slightly larger than VK's success_token lifetime so the
// operator has a comfortable window to react.
const captchaChallengeTTL = 5 * time.Minute

// CaptchaBroker is the admin-side captcha mediator. Implements
// [vkcalls.AdminCaptchaBroker].
type CaptchaBroker struct {
	mu      sync.Mutex
	pending map[string]*captchaEntry

	// mux is the admin server's HTTP mux — broker mounts per-
	// challenge proxy handlers on it. nil while broker hasn't been
	// attached to a server (Register will return an error).
	mux *http.ServeMux

	// proxyMu protects mux access during dynamic mount/unmount.
	// http.ServeMux doesn't support unmount; instead we track
	// per-challenge handlers in a wrapper map and route through it.
	proxyMu      sync.RWMutex
	proxyMounted map[string]http.Handler
}

// captchaEntry is one in-flight challenge.
type captchaEntry struct {
	id           string
	target       *neturl.URL
	registeredAt time.Time
	tag          string // optional inbound tag for admin UI

	doneOnce sync.Once
	done     chan string
}

// NewCaptchaBroker returns a fresh broker. AttachToMux must be called
// once before Register can be used.
func NewCaptchaBroker() *CaptchaBroker {
	return &CaptchaBroker{
		pending:      map[string]*captchaEntry{},
		proxyMounted: map[string]http.Handler{},
	}
}

// AttachToMux installs the broker's HTTP routes on mux:
//
//	GET  /captcha-proxy/{id}/...   — per-challenge reverse-proxy +
//	                                 JS shim, mounted dynamically by
//	                                 [Register].
//	GET  /api/captcha/pending      — JSON list of pending challenges
//
// Must be called exactly once. Subsequent Register calls require this.
func (b *CaptchaBroker) AttachToMux(mux *http.ServeMux) {
	b.mu.Lock()
	b.mux = mux
	b.mu.Unlock()

	// Single dispatcher under captchaURLPrefix; routes by id from the
	// path. We can't rely on http.ServeMux to discover handlers added
	// dynamically (registering during runtime works but pattern
	// shadowing is per-Mux), so we install one entry up-front.
	mux.HandleFunc(captchaURLPrefix+"/", b.dispatchProxy)
}

// dispatchProxy is the catch-all under captchaURLPrefix. It resolves
// the {id} segment, looks up the per-challenge handler, and forwards
// to it. 404 if the id is unknown or expired.
func (b *CaptchaBroker) dispatchProxy(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, captchaURLPrefix+"/")
	id, _, _ := strings.Cut(rest, "/")
	if id == "" {
		http.Error(w, "captcha id missing", http.StatusBadRequest)
		return
	}

	b.proxyMu.RLock()
	h, ok := b.proxyMounted[id]
	b.proxyMu.RUnlock()
	if !ok {
		http.Error(w, "captcha challenge not found or expired", http.StatusNotFound)
		return
	}
	h.ServeHTTP(w, r)
}

// Register implements [vkcalls.AdminCaptchaBroker]. Called by
// [vkcalls.AdminWebviewCaptchaSolver] each time an inbound auth
// chain hits a captcha challenge.
func (b *CaptchaBroker) Register(ctx context.Context, ch sfu.VKCaptchaChallenge, tag string) (string, <-chan string) {
	target, err := neturl.Parse(ch.RedirectURI)
	if err != nil || target.Host == "" {
		// Invalid URI — return a closed channel so the solver fails
		// fast with a clear error.
		c := make(chan string)
		close(c)
		return "", c
	}

	b.mu.Lock()
	if b.mux == nil {
		b.mu.Unlock()
		c := make(chan string)
		close(c)
		return "", c
	}
	id := newCaptchaID()
	e := &captchaEntry{
		id:           id,
		target:       target,
		registeredAt: time.Now(),
		tag:          tag,
		done:         make(chan string, 1),
	}
	b.pending[id] = e
	b.mu.Unlock()

	urlPrefix := captchaURLPrefix + "/" + id
	// Build a per-challenge mux + mount the proxy handlers there.
	chMux := http.NewServeMux()
	if err := vkcalls.MountAdminCaptchaProxy(chMux, urlPrefix, target, func(tok string) {
		b.resolve(id, tok)
	}); err != nil {
		// Should never happen with our params, but if it does, fail
		// the challenge fast.
		close(e.done)
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
		return "", e.done
	}

	b.proxyMu.Lock()
	b.proxyMounted[id] = chMux
	b.proxyMu.Unlock()

	// Schedule expiration. If the operator never solves the captcha
	// within TTL, close the channel and reclaim resources.
	go func() {
		select {
		case <-time.After(captchaChallengeTTL):
			b.expire(id)
		case <-ctx.Done():
			b.expire(id)
		case <-e.done:
			// Resolved naturally; cleanup happens in resolve().
		}
	}()

	proxyURL := vkcalls.AdminCaptchaProxyURL(urlPrefix, target)
	return proxyURL, e.done
}

// Pending returns a snapshot of the in-flight challenges for the
// admin UI / API.
func (b *CaptchaBroker) Pending() []PendingCaptcha {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]PendingCaptcha, 0, len(b.pending))
	for _, e := range b.pending {
		out = append(out, PendingCaptcha{
			ID:           e.id,
			InboundTag:   e.tag,
			ProxyURL:     vkcalls.AdminCaptchaProxyURL(captchaURLPrefix+"/"+e.id, e.target),
			RegisteredAt: e.registeredAt,
			ExpiresAt:    e.registeredAt.Add(captchaChallengeTTL),
		})
	}
	return out
}

// PendingCaptcha is the JSON-friendly view of an in-flight challenge.
type PendingCaptcha struct {
	ID           string    `json:"id"`
	InboundTag   string    `json:"inbound_tag,omitempty"`
	ProxyURL     string    `json:"proxy_url"`
	RegisteredAt time.Time `json:"registered_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// resolve fires the done channel for id with the captured token, then
// cleans up the per-challenge mux entry. Idempotent.
func (b *CaptchaBroker) resolve(id, token string) {
	b.mu.Lock()
	e, ok := b.pending[id]
	if !ok {
		b.mu.Unlock()
		return
	}
	delete(b.pending, id)
	b.mu.Unlock()

	e.doneOnce.Do(func() {
		if token != "" {
			e.done <- token
		}
		close(e.done)
	})

	b.proxyMu.Lock()
	delete(b.proxyMounted, id)
	b.proxyMu.Unlock()
}

// expire is resolve with empty token — operator missed the deadline.
func (b *CaptchaBroker) expire(id string) {
	b.resolve(id, "")
}

// newCaptchaID returns 16 hex chars of randomness — enough to avoid
// collisions and short enough to be readable in URLs.
func newCaptchaID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
