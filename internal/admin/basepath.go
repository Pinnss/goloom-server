package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/Pinnss/goloom-server/internal/admin/uipath"
)

// See internal/admin/uipath for why the prefix never reaches the router.

// NormalizeBasePath is [uipath.Normalize], re-exported so callers configuring
// the server do not need the leaf package.
func NormalizeBasePath(p string) string { return uipath.Normalize(p) }

// URL is [uipath.URL], for the handlers that emit redirects.
func URL(ctx context.Context, path string) string { return uipath.URL(ctx, path) }

// withBasePath publishes the prefix on every request context so templates can
// reach it. It is installed even when the prefix is empty, so the helper
// behaves identically at the root and never has to care which mode it is in.
func withBasePath(base string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(uipath.With(r.Context(), base)))
	})
}

// mountUnderBasePath serves next only under base. Anything outside gets 404
// rather than a redirect: a redirect would confirm to a prober that the prefix
// exists, which is the whole thing being hidden.
func mountUnderBasePath(base string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
			http.NotFound(w, r)
			return
		}
		// The bare prefix redirects to its slashed form instead of rendering.
		// The page's own links are relative, and "login" resolves against
		// "/secret" as "/login" but against "/secret/" as "/secret/login" —
		// so serving the root page at the unslashed URL would hand the browser
		// links that all miss. The requester already knows the prefix, so this
		// redirect reveals nothing a 404 would have hidden.
		rest := strings.TrimPrefix(r.URL.Path, base)
		if rest == "" {
			target := base + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		next.ServeHTTP(w, r2)
	})
}

// cookiePath is the Path a session cookie must carry: the panel's own prefix,
// so the browser returns it for every panel request and for nothing else.
func (s *Server) cookiePath() string {
	if s.opts.BasePath == "" {
		return "/"
	}
	return s.opts.BasePath + "/"
}
