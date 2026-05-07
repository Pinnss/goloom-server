package admin

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	"github.com/Pinnss/goloom-server/internal/admin/ui/pages"
)

// staticFS holds the JS/CSS assets the dashboard depends on (HTMX,
// Alpine, the SSE extension, and the Tailwind output). Embedding keeps
// the binary self-contained — no separate webroot to ship in deploys.
//
//go:embed static
var staticFS embed.FS

// staticHandler serves /static/* with a moderate cache so a redeploy
// with new tailwind.css invalidates quickly while the vendored JS still
// gets a free ride on browser cache between page loads.
func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.StripPrefix("/static/", cacheHeaders(http.FileServer(http.FS(sub))))
}

func cacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// handleDashboard renders the dashboard page with the current set of
// inbounds and admin state. All HTML now lives in templ files — see
// internal/admin/ui/pages/dashboard.templ.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	username, _ := s.currentUser(r)
	state := s.opts.Credentials.State()

	data := pages.DashboardData{
		Username:          username,
		IsDefaultPassword: state.IsDefaultPassword,
		Inbounds:          s.opts.Manager.Statuses(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.Dashboard(data).Render(reqCtx(r), w)
}

// reqCtx returns the request's cancellation context, falling back to
// Background for direct callers (tests).
func reqCtx(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}
