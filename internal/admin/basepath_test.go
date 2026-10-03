package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Pinnss/goloom-server/internal/admin/uipath"
)

func TestNormalizeBasePath(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"/":          "",
		"   ":        "",
		"secret":     "/secret",
		"/secret":    "/secret",
		"/secret/":   "/secret",
		"secret/":    "/secret",
		"//secret//": "/secret",
		" /secret ":  "/secret",
	}
	for in, want := range cases {
		if got := NormalizeBasePath(in); got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every URL the panel emits has to carry the prefix, because the browser
// resolves it against the real location. One that skips it resolves at the
// server root and 404s — which is exactly how a panel mounted under a prefix
// loses its stylesheets and every htmx call at once.
func TestURLPrefixesEmittedPaths(t *testing.T) {
	root := context.Background()
	under := uipath.With(root, "/secret")

	for _, tc := range []struct{ in, atRoot, prefixed string }{
		{"/", "/", "/secret/"},
		{"/login", "/login", "/secret/login"},
		{"/static/htmx.min.js", "/static/htmx.min.js", "/secret/static/htmx.min.js"},
		{"/api/admin/password", "/api/admin/password", "/secret/api/admin/password"},
	} {
		if got := uipath.URL(root, tc.in); got != tc.atRoot {
			t.Errorf("at root: URL(%q) = %q, want %q", tc.in, got, tc.atRoot)
		}
		if got := uipath.URL(under, tc.in); got != tc.prefixed {
			t.Errorf("under prefix: URL(%q) = %q, want %q", tc.in, got, tc.prefixed)
		}
	}
}

// The prefix must never reach the router: the mux, the auth middleware and the
// session lookup are all written against unprefixed paths, so stripping it at
// the edge is what keeps them working untouched.
func TestMountUnderBasePathStripsBeforeRouting(t *testing.T) {
	var seen string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	h := mountUnderBasePath("/secret", inner)

	for _, tc := range []struct {
		request string
		want    string
	}{
		{"/secret/", "/"},
		{"/secret/login", "/login"},
		{"/secret/static/app.css", "/static/app.css"},
	} {
		seen = ""
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.request, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", tc.request, rec.Code)
		}
		if seen != tc.want {
			t.Errorf("%s: router saw %q, want %q", tc.request, seen, tc.want)
		}
	}
}

// Anything outside the prefix gets a flat 404. A redirect would confirm to a
// prober that the prefix exists, which defeats hiding the panel behind one.
func TestMountUnderBasePathHidesEverythingElse(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("router was reached for a path outside the prefix")
		w.WriteHeader(http.StatusOK)
	})
	h := mountUnderBasePath("/secret", inner)

	for _, p := range []string{"/", "/login", "/static/app.css", "/secretish", "/secretish/x"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s: sent Location %q — that confirms the prefix exists", p, loc)
		}
	}
}

// The session cookie has to be scoped to the panel: at the root that is "/",
// and under a prefix it must be the prefix, or the browser either stops
// sending it back or hands it to every other app on the same host.
func TestCookiePathFollowsBasePath(t *testing.T) {
	atRoot := &Server{opts: Options{}}
	if got := atRoot.cookiePath(); got != "/" {
		t.Errorf("cookiePath at root = %q, want /", got)
	}
	under := &Server{opts: Options{BasePath: "/secret"}}
	if got := under.cookiePath(); got != "/secret/" {
		t.Errorf("cookiePath under prefix = %q, want /secret/", got)
	}
}

// The bare prefix must redirect to its slashed form rather than render. The
// panel's redirects and its one htmx refresh are relative, and "login"
// resolves against "/secret" as "/login" but against "/secret/" as
// "/secret/login" — so rendering at the unslashed URL would hand the browser
// links that all miss.
func TestMountUnderBasePathSlashesTheBarePrefix(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("bare prefix was rendered instead of redirected")
	})
	h := mountUnderBasePath("/secret", inner)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secret", nil))
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/secret/" {
		t.Errorf("Location = %q, want /secret/", loc)
	}

	// A query string has to survive the redirect.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secret?tab=vk", nil))
	if loc := rec.Header().Get("Location"); loc != "/secret/?tab=vk" {
		t.Errorf("Location = %q, want /secret/?tab=vk", loc)
	}
}
