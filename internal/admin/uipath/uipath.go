package uipath

import (
	"context"
	"strings"
)

// The admin panel can be mounted under a URL prefix so it hides behind an
// unguessable path on a shared vhost, the way x-ui does on the same box. The
// alternative — a dedicated subdomain — needs a DNS record and a certificate
// naming it, and both announce publicly that something is there.
//
// The prefix deliberately does not reach the router: the server strips it
// before the mux sees anything, so every route, the auth middleware and the
// session lookup keep working on the paths they were written for. What DOES
// need it is every URL the panel EMITS, because the browser resolves those
// against the real location — the templates' links and htmx targets, the
// redirects, and the session cookie's Path.
//
// This lives in its own leaf package because the templates need it and the
// admin package imports the templates: putting it next to the server would be
// an import cycle.

type key struct{}

// Normalize turns operator input into a prefix that is safe to concatenate:
// "" stays empty, "secret" and "/secret/" both become "/secret".
func Normalize(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

// With puts the prefix on a context so templates can reach it through URL.
func With(ctx context.Context, base string) context.Context {
	return context.WithValue(ctx, key{}, base)
}

// From returns the prefix carried by ctx, or "" at the root.
func From(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(key{}).(string); ok {
		return v
	}
	return ""
}

// URL prefixes an absolute in-panel path. Templates call it for every link,
// asset and htmx target; a path that skips it resolves against the server root
// and 404s as soon as the panel is mounted under a prefix.
func URL(ctx context.Context, path string) string {
	base := From(ctx)
	if base == "" {
		return path
	}
	if path == "/" {
		return base + "/"
	}
	if !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	return base + path
}
