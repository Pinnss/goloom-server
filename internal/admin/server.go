// Package admin is the HTTP control panel for goloom-wg-server.
//
// Endpoints:
//
//	GET  /                              dashboard HTML
//	GET  /static/style.css              styling
//	GET  /api/inbounds                  list (JSON)
//	POST /api/inbounds                  create (provisions WG iface, joins meeting)
//	DELETE /api/inbounds/{id}           remove (tears down WG iface)
//	POST /api/inbounds/{id}/toggle      pause/resume
//	GET  /api/inbounds/{id}/client.conf wg client config
//	GET  /api/inbounds/{id}/connstr     goloom:// connection string
//	GET  /api/inbounds/{id}/qr.png      QR PNG of the connection string
//
// Auth is a single bearer token from the YAML; all routes require it
// (sent via Authorization header or ?token= query param). Listening on
// 127.0.0.1 by default — operators expose via SSH tunnel or reverse proxy.
package admin

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Sv9toslavPinigin/goloom-server/internal/inbound"
	"github.com/Sv9toslavPinigin/goloom-server/internal/wgprovision"
)

type Options struct {
	Listen         string
	Token          string
	TLSCert        string
	TLSKey         string
	AutoSelfSigned bool
	Manager        *inbound.Manager
	Provisioner    *wgprovision.Provisioner // optional; nil = no auto-provisioning, only manual inbounds
	Logger         *log.Logger

	// PublicEndpointHint is used when generating client WG configs to
	// fill in the [Peer] Endpoint. For the goloom architecture this is
	// always "127.0.0.1:<port>" because the user runs the joiner locally,
	// but a future direct-WG mode would use the VPS's public IP.
	PublicEndpointHint string
}

type Server struct {
	opts    Options
	srv     *http.Server
	tlsCfg  *tls.Config
}

func New(opts Options) (*Server, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8443"
	}
	if opts.Manager == nil {
		return nil, errors.New("admin: Manager required")
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.PublicEndpointHint == "" {
		opts.PublicEndpointHint = "127.0.0.1:51820"
	}

	tlsCfg, err := buildTLSConfig(opts)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	s := &Server{opts: opts, tlsCfg: tlsCfg}
	s.registerRoutes(mux)

	s.srv = &http.Server{
		Addr:              opts.Listen,
		Handler:           s.authMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsCfg,
	}
	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()

	scheme := "http"
	if s.tlsCfg != nil {
		scheme = "https"
	}
	s.opts.Logger.Printf("ADMIN serving %s://%s", scheme, s.opts.Listen)

	var err error
	if s.tlsCfg != nil {
		err = s.srv.ListenAndServeTLS("", "")
	} else {
		err = s.srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := extractToken(r)
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.opts.Token)) != 1 {
			if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
				renderLogin(w)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("goloom_token"); err == nil {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

func renderLogin(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>goloom admin</title>
<style>body{font-family:system-ui;background:#111;color:#eee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#1a1a1a;padding:24px;border-radius:8px;min-width:300px}
h1{margin:0 0 16px;font-size:18px}
input{width:100%;padding:8px;background:#222;border:1px solid #333;color:#eee;border-radius:4px;font-family:monospace}
button{margin-top:12px;width:100%;padding:8px;background:#3a8;color:#fff;border:0;border-radius:4px;cursor:pointer}
</style></head><body>
<form method="GET" action="/">
<h1>goloom admin</h1>
<input type="password" name="token" placeholder="bearer token" autofocus>
<button>Войти</button>
</form>
<script>
document.querySelector('form').addEventListener('submit',function(e){
  e.preventDefault();
  var t=document.querySelector('input[name=token]').value;
  document.cookie='goloom_token='+t+'; path=/; max-age=86400; samesite=strict';
  location='/';
});
</script>
</body></html>`)
}
