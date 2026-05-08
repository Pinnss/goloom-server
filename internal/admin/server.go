// Package admin is the HTTP control panel for goloom-wg-server.
//
// Endpoints:
//
//	GET    /                                dashboard HTML
//	GET    /static/style.css                styling
//	GET    /login                           login form
//	POST   /login                           username+password → session cookie
//	POST   /logout                          revoke session cookie
//	GET    /api/admin/state                 { username, is_default_password }
//	POST   /api/admin/password              change password (current+new)
//	GET    /api/inbounds                    list (JSON)
//	POST   /api/inbounds                    create
//	DELETE /api/inbounds/{id}               remove
//	POST   /api/inbounds/{id}/toggle        pause/resume
//	GET    /api/inbounds/{id}/client.conf   wg client config
//	GET    /api/inbounds/{id}/connstr       goloom:// connection string
//	GET    /api/inbounds/{id}/qr.png        QR PNG of the connection string
//	GET    /api/inbounds/{id}/history       per-inbound traffic samples
//	GET    /api/system/wg-interfaces        live wg interface list
//
// Auth is username + password (bcrypt-hashed) stored in a JSON file
// alongside the YAML config. On first start a random "admin" password
// is generated and printed to the log; the operator changes it via the
// dashboard. Sessions are in-memory (revoked on server restart).
package admin

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Pinnss/goloom-server/internal/inbound"
	"github.com/Pinnss/goloom-server/internal/wgprovision"
)

type Options struct {
	Listen         string
	Credentials    *CredentialStore
	TLSCert        string
	TLSKey         string
	AutoSelfSigned bool
	Manager        *inbound.Manager
	Provisioner    *wgprovision.Provisioner
	Logger         *log.Logger

	// PublicEndpointHint fills in [Peer] Endpoint when generating
	// client wg-quick configs. For the goloom architecture this is
	// always loopback because the user runs the joiner locally; a
	// future direct-WG mode would use the VPS's public IP here.
	PublicEndpointHint string

	// PublicURL — внешний URL admin-сервера. Пробрасывается клиенту
	// в connstr (CtrlURL) для S2/S3 client-meeting mode. Пример:
	// "https://45.43.89.67:9443". Если пусто, ctrl-ws bootstrap
	// в connstr не пишется и client-meeting инбаунды доступны
	// только через ручной ввод URL'а.
	PublicURL string

	// CaptchaBroker, when non-nil, exposes the VK Calls admin-webview
	// captcha solver via /captcha-proxy/<id>/* and /api/captcha/*.
	// The broker is also passed into the inbound.Manager so VK
	// inbounds with captcha_mode=admin-webview can delegate solves to
	// the operator's browser. nil disables the admin-webview path
	// (auto/none modes still work via the Manager's other knobs).
	CaptchaBroker *CaptchaBroker
}

type Server struct {
	opts     Options
	srv      *http.Server
	tlsCfg   *tls.Config
	sessions *sessionStore
}

func New(opts Options) (*Server, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8443"
	}
	if opts.Manager == nil {
		return nil, errors.New("admin: Manager required")
	}
	if opts.Credentials == nil {
		return nil, errors.New("admin: Credentials required")
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
	s := &Server{
		opts:     opts,
		tlsCfg:   tlsCfg,
		sessions: newSessionStore(),
	}
	s.registerRoutes(mux)

	// Captcha broker bolts on extra mux routes:
	//   /captcha-proxy/<id>/...   per-challenge reverse-proxy
	//   /api/captcha/pending      JSON list of pending challenges
	if opts.CaptchaBroker != nil {
		opts.CaptchaBroker.AttachToMux(mux)
		mux.HandleFunc("GET /api/captcha/pending", s.handleCaptchaPending)
	}

	// Ctrl-WS (S2/S3): /ctrl/inbound/<id>?token=<bearer> — клиентский
	// control channel для VK инбаундов в режиме client-meeting. Auth
	// делается per-inbound bearer'ом, не сессионной cookie, потому
	// что клиент — отдельный процесс (goloom-wg-client / GUI / mobile),
	// не human-driven.
	if opts.Manager != nil {
		ctrl := newCtrlServer(opts.Manager, opts.Logger)
		ctrl.AttachToMux(mux)
	}

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

// authMiddleware gatekeeps everything except the unauthenticated
// surfaces (login form + its CSS + favicon). API endpoints get a 401
// JSON-style response so client JS can show an inline error; HTML
// routes get a 303 redirect to the login page.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := s.currentUser(r); !ok {
			if isAPIPath(r.URL.Path) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) currentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	user, err := s.sessions.Lookup(c.Value)
	if err != nil {
		return "", false
	}
	return user, true
}

func isPublicPath(p string) bool {
	if p == "/login" || p == "/favicon.ico" {
		return true
	}
	// Static assets (Tailwind CSS, HTMX, Alpine, htmx-sse) must be
	// reachable from the unauthenticated login page.
	if strings.HasPrefix(p, "/static/") {
		return true
	}
	// Ctrl-WS — auth через per-inbound bearer query param,
	// session-cookie-flow не применяется.
	return strings.HasPrefix(p, "/ctrl/")
}

func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/")
}
