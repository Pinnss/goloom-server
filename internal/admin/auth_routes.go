package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Pinnss/goloom-server/internal/admin/ui/pages"
)

// registerAuthRoutes wires endpoints that the auth middleware lets
// through unauthenticated (the login form and its POST handler) plus
// the post-auth state and password-change endpoints.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /api/admin/state", s.handleAdminState)
	mux.HandleFunc("POST /api/admin/password", s.handleChangePassword)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.Login("").Render(reqCtx(r), w)
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin accepts both JSON (legacy fetch-based clients) and
// form-encoded bodies (HTMX form submissions). Successful login writes
// the session cookie and returns 204 — the HTMX afterRequest hook on
// the login page redirects on success, so no body is needed.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLoginRequest(r)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !s.opts.Credentials.Verify(req.Username, req.Password) {
		// HTMX clients swap the response body into the error slot; for
		// non-HTMX callers the same string body lands in alert(). 401
		// stays so any tooling can distinguish bad creds.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = pages.LoginError("Неверный логин или пароль").Render(reqCtx(r), w)
		return
	}

	tok, err := s.sessions.New(req.Username)
	if err != nil {
		http.Error(w, "session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		// Secure cookie only over TLS, otherwise browsers drop it on
		// http (matters for local dev where TLS is off).
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	w.WriteHeader(http.StatusNoContent)
}

func decodeLoginRequest(r *http.Request) (loginReq, error) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.Contains(ct, "application/json"):
		var req loginReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return loginReq{}, err
		}
		req.Username = strings.TrimSpace(req.Username)
		return req, nil
	default:
		// HTMX (and HTML form fallback) send url-encoded bodies.
		if err := r.ParseForm(); err != nil {
			return loginReq{}, err
		}
		return loginReq{
			Username: strings.TrimSpace(r.PostFormValue("username")),
			Password: r.PostFormValue("password"),
		}, nil
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.Revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminState(w http.ResponseWriter, r *http.Request) {
	st := s.opts.Credentials.State()
	writeJSON(w, http.StatusOK, st)
}

type changePasswordReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// handleChangePassword accepts JSON (json-enc HTMX, fetch) or form
// bodies; the form path also supports a `confirm` field for the
// settings page.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, _ := s.currentUser(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, confirm, err := decodeChangePasswordRequest(r)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if confirm != "" && confirm != req.New {
		http.Error(w, "новый пароль и подтверждение не совпадают", http.StatusBadRequest)
		return
	}
	if !s.opts.Credentials.Verify(username, req.Current) {
		http.Error(w, "current password is wrong", http.StatusForbidden)
		return
	}
	if err := s.opts.Credentials.ChangePassword(req.New); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeChangePasswordRequest(r *http.Request) (changePasswordReq, string, error) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.Contains(ct, "application/json"):
		var req changePasswordReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return changePasswordReq{}, "", err
		}
		return req, "", nil
	default:
		if err := r.ParseForm(); err != nil {
			return changePasswordReq{}, "", err
		}
		req := changePasswordReq{
			Current: r.PostFormValue("current"),
			New:     r.PostFormValue("new"),
		}
		if req.New == "" {
			return req, "", errors.New("new password is required")
		}
		return req, r.PostFormValue("confirm"), nil
	}
}
