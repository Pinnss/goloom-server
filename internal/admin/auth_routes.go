package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// registerAuthRoutes wires endpoints that the auth-middleware lets
// through unauthenticated (login form) plus the post-auth endpoints
// for state and password change.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /api/admin/state", s.handleAdminState)
	mux.HandleFunc("POST /api/admin/password", s.handleChangePassword)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Если уже залогинен — сразу на дашборд.
	if _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginHTML)
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !s.opts.Credentials.Verify(req.Username, req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
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
		// Secure только если соединение TLS — иначе браузер не сохранит
		// cookie при заходе по http (например в локальной разработке).
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	w.WriteHeader(http.StatusNoContent)
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

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, _ := s.currentUser(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req changePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
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

const loginHTML = `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>goloom admin · вход</title>
<link rel="stylesheet" href="/static/style.css">
<style>
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:80vh}
.login-form{background:var(--panel);padding:24px;border-radius:8px;min-width:320px;border:1px solid #232938}
.login-form h1{margin:0 0 16px;font-size:18px}
.login-form .field{margin:10px 0}
.login-form .field input{width:100%}
.login-form button{width:100%;margin-top:12px}
.login-form .err{color:var(--danger);font-size:12px;margin-top:8px;min-height:16px}
</style>
</head><body>
<div class="login-wrap"><form class="login-form" id="loginForm">
<h1>goloom admin</h1>
<div class="field"><label>Логин</label><input id="username" autofocus value="admin" autocomplete="username"></div>
<div class="field"><label>Пароль</label><input id="password" type="password" autocomplete="current-password"></div>
<div class="err" id="err"></div>
<button>Войти</button>
</form></div>
<script>
document.getElementById("loginForm").addEventListener("submit",async function(e){
  e.preventDefault();
  var err=document.getElementById("err");err.textContent="";
  try{
    var r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:document.getElementById("username").value,
                           password:document.getElementById("password").value})});
    if(r.ok){location="/";return}
    err.textContent=r.status===401?"Неверный логин или пароль":(await r.text());
  }catch(ex){err.textContent="Сетевая ошибка: "+ex.message}
});
</script>
</body></html>`
