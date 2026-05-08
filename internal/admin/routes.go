package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/inbound"
	"github.com/Pinnss/goloom-server/internal/wgprovision"
)

func wgInterfaceList(opts Options) []wgInterfaceInfo {
	specs := opts.Manager.List()
	managed := make(map[string]string, len(specs)) // iface -> tag
	for _, s := range specs {
		if s.WGInterface != "" {
			managed[s.WGInterface] = s.Tag
		}
	}
	live := wgprovision.InspectInterfaces()
	out := make([]wgInterfaceInfo, 0, len(live))
	for _, info := range live {
		entry := wgInterfaceInfo{
			Name:       info.Name,
			ListenPort: info.ListenPort,
			PublicKey:  info.PublicKey,
			NumPeers:   info.NumPeers,
		}
		if tag, ok := managed[info.Name]; ok {
			entry.Managed = true
			entry.InboundTag = tag
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	s.registerAuthRoutes(mux)

	// Static assets — embedded JS/CSS, served from internal/admin/static.
	mux.Handle("GET /static/", staticHandler())

	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /settings", s.handleSettings)

	// JSON API kept stable so anything scripting against it (e.g.
	// the existing fetch-based UI scripts in pre-templ deploys) keeps
	// working during the rollout.
	mux.HandleFunc("GET /api/inbounds", s.handleListInbounds)
	mux.HandleFunc("POST /api/inbounds", s.handleCreateInbound)
	mux.HandleFunc("DELETE /api/inbounds/{id}", s.handleDeleteInbound)
	mux.HandleFunc("POST /api/inbounds/{id}/toggle", s.handleToggleInbound)
	mux.HandleFunc("GET /api/inbounds/{id}/client.conf", s.handleClientConf)
	mux.HandleFunc("GET /api/inbounds/{id}/connstr", s.handleConnStr)
	mux.HandleFunc("GET /api/inbounds/{id}/qr.png", s.handleQR)
	mux.HandleFunc("GET /api/system/wg-interfaces", s.handleListWGInterfaces)
	mux.HandleFunc("GET /api/inbounds/{id}/history", s.handleInboundHistory)

	// HTMX-fragment endpoints — HTML responses small enough to swap
	// directly. Kept under /htmx/ so the API surface stays clean.
	s.registerHTMXRoutes(mux)
}

func (s *Server) handleInboundHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hist := s.opts.Manager.History().Snapshot(id)
	writeJSON(w, http.StatusOK, hist)
}

// handleCaptchaPending serves the JSON list of in-flight captcha
// challenges so the admin UI's badge component can poll/render. nil
// broker → empty slice (route only registers when a broker is wired).
func (s *Server) handleCaptchaPending(w http.ResponseWriter, r *http.Request) {
	if s.opts.CaptchaBroker == nil {
		writeJSON(w, http.StatusOK, []PendingCaptcha{})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.CaptchaBroker.Pending())
}

// wgInterfaceInfo augments wgprovision.InterfaceInfo with a "managed"
// flag so the panel can render unmanaged interfaces (manual setups,
// leftovers from prior deploys) differently from panel-managed ones.
type wgInterfaceInfo struct {
	Name        string `json:"name"`
	ListenPort  int    `json:"listen_port"`
	PublicKey   string `json:"public_key"`
	NumPeers    int    `json:"num_peers"`
	Managed     bool   `json:"managed"`
	InboundTag  string `json:"inbound_tag,omitempty"`
}

func (s *Server) handleListWGInterfaces(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provisioner == nil {
		writeJSON(w, http.StatusOK, []wgInterfaceInfo{})
		return
	}
	live := wgInterfaceList(s.opts)
	writeJSON(w, http.StatusOK, live)
}

func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request) {
	statuses := s.opts.Manager.Statuses()
	writeJSON(w, http.StatusOK, statuses)
}

type createInboundReq struct {
	Tag         string `json:"tag"`
	Meeting     string `json:"meeting"`
	DisplayName string `json:"display_name"`

	// Transport selects the SFU implementation. Form values:
	//   "telemost"  → KindTelemost (default)
	//   "wb_stream" → KindLiveKitWBStream
	//   "vk-calls"  → KindVKCalls
	Transport string `json:"transport"`

	// VKCaptchaMode + VKRole are honoured only when Transport=vk-calls.
	VKCaptchaMode string `json:"vk_captcha_mode"`
	VKRole        string `json:"vk_role"`

	// AutoProvision asks the server to allocate a fresh wgN interface
	// from the provisioner pool. If false, WGEndpoint must be supplied.
	AutoProvision bool   `json:"auto_provision"`
	WGEndpoint    string `json:"wg_endpoint"`
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	req, err := decodeCreateInboundRequest(r)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Tag == "" || req.Meeting == "" {
		http.Error(w, "tag and meeting are required", http.StatusBadRequest)
		return
	}

	spec := inbound.Spec{
		ID:          newID(),
		Tag:         req.Tag,
		Meeting:     req.Meeting,
		DisplayName: req.DisplayName,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	}

	// Transport mapping. "" / "telemost" stay as the empty default
	// (== KindTelemost) for backward compatibility with pre-existing
	// inbounds; only non-default transports go on disk explicitly.
	switch req.Transport {
	case "", "telemost":
		// keep spec.Transport == ""
	case "wb_stream":
		spec.Transport = "livekit-wb-stream"
		// LiveKit credentials get filled by the webview-auth flow
		// later; the bare inbound is created in a "needs auth" state.
	case "vk-calls":
		spec.Transport = "vk-calls"
		spec.VKCalls = &inbound.VKCallsSpec{
			MeetingURL:  req.Meeting,
			Role:        coalesceStr(req.VKRole, "receiver"),
			CaptchaMode: coalesceStr(req.VKCaptchaMode, "admin-webview"),
		}
	default:
		http.Error(w, "unknown transport: "+req.Transport, http.StatusBadRequest)
		return
	}

	if req.AutoProvision {
		if s.opts.Provisioner == nil {
			http.Error(w, "auto-provisioning disabled on this server", http.StatusBadRequest)
			return
		}
		alloc, err := s.opts.Provisioner.Allocate()
		if err != nil {
			http.Error(w, "allocate: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.opts.Provisioner.CreateInterface(alloc); err != nil {
			http.Error(w, "create interface: "+err.Error(), http.StatusInternalServerError)
			return
		}
		spec.WGInterface = alloc.Iface
		spec.WGSubnet = alloc.Subnet
		spec.WGEndpoint = fmt.Sprintf("127.0.0.1:%d", alloc.Port)
		spec.ServerWGPrivateKey = alloc.Server.Private
		spec.ServerWGPublicKey = alloc.Server.Public
		spec.ClientWGPrivateKey = alloc.Client.Private
		spec.ClientWGPublicKey = alloc.Client.Public
	} else {
		if req.WGEndpoint == "" {
			http.Error(w, "wg_endpoint required when auto_provision=false", http.StatusBadRequest)
			return
		}
		spec.WGEndpoint = req.WGEndpoint
	}

	if err := s.opts.Manager.Add(r.Context(), spec); err != nil {
		http.Error(w, "add: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, spec)
}

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.opts.Manager.Remove(id); err != nil {
		http.Error(w, "remove: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if spec.WGInterface != "" && s.opts.Provisioner != nil {
		port := portFromEndpoint(spec.WGEndpoint)
		if err := s.opts.Provisioner.DestroyInterface(spec.WGInterface, spec.WGSubnet, port); err != nil {
			s.opts.Logger.Printf("admin: DestroyInterface(%s): %v", spec.WGInterface, err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleToggleInbound(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.opts.Manager.SetEnabled(context.Background(), id, !spec.Enabled); err != nil {
		http.Error(w, "toggle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClientConf(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if spec.ClientWGPrivateKey == "" {
		http.Error(w, "no client config available — inbound was not auto-provisioned", http.StatusBadRequest)
		return
	}
	conf := buildClientConf(spec, s.opts.PublicEndpointHint)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wg-%s.conf"`, spec.Tag))
	fmt.Fprint(w, conf)
}

func (s *Server) handleConnStr(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	uri, err := buildConnStr(spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, uri)
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	uri, err := buildConnStr(spec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func buildClientConf(spec inbound.Spec, publicEndpoint string) string {
	dnsLine := "DNS = 1.1.1.1, 8.8.8.8\n"
	clientIP := strings.Replace(spec.WGSubnet, ".0/24", ".2/24", 1)
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
%s
[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
PersistentKeepalive = 25
`,
		spec.ClientWGPrivateKey,
		clientIP,
		dnsLine,
		spec.ServerWGPublicKey,
		publicEndpoint,
	)
}

// buildConnStr embeds the full WG client config in the connection string
// when the inbound was auto-provisioned (so a mobile app gets everything
// it needs from one QR scan). Manually-managed inbounds — those without
// stored client keys — fall back to a meeting-only string and the
// operator distributes the .conf out-of-band.
func buildConnStr(spec inbound.Spec) (string, error) {
	p := &connstr.Params{
		Meeting: spec.Meeting,
		Tag:     spec.Tag,
	}
	if spec.ClientWGPrivateKey != "" && spec.ServerWGPublicKey != "" && spec.WGSubnet != "" {
		p.WGClientPrivate = spec.ClientWGPrivateKey
		p.WGServerPublic = spec.ServerWGPublicKey
		p.WGClientAddr = strings.Replace(spec.WGSubnet, ".0/24", ".2/24", 1)
		p.WGEndpoint = "127.0.0.1:51820"
		p.WGDNS = "1.1.1.1,8.8.8.8"
	}
	return connstr.Encode(p)
}

func portFromEndpoint(endpoint string) int {
	idx := strings.LastIndex(endpoint, ":")
	if idx < 0 {
		return 0
	}
	port := 0
	for _, c := range endpoint[idx+1:] {
		if c < '0' || c > '9' {
			return 0
		}
		port = port*10 + int(c-'0')
	}
	return port
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeCreateInboundRequest accepts JSON (legacy fetch + json-enc HTMX)
// or url-encoded form bodies (default HTMX). Form bodies use string
// values for booleans, so we coerce common truthy strings.
func decodeCreateInboundRequest(r *http.Request) (createInboundReq, error) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var req createInboundReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return createInboundReq{}, err
		}
		return req, nil
	}
	if err := r.ParseForm(); err != nil {
		return createInboundReq{}, err
	}
	return createInboundReq{
		Tag:           strings.TrimSpace(r.PostFormValue("tag")),
		Meeting:       strings.TrimSpace(r.PostFormValue("meeting")),
		DisplayName:   strings.TrimSpace(r.PostFormValue("display_name")),
		Transport:     strings.TrimSpace(r.PostFormValue("transport")),
		VKCaptchaMode: strings.TrimSpace(r.PostFormValue("vk_captcha_mode")),
		VKRole:        strings.TrimSpace(r.PostFormValue("vk_role")),
		AutoProvision: parseBool(r.PostFormValue("auto_provision")),
		WGEndpoint:    strings.TrimSpace(r.PostFormValue("wg_endpoint")),
	}, nil
}

func coalesceStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "on", "true", "yes":
		return true
	default:
		return false
	}
}
