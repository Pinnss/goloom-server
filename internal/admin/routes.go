package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/inbound"
	vkturnpkg "github.com/Pinnss/goloom-server/internal/relay/vkturn"
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
	mux.HandleFunc("GET /api/inbounds/{id}/vkturn-link", s.handleVKTurnLink)
	mux.HandleFunc("GET /api/inbounds/{id}/vkturn-qr.png", s.handleVKTurnQR)
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

	// Transport selects the implementation. Form values:
	//   "telemost"  → sfu.KindTelemost (default)
	//   "wb_stream" → sfu.KindLiveKitWBStream
	//   "vk-calls"  → sfu.KindVKCalls
	//   "vk-turn"   → relay.KindVKTurn (separate listener-shaped family)
	Transport string `json:"transport"`

	// VKCaptchaMode + VKRole are honoured only when Transport=vk-calls.
	VKCaptchaMode string `json:"vk_captcha_mode"`
	VKRole        string `json:"vk_role"`

	// VKTurnListenAddr / VKTurnUseWrap are honoured only when
	// Transport=vk-turn. ListenAddr is the public UDP bind for the
	// DTLS relay (e.g. "0.0.0.0:56001"). UseWrap toggles the
	// ChaCha20-XOR obfuscation layer; the wrap key is auto-generated
	// server-side and surfaced in the client-link payload.
	VKTurnListenAddr string `json:"vk_turn_listen_addr"`
	VKTurnUseWrap    bool   `json:"vk_turn_use_wrap"`

	// AutoProvision asks the server to allocate a fresh wgN interface
	// from the provisioner pool. If false, WGEndpoint must be supplied.
	AutoProvision bool   `json:"auto_provision"`
	WGEndpoint    string `json:"wg_endpoint"`

	// PoolSize, when >1, enables the SFU pool architecture for Telemost
	// inbounds — N parallel room participants per logical inbound to
	// aggregate around the per-publisher bandwidth cap.
	PoolSize int `json:"pool_size"`
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request) {
	req, err := decodeCreateInboundRequest(r)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Tag == "" {
		http.Error(w, "tag is required", http.StatusBadRequest)
		return
	}
	// vk-turn-srtp doesn't need a call URL at inbound-create time —
	// the server never uses it (clients fetch their own TURN creds
	// against whatever call URL they paste/import into the iOS app).
	// We still write it into the connection-link payload as a
	// convenience, but operators can leave it blank and have the
	// link include a placeholder for the client to swap in.
	if req.Meeting == "" && req.Transport != "vk-turn-srtp" {
		http.Error(w, "meeting URL is required for this transport", http.StatusBadRequest)
		return
	}

	spec := inbound.Spec{
		ID:          newID(),
		Tag:         req.Tag,
		Meeting:     req.Meeting,
		DisplayName: req.DisplayName,
		PoolSize:    req.PoolSize,
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
	case "vk-turn":
		spec.Transport = "vk-turn"
		if req.VKTurnListenAddr == "" {
			http.Error(w, "vk_turn_listen_addr is required for vk-turn transport", http.StatusBadRequest)
			return
		}
		spec.VKTurn = &inbound.VKTurnSpec{
			ListenAddr: req.VKTurnListenAddr,
			VKLink:     req.Meeting,
			UseWrap:    req.VKTurnUseWrap,
		}
		if req.VKTurnUseWrap {
			key, err := generateWrapKey()
			if err != nil {
				http.Error(w, "wrap key gen: "+err.Error(), http.StatusInternalServerError)
				return
			}
			spec.VKTurn.WrapKeyHex = key
		}
	case "vk-turn-srtp":
		// Re-uses VKTurnSpec for ListenAddr / VKLink / PresharedKey.
		// WRAP fields stay zero — SRTP supersedes WRAP on the anton48
		// build125+ client side, you don't run both at once.
		spec.Transport = "vk-turn-srtp"
		if req.VKTurnListenAddr == "" {
			http.Error(w, "vk_turn_listen_addr is required for vk-turn-srtp transport", http.StatusBadRequest)
			return
		}
		spec.VKTurn = &inbound.VKTurnSpec{
			ListenAddr: req.VKTurnListenAddr,
			VKLink:     req.Meeting,
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

		// vk-turn / vk-turn-srtp clients (anton48/Moroka8) require a
		// non-empty PresharedKey in the wg config — generate one and
		// bake it into both the wg-quick peer section (server side)
		// and the Spec so the connection-link generator can surface it.
		if spec.Transport == "vk-turn" || spec.Transport == "vk-turn-srtp" {
			psk, err := generateWGPresharedKey()
			if err != nil {
				http.Error(w, "preshared-key gen: "+err.Error(), http.StatusInternalServerError)
				return
			}
			alloc.PresharedKey = psk
			if spec.VKTurn != nil {
				spec.VKTurn.PresharedKey = psk
			}
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
	uri, err := buildConnStr(spec, s.opts.PublicURL)
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
	uri, err := buildConnStr(spec, s.opts.PublicURL)
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

// handleVKTurnLink returns a `vkturnproxy://import?data=…` link the
// upstream anton48/Moroka8 vk-turn clients accept. Used as a stopgap
// until goloom ships its own native vk-turn client.
//
// 400 for non-vk-turn inbounds. 500 if the inbound is missing the
// auto-provisioned WG identity (operator created it without
// AutoProvision and didn't paste keys manually).
func (s *Server) handleVKTurnLink(w http.ResponseWriter, r *http.Request) {
	uri, err := s.buildVKTurnLink(r.PathValue("id"), r.URL.Query().Get("vk_link"))
	if err != nil {
		http.Error(w, err.Error(), errStatus(err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, uri)
}

// handleVKTurnQR is the QR-PNG counterpart of [handleVKTurnLink].
func (s *Server) handleVKTurnQR(w http.ResponseWriter, r *http.Request) {
	uri, err := s.buildVKTurnLink(r.PathValue("id"), r.URL.Query().Get("vk_link"))
	if err != nil {
		http.Error(w, err.Error(), errStatus(err))
		return
	}
	// vkturnproxy:// payload is ~700 chars (versioned JSON envelope
	// with WG keys + VK URL); medium ECC + 320px keeps it scannable
	// from a phone held a comfortable distance from a 1080p monitor.
	png, err := qrcode.Encode(uri, qrcode.Medium, 320)
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
//
// publicAdminURL зарезервирован для будущего (раньше был CtrlURL,
// сейчас не используется — bootstrap идёт через VK SFU lobby).
func buildConnStr(spec inbound.Spec, publicAdminURL string) (string, error) {
	_ = publicAdminURL
	p := &connstr.Params{
		Meeting:   spec.Meeting,
		Tag:       spec.Tag,
		Transport: spec.Transport, // empty stays empty (== telemost default)
		PoolSize:  spec.PoolSize,  // 0 stays 0 (== legacy single-instance)
	}
	// VK Calls ships its own MeetingURL in the per-transport sub-spec —
	// the generic Spec.Meeting may be empty when the operator typed the
	// link into the VK form. Prefer that.
	if spec.VKCalls != nil && spec.VKCalls.MeetingURL != "" {
		p.Meeting = spec.VKCalls.MeetingURL
	}
	// VK Codec пробрасываем — клиент должен совпадать.
	if spec.VKCalls != nil && spec.VKCalls.Codec != "" {
		p.Codec = spec.VKCalls.Codec
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
	poolSize, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("pool_size")))
	return createInboundReq{
		Tag:              strings.TrimSpace(r.PostFormValue("tag")),
		Meeting:          strings.TrimSpace(r.PostFormValue("meeting")),
		DisplayName:      strings.TrimSpace(r.PostFormValue("display_name")),
		Transport:        strings.TrimSpace(r.PostFormValue("transport")),
		VKCaptchaMode:    strings.TrimSpace(r.PostFormValue("vk_captcha_mode")),
		VKRole:           strings.TrimSpace(r.PostFormValue("vk_role")),
		VKTurnListenAddr: strings.TrimSpace(r.PostFormValue("vk_turn_listen_addr")),
		VKTurnUseWrap:    parseBool(r.PostFormValue("vk_turn_use_wrap")),
		AutoProvision:    parseBool(r.PostFormValue("auto_provision")),
		WGEndpoint:       strings.TrimSpace(r.PostFormValue("wg_endpoint")),
		PoolSize:         poolSize,
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

// generateWrapKey rolls a fresh 32-byte secret for the vk-turn WRAP
// layer and returns it as 64 hex chars. Same encoding the upstream
// Moroka8 client expects on its `-wrap-key` flag.
func generateWrapKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// generateWGPresharedKey rolls a fresh 32-byte WG PresharedKey and
// returns it as a 44-char standard base64 string (the encoding wg(8)
// accepts in conf files and what `wg genpsk` produces).
func generateWGPresharedKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// vkTurnLinkErr typed so [errStatus] can map common failure modes to
// useful HTTP codes (404 missing inbound, 400 wrong transport, …).
type vkTurnLinkErr struct {
	status int
	msg    string
}

func (e *vkTurnLinkErr) Error() string { return e.msg }

func errStatus(err error) int {
	if e, ok := err.(*vkTurnLinkErr); ok {
		return e.status
	}
	return http.StatusInternalServerError
}

// vkLinkPlaceholder is what gets baked into the link payload when no
// VK call URL was supplied (neither at inbound-create time nor via
// the override query param). The iOS-side anton48 BackupManager
// rejects empty strings, so we plant a clearly-recognisable sentinel
// the operator can spot in the iOS UI and replace before connecting.
const vkLinkPlaceholder = "https://vk.com/call/join/REPLACE_ME"

// buildVKTurnLink assembles the anton48 connection link for a vk-turn
// or vk-turn-srtp inbound. `vkLinkOverride` is honoured when non-empty;
// otherwise Spec.VKTurn.VKLink is used; if both are empty, the link
// payload contains the placeholder above.
func (s *Server) buildVKTurnLink(id, vkLinkOverride string) (string, error) {
	spec, ok := s.opts.Manager.Get(id)
	if !ok {
		return "", &vkTurnLinkErr{http.StatusNotFound, "inbound not found"}
	}
	if spec.Transport != "vk-turn" && spec.Transport != "vk-turn-srtp" {
		return "", &vkTurnLinkErr{http.StatusBadRequest, "inbound transport is not in the vk-turn family"}
	}
	if spec.VKTurn == nil {
		return "", &vkTurnLinkErr{http.StatusInternalServerError, "spec has no VKTurn data (corrupted state)"}
	}
	if spec.ClientWGPrivateKey == "" || spec.ServerWGPublicKey == "" {
		return "", &vkTurnLinkErr{http.StatusBadRequest, "no auto-provisioned WG identity — recreate inbound with AutoProvision=true"}
	}
	if spec.VKTurn.PresharedKey == "" {
		return "", &vkTurnLinkErr{http.StatusInternalServerError, "missing preshared key (auto-provision skipped it?)"}
	}
	vkLink := strings.TrimSpace(vkLinkOverride)
	if vkLink == "" {
		vkLink = spec.VKTurn.VKLink
	}
	if vkLink == "" {
		vkLink = vkLinkPlaceholder
	}

	publicHost, err := s.publicHostForLink()
	if err != nil {
		return "", &vkTurnLinkErr{http.StatusInternalServerError, err.Error()}
	}
	// vk-turn listener port lives in the spec; combine with the public
	// host from the global hint. ListenAddr typically has form
	// "0.0.0.0:56001" — strip the bind address, keep the port.
	port, err := portFromListenAddr(spec.VKTurn.ListenAddr)
	if err != nil {
		return "", &vkTurnLinkErr{http.StatusInternalServerError, "vk_turn.listen_addr malformed: " + err.Error()}
	}

	// Tunnel address is the client side of the auto-provisioned /24
	// (e.g. 10.66.1.2/24). We don't persist ClientIP in Spec directly,
	// so we re-derive it from WGSubnet — host index 2 by wgprovision
	// convention.
	tunnelAddr, err := clientTunnelAddrFromSubnet(spec.WGSubnet)
	if err != nil {
		return "", &vkTurnLinkErr{http.StatusInternalServerError, "spec.WGSubnet malformed: " + err.Error()}
	}

	link, err := vkturnpkg.BuildAnton48Link(vkturnpkg.LinkParams{
		ClientPrivateKey: spec.ClientWGPrivateKey,
		ServerPublicKey:  spec.ServerWGPublicKey,
		PresharedKey:     spec.VKTurn.PresharedKey,
		TunnelAddress:    tunnelAddr,
		VKLink:           vkLink,
		PeerAddress:      net.JoinHostPort(publicHost, port),
		UseWrap:          spec.VKTurn.UseWrap,
		WrapKeyHex:       spec.VKTurn.WrapKeyHex,
		UseSrtp:          spec.Transport == "vk-turn-srtp",
		DNSServers:       "8.8.8.8",
		NumConnections:   10,
	})
	if err != nil {
		return "", err
	}
	return link, nil
}

// publicHostForLink picks the externally-reachable host for vk-turn
// client links. Tries PublicEndpointHint first (best — it's the field
// operators set explicitly when running multi-homed deployments) and
// falls back to the host of PublicURL (which every operator has to
// set for the admin UI itself to work). Loopback values are rejected
// — the resulting link would be useless from a phone.
func (s *Server) publicHostForLink() (string, error) {
	if h := nonLoopbackHostFromHostPort(s.opts.PublicEndpointHint); h != "" {
		return h, nil
	}
	if h := nonLoopbackHostFromURL(s.opts.PublicURL); h != "" {
		return h, nil
	}
	return "", fmt.Errorf("can't derive a public host for the vk-turn link: PublicEndpointHint=%q PublicURL=%q (both loopback or empty — set one to the VPS's external IP)", s.opts.PublicEndpointHint, s.opts.PublicURL)
}

func nonLoopbackHostFromHostPort(hp string) string {
	if hp == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(hp)
	if err != nil {
		return ""
	}
	if isLoopbackHost(host) {
		return ""
	}
	return host
}

func nonLoopbackHostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	// Strip "scheme://" — net.SplitHostPort works on host:port pairs.
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	// rest is now "host[:port]"; SplitHostPort handles both.
	host := rest
	if strings.Contains(rest, ":") {
		h, _, err := net.SplitHostPort(rest)
		if err == nil {
			host = h
		}
	}
	if isLoopbackHost(host) {
		return ""
	}
	return host
}

func isLoopbackHost(host string) bool {
	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// portFromListenAddr returns the port part of "<host>:<port>". host
// may be 0.0.0.0 or empty — we only need the number.
func portFromListenAddr(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return port, nil
}

// clientTunnelAddrFromSubnet returns "<client-ip>/<mask>" for the WG
// subnet (e.g. "10.66.1.0/24" → "10.66.1.2/24"). wgprovision
// convention puts the client at host index 2.
func clientTunnelAddrFromSubnet(subnet string) (string, error) {
	if subnet == "" {
		return "", fmt.Errorf("Spec.WGSubnet is empty")
	}
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	_ = ip
	mask4 := ipnet.Mask
	ones, _ := mask4.Size()
	clientIP := make(net.IP, 4)
	copy(clientIP, ipnet.IP.To4())
	clientIP[3] = 2
	return fmt.Sprintf("%s/%d", clientIP.String(), ones), nil
}
