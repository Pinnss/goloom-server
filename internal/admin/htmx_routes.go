package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Pinnss/goloom-server/internal/admin/ui/components"
	"github.com/Pinnss/goloom-server/internal/admin/ui/pages"
)

// registerHTMXRoutes wires the small HTML-fragment endpoints used by
// HTMX swaps and the dashboard's SSE feed.
func (s *Server) registerHTMXRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /htmx/inbounds", s.handleHTMXInboundList)
	mux.HandleFunc("GET /htmx/inbound/new", s.handleHTMXInboundForm)
	mux.HandleFunc("GET /htmx/inbound/{id}/status", s.handleHTMXInboundStatus)
	mux.HandleFunc("GET /htmx/inbound/{id}/connstr", s.handleHTMXConnStrToast)
	mux.HandleFunc("GET /htmx/wg-interfaces", s.handleHTMXWGInterfaces)
	mux.HandleFunc("GET /htmx/inbounds/stream", s.handleHTMXInboundsStream)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	username, _ := s.currentUser(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.Settings(username).Render(reqCtx(r), w)
}

func (s *Server) handleHTMXInboundList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = components.InboundCardList(s.opts.Manager.Statuses()).Render(reqCtx(r), w)
}

func (s *Server) handleHTMXInboundForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.InboundForm().Render(reqCtx(r), w)
}

func (s *Server) handleHTMXInboundStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, st := range s.opts.Manager.Statuses() {
		if st.ID == id {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = components.InboundCard(st).Render(reqCtx(r), w)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// handleHTMXConnStrToast returns a small toast HTML fragment with the
// connection string; the dashboard swaps it into #toast and the chip
// fades itself away via Alpine.
func (s *Server) handleHTMXConnStrToast(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Inline-render rather than templ so the toast stays a single self-
	// contained fragment without a dedicated *.templ file.
	//
	// Layout notes:
	// - The connstr is dropped into a hidden textarea sibling; the
	//   copy button reads it from there. Avoids the Alpine `$el` /
	//   `this` confusion of the original implementation (where `this`
	//   resolved to the Alpine component scope, not the DOM element,
	//   so the copy handler silently no-op'd).
	// - max-w-[min(560px,calc(100vw-2rem))] keeps the popover from
	//   overflowing the viewport on narrow windows / RDP sessions
	//   where bottom-4 right-4 anchoring would push it off-screen.
	// - The connstr <div> uses break-all + whitespace-pre-wrap so a
	//   long string wraps inside the card instead of growing it
	//   horizontally past the viewport edge.
	uriEsc := escapeHTML(uri)
	fmt.Fprintf(w, `<div
	  class="card text-xs w-[min(560px,calc(100vw-2rem))]"
	  x-data="{shown:true,copied:false,
	           copy(){
	             const ta=document.getElementById('toast-cs-src');
	             navigator.clipboard.writeText(ta.value).then(()=>{
	               this.copied=true;
	               setTimeout(()=>{this.shown=false},900);
	             }).catch(()=>{
	               ta.removeAttribute('readonly'); ta.select();
	               document.execCommand('copy');
	               this.copied=true;
	               setTimeout(()=>{this.shown=false},900);
	             });
	           }}"
	  x-init="setTimeout(()=>shown=false,8000)"
	  x-show="shown" x-transition.opacity
	>
	  <div class="flex items-center gap-2 mb-2">
	    <strong>connection string</strong>
	    <button class="ml-auto btn-primary text-[10px] px-2 py-0.5"
	      @click="copy()" x-text="copied ? '✓ скопировано' : '📋 Скопировать'"
	    >📋 Скопировать</button>
	  </div>
	  <textarea id="toast-cs-src" readonly
	    class="font-mono text-[11px] w-full bg-bg/60 p-2 rounded border border-border resize-none break-all"
	    style="overflow-wrap:anywhere; word-break:break-all; white-space:pre-wrap"
	    rows="4" onclick="this.select()"
	  >%s</textarea>
	</div>`, uriEsc)
}

func (s *Server) handleHTMXWGInterfaces(w http.ResponseWriter, r *http.Request) {
	rows := []components.WGRow{}
	if s.opts.Provisioner != nil {
		for _, info := range wgInterfaceList(s.opts) {
			rows = append(rows, components.WGRow{
				Name:       info.Name,
				ListenPort: info.ListenPort,
				NumPeers:   info.NumPeers,
				Managed:    info.Managed,
				InboundTag: info.InboundTag,
			})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = components.WGTable(rows).Render(reqCtx(r), w)
}

// handleHTMXInboundsStream pushes a fresh InboundCardList every second
// using SSE. Browsers stop the EventSource on tab close, so each
// request is naturally bounded by the connection lifetime.
func (s *Server) handleHTMXInboundsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering when fronted

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// First push immediately so the client has live data before the
	// initial timer fires. After that we tick every second; runner-side
	// events would let us push only on change but that's beyond the
	// scope of this branch — once-per-second is plenty for a UI.
	if err := writeInboundsEvent(w, flusher, s); err != nil {
		return
	}

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := writeInboundsEvent(w, flusher, s); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				return
			}
		}
	}
}

func writeInboundsEvent(w http.ResponseWriter, f http.Flusher, s *Server) error {
	// Render the card list to a buffer first so we can flatten newlines —
	// SSE event data must not contain bare LFs without leading "data: ".
	var buf bytes.Buffer
	if err := components.InboundCardList(s.opts.Manager.Statuses()).Render(context.Background(), &buf); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "event: inbounds\n"); err != nil {
		return err
	}
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	f.Flush()
	return nil
}

// escapeHTML is a stdlib-equivalent fast escape used for the toast
// fragment where templ would be overkill.
func escapeHTML(s string) string {
	repl := []struct{ old, new string }{
		{"&", "&amp;"},
		{"<", "&lt;"},
		{">", "&gt;"},
		{"\"", "&quot;"},
		{"'", "&#39;"},
	}
	out := s
	for _, r := range repl {
		out = replace(out, r.old, r.new)
	}
	return out
}

func replace(s, old, new string) string {
	var b []byte
	for {
		i := indexOf(s, old)
		if i < 0 {
			b = append(b, s...)
			return string(b)
		}
		b = append(b, s[:i]...)
		b = append(b, new...)
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
