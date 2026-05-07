// Package wgclient encapsulates the goloom client-side tunnel
// (Telemost / WB-Stream LiveKit → local UDP for WireGuard userspace)
// behind an event-driven [Service] API. The same package backs both
// the CLI (cmd/goloom-wg-client) and the GUI (cmd/goloom-wg-gui),
// so client behaviour stays in one place.
//
// Lifecycle:
//
//	svc := wgclient.New()
//	defer svc.Stop()
//
//	events, cancel := svc.Subscribe()
//	defer cancel()
//
//	go func() {
//	    for ev := range events {
//	        // ev.Status — phase/transport/tx/rx changes
//	        // ev.Log    — log lines emitted by the running session
//	    }
//	}()
//
//	svc.Start(ctx, cfg) // returns immediately; runs in background
//	<-ctx.Done()        // user wants to quit
//	svc.Stop()          // graceful tunnel teardown
//
// Concurrency: all public methods are safe to call from any goroutine.
// Subscribe channels are non-blocking — slow consumers drop events
// rather than back-pressure the producer.
package wgclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/connstr"
	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"

	// Side-effect imports — register transports with the sfu registry.
	_ "github.com/Pinnss/goloom-server/internal/sfu/livekit"
	telemost "github.com/Pinnss/goloom-server/internal/sfu/telemost"

	"github.com/Pinnss/goloom-server/internal/tun"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// Phase is a coarse-grained tunnel state suitable for surfacing in a UI.
type Phase string

const (
	PhaseIdle         Phase = "idle"         // never started, or after Stop()
	PhaseConnecting   Phase = "connecting"   // transport.Connect in flight
	PhaseHandshaking  Phase = "handshaking"  // peer found, in-band handshake
	PhaseRelaying     Phase = "relaying"     // bridge.Run live
	PhaseReconnecting Phase = "reconnecting" // backoff window between sessions
	PhaseError        Phase = "error"        // fatal: bad config, no transport, etc.
)

// Status snapshots the running session. Returned by [Service.Status]
// and pushed inside [Event.Status] on every change.
type Status struct {
	Phase     Phase     `json:"phase"`
	Transport string    `json:"transport"` // "telemost" | "livekit-wb-stream"
	Meeting   string    `json:"meeting,omitempty"`
	PeerID    string    `json:"peer_id,omitempty"`
	LocalAddr string    `json:"local_addr,omitempty"` // "127.0.0.1:51820"
	StartedAt time.Time `json:"started_at,omitempty"`
	LastError string    `json:"last_error,omitempty"`

	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
}

// LogLine is one line captured from the underlying session logger.
type LogLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // "info" | "warn" | "error"
	Text  string    `json:"text"`
}

// EventKind discriminates the union inside [Event].
type EventKind string

const (
	EventStatus EventKind = "status"
	EventLog    EventKind = "log"
)

// Event is the wire format pushed to subscribers. Exactly one of
// Status / Log is non-nil per event.
type Event struct {
	Kind   EventKind `json:"kind"`
	Status *Status   `json:"status,omitempty"`
	Log    *LogLine  `json:"log,omitempty"`
}

// Config is the input to [Service.Start]. Mirrors the YAML/connstr
// schema used by the standalone client. Only Meeting (for Telemost)
// or the LiveKit* fields (for WB-Stream) are required depending on
// Transport; ListenAddr defaults to 127.0.0.1:51820.
type Config struct {
	Transport          string `json:"transport"` // empty == "telemost"
	Meeting            string `json:"meeting"`
	LiveKitRoomURL     string `json:"livekit_room_url"`
	LiveKitAccessToken string `json:"livekit_access_token"`
	LiveKitCookies     string `json:"livekit_cookies"`
	DisplayName        string `json:"display_name"`
	ListenAddr         string `json:"listen_addr"` // default 127.0.0.1:51820
}

// FromConnStr decodes a goloom:// connection string into a [Config].
// Only Telemost connstrings are supported today; WB-Stream credentials
// arrive via the admin webview-auth flow, not the connstr.
func FromConnStr(s string) (Config, error) {
	p, err := connstr.Decode(s)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Transport:   "telemost",
		Meeting:     p.Meeting,
		DisplayName: p.DisplayName,
		ListenAddr:  "127.0.0.1:51820",
	}
	return cfg, nil
}

// Validate returns an error if cfg is missing fields required by its
// declared Transport.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:51820"
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr %q: %w", c.ListenAddr, err)
	}
	switch c.Transport {
	case "", "telemost":
		if c.Meeting == "" {
			return errors.New("meeting URL required for transport=telemost")
		}
	case "livekit-wb-stream":
		if c.LiveKitRoomURL == "" {
			return errors.New("livekit_room_url required")
		}
		if c.LiveKitAccessToken == "" {
			return errors.New("livekit_access_token required (operator runs admin webview-auth)")
		}
	default:
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	return nil
}

// ErrAlreadyRunning is returned by [Service.Start] when a session is
// already active. Stop the existing session first.
var ErrAlreadyRunning = errors.New("wgclient: session already running")

// ─── Service ────────────────────────────────────────────────────────

// Service manages a single tunnel session lifecycle. Construct one
// per process — concurrent sessions aren't supported (one bridge,
// one local UDP port).
type Service struct {
	mu     sync.Mutex
	cancel context.CancelFunc // non-nil while a session is running
	done   chan struct{}      // closed when the supervise goroutine exits

	statusPtr    atomic.Pointer[Status]
	activeBridge atomic.Pointer[wgrelay.SFUBridge]

	subsMu sync.Mutex
	subs   []chan Event

	logBufMu sync.Mutex
	logBuf   []LogLine
	logger   *log.Logger
}

const logBufCap = 500

// New returns a fresh Service in PhaseIdle.
func New() *Service {
	s := &Service{}
	idle := Status{Phase: PhaseIdle}
	s.statusPtr.Store(&idle)

	w := &lineWriter{onLine: s.captureLog}
	s.logger = log.New(w, "[goloom-wg] ", log.LstdFlags|log.Lmicroseconds)
	return s
}

// Status returns a snapshot of the current state, augmented with live
// byte counters from the running bridge if any.
func (s *Service) Status() Status {
	st := *s.statusPtr.Load()
	if br := s.activeBridge.Load(); br != nil {
		st.TxPackets = br.TxPackets.Load()
		st.TxBytes = br.TxBytes.Load()
		st.RxPackets = br.RxPackets.Load()
		st.RxBytes = br.RxBytes.Load()
	}
	return st
}

// Start spawns the supervise loop in the background. Returns
// immediately. Subsequent Start calls while a session is active are
// rejected with ErrAlreadyRunning.
func (s *Service) Start(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return ErrAlreadyRunning
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.mu.Unlock()

	go func() {
		defer close(s.done)
		defer func() {
			s.mu.Lock()
			s.cancel = nil
			s.mu.Unlock()
			s.setStatus(func(st *Status) { st.Phase = PhaseIdle })
		}()
		s.supervise(runCtx, cfg)
	}()
	return nil
}

// Stop signals graceful shutdown of any running session and blocks
// until the supervise loop has exited. Safe to call when idle.
func (s *Service) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	doneCh := s.done
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if doneCh != nil {
		<-doneCh
	}
}

// Subscribe returns a buffered channel of events plus a cancel func
// that detaches the subscription. Slow consumers have events dropped.
func (s *Service) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)

	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()

	cancel := func() {
		s.subsMu.Lock()
		defer s.subsMu.Unlock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, cancel
}

// RecentLogs returns the last `limit` captured log lines (newest last).
// limit ≤ 0 means "all".
func (s *Service) RecentLogs(limit int) []LogLine {
	s.logBufMu.Lock()
	defer s.logBufMu.Unlock()
	if limit <= 0 || limit > len(s.logBuf) {
		limit = len(s.logBuf)
	}
	out := make([]LogLine, limit)
	copy(out, s.logBuf[len(s.logBuf)-limit:])
	return out
}

// Logger exposes the captured *log.Logger so external code can pipe
// through the same capture pipeline (e.g. the CLI tool reusing this
// package).
func (s *Service) Logger() *log.Logger { return s.logger }

// ─── private machinery ─────────────────────────────────────────────

// supervise mirrors the legacy cmd/goloom-wg-client/main.go supervise
// loop, with status reporting hooks.
func (s *Service) supervise(ctx context.Context, cfg Config) {
	lg := s.logger
	rm := tun.NewRouteManager("", nil, 0, lg)
	if err := rm.SaveOriginalState(); err != nil {
		s.fatalf("save routes: %v", err)
		return
	}
	defer rm.Restore()

	// Pre-resolve well-known SFU IPs to exclude from default route.
	// LiveKit dynamic hosts are added inside run() once we have a session.
	if sfu.Kind(cfg.Transport) == sfu.KindTelemost || cfg.Transport == "" {
		if ips, err := telemost.ResolveSFUIPs(cfg.Meeting); err == nil {
			lg.Printf("TELEMOST IPs to exclude (initial): %v", ips)
			_ = rm.ExcludeIPs(ips)
		} else {
			lg.Printf("WARN initial Telemost IP resolve: %v", err)
		}
	}

	backoff := 5 * time.Second
	for {
		err := s.runOnce(ctx, cfg, rm)

		if ctx.Err() != nil {
			return
		}

		retryAfter := backoff
		switch {
		case errors.Is(err, sfu.ErrPeerRehandshake), errors.Is(err, wgrelay.ErrPeerRehandshake):
			lg.Printf("peer rehandshake — reconnecting in 1s (letting SFU release old peer slot)")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		case errors.Is(err, wgrelay.ErrRxStall):
			lg.Printf("rx stall — SFU likely shaped our tracks; reconnecting in 1s")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		case err != nil:
			lg.Printf("session ended: %v — retrying in %s", err, backoff)
		default:
			lg.Printf("session ended cleanly — retrying in %s", backoff)
		}

		s.setStatus(func(st *Status) {
			st.Phase = PhaseReconnecting
			if err != nil {
				st.LastError = err.Error()
			}
		})

		fastRetry := errors.Is(err, sfu.ErrPeerRehandshake) ||
			errors.Is(err, wgrelay.ErrPeerRehandshake) ||
			errors.Is(err, wgrelay.ErrRxStall)

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryAfter):
		}
		if !fastRetry && backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// runOnce wraps a single connect+bridge attempt and reports phase
// transitions to subscribers.
func (s *Service) runOnce(ctx context.Context, cfg Config, rm *tun.RouteManager) error {
	lg := s.logger

	transport, err := sfu.Get(sfu.Kind(cfg.Transport))
	if err != nil {
		return err
	}

	s.setStatus(func(st *Status) {
		st.Phase = PhaseConnecting
		st.Transport = string(transport.Kind())
		st.Meeting = cfg.Meeting
		st.LocalAddr = cfg.ListenAddr
		st.LastError = ""
		st.StartedAt = time.Now()
	})

	connectSpec := s.buildConnectSpec(cfg)
	lg.Printf("connecting via transport=%s", connectSpec.Kind)

	sess, err := transport.Connect(ctx, connectSpec)
	if err != nil {
		return err
	}
	defer sess.Close()

	// Add dynamically-discovered ICE hosts to the route-exclusion set
	// (TURN servers from serverHello / connection-details).
	if hp, ok := sess.(sfu.ICEHostsProvider); ok {
		var iceIPs []net.IP
		for _, host := range hp.ICEHosts() {
			ips, err := net.LookupIP(host)
			if err != nil {
				continue
			}
			iceIPs = append(iceIPs, ips...)
		}
		if len(iceIPs) > 0 {
			_ = rm.ExcludeIPs(iceIPs)
		}
	}

	s.setStatus(func(st *Status) { st.Phase = PhaseHandshaking })

	bridge := wgrelay.NewClientBridge(cfg.ListenAddr, sess, lg)
	s.activeBridge.Store(bridge)
	defer s.activeBridge.Store(nil)

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go bridge.RunRxStallWatchdog(runCtx, runCancel, lg, 30*time.Second, 2*time.Minute)

	s.setStatus(func(st *Status) { st.Phase = PhaseRelaying })

	lg.Printf("✓ goloom-wg ready — local UDP=%s; activate WireGuard tunnel pointing here", cfg.ListenAddr)

	bridgeErr := bridge.Run(runCtx)

	if bridge.Stalled() {
		return wgrelay.ErrRxStall
	}
	if errors.Is(bridgeErr, sfu.ErrPeerRehandshake) {
		return bridgeErr
	}
	if bridgeErr != nil && !errors.Is(bridgeErr, wgrelay.ErrTunnelClosed) {
		return bridgeErr
	}
	return nil
}

func (s *Service) buildConnectSpec(cfg Config) sfu.ConnectSpec {
	kind := sfu.Kind(cfg.Transport)
	if kind == "" {
		kind = sfu.KindTelemost
	}
	cs := sfu.ConnectSpec{
		Kind:        kind,
		DisplayName: identity.NameOrGenerate(cfg.DisplayName),
		Logger:      s.logger,
	}
	switch kind {
	case sfu.KindTelemost:
		cs.Telemost = &sfu.TelemostConnect{MeetingURL: cfg.Meeting}
	case sfu.KindLiveKitWBStream:
		cs.LiveKitWBStream = &sfu.LiveKitWBStreamConnect{
			RoomURL:     cfg.LiveKitRoomURL,
			AccessToken: cfg.LiveKitAccessToken,
			Cookies:     cfg.LiveKitCookies,
		}
	}
	return cs
}

// setStatus mutates the current status under copy-on-write semantics
// and broadcasts an EventStatus to subscribers.
func (s *Service) setStatus(mutate func(*Status)) {
	prev := *s.statusPtr.Load()
	mutate(&prev)
	s.statusPtr.Store(&prev)

	cp := prev
	s.broadcast(Event{Kind: EventStatus, Status: &cp})
}

// fatalf flips to PhaseError with the formatted message.
func (s *Service) fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	s.logger.Printf("FATAL %s", msg)
	s.setStatus(func(st *Status) {
		st.Phase = PhaseError
		st.LastError = msg
	})
}

// captureLog is fed each completed line by lineWriter. It tags level,
// pushes into the ring buffer, and broadcasts an EventLog.
func (s *Service) captureLog(text string) {
	level := classifyLogLevel(text)
	line := LogLine{Time: time.Now(), Level: level, Text: text}

	s.logBufMu.Lock()
	if len(s.logBuf) >= logBufCap {
		s.logBuf = s.logBuf[len(s.logBuf)-logBufCap+1:]
	}
	s.logBuf = append(s.logBuf, line)
	s.logBufMu.Unlock()

	cp := line
	s.broadcast(Event{Kind: EventLog, Log: &cp})
}

// broadcast non-blocks each subscriber; full channels drop the event.
func (s *Service) broadcast(ev Event) {
	s.subsMu.Lock()
	subs := make([]chan Event, len(s.subs))
	copy(subs, s.subs)
	s.subsMu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// slow consumer; drop. UI can resync with Status() / RecentLogs().
		}
	}
}

// classifyLogLevel labels a captured line by severity.
//
// "trace" is reserved for high-volume diagnostic output that's
// useful for SFU debugging but unhelpful at the operator level
// (RTCP SR per packet, slot rebind scans, raw SDP attribute lines,
// per-Nth WG-bridge packet counters). The GUI hides trace by
// default; the CLI shows everything because operators run it for
// diagnostics anyway.
//
// The detection is deliberately conservative — we only down-rank
// patterns we've explicitly seen contribute the bulk of the spam.
// New noise sources should be added here once observed.
func classifyLogLevel(text string) string {
	upper := strings.ToUpper(text)

	switch {
	case strings.Contains(upper, "FATAL"), strings.Contains(upper, "ERROR"), strings.Contains(upper, " ERR "):
		return "error"
	case strings.Contains(upper, "WARN"):
		return "warn"
	}

	if isTraceNoise(text) {
		return "trace"
	}
	return "info"
}

// isTraceNoise returns true for lines that shouldn't show up in the
// operator's log pane by default. Patterns are deliberately anchored
// on substrings unique to the high-volume diagnostic categories the
// SFU stack emits at info level by default.
//
// We don't strip the standard logger's "[goloom-wg] DATE TIME"
// prefix before matching — it's enough to look for distinctive
// fragments anywhere in the line.
func isTraceNoise(text string) bool {
	// SubscriberMaster slot scan: "slot[12] empty/other raw=..."
	if strings.Contains(text, " slot[") &&
		(strings.Contains(text, "empty/other") || strings.Contains(text, " empty/")) {
		return true
	}
	// All PUB-rtcp / SUB-rtcp forwarding chatter. Pion logs every
	// received report — SR/RR statistics, transport-cc CCFeedback,
	// REMB, NACK, PLI, FIR. All are SFU-debug useful, operator
	// noise. Examples:
	//   "PUB-rtcp[audio] *rtcp.CCFeedbackReport"
	//   "SUB-rtcp[ef09f86a] SR ssrc=4006457592 packets=42 octets=1049"
	//   "PUB-rtcp[abcd1234] *rtcp.PictureLossIndication"
	if strings.Contains(text, "PUB-rtcp[") || strings.Contains(text, "SUB-rtcp[") {
		return true
	}
	// Tunnel keepalive ping/ack pairs (every ~5s):
	//   "→ ping (uid=..., 56 bytes)"
	//   "← ack  (uid=..., 96 bytes)"
	if strings.Contains(text, "ping (uid=") || strings.Contains(text, "ack (uid=") {
		return true
	}
	// WG bridge packet counters: "WG-BRIDGE ↑ pkt #123 ..." (every 200th)
	if strings.Contains(text, "WG-BRIDGE") && strings.Contains(text, " pkt #") {
		return true
	}
	// Raw SDP / signalling dumps occasionally make it through —
	// "a=...", "v=...", "m=...". Recognise by an "=" within the
	// first 3 chars and no spaces before it (SDP is single-letter k=v).
	if len(text) > 2 && text[1] == '=' &&
		(text[0] == 'a' || text[0] == 'v' || text[0] == 'o' || text[0] == 's' ||
			text[0] == 'c' || text[0] == 't' || text[0] == 'm') {
		return true
	}
	return false
}
