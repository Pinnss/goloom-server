// Package sfu defines an abstraction over the SFU/transport layer that
// carries WireGuard datagrams between a goloom client and server.
//
// The current ("classic") goloom architecture rides on top of Yandex
// Telemost's video tracks: VP8-faked frames carry tunnel datagrams,
// custom in-band handshake establishes peer identity. That has known
// limits — per-track ~40 Mbit/s SFU cap, no DataChannel support, fragile
// multipart packetization. See scripts/bench/RESULTS-multiplex.md for
// numbers.
//
// Some other meeting platforms expose a public LiveKit-compatible API
// (e.g. WB Stream uses LiveKit SFU under the hood with a custom auth
// gateway). LiveKit DataChannels are a first-class transport — bytes in,
// bytes out, no codec faking. RTT ~3-5x better, throughput ~3x higher
// in our measurements (RTT 26ms vs 141ms; peak 105 vs 38 Mbit/s).
//
// Rather than fork the codebase between transports, we introduce this
// abstraction. A [Transport] is a factory that creates [Session]s; a
// Session is a logical bidirectional byte stream that the wgrelay layer
// can use without caring whether it's underneath a Pion video-track loop
// or a LiveKit DataChannel.
//
// Adding a new transport is now a matter of implementing two interfaces
// and registering a factory; runner.go and the rest of the inbound stack
// see only [Session].
package sfu

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
)

// Kind names a registered transport. Used as the discriminator in
// [ConnectSpec] and persisted in inbound.Spec.Transport.
//
// Empty string ("") is treated as KindTelemost for backward
// compatibility with pre-multi-transport configs.
type Kind string

const (
	// KindTelemost — classic Yandex Telemost path: Pion+VP8 hack +
	// custom handshake protocol. Implementation in
	// [github.com/Pinnss/goloom-server/internal/sfu/telemost].
	KindTelemost Kind = "telemost"

	// KindLiveKitWBStream — Wildberries' WB Stream beta which uses a
	// LiveKit SFU behind a Cloudflare-protected gRPC-Web auth gateway.
	// Authentication is multi-step (guest-register → access token →
	// connection-details → roomToken), see
	// [github.com/Pinnss/goloom-server/internal/sfu/livekit].
	KindLiveKitWBStream Kind = "livekit-wb-stream"

	// KindVKCalls — VK Calls anonymous peer-join. We auth via the
	// public vk.com call-link flow (4-step chain ending in
	// joinConversationByLink) and join the same SFU as a regular
	// participant. WireGuard datagrams ride inside an H.264 I_PCM
	// video track (Reed-Solomon coded) — the SFU is a pure RTP
	// forwarder so byte integrity survives. See
	// [github.com/Pinnss/goloom-server/internal/sfu/vkcalls].
	//
	// Auth requires a captcha solve; the operator wires their own
	// solver implementation via VKCallsConnect.CaptchaSolver
	// (browser pop-up for CLI, webview for GUI, cached token for
	// headless server, …).
	KindVKCalls Kind = "vk-calls"
)

// ConnectSpec is what runner builds and hands to a Transport.Connect.
// It's a discriminated union — exactly one of Telemost / LiveKitWBStream /
// VKCalls fields should be non-nil based on Kind.
type ConnectSpec struct {
	Kind        Kind
	DisplayName string
	Logger      *log.Logger

	// Side identifies the pool side this session belongs to. Transports
	// that wrap WG payload through a tunnel layer (currently Telemost)
	// use this to stamp the side flag on outbound frames and drop
	// same-side frames on inbound. Allowed values: "server", "client",
	// "" (no side — single-instance legacy behaviour). See
	// [internal/sfu/sfupool] for the pool architecture rationale.
	Side string

	// Telemost is set when Kind == KindTelemost.
	Telemost *TelemostConnect

	// LiveKitWBStream is set when Kind == KindLiveKitWBStream.
	LiveKitWBStream *LiveKitWBStreamConnect

	// VKCalls is set when Kind == KindVKCalls.
	VKCalls *VKCallsConnect
}

// TelemostConnect carries the inputs for the Telemost transport.
type TelemostConnect struct {
	// MeetingURL — full Telemost share link (https://telemost.yandex.ru/j/<id>).
	MeetingURL string
}

// LiveKitWBStreamConnect carries the inputs for the WB-Stream LiveKit
// transport.
//
// Note that the AccessToken is a long-lived guest credential the operator
// captures once via webview-auth and stores in inbound.Spec; the
// short-lived (~2 min) LiveKit roomToken is minted at Connect-time using
// AccessToken+Cookies against WB's connection-details endpoint, so the
// caller does not need to deal with token rotation themselves.
type LiveKitWBStreamConnect struct {
	// RoomURL — public room link (https://stream.wb.ru/room/<id>). The
	// room id is parsed from the URL's last path segment.
	RoomURL string

	// AccessToken — guest user's long-lived JWT (from
	// localStorage.wb_auth_auth_slice.accessToken). Used as Bearer in
	// connection-details requests.
	AccessToken string

	// Cookies — request cookies needed for Cloudflare and WB-AAS
	// validation; typically `_wbafp` and `x_wbaas_token` joined with
	// "; ". Cookie expiry is the bottleneck (~14 days), at which point
	// the operator must re-auth via the admin webview.
	Cookies string
}

// VKCallsConnect carries the inputs for the VK Calls transport.
//
// Auth is short-lived (~minutes) and requires a captcha solve, so the
// caller injects their own [VKCaptchaSolver] suitable for the runtime
// environment. CLI tools open a browser pop-up; GUI clients show a
// webview; headless servers cache a pre-solved token via the admin
// webview-auth flow.
//
// Role determines which side of the call we play: "caller" creates the
// SDP offer, "receiver" answers. For the standard goloom topology the
// server pretends to be receiver (joins first, waits) and clients are
// callers (join second, drive offer). One link can only host one
// caller+receiver pair at a time.
type VKCallsConnect struct {
	// MeetingURL — full VK call share link (https://vk.com/call/join/<id>)
	// or just the bare <id> short string.
	MeetingURL string

	// Role is "caller" or "receiver". Empty defaults to "receiver"
	// (server-side default — clients should set this explicitly).
	Role string

	// CaptchaSolver, when non-nil, is invoked when VK demands a
	// captcha during anonymous-login. Nil means the connect fails
	// fast on a captcha challenge — only useful for replay tests
	// where a pre-solved token has been baked into AuthOverride.
	CaptchaSolver VKCaptchaSolver

	// Codec выбирает video transport stack:
	//   - "h264" / "" (default) — Reed-Solomon I_PCM grid в
	//     [internal/sfu/vkcalls/videocode], throughput ~600 Kbit/s в туннеле
	//     (значимый shaping VK или внутренние bottleneck'и).
	//   - "vp8" — VP8-faked frames через [internal/tunnel] + wgrelay
	//     (тот же стек что Telemost), целевая скорость ~30+ Mbit/s.
	// Эксперимент: по PoC findings VP8 видео на VK SFU шейпится менее
	// агрессивно, чем H.264.
	Codec string
}

// VKCaptchaSolver is invoked when VK's anonymous-login surface
// demands an "I'm not a robot" checkbox solve. Implementations are
// runtime-specific:
//   - CLI tools (goloom-wg-client) open a local reverse-proxy and
//     auto-launch the user's default browser
//   - GUI clients (goloom-wg-gui) show the captcha in their own
//     webview component
//   - Headless servers fetch a cached token from the admin panel
//     (replenished by an operator via the same flow)
//
// The solver is allowed to block until the user/operator finishes
// the challenge — auth honours ctx for cancellation/timeout.
type VKCaptchaSolver func(ctx context.Context, ch VKCaptchaChallenge) (VKCaptchaSolution, error)

// VKCaptchaChallenge is what VK hands us when it wants a captcha
// proven. RedirectURI is the URL to open in a browser/webview (it
// renders the I-am-not-a-robot widget); the SessionToken /
// Sid / Ts triple is needed to complete the round-trip on VK's
// captchaNotRobot.check endpoint.
type VKCaptchaChallenge struct {
	Sid          string
	Ts           float64
	Attempt      string
	RedirectURI  string
	SessionToken string

	// Refresh, if non-nil, mints a brand-new challenge (fresh
	// session_token/sid) by re-invoking VK's getAnonymousToken. A
	// composite solver MUST call this before an interactive fallback
	// when an earlier auto attempt has already spent the original
	// session: VK serves a blank captcha page for a consumed
	// session_token, so reusing it strands the user on a white screen.
	Refresh func(context.Context) (VKCaptchaChallenge, error)
}

// VKCaptchaSolution is what the solver returns once the user has
// passed the challenge. SuccessToken is what gets re-sent on the
// next anonymous-login attempt (within ~minutes — tokens expire
// fast).
//
// Sid/Ts/Attempt identify the challenge the token was actually issued
// for. A composite solver may solve a *different* (refreshed) challenge
// than the one passed in (see [VKCaptchaChallenge.Refresh]); the auth
// ladder must replay with these, not the original challenge's values.
// Zero values mean "same as the input challenge".
type VKCaptchaSolution struct {
	SuccessToken string
	Sid          string
	Ts           float64
	Attempt      string
}

// Validate returns nil if the spec is internally consistent, else a
// descriptive error. Transport implementations call this before
// expensive setup work.
func (c *ConnectSpec) Validate() error {
	if c == nil {
		return errors.New("sfu: nil ConnectSpec")
	}
	switch c.Kind {
	case KindTelemost, "":
		if c.Telemost == nil {
			return errors.New("sfu: Telemost spec required for Kind=telemost")
		}
		if c.Telemost.MeetingURL == "" {
			return errors.New("sfu: Telemost.MeetingURL is empty")
		}
	case KindLiveKitWBStream:
		lk := c.LiveKitWBStream
		if lk == nil {
			return errors.New("sfu: LiveKitWBStream spec required for Kind=livekit-wb-stream")
		}
		if lk.RoomURL == "" {
			return errors.New("sfu: LiveKitWBStream.RoomURL is empty")
		}
		if lk.AccessToken == "" {
			return errors.New("sfu: LiveKitWBStream.AccessToken is empty (operator needs to re-auth via admin webview)")
		}
	case KindVKCalls:
		vk := c.VKCalls
		if vk == nil {
			return errors.New("sfu: VKCalls spec required for Kind=vk-calls")
		}
		if vk.MeetingURL == "" {
			return errors.New("sfu: VKCalls.MeetingURL is empty")
		}
		if vk.Role != "" && vk.Role != "caller" && vk.Role != "receiver" {
			return fmt.Errorf("sfu: VKCalls.Role must be \"caller\" or \"receiver\" (got %q)", vk.Role)
		}
	default:
		return fmt.Errorf("sfu: unknown Kind %q", c.Kind)
	}
	return nil
}

// Transport is the factory for [Session]s. Implementations are expected
// to be stateless singletons (registered once per process via [Register]).
type Transport interface {
	// Kind returns the discriminator this transport handles. Used by
	// the registry.
	Kind() Kind

	// Connect builds a Session per ConnectSpec. Returns an error
	// without leaking any goroutines or sockets if setup fails. The
	// caller is responsible for calling Session.Close once done.
	//
	// The returned Session is "ready" for I/O — handshake/peer-detection
	// is complete or already in flight, and Send may be called
	// immediately. Implementations that need to wait for a peer before
	// allowing transmit should block here, surfacing failures via the
	// returned error rather than silent dead-ends.
	Connect(ctx context.Context, spec ConnectSpec) (Session, error)
}

// Session is the bidirectional byte-stream surface seen by wgrelay.
// Implementations bridge to whatever underlying transport handles the
// wire (Pion video tracks, LiveKit DataChannel, hypothetical future
// Jitsi/QUIC, …).
//
// The packet boundary is preserved — Send/Frames operate on whole
// datagrams, not a stream. This matches WireGuard's own UDP packet
// model.
type Session interface {
	// Send transmits one WG datagram. Returns immediately; actual
	// transmission may be queued/batched by the implementation.
	// Returns ErrSessionClosed if the session is no longer usable.
	Send(payload []byte) error

	// Frames yields incoming WG datagrams from the peer. Closed when
	// the session ends (either by Close or remote disconnect).
	Frames() <-chan []byte

	// Done closes when the session terminates for any reason. Call
	// Err afterwards to learn why.
	Done() <-chan struct{}

	// Err is populated once Done is closed, with nil for clean
	// teardown or the underlying error.
	Err() error

	// Close releases all resources. Idempotent and safe to call from
	// any goroutine. After Close, Send returns ErrSessionClosed and
	// Frames is closed.
	Close() error
}

// ErrSessionClosed is returned from Session.Send after the session has
// been torn down (either via Close or remote-side disconnect).
var ErrSessionClosed = errors.New("sfu: session closed")

// ErrPeerRehandshake signals the remote peer wants to renegotiate from
// scratch (i.e. server restarted, or client reconnected with fresh
// state). Callers should propagate this up through their supervise loop
// for fast retry without exponential backoff. Mirrors the existing
// wgrelay.ErrPeerRehandshake semantics so the Telemost transport can
// surface it directly.
var ErrPeerRehandshake = errors.New("sfu: peer initiated re-handshake")

// ICEHostsProvider is an optional interface a Session may implement
// when its underlying transport exposes the set of ICE/TURN/STUN hosts
// that the client should exclude from its default-route capture.
//
// Telemost transports populate this from serverHello.RtcConfiguration
// after Connect; LiveKit transports return the iceServers from the
// connection-details response. Other transports may return an empty
// slice if they don't have a meaningful list (or use a fixed
// well-known endpoint outside the tunnel anyway).
//
// Clients use this to set up VpnService/route exclusions so Pion's
// outbound sockets aren't captured by their own WG tunnel.
type ICEHostsProvider interface {
	// ICEHosts returns hostnames (no scheme/port) of all signalling
	// and TURN/STUN endpoints whose traffic must bypass the tunnel.
	// May return nil if the session hasn't completed handshake yet.
	ICEHosts() []string
}

// ─── registry ───────────────────────────────────────────────────────

var (
	registryMu sync.RWMutex
	registry   = map[Kind]Transport{}
)

// Register adds a transport factory. Called from each transport
// package's init() so the runner can discover them by Kind without
// import cycles. Panics if Kind already registered.
func Register(t Transport) {
	registryMu.Lock()
	defer registryMu.Unlock()
	k := t.Kind()
	if _, dup := registry[k]; dup {
		panic(fmt.Sprintf("sfu: duplicate registration for Kind=%q", k))
	}
	registry[k] = t
}

// Get returns the Transport registered for the given Kind, or an error
// if no implementation is loaded. Empty Kind defaults to KindTelemost.
func Get(k Kind) (Transport, error) {
	if k == "" {
		k = KindTelemost
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	t, ok := registry[k]
	if !ok {
		return nil, fmt.Errorf("sfu: no transport registered for Kind=%q (forgot to import its package?)", k)
	}
	return t, nil
}

// Kinds returns all registered transport kinds — used by admin UI to
// populate the dropdown.
func Kinds() []Kind {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Kind, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
