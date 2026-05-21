// Package relay defines the listener-shaped transport family — relays
// that accept incoming connections (DTLS, TURN, raw UDP, etc.) and
// forward decrypted payload to a local WireGuard endpoint.
//
// This is deliberately separate from [github.com/Pinnss/goloom-server/internal/sfu]:
// SFU transports are *client-shaped* — they dial out to a meeting URL,
// negotiate as a participant, and pump WG datagrams over the SFU's
// data channel. Relay transports are *server-shaped* — they bind a
// public socket and wait for incoming clients (which on their side
// run the symmetric client of the same protocol).
//
// The two are not interchangeable; trying to fit relay into sfu.Transport
// would force "Connect" to mean "Listen" and Session to mean
// "accept-loop handle", muddying both. Separate registries keep each
// abstraction honest.
//
// Adding a new relay is two interfaces: implement [Relay] and
// [Handle], then [Register] in init(). Inbound runner picks the
// right family based on the spec's Transport kind — see
// runner-integration in a follow-up PR.
package relay

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Kind names a registered relay type. Mirrors sfu.Kind but stays in
// its own namespace because relay is a separate transport family.
type Kind string

const (
	// KindVKTurn — legacy VK TURN proxy server (see
	// [github.com/Pinnss/goloom-server/internal/relay/vkturn]).
	// Binds UDP, terminates DTLS (optionally wrapped with ChaCha20-XOR
	// obfuscation), and forwards plaintext payload to a local WG endpoint.
	//
	// VK started shape-policing DTLS+WG signatures around 2026-05; per
	// allocation throughput on this path collapsed to ~7-9 KB/s. Keep
	// for back-compat, prefer KindVKTurnSRTP for new inbounds.
	KindVKTurn Kind = "vk-turn"

	// KindVKTurnSRTP — SRTP-framed VK TURN proxy server (see
	// [github.com/Pinnss/goloom-server/internal/relay/vkturnsrtp]).
	// Wraps each WG packet as an RTP record then SRTP-encrypts it so
	// the VK TURN-relay content classifier sees what looks like
	// WebRTC media. Bypasses VK's per-allocation shape policy —
	// empirical ~30-40 Mbps sustained vs ~2 Mbps on the legacy
	// DTLS+WG path (anton48/vk-turn-proxy build125 soak test, 2026-05-20).
	//
	// Wire-compatible with anton48/vk-turn-proxy add-server-srtp-layer
	// branch — same DTLS-SRTP handshake, same SRTP_AES128_CM_HMAC_SHA1_80
	// protection profile, same PayloadType=100 RTP framing.
	KindVKTurnSRTP Kind = "vk-turn-srtp"
)

// Config is per-instance start params for [Relay.Start]. Concrete
// relay impls read only the fields they care about; unused fields are
// ignored.
type Config struct {
	// ListenAddr — public UDP endpoint the relay binds to, e.g.
	// "0.0.0.0:56001". The protocol stack ON TOP of UDP (DTLS, WRAP,
	// etc.) is up to the relay implementation.
	ListenAddr string

	// ConnectAddr — local UDP target the relay forwards decrypted
	// payload to, e.g. "127.0.0.1:51831" for a kernel WG instance
	// provisioned by the inbound manager.
	ConnectAddr string

	// Options — per-relay knobs. Concrete relays type-assert this to
	// their own Options struct (e.g. vkturn.Options). nil is allowed
	// when defaults suffice.
	Options Options

	// Logger may be nil → silent operation.
	Logger *log.Logger
}

// Options is the marker interface for relay-specific knobs. Concrete
// relay packages define a struct that implements [IsRelayOptions];
// the marker exists purely to make the intent clear at the [Config]
// declaration site (rather than `any`).
//
// Go doesn't support sealed unions across packages, so we use an
// exported marker method instead of the unexported-method trick.
type Options interface {
	IsRelayOptions()
}

// Handle is what [Relay.Start] returns. The relay's listener and
// per-connection goroutines run independently; Status() lets
// supervisors poll readiness, Close() tears it down.
type Handle interface {
	// Status returns a live snapshot.
	Status() Status

	// Close stops accepting new connections, terminates active ones,
	// and waits for goroutines to drain. Safe to call from any
	// goroutine; idempotent.
	Close() error
}

// Status is the renderable snapshot a Handle exposes — feeds into
// admin panel "is this relay up" lights and per-inbound stats.
type Status struct {
	Running           bool   `json:"running"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections uint64 `json:"active_connections"`
	TotalAccepted     uint64 `json:"total_accepted"`
	LastErr           string `json:"last_err,omitempty"`
}

// Relay is the registered factory. A relay impl owns its Kind — see
// [github.com/Pinnss/goloom-server/internal/relay/vkturn].
type Relay interface {
	Kind() Kind

	// Start binds the listener and returns a Handle that is "running"
	// by the time Start returns nil. The Handle's lifetime is owned
	// by the caller — no automatic teardown on ctx-cancel; stop via
	// Close() explicitly.
	//
	// The ctx parameter is only for setup-phase cancellation (DNS
	// resolution, certificate generation). After Start returns,
	// lifecycle is decoupled from ctx.
	Start(ctx context.Context, cfg Config) (Handle, error)
}

// ─── registry ───────────────────────────────────────────────────────

var (
	registryMu sync.RWMutex
	registry   = map[Kind]Relay{}
)

// Register adds a relay factory. Called from each relay package's
// init(). Panics if Kind already registered to surface duplicate
// imports early.
func Register(r Relay) {
	registryMu.Lock()
	defer registryMu.Unlock()
	k := r.Kind()
	if _, dup := registry[k]; dup {
		panic(fmt.Sprintf("relay: duplicate registration for Kind=%q", k))
	}
	registry[k] = r
}

// Get returns the Relay registered for the given Kind, or an error
// if no implementation is loaded (typically because the side-effect
// import was missing).
func Get(k Kind) (Relay, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	r, ok := registry[k]
	if !ok {
		return nil, fmt.Errorf("relay: no relay registered for Kind=%q (forgot to side-effect-import its package?)", k)
	}
	return r, nil
}

// Kinds returns all registered relay kinds — used by admin UI to
// populate the inbound transport dropdown.
func Kinds() []Kind {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Kind, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
