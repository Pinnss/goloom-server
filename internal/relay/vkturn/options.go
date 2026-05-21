package vkturn

import "github.com/Pinnss/goloom-server/internal/relay"

// Options is the vkturn-specific knob set passed via [relay.Config.Options].
//
// Zero value (`Options{}`) is valid: DTLS+UDP, no WRAP obfuscation, no
// throughput logging — the defaults that match vk-turn-proxy's
// `vk-turn-server -listen … -connect …` invocation without flags.
type Options struct {
	// UseWrap enables the ChaCha20-XOR obfuscation layer between UDP
	// and DTLS — symmetric to client `-wrap`. When true, [WrapKey]
	// must be exactly 32 bytes; the client side must use the same key.
	UseWrap bool

	// WrapKey — 32-byte shared secret consumed when UseWrap is true.
	// Ignored otherwise.
	WrapKey []byte

	// Debug enables per-session throughput logging every 5s. Off by
	// default; turn on only when investigating throughput issues —
	// it adds one goroutine per active session.
	Debug bool
}

// IsRelayOptions tags Options as a member of [relay.Options].
func (Options) IsRelayOptions() {}

// compile-time check
var _ relay.Options = Options{}
