package vkturnsrtp

import "github.com/Pinnss/goloom-server/internal/relay"

// Options is the vkturn-srtp-specific knob set passed via
// [relay.Config.Options]. Currently empty — SRTP listener has no
// per-inbound configuration beyond what's already in [relay.Config]
// (ListenAddr, ConnectAddr).
//
// Reserved as a struct (rather than no-Options-at-all) so future
// SRTP-specific tunables can be added without breaking the Config
// shape for existing inbounds.
type Options struct{}

// IsRelayOptions tags Options as a member of [relay.Options].
func (Options) IsRelayOptions() {}

// compile-time check
var _ relay.Options = Options{}
