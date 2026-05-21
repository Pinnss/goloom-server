// Public API + registry hook for the vkturn-srtp relay.
//
// Side-effect-importing this package (or non-blank-importing it from
// internal/inbound/runner.go) registers KindVKTurnSRTP into the
// internal/relay factory, mirroring how vkturn registers KindVKTurn.

package vkturnsrtp

import (
	"context"

	"github.com/Pinnss/goloom-server/internal/relay"
)

// Transport is the [relay.Relay] implementation for KindVKTurnSRTP.
// Stateless singleton — one instance lives in the registry, each call
// to Start spawns an independent [listener].
type Transport struct{}

// Kind reports the relay kind this Transport handles.
func (Transport) Kind() relay.Kind { return relay.KindVKTurnSRTP }

// Start binds the SRTP listener and returns a Handle. See
// [relay.Relay.Start] contract — ctx is only honoured during setup;
// lifecycle past return is controlled by Handle.Close.
func (Transport) Start(ctx context.Context, cfg relay.Config) (relay.Handle, error) {
	return newListener(ctx, cfg)
}

func init() {
	relay.Register(Transport{})
}
