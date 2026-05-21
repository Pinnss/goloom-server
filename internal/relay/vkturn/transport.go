// Public API + registry hook for the vkturn relay.
//
// Side-effect import this package from cmd/goloom-wg-server to make
// [relay.Get](relay.KindVKTurn) resolvable at runtime:
//
//	import _ "github.com/Pinnss/goloom-server/internal/relay/vkturn"
//
// After that, the inbound runner (follow-up PR) can spin up a vkturn
// listener via the generic [relay.Relay] interface without importing
// this package directly — keeps the abstraction clean.

package vkturn

import (
	"context"

	"github.com/Pinnss/goloom-server/internal/relay"
)

// Transport is the [relay.Relay] implementation for KindVKTurn.
// Stateless singleton — one instance lives in the registry, each call
// to Start spawns an independent [listener].
type Transport struct{}

// Kind reports the relay kind this Transport handles.
func (Transport) Kind() relay.Kind { return relay.KindVKTurn }

// Start binds the listener and returns a Handle. See [relay.Relay.Start]
// contract — ctx is only honoured during setup; lifecycle past return
// is controlled by Handle.Close.
func (Transport) Start(ctx context.Context, cfg relay.Config) (relay.Handle, error) {
	return newListener(ctx, cfg)
}

func init() {
	relay.Register(Transport{})
}
