//go:build !windows

package wgclient

import (
	"context"
	"log"
)

// runVKTurnSRTPSession is the non-Windows stub for the SRTP client
// session. Returns errSRTPClientUnsupported immediately so the
// supervisor logs a clear message rather than silently looping.
func runVKTurnSRTPSession(_ context.Context, _ *log.Logger, _ Config, _ any) error {
	return errSRTPClientUnsupported
}
