// Session orchestrator for the vk-turn-srtp client path. The
// platform-specific implementations live next door:
//
//   srtp_session_windows.go — full implementation (wintun + wireguard-go
//                             userspace + SRTP bind)
//   srtp_session_other.go   — stub returning unsupported error
//
// Windows-first because Wintun is the only userspace WG TUN driver
// goloom currently ships with; macOS / Linux desktop support is a
// follow-up once those platforms have an analogous TUN backend.

package wgclient

import (
	"errors"
	"strings"
)

// errSRTPClientUnsupported is returned by [runVKTurnSRTPSession] on
// platforms that don't have a working TUN backend integrated yet.
var errSRTPClientUnsupported = errors.New("vk-turn-srtp client: not supported on this OS yet (Windows-only at the moment — wintun required)")

// parseTURNHostPort extracts the host:port from a stun: / turn: /
// turns: URI of the shape pion/turn.NewClient expects. Mirrors the
// internal/sfu/vkcalls.extractURLHost helper but keeps the port.
// Returns "" if the URI couldn't be parsed.
func parseTURNHostPort(raw string) string {
	for _, prefix := range []string{"turns:", "turn:", "stun:"} {
		if strings.HasPrefix(raw, prefix) {
			rest := raw[len(prefix):]
			if i := strings.IndexAny(rest, "?#"); i >= 0 {
				rest = rest[:i]
			}
			return rest
		}
	}
	return ""
}
