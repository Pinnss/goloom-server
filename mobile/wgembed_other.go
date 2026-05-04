//go:build !linux

package mobile

import "errors"

// ErrEmbeddedWGUnsupported is returned by AdoptTun on platforms where
// the embedded wireguard-go userspace can't take a raw TUN fd. iOS uses
// NEPacketTunnelProvider's higher-level API and macOS/Windows desktop
// builds simply have no use for AdoptTun (they don't run inside a VPN
// service). Native code should branch on this error and fall back to
// the platform-native WG client when applicable.
var ErrEmbeddedWGUnsupported = errors.New("embedded wireguard-go: unsupported on this platform")

// AdoptTun is a no-op stub on non-Linux platforms. Returns
// ErrEmbeddedWGUnsupported so callers can detect it.
func (c *Client) AdoptTun(tunFd int, wgUserspaceConfig string) error {
	return ErrEmbeddedWGUnsupported
}

// disconnectEmbedded is a no-op stub matching the Linux signature.
func disconnectEmbedded(logger interface{ Printf(string, ...any) }) {}
