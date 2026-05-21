//go:build !windows

// Non-Windows stub for the desktop client's route manager. The
// mobile builds (Android/iOS) and CI builds on Linux/macOS need
// internal/tun to compile, but route management is only meaningful
// on Windows desktops where we own the default route. Other
// platforms either delegate routing to the OS-level VPN service
// (VpnService on Android, NEPacketTunnelProvider on iOS) or simply
// don't ship the desktop GUI.
//
// Every method is a successful no-op so callers can keep their
// "best-effort" flow unchanged.

package tun

import (
	"log"
	"net"
)

// RouteManager is the stub mirror of the Windows-side type.
type RouteManager struct{}

// NewRouteManager returns a no-op stub on non-Windows platforms.
func NewRouteManager(_ *log.Logger) *RouteManager { return &RouteManager{} }

// SaveOriginalState is a no-op on non-Windows. Returns nil.
func (r *RouteManager) SaveOriginalState() error { return nil }

// Restore is a no-op on non-Windows.
func (r *RouteManager) Restore() {}

// ExcludeIPs is a no-op on non-Windows. Returns nil.
func (r *RouteManager) ExcludeIPs(_ []net.IP) error { return nil }

// SetDefaultRoute is a no-op on non-Windows. Returns nil. Kept
// here so cross-platform tests can call it safely even though only
// the Windows-side autoWG uses it for real.
func (r *RouteManager) SetDefaultRoute(_ net.IP, _ int) error { return nil }
