// Auto-WG: bring up a wintun adapter + wireguard-go userspace tunnel
// in-process so the GUI doesn't need a separate WireGuard for Windows
// install. Only used when [Config.AutoWG] is true and [Config.WG] is
// populated (the connstr's auto-provision path).
//
// The tunnel lives at the supervise() level — created before the SFU
// run loop, torn down after it returns. The WG userspace dials our
// own [wgrelay.SFUBridge] listener at cfg.ListenAddr, so packets
// flow:
//
//	app socket → wintun → wg userspace → 127.0.0.1:51820 → SFUBridge
//	          → SFU session → server WG → eth0 (VPS) → internet
//
// Routes: SaveOriginalState captures the upstream gateway, ExcludeIPs
// pins SFU IPs to it, and SetDefaultRoute(tun) installs 0/1 + 128/1
// pair via the TUN. WG handshake retries during the brief
// listener-recreation window between SFU reconnects, so this stays
// stable across rehandshakes without rebuilding the tun.

package wgclient

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/Pinnss/goloom-server/internal/tun"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	autoWGTunName = "goloom"
	autoWGMTU     = 1420
)

// autoWG owns the wintun device + wg userspace device for one
// AutoWG-enabled session. Stop is idempotent.
type autoWG struct {
	tun    *tun.Device
	dev    *device.Device
	logger *log.Logger
}

// startAutoWG brings up the tun + wg pipeline. The route manager
// must already have SaveOriginalState'd; this call adds the
// 0/1+128/1 default-route pair via the new tun before returning.
//
// On any error the partial state is rolled back so the caller
// doesn't have to remember which steps succeeded.
func startAutoWG(ctx context.Context, lg *log.Logger, cfg WGParams, listenAddr string, rm *tun.RouteManager) (*autoWG, error) {
	if !cfg.Valid() {
		return nil, errors.New("auto-WG: incomplete WGParams (need client_private_key, server_public_key, client_addr)")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = listenAddr
	}
	if endpoint == "" {
		return nil, errors.New("auto-WG: empty endpoint")
	}

	dns := cfg.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	tunDev, err := tun.CreateTUN(autoWGTunName, cfg.ClientAddr, autoWGMTU, dns, lg)
	if err != nil {
		return nil, fmt.Errorf("auto-WG: create wintun: %w", err)
	}

	// Cleanup helper for early exit. Reset to nil on success.
	cleanup := func() {
		if tunDev.Dev != nil {
			tunDev.Dev.Close()
		}
	}
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	privHex, err := keyB64ToHex(cfg.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("auto-WG: client private key: %w", err)
	}
	pubHex, err := keyB64ToHex(cfg.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("auto-WG: server public key: %w", err)
	}

	// wireguard-go has its own logger using its severity levels;
	// route through ours so trace stays filtered. LogLevelError
	// keeps the chatter down — we get only real failures.
	bind := conn.NewDefaultBind()
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {}, // suppress
		Errorf:   func(format string, args ...any) { lg.Printf("WARN auto-WG: "+format, args...) },
	}
	wgDev := device.NewDevice(tunDev.Dev, bind, wgLogger)

	spec := strings.Join([]string{
		"private_key=" + privHex,
		"replace_peers=true",
		"public_key=" + pubHex,
		"endpoint=" + endpoint,
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/1",
		"allowed_ip=128.0.0.0/1",
		"",
	}, "\n")
	if err := wgDev.IpcSet(spec); err != nil {
		wgDev.Close()
		return nil, fmt.Errorf("auto-WG: ipc-set: %w", err)
	}

	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		return nil, fmt.Errorf("auto-WG: bring up: %w", err)
	}
	cleanup = func() {
		wgDev.Close() // closes underlying tunDev as well
	}

	// Default-route pair via the TUN. Use the tunnel address as the
	// gateway hint; the route command on Windows accepts the local
	// peer address as next-hop on the tun ifIndex.
	tunGW, _, err := net.ParseCIDR(cfg.ClientAddr)
	if err != nil {
		return nil, fmt.Errorf("auto-WG: parse tun CIDR %q: %w", cfg.ClientAddr, err)
	}
	if tunDev.IfIndex <= 0 {
		return nil, fmt.Errorf("auto-WG: missing TUN ifIndex (netsh races?)")
	}
	if rm != nil {
		if err := rm.SetDefaultRoute(tunGW, tunDev.IfIndex); err != nil {
			return nil, fmt.Errorf("auto-WG: set default route: %w", err)
		}
	}

	lg.Printf("auto-WG ✓ — tun=%s addr=%s endpoint=%s peer=%s",
		tunDev.Name, cfg.ClientAddr, endpoint, abbrevKey(cfg.ServerPublicKey))

	cleanup = nil
	return &autoWG{tun: tunDev, dev: wgDev, logger: lg}, nil
}

// Stop closes the wg device (which closes the tun device too) and
// drops the in-tunnel default route. Safe to call any number of
// times; second + later calls are no-ops.
func (a *autoWG) Stop() {
	if a == nil {
		return
	}
	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
	a.tun = nil
}

// keyB64ToHex converts a 32-byte base64 WG key into the hex form
// expected by wireguard-go's IpcSet / IpcGet.
func keyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 raw bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func abbrevKey(b64 string) string {
	if len(b64) <= 12 {
		return b64
	}
	return b64[:8] + "…" + b64[len(b64)-4:]
}
