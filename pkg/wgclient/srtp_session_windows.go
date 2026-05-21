//go:build windows

// Windows implementation of the vk-turn-srtp client session.
//
// Flow:
//   1. VK anonymous-auth ladder → TURN credentials + relay URLs
//      (reuses internal/sfu/vkcalls.DoAuth, the same chain the SFU
//      vk-calls transport uses; captcha solver is the same AutoProxy
//      one autoWG_windows uses for vk-calls auto-mode).
//   2. TURN ALLOCATE against the first reachable VK TURN node.
//   3. DTLS-SRTP handshake through the TURN relay to the goloom
//      server's vk-turn-srtp listener (peerAddress from the link).
//   4. Wintun TUN device + wireguard-go userspace, bound to a
//      [srtpBind] that pipes WG packets through the SRTP wrapped
//      conn instead of a real UDP socket.
//   5. Default-route the box through the new TUN, idle until ctx
//      cancellation, tear everything down.

package wgclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/device"

	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/relay/vkturnsrtp"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
	"github.com/Pinnss/goloom-server/internal/tun"
	"github.com/Pinnss/goloom-server/pkg/vkauth"
)

// runVKTurnSRTPSession runs one connect attempt. Returns when the
// session ends (ctx cancelled or any setup step fails). Caller —
// typically [Service.runOnce] — handles retry / backoff.
//
// rm is the active RouteManager from supervise(); SetDefaultRoute is
// called on it once the wg device is up. svc is optional and goes
// unused here for now (state-probe parity with autoWG can come
// later if needed).
func runVKTurnSRTPSession(ctx context.Context, lg *log.Logger, cfg Config, rmAny any) error {
	rm, _ := rmAny.(*tun.RouteManager)

	if cfg.Transport != "vk-turn-srtp" {
		return fmt.Errorf("vk-turn-srtp session called for transport=%q", cfg.Transport)
	}
	if cfg.VKTurnSRTP.PeerAddress == "" {
		return errors.New("vk-turn-srtp: missing PeerAddress")
	}
	if cfg.Meeting == "" || strings.Contains(cfg.Meeting, "REPLACE_ME") {
		return errors.New("vk-turn-srtp: missing VK call URL (paste a working vk.com/call/join/<id> into the config)")
	}
	if !cfg.WG.Valid() {
		return errors.New("vk-turn-srtp: incomplete WG identity (private key + server pubkey + tunnel address required)")
	}

	// ── 1. VK auth: get TURN credentials ───────────────────────────
	shortID := parseVKShortID(cfg.Meeting)
	if shortID == "" {
		return fmt.Errorf("vk-turn-srtp: can't parse short id out of %q", cfg.Meeting)
	}

	solver := vkauth.AutoProxyCaptchaSolver(2*time.Minute, lg, nil)
	authCtx, authCancel := context.WithTimeout(ctx, 3*time.Minute)
	authRes, err := vkcalls.DoAuth(authCtx, lg, vkcalls.AuthSpec{
		ShortID: shortID,
		// VK's getAnonymousToken requires a non-empty display name —
		// without it the request fails with "vk error 100: name is
		// undefined" at step 1. Generate a plausible Russian name
		// the same way the SFU vk-calls transport does (see
		// internal/sfu/vkcalls/transport.go).
		Name:     identity.NameOrGenerate(cfg.DisplayName),
		DeviceID: uuid.NewString(),
		Solver:   solver,
	})
	authCancel()
	if err != nil {
		return fmt.Errorf("vk-turn-srtp: VK auth: %w", err)
	}
	if len(authRes.TurnURLs) == 0 {
		return errors.New("vk-turn-srtp: VK returned 0 TURN URLs")
	}
	lg.Printf("vk-turn-srtp: VK auth ok — %d TURN URL(s), peer_id=%s", len(authRes.TurnURLs), authRes.PeerID)

	// ── 2. TURN ALLOCATE ───────────────────────────────────────────
	creds := turnCreds{Username: authRes.TurnUser, Password: authRes.TurnPass}
	var alloc *turnAllocation
	for _, raw := range authRes.TurnURLs {
		hp := parseTURNHostPort(raw)
		if hp == "" {
			lg.Printf("vk-turn-srtp: skipping malformed TURN URL %q", raw)
			continue
		}
		// Skip turns:/stuns: variants — they need TLS-over-TCP which
		// pion/turn supports differently. UDP-only "turn:host:port"
		// is what we actually want for the high-throughput path.
		if strings.HasPrefix(raw, "turns:") {
			continue
		}
		a, allocErr := allocateTURN(ctx, hp, cfg.VKTurnSRTP.PeerAddress, creds)
		if allocErr != nil {
			lg.Printf("vk-turn-srtp: TURN allocate against %s failed: %v", hp, allocErr)
			continue
		}
		alloc = a
		lg.Printf("vk-turn-srtp: TURN allocation via %s — relay=%s peer=%s", hp, a.relay.LocalAddr(), a.PeerAddr())
		break
	}
	if alloc == nil {
		return errors.New("vk-turn-srtp: every VK TURN URL failed to allocate")
	}
	defer alloc.Close()

	// ── 3. DTLS-SRTP handshake through the relay ───────────────────
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	srtpConn, err := vkturnsrtp.Client(hsCtx, alloc.Relay(), alloc.PeerAddr())
	hsCancel()
	if err != nil {
		return fmt.Errorf("vk-turn-srtp: DTLS-SRTP handshake: %w", err)
	}
	defer srtpConn.Close()
	lg.Printf("vk-turn-srtp: DTLS-SRTP handshake ok")

	// ── 4. Wintun + wireguard-go bound to the SRTP conn ─────────────
	dns := cfg.WG.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	mtu := cfg.VKTurnSRTP.MTU
	if mtu == 0 {
		mtu = 1280
	}
	tunDev, err := tun.CreateTUN(autoWGTunName, cfg.WG.ClientAddr, mtu, dns, lg)
	if err != nil {
		return fmt.Errorf("vk-turn-srtp: wintun create: %w", err)
	}
	tunOwned := true
	defer func() {
		if tunOwned && tunDev.Dev != nil {
			tunDev.Dev.Close()
		}
	}()

	bind := newSRTPBind(srtpConn)
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) { lg.Printf("WG-USERSPACE: "+format, args...) },
		Errorf:   func(format string, args ...any) { lg.Printf("WARN WG-USERSPACE: "+format, args...) },
	}
	wgDev := device.NewDevice(tunDev.Dev, bind, wgLogger)

	privHex, err := keyB64ToHex(cfg.WG.ClientPrivateKey)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("vk-turn-srtp: client private key: %w", err)
	}
	pubHex, err := keyB64ToHex(cfg.WG.ServerPublicKey)
	if err != nil {
		wgDev.Close()
		return fmt.Errorf("vk-turn-srtp: server public key: %w", err)
	}
	pskLine := ""
	if cfg.WG.PresharedKey != "" {
		pskHex, err := keyB64ToHex(cfg.WG.PresharedKey)
		if err != nil {
			wgDev.Close()
			return fmt.Errorf("vk-turn-srtp: preshared key: %w", err)
		}
		pskLine = "preshared_key=" + pskHex + "\n"
	}

	spec := "private_key=" + privHex + "\n" +
		"replace_peers=true\n" +
		"public_key=" + pubHex + "\n" +
		pskLine +
		"endpoint=127.0.0.1:1\n" + // bound to srtpEndpoint — value is ignored
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/1\n" +
		"allowed_ip=128.0.0.0/1\n"
	if err := wgDev.IpcSet(spec); err != nil {
		wgDev.Close()
		return fmt.Errorf("vk-turn-srtp: ipc-set: %w", err)
	}
	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		return fmt.Errorf("vk-turn-srtp: wg up: %w", err)
	}
	defer wgDev.Close()
	tunOwned = false // wgDev.Close() owns the TUN now

	// ── 5. Default route through the new TUN ───────────────────────
	tunGW, _, err := net.ParseCIDR(cfg.WG.ClientAddr)
	if err != nil {
		return fmt.Errorf("vk-turn-srtp: parse tun CIDR %q: %w", cfg.WG.ClientAddr, err)
	}
	if rm != nil && tunDev.IfIndex > 0 {
		if err := rm.SetDefaultRoute(tunGW, tunDev.IfIndex); err != nil {
			return fmt.Errorf("vk-turn-srtp: set default route: %w", err)
		}
	}

	lg.Printf("vk-turn-srtp ✓ tunnel up — tun=%s addr=%s peer=%s tunnel_mtu=%d",
		tunDev.Name, cfg.WG.ClientAddr, cfg.VKTurnSRTP.PeerAddress, mtu)

	// Idle until the supervisor decides to retry / shut down.
	<-ctx.Done()
	return ctx.Err()
}

// parseVKShortID extracts the call short id from
// "https://vk.com/call/join/<id>" / "https://vk.me/join/<id>" forms.
// Returns "" if not recognised. Mirrors vkcalls' internal helper but
// kept here so we don't pull more of vkcalls' surface into wgclient.
func parseVKShortID(meetingURL string) string {
	for _, marker := range []string{"/call/join/", "/join/"} {
		if i := strings.Index(meetingURL, marker); i >= 0 {
			rest := meetingURL[i+len(marker):]
			if j := strings.IndexAny(rest, "?#/"); j >= 0 {
				rest = rest[:j]
			}
			return rest
		}
	}
	return ""
}
