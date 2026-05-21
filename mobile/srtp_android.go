//go:build linux

// vk-turn-srtp client entry point exposed to the Android (and any
// future Linux-host) side. Mirrors what
// pkg/wgclient/srtp_session_windows.go does on the desktop, but:
//
//   - the TUN comes from VpnService.Builder.establish() on the Java
//     side and is passed in as a file descriptor — no Wintun;
//   - the captcha solver is the same BrowserLauncher-backed solver
//     vk-calls already uses on mobile (see mobile/vk.go);
//   - the wireguard-go device is held in the same singleton
//     [wgEmbed] that AdoptTun uses, so Disconnect tears it down
//     uniformly regardless of which transport opened it.

package mobile

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/relay/vkturnsrtp"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
	"github.com/Pinnss/goloom-server/pkg/wgclient"
)

// ConnectVKTurnSRTP is the mobile entry point for the vk-turn-srtp
// transport. Drives the full flow:
//
//   1. Decode a vkturnproxy:// link.
//   2. Anonymous-join VK auth ladder (reusing vkcalls.DoAuth + the
//      BrowserLauncher captcha solver from mobile/vk.go).
//   3. Open Config.VKTurnSRTP.NumConnections parallel TURN
//      allocations against the VK TURN nodes; DTLS-SRTP handshake
//      through each.
//   4. Adopt the supplied TUN file descriptor (already configured
//      with address/routes/MTU by VpnService.Builder on the Java
//      side) and start wireguard-go bound to a SRTPBind over the
//      pool of SRTP-wrapped conns.
//   5. Return a ConnectResult JSON for the UI.
//
// tunFd must come from VpnService.Builder.establish().detachFd() —
// Go takes ownership and closes it on Disconnect.
//
// Errors are surfaced as typed mobileErr (see errors.go) so the
// Kotlin caller can branch on category (Captcha vs Network vs
// Auth vs internal).
func (c *Client) ConnectVKTurnSRTP(connectionString string, tunFd int) (string, error) {
	c.mu.Lock()
	if c.running.Load() {
		c.mu.Unlock()
		err := mobileErr(ErrAlreadyConnected, errors.New("already connected"))
		c.recordErr(err)
		return "", err
	}
	c.mu.Unlock()

	cfg, err := wgclient.FromVKTurnProxyLink(connectionString)
	if err != nil {
		typed := mobileErr(ErrInvalidConnString, err)
		c.recordErr(typed)
		return "", typed
	}
	if cfg.Transport != "vk-turn-srtp" {
		typed := mobileErr(ErrInvalidConnString, fmt.Errorf("link is %s, not vk-turn-srtp — use the standard Connect() for that path", cfg.Transport))
		c.recordErr(typed)
		return "", typed
	}
	if cfg.Meeting == "" || strings.Contains(cfg.Meeting, "REPLACE_ME") {
		typed := mobileErr(ErrInvalidConnString, errors.New("link has no working VK call URL — admin must fill it before sharing the link"))
		c.recordErr(typed)
		return "", typed
	}

	parentCtx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.cancel = cancel
	c.connectedTo = cfg.Meeting
	c.connStr = connectionString
	c.listenAddr = ""
	c.mu.Unlock()
	c.emitPhase("init", "vk-turn-srtp")

	// ── VK auth ────────────────────────────────────────────────────
	c.emitPhase("vk_auth", "fetching TURN credentials")
	displayName := identity.NameOrGenerate(cfg.DisplayName)
	c.mu.Lock()
	c.displayName = displayName
	c.mu.Unlock()

	solver := c.buildVKCaptchaSolver()
	if solver == nil {
		cancel()
		err := mobileErr(ErrSessionSetup, errors.New("no captcha solver — set BrowserLauncher before Connect"))
		c.recordErr(err)
		c.emitPhase("error", err.Error())
		return "", err
	}
	authCtx, authCancel := context.WithTimeout(parentCtx, 3*time.Minute)
	authRes, err := vkcalls.DoAuth(authCtx, c.logger, vkcalls.AuthSpec{
		ShortID:  parseShortIDFromVKLink(cfg.Meeting),
		Name:     displayName,
		DeviceID: uuid.NewString(),
		Solver:   solver,
	})
	authCancel()
	if err != nil {
		cancel()
		typed := classify(err)
		c.recordErr(typed)
		c.emitPhase("error", typed.Error())
		return "", typed
	}
	if len(authRes.TurnURLs) == 0 {
		cancel()
		err := mobileErr(ErrSessionSetup, errors.New("VK returned 0 TURN URLs"))
		c.recordErr(err)
		c.emitPhase("error", err.Error())
		return "", err
	}
	c.logger.Printf("vk-turn-srtp: VK auth ok — %d TURN URL(s), peer_id=%s", len(authRes.TurnURLs), authRes.PeerID)

	// ── TURN allocate + DTLS-SRTP handshake (N parallel) ───────────
	c.emitPhase("turn_allocate", fmt.Sprintf("opening %d parallel relays", maxInt(cfg.VKTurnSRTP.NumConnections, 10)))
	turnEndpoints := mobileFilterTurnEndpoints(authRes.TurnURLs)
	if len(turnEndpoints) == 0 {
		cancel()
		err := mobileErr(ErrSessionSetup, errors.New("VK returned no UDP TURN endpoints (all turns://)"))
		c.recordErr(err)
		c.emitPhase("error", err.Error())
		return "", err
	}
	numConns := cfg.VKTurnSRTP.NumConnections
	if numConns <= 0 {
		numConns = 10
	}

	creds := wgclient.TURNCreds{Username: authRes.TurnUser, Password: authRes.TurnPass}
	var (
		allocs    []*wgclient.TURNAllocation
		srtpConns []net.Conn
	)
	for i := 0; i < numConns; i++ {
		hp := turnEndpoints[i%len(turnEndpoints)]
		alloc, allocErr := wgclient.AllocateTURN(parentCtx, hp, cfg.VKTurnSRTP.PeerAddress, creds)
		if allocErr != nil {
			c.logger.Printf("vk-turn-srtp: TURN allocate %d/%d via %s failed: %v", i+1, numConns, hp, allocErr)
			continue
		}
		hsCtx, hsCancel := context.WithTimeout(parentCtx, 15*time.Second)
		conn, hsErr := vkturnsrtp.Client(hsCtx, alloc.Relay(), alloc.PeerAddr())
		hsCancel()
		if hsErr != nil {
			c.logger.Printf("vk-turn-srtp: DTLS-SRTP handshake %d/%d failed: %v", i+1, numConns, hsErr)
			alloc.Close()
			continue
		}
		allocs = append(allocs, alloc)
		srtpConns = append(srtpConns, conn)
		c.logger.Printf("vk-turn-srtp: conn %d/%d up via %s", i+1, numConns, hp)
	}
	if len(srtpConns) == 0 {
		cancel()
		for _, a := range allocs {
			a.Close()
		}
		err := mobileErr(ErrSessionSetup, errors.New("every TURN allocate / DTLS handshake failed"))
		c.recordErr(err)
		c.emitPhase("error", err.Error())
		return "", err
	}
	if len(srtpConns) < numConns {
		c.logger.Printf("vk-turn-srtp: %d/%d conns up; continuing with reduced parallelism", len(srtpConns), numConns)
	}

	// ── adopt TUN fd + bring wireguard-go up over the SRTP pool ────
	c.emitPhase("wg_setup", "adopting TUN fd")
	if err := adoptTUNWithSRTPBind(c, tunFd, srtpConns, cfg.WG); err != nil {
		cancel()
		for _, conn := range srtpConns {
			_ = conn.Close()
		}
		for _, a := range allocs {
			a.Close()
		}
		typed := mobileErr(ErrSessionSetup, fmt.Errorf("wg adopt: %w", err))
		c.recordErr(typed)
		c.emitPhase("error", typed.Error())
		return "", typed
	}

	// Keep the TURN allocations alive next to the wg device until
	// Disconnect runs. The SRTP conns are owned by the SRTPBind via
	// adoptTUNWithSRTPBind; allocs we close from a goroutine
	// triggered by the cancel() on Disconnect.
	go func() {
		<-parentCtx.Done()
		for _, a := range allocs {
			a.Close()
		}
	}()

	c.running.Store(true)
	c.emitPhase("ready", fmt.Sprintf("%d allocs up", len(srtpConns)))

	res := ConnectResult{
		DisplayName:    displayName,
		WGEndpoint:     "srtp-pool",
		WGClientAddr:   cfg.WG.ClientAddr,
		WGClientConfig: "", // not applicable — wg device already configured
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// adoptTUNWithSRTPBind takes ownership of tunFd, creates a
// wireguard-go device on it bound to a SRTPBind over srtpConns,
// applies the WG IPC config (private/peer key + optional PSK +
// allowed_ips covering the whole IPv4 space), and brings the
// device up. Stored in the package-global wgEmbed singleton so
// disconnectEmbedded (called from Disconnect) closes both wg and
// TUN uniformly.
func adoptTUNWithSRTPBind(c *Client, tunFd int, srtpConns []net.Conn, wg wgclient.WGParams) error {
	embedded.mu.Lock()
	defer embedded.mu.Unlock()

	if embedded.dev != nil {
		return errors.New("tunnel already adopted; call Disconnect first")
	}
	if tunFd < 0 {
		return errors.New("invalid tun fd")
	}

	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		return fmt.Errorf("create tun from fd: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[wg-srtp] ")
	logger.Verbosef = func(format string, args ...interface{}) {
		c.logger.Printf("[wg-srtp-verbose] "+format, args...)
	}
	logger.Errorf = func(format string, args ...interface{}) {
		c.logger.Printf("[wg-srtp-error] "+format, args...)
	}

	bind := wgclient.NewSRTPBind(srtpConns)
	dev := device.NewDevice(tunDev, bind, logger)

	privHex, err := keyB64ToHex(wg.ClientPrivateKey)
	if err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("client private key: %w", err)
	}
	pubHex, err := keyB64ToHex(wg.ServerPublicKey)
	if err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("server public key: %w", err)
	}
	pskLine := ""
	if wg.PresharedKey != "" {
		pskHex, err := keyB64ToHex(wg.PresharedKey)
		if err != nil {
			dev.Close()
			_ = tunDev.Close()
			return fmt.Errorf("preshared key: %w", err)
		}
		pskLine = "preshared_key=" + pskHex + "\n"
	}
	spec := "private_key=" + privHex + "\n" +
		"replace_peers=true\n" +
		"public_key=" + pubHex + "\n" +
		pskLine +
		"endpoint=127.0.0.1:1\n" + // ignored by SRTPBind
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/1\n" +
		"allowed_ip=128.0.0.0/1\n"
	if err := dev.IpcSet(spec); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("ipcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	embedded.dev = dev
	embedded.tunDev = tunDev
	c.logger.Printf("vk-turn-srtp: wg-userspace adopted tun '%s' fd=%d (pool=%d)", name, tunFd, len(srtpConns))
	return nil
}

// parseShortIDFromVKLink extracts the call short id from
// "https://vk.com/call/join/<id>" / "https://vk.me/join/<id>" forms.
// Returns "" if not recognised. Duplicated from
// pkg/wgclient/srtp_session_windows.go so mobile/ doesn't have to
// pull in wgclient's Windows-only files.
func parseShortIDFromVKLink(meetingURL string) string {
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

// mobileFilterTurnEndpoints drops turns:// (we don't wire up the
// TLS-over-TCP path yet) and unparseable URLs, returning only the
// usable UDP host:port pairs.
func mobileFilterTurnEndpoints(raws []string) []string {
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		if strings.HasPrefix(raw, "turns:") {
			continue
		}
		for _, prefix := range []string{"turn:", "stun:"} {
			if strings.HasPrefix(raw, prefix) {
				rest := raw[len(prefix):]
				if i := strings.IndexAny(rest, "?#"); i >= 0 {
					rest = rest[:i]
				}
				if rest != "" {
					out = append(out, rest)
				}
				break
			}
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// keyB64ToHex converts a 32-byte base64 WG key into the hex form
// expected by wireguard-go's IpcSet. Duplicated from
// pkg/wgclient/autowg_windows.go since mobile/ can't import a
// windows-tagged file.
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
