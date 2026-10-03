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
	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
	"github.com/Pinnss/goloom-server/pkg/wgclient"
)

// ConnectVKTurnSRTP is the mobile entry point for the vk-turn-srtp
// transport. Drives the full flow:
//
//  1. Decode a vkturnproxy:// link.
//  2. Anonymous-join VK auth ladder (reusing vkcalls.DoAuth + the
//     BrowserLauncher captcha solver from mobile/vk.go).
//  3. Open Config.VKTurnSRTP.NumConnections parallel TURN
//     allocations against the VK TURN nodes; DTLS-SRTP handshake
//     through each.
//  4. Adopt the supplied TUN file descriptor (already configured
//     with address/routes/MTU by VpnService.Builder on the Java
//     side) and start wireguard-go bound to a SRTPBind over the
//     pool of SRTP-wrapped conns.
//  5. Return a ConnectResult JSON for the UI.
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

	// Default to TCP control channel (anton48 build128+ default).
	// Per-cred VK allocation-rate throttle is ~0% on TCP vs 36-58%
	// on UDP. Honour UseUDPForTURN if the link / settings flipped it.
	useTCP := !cfg.VKTurnSRTP.UseUDPForTURN
	identities := []wgclient.TURNIdentity{{
		Creds: wgclient.TURNCreds{
			Username: authRes.TurnUser,
			Password: authRes.TurnPass,
			UseTCP:   useTCP,
		},
		Endpoints: turnEndpoints,
	}}

	// VK's quota is per credential, so one identity caps the tunnel at
	// relays x 10 allocations whatever numConnections says. Each extra identity
	// is a whole anonymous join — and a captcha the USER taps through — so they
	// are minted only while they are still needed, one at a time, and anything
	// that fails just leaves the pool smaller.
	identities = append(identities, c.mintExtraIdentities(
		parentCtx, cfg, displayName, solver, useTCP, numConns, len(turnEndpoints), authRes.TurnUser)...)

	if exp := wgclient.EarliestExpiry(identities); !exp.IsZero() {
		c.credsExpireUnix.Store(exp.Unix())
		c.logger.Printf("vk-turn-srtp: VK credentials good until %s", exp.UTC().Format(time.RFC3339))
	} else {
		c.credsExpireUnix.Store(0)
	}

	// Announced only now: minting can stop for more captchas, and a phase that
	// went turn_allocate -> vk_auth -> turn_allocate would read as the connect
	// going backwards.
	c.emitPhase("turn_allocate", fmt.Sprintf("opening %d relays across %d identity/identities",
		numConns, len(identities)))

	pool, srtpConns, poolErr := wgclient.NewSRTPPool(
		parentCtx, identities, cfg.VKTurnSRTP.PeerAddress, numConns, c.logger)
	if poolErr != nil {
		cancel()
		err := mobileErr(ErrSessionSetup, poolErr)
		c.recordErr(err)
		c.emitPhase("error", err.Error())
		return "", err
	}
	// Count real conns, not slots. The pool returns EXACTLY numConns entries with
	// nil where an allocate failed — that index alignment is what lets a redial
	// rebuild the right slot — so len() is always numConns and comparing it was
	// dead code. Worse, reporting it as the allocation count told the user
	// "10 allocs up" when three were up, which is the same lie as declaring a
	// dead tunnel ready.
	allocsUp := 0
	for _, sc := range srtpConns {
		if sc != nil {
			allocsUp++
		}
	}
	if allocsUp < numConns {
		c.logger.Printf("vk-turn-srtp: %d/%d conns up; continuing with reduced parallelism", allocsUp, numConns)
	}

	// ── adopt TUN fd + bring wireguard-go up over the SRTP pool ────
	c.emitPhase("wg_setup", "adopting TUN fd")
	if err := adoptTUNWithSRTPBind(c, tunFd, srtpConns, cfg.WG, pool); err != nil {
		cancel()
		for _, conn := range srtpConns {
			if conn != nil {
				_ = conn.Close()
			}
		}
		// Release the TURN allocations too: without this every failed adopt
		// leaked all N of them, and VK answers 486 past ten per credential.
		pool.Close()
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
		pool.Close()
	}()

	c.running.Store(true)
	c.emitPhase("ready", fmt.Sprintf("%d allocs up", allocsUp))

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
func adoptTUNWithSRTPBind(c *Client, tunFd int, srtpConns []net.Conn, wg wgclient.WGParams, pool *wgclient.SRTPPool) error {
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
	bind.SetLogger(c.logger)
	if pool != nil {
		// Let the bind's watchdog rebuild a slot instead of only retiring it.
		bind.Redial = pool.Redial
		bind.GroupHello = pool.GroupHello()
	}
	c.srtpBind.Store(bind)
	// Every failure below returns with the conns still open, because the bind —
	// not dev.Close() — owns them now. Release them on the way out unless the
	// adopt actually succeeded.
	adopted := false
	defer func() {
		if !adopted {
			_ = bind.Shutdown()
			c.srtpBind.Store(nil)
		}
	}()
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
	adopted = true
	c.logger.Printf("vk-turn-srtp: wg-userspace adopted tun '%s' fd=%d (pool=%d/%d)",
		name, tunFd, connsUp(srtpConns), len(srtpConns))
	return nil
}

// mintExtraIdentities runs the anonymous-join flow again for each identity the
// pool still needs beyond the one already in hand.
//
// Every one of these is a captcha the USER solves by hand, so this is written to
// be frugal and interruptible: it asks for the fewest identities that cover
// numConns, reuses anything still fresh from an earlier connect, stops at the
// first failure instead of marching through the rest, and never turns a failure
// into a connect error — a smaller pool is a slower tunnel, not a broken one.
func (c *Client) mintExtraIdentities(
	ctx context.Context,
	cfg wgclient.Config,
	displayName string,
	solver sfu.VKCaptchaSolver,
	useTCP bool,
	numConns, relays int,
	primaryUser string,
) []wgclient.TURNIdentity {
	// relays is what the FIRST identity was given. A later one could in principle
	// be handed a different number; that only makes this estimate slightly off,
	// because the planner lays slots out from each identity's own relay list.
	want := wgclient.IdentitiesNeeded(numConns, relays)
	if want <= 1 {
		return nil
	}

	// Track which VK users we already hold, counting the caller's own identity:
	// a repeat shares its quota and is worth nothing.
	seen := map[string]bool{}
	if user, _, ok := wgclient.TURNUserID(primaryUser); ok {
		seen[user] = true
	}

	// Cached identities must be checked against `seen` too, not merely added to
	// it. The primary identity is minted fresh on every connect and VK can hand
	// back a user we already hold, so a cached entry can collide with it. Such
	// an entry is not merely useless: planSlots would still give it a full
	// quota's worth of slots, its first allocate would be refused 486, and the
	// rest of its block would be skipped — stranding a third of the pool the
	// user paid a captcha for, with nothing in the log naming the cause.
	var usable []wgclient.TURNIdentity
	for _, id := range c.freshIdentities(useTCP) {
		user, _, ok := wgclient.TURNUserID(id.Creds.Username)
		if ok && seen[user] {
			c.logger.Printf("vk-turn-srtp: dropping a cached identity — VK re-issued the same user, " +
				"so it would share a quota instead of adding one")
			continue
		}
		if ok {
			seen[user] = true
		}
		usable = append(usable, id)
	}
	if len(usable) >= want-1 {
		c.logger.Printf("vk-turn-srtp: reusing %d cached identity/identities — no captcha needed", want-1)
		return usable[:want-1]
	}
	out := usable

	for len(out) < want-1 {
		have := len(out) + 1 // the caller's own identity counts
		c.emitPhase("vk_auth", fmt.Sprintf("identity %d of %d — solve the captcha to widen the tunnel", have+1, want))

		authCtx, authCancel := context.WithTimeout(ctx, 3*time.Minute)
		res, err := vkcalls.DoAuth(authCtx, c.logger, vkcalls.AuthSpec{
			ShortID:  parseShortIDFromVKLink(cfg.Meeting),
			Name:     displayName,
			DeviceID: uuid.NewString(),
			Solver:   solver,
		})
		authCancel()
		if err != nil {
			// Cancelled captcha, timeout, VK refusing another anonymous join —
			// all the same here: keep what we have and get the tunnel up.
			c.logger.Printf("vk-turn-srtp: identity %d/%d not obtained (%v); continuing with %d",
				have+1, want, err, have)
			break
		}
		eps := mobileFilterTurnEndpoints(res.TurnURLs)
		if len(eps) == 0 {
			c.logger.Printf("vk-turn-srtp: identity %d/%d returned no UDP relays; continuing with %d",
				have+1, want, have)
			break
		}
		// VK sometimes hands back an anonymous user we already hold. The quota
		// is keyed on the user, so such an identity adds no allocations at all —
		// and asking for another captcha would spend the user's time on nothing.
		if user, _, ok := wgclient.TURNUserID(res.TurnUser); ok {
			if seen[user] {
				c.logger.Printf("vk-turn-srtp: identity %d/%d is the same VK user as one we hold — "+
					"it shares its quota, so stopping at %d", have+1, want, have)
				break
			}
			seen[user] = true
		}
		out = append(out, wgclient.TURNIdentity{
			Creds: wgclient.TURNCreds{
				Username: res.TurnUser,
				Password: res.TurnPass,
				UseTCP:   useTCP,
			},
			Endpoints: eps,
		})
		c.logger.Printf("vk-turn-srtp: identity %d/%d ok — %d relay(s)", have+1, want, len(eps))
	}

	c.storeIdentities(out, useTCP)
	return out
}

// connsUp counts the slots that actually hold a conn; the rest are nil
// placeholders keeping slot indices aligned with the pool's.
func connsUp(conns []net.Conn) int {
	n := 0
	for _, c := range conns {
		if c != nil {
			n++
		}
	}
	return n
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

// VKTurnProxyPreview is the JSON payload PreviewVKTurnProxyLink emits.
// Kotlin / Swift parses it to populate VpnService.Builder /
// NEPacketTunnelNetworkSettings without re-implementing the JSON+base64
// link decode on the native side.
type vkTurnProxyPreview struct {
	Transport     string   `json:"transport"`      // "vk-turn-srtp" or "vk-turn"
	TunnelAddress string   `json:"tunnel_address"` // CIDR e.g. "10.66.66.3/24"
	MTU           int      `json:"mtu"`            // 0 → caller picks default (1280)
	DNS           []string `json:"dns,omitempty"`
	VKLink        string   `json:"vk_link,omitempty"`
}

// PreviewVKTurnProxyLink decodes a vkturnproxy:// connection link
// into the network parameters the native side needs to build its
// TUN device (address, MTU, DNS) — without actually opening any
// connections. Use it from Kotlin / Swift to populate the
// VpnService.Builder / NEPacketTunnelNetworkSettings before calling
// the matching Connect* method.
//
// Returns the JSON-serialised [vkTurnProxyPreview]. Errors come back
// as typed [MobileError] so the UI can classify (invalid link =
// validation; other = unknown).
func (c *Client) PreviewVKTurnProxyLink(connectionString string) (string, error) {
	cfg, err := wgclient.FromVKTurnProxyLink(connectionString)
	if err != nil {
		return "", mobileErr(ErrInvalidConnString, err)
	}
	prev := vkTurnProxyPreview{
		Transport:     cfg.Transport,
		TunnelAddress: cfg.WG.ClientAddr,
		MTU:           cfg.VKTurnSRTP.MTU,
		DNS:           cfg.WG.DNS,
		VKLink:        cfg.Meeting,
	}
	if prev.MTU == 0 {
		prev.MTU = 1280
	}
	out, _ := json.Marshal(prev)
	return string(out), nil
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
