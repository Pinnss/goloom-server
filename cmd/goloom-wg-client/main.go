// goloom-wg-client connects to a Goloom inbound and exposes a local
// UDP listener for the system WireGuard userspace to dial. After the
// upstream sfu/transport refactor this binary stays transport-agnostic:
// it asks the [sfu] registry for whatever transport the connstr (or
// YAML config) specifies, hands the resulting Session to a
// [wgrelay.SFUBridge], and keeps the bridge alive across reconnects.
//
// For now connstr only carries Telemost meeting URLs, so the practical
// result is identical to the pre-refactor client. WB Stream support
// will land once we wire a long-lived credential bundle into connstr.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"

	// Side-effect imports — register transports with the sfu registry.
	_ "github.com/Pinnss/goloom-server/internal/sfu/livekit"
	telemost "github.com/Pinnss/goloom-server/internal/sfu/telemost"

	"github.com/Pinnss/goloom-server/internal/tun"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// supervise runs the tunnel in a loop, restarting on peer-rehandshake
// (server restart) immediately and on other errors with exponential
// backoff. Owns the RouteManager so SFU IP exclusions survive across
// reconnects (otherwise the new run() can't reach the SFU because WG's
// default route would have captured Telemost/LiveKit traffic).
func supervise(ctx context.Context, cfg *Config, lg *log.Logger) {
	rm := tun.NewRouteManager("", nil, 0, lg)
	if err := rm.SaveOriginalState(); err != nil {
		lg.Printf("FATAL save routes: %v", err)
		return
	}
	defer rm.Restore()

	// Pre-resolve the SFU's well-known hosts so we have *something* to
	// exclude from the tunnel before the first Connect — otherwise our
	// pion sockets get captured by our own WG default route and the
	// bootstrap stalls. Dynamic ICE hosts get added after Connect via
	// sfu.ICEHostsProvider.
	if sfu.Kind(cfg.Transport) == sfu.KindTelemost || cfg.Transport == "" {
		if ips, err := telemost.ResolveSFUIPs(cfg.Meeting); err == nil {
			lg.Printf("TELEMOST IPs to exclude (initial): %v", ips)
			_ = rm.ExcludeIPs(ips)
		} else {
			lg.Printf("WARN initial Telemost IP resolve: %v", err)
		}
	}
	// LiveKit/WB Stream IPs are dynamic per-connection (returned in the
	// connection-details response); we'll add them after Connect.

	backoff := 5 * time.Second
	for {
		err := run(ctx, cfg, lg, rm)

		if ctx.Err() != nil {
			return
		}

		retryAfter := backoff
		switch {
		case errors.Is(err, sfu.ErrPeerRehandshake), errors.Is(err, wgrelay.ErrPeerRehandshake):
			// Wait ~1s before reconnecting so the SFU finishes
			// processing the WS bye + DTLS close from the old session
			// and removes our peer slot.
			lg.Printf("peer rehandshake — reconnecting in 1s (letting SFU release old peer slot)")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		case errors.Is(err, wgrelay.ErrRxStall):
			// Watchdog detected media-track shaping. Same fast-retry
			// strategy as a peer-rehandshake.
			lg.Printf("rx stall — SFU likely shaped our tracks; reconnecting in 1s")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		case err != nil:
			lg.Printf("session ended: %v — retrying in %s", err, backoff)
		default:
			lg.Printf("session ended cleanly — retrying in %s", backoff)
		}

		fastRetry := errors.Is(err, sfu.ErrPeerRehandshake) ||
			errors.Is(err, wgrelay.ErrPeerRehandshake) ||
			errors.Is(err, wgrelay.ErrRxStall)

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryAfter):
		}
		if !fastRetry && backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	connectStr := flag.String("connect", "", "connection string (goloom://...)")
	listenAddr := flag.String("listen", "", "override UDP listen address (default 127.0.0.1:51820)")
	flag.Parse()

	lg := log.New(os.Stdout, "[goloom-wg] ", log.LstdFlags|log.Lmicroseconds)

	var cfg *Config
	var err error

	switch {
	case *connectStr != "":
		cfg, err = ConfigFromConnStr(*connectStr)
		if err != nil {
			lg.Fatalf("CONNECTION STRING: %v", err)
		}
	case *configPath != "":
		cfg, err = LoadConfig(*configPath)
		if err != nil {
			lg.Fatalf("CONFIG: %v", err)
		}
	default:
		if _, statErr := os.Stat("goloom-wg-client.yaml"); statErr == nil {
			cfg, err = LoadConfig("goloom-wg-client.yaml")
			if err != nil {
				lg.Fatalf("CONFIG: %v", err)
			}
		} else {
			lg.Fatalf("usage: goloom-wg-client -connect goloom://... [-listen 127.0.0.1:51820]")
		}
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	lg.Printf("config loaded: transport=%s meeting=%s listen=%s",
		cfg.Transport, cfg.Meeting, cfg.ListenAddr)

	if !isAdmin() {
		lg.Fatalf("goloom-wg-client must run as Administrator (route management for SFU IP exclusion)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	supervise(ctx, cfg, lg)
}

// run executes a single tunnel attempt. Returns when the session ends
// or the watchdog forces a reconnect. supervise() then decides how
// fast to retry based on the returned error.
func run(ctx context.Context, cfg *Config, lg *log.Logger, rm *tun.RouteManager) error {
	transport, err := sfu.Get(sfu.Kind(cfg.Transport))
	if err != nil {
		return err
	}

	connectSpec := buildConnectSpec(cfg, lg)
	lg.Printf("connecting via transport=%s", connectSpec.Kind)

	sess, err := transport.Connect(ctx, connectSpec)
	if err != nil {
		return err
	}
	defer sess.Close()

	// Add dynamically-discovered ICE hosts to the route-exclusion set
	// (TURN servers from serverHello / connection-details).
	if hp, ok := sess.(sfu.ICEHostsProvider); ok {
		var iceIPs []net.IP
		for _, host := range hp.ICEHosts() {
			ips, err := net.LookupIP(host)
			if err != nil {
				continue
			}
			iceIPs = append(iceIPs, ips...)
		}
		if len(iceIPs) > 0 {
			_ = rm.ExcludeIPs(iceIPs)
		}
	}

	// Bridge the Session ↔ local UDP socket the WireGuard userspace
	// dials. runCtx lets the watchdog forcibly tear down a stalled
	// session without taking down the whole supervise loop.
	bridge := wgrelay.NewClientBridge(cfg.ListenAddr, sess, lg)

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go bridge.RunRxStallWatchdog(runCtx, runCancel, lg, 30*time.Second, 2*time.Minute)

	lg.Printf("✓ goloom-wg-client ready — now activate your WireGuard tunnel")
	lg.Printf("  WG should point Endpoint at %s", cfg.ListenAddr)

	bridgeErr := bridge.Run(runCtx)

	if bridge.Stalled() {
		return wgrelay.ErrRxStall
	}
	if errors.Is(bridgeErr, sfu.ErrPeerRehandshake) {
		return bridgeErr
	}
	if bridgeErr != nil && !errors.Is(bridgeErr, wgrelay.ErrTunnelClosed) {
		return bridgeErr
	}
	return nil
}

// buildConnectSpec maps the loaded YAML/connstr Config onto an
// sfu.ConnectSpec. Empty Transport defaults to Telemost for backward
// compatibility with old connstrings/configs.
func buildConnectSpec(cfg *Config, lg *log.Logger) sfu.ConnectSpec {
	kind := sfu.Kind(cfg.Transport)
	if kind == "" {
		kind = sfu.KindTelemost
	}
	cs := sfu.ConnectSpec{
		Kind:        kind,
		DisplayName: identity.NameOrGenerate(cfg.DisplayName),
		Logger:      lg,
	}
	switch kind {
	case sfu.KindTelemost:
		cs.Telemost = &sfu.TelemostConnect{MeetingURL: cfg.Meeting}
	case sfu.KindLiveKitWBStream:
		cs.LiveKitWBStream = &sfu.LiveKitWBStreamConnect{
			RoomURL:     cfg.LiveKitRoomURL,
			AccessToken: cfg.LiveKitAccessToken,
			Cookies:     cfg.LiveKitCookies,
		}
	}
	return cs
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}
