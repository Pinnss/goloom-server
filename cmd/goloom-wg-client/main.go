package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Pinnss/goloom-server/internal/identity"
	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/session"
	"github.com/Pinnss/goloom-server/internal/tun"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// supervise runs the tunnel in a loop, restarting on peer-rehandshake
// (server restart) immediately and on other errors with exponential
// backoff. Owns the RouteManager so Telemost IP exclusions survive
// across reconnects (otherwise the new run() can't reach the SFU
// because WG's default route would have captured Telemost traffic).
func supervise(ctx context.Context, cfg *Config, lg *log.Logger) {
	rm := tun.NewRouteManager("", nil, 0, lg)
	if err := rm.SaveOriginalState(); err != nil {
		lg.Printf("FATAL save routes: %v", err)
		return
	}
	defer rm.Restore()

	if telemostIPs, err := resolveTelemostIPs(cfg.Meeting); err == nil {
		lg.Printf("TELEMOST IPs to exclude (initial): %v", telemostIPs)
		_ = rm.ExcludeIPs(telemostIPs)
	} else {
		lg.Printf("WARN initial Telemost IP resolve: %v", err)
	}

	backoff := 5 * time.Second
	for {
		err := run(ctx, cfg, lg, rm)

		if ctx.Err() != nil {
			return
		}

		retryAfter := backoff
		if errors.Is(err, wgrelay.ErrPeerRehandshake) {
			// Wait ~1s before reconnecting so the SFU finishes
			// processing the WS bye + DTLS close from the old session
			// and removes our peer slot. Without this delay the new
			// session shows up alongside the old one for ICE-timeout
			// duration (~30s), creating a "zombie" participant.
			lg.Printf("peer rehandshake — reconnecting in 1s (letting SFU release old peer slot)")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		} else if errors.Is(err, wgrelay.ErrRxStall) {
			// Watchdog detected media-track shaping. Same fast-retry
			// strategy as a peer-rehandshake — old SFU session needs a
			// brief moment to wind down before we rejoin, otherwise we
			// can collide with our zombie subscription.
			lg.Printf("rx stall — Telemost SFU likely shaped our tracks; reconnecting in 1s")
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		} else if err != nil {
			lg.Printf("session ended: %v — retrying in %s", err, backoff)
		} else {
			lg.Printf("session ended cleanly — retrying in %s", backoff)
		}

		fastRetry := errors.Is(err, wgrelay.ErrPeerRehandshake) ||
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
	lg.Printf("config loaded: meeting=%s listen=%s", cfg.Meeting, cfg.ListenAddr)

	if !isAdmin() {
		lg.Fatalf("goloom-wg-client must run as Administrator (route management for Telemost IP exclusion)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	supervise(ctx, cfg, lg)
}

func run(ctx context.Context, cfg *Config, lg *log.Logger, rm *tun.RouteManager) error {
	displayName := identity.NameOrGenerate(cfg.DisplayName)
	lg.Printf("display name: %s", displayName)
	sess, err := session.SetupSession(ctx, lg, cfg.Meeting, displayName)
	if err != nil {
		return fmt.Errorf("session setup: %w", err)
	}
	defer sess.Close()

	// ICE server IPs only become known after SetupSession completes —
	// add them now (idempotent: RouteManager just logs duplicates).
	if sess.ServerHello() != nil {
		var iceIPs []net.IP
		for _, ice := range sess.ServerHello().RtcConfiguration.ICEServers {
			for _, u := range ice.URLs {
				if host := extractHost(u); host != "" {
					if ips, err := net.LookupIP(host); err == nil {
						iceIPs = append(iceIPs, ips...)
					}
				}
			}
		}
		if len(iceIPs) > 0 {
			_ = rm.ExcludeIPs(iceIPs)
		}
	}

	go session.RunOpusSilenceLoop(ctx, lg, sess.AudioTrack)
	go session.RunKeyframeRefresh(ctx, lg, sess.VideoTrack)
	if err := session.SendInitialKeyframes(lg, sess.VideoTrack, 10); err != nil {
		return fmt.Errorf("camera keyframe warmup: %w", err)
	}
	lg.Printf("WARMUP camera keyframe done")

	merged := make(chan tunnel.ReceivedFrame, 512)
	go func() {
		idx := 0
		for {
			select {
			case <-ctx.Done():
				return
			case tr, ok := <-sess.NewVideoTracks():
				if !ok {
					return
				}
				idx++
				lg.Printf("RECV spawning receiver #%d for track id=%s", idx, tr.ID())
				r := tunnel.NewReceiver(256)
				go r.Run(ctx, tr, lg)
				go func(i int, recv *tunnel.Receiver) {
					for f := range recv.Frames() {
						select {
						case merged <- f:
						case <-ctx.Done():
							return
						}
					}
				}(idx, r)
			}
		}
	}()

	lg.Printf("WAIT waiting for server peer...")
	if _, err := sess.WaitForPeer(ctx, 5*time.Minute); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	lg.Printf("WAIT peer detected, starting handshake")

	cameraSender := tunnel.NewSender(sess.VideoTrack)
	cameraSender.VP8Wrap = true
	cameraSender.VP8Prefix = mediastubs.VP8BlackKeyframe
	cameraSender.Start()
	defer cameraSender.Close()

	peerID, err := session.Handshake(ctx, lg, sess, cameraSender, merged, 1)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	lg.Printf("HANDSHAKE ✓ peer=%s", peerID)

	pushKeyframeOnPLI := session.MakeKeyframePusher(sess.VideoTrack, lg, 100*time.Millisecond)
	session.StartRTCPLoop(ctx, lg, "PUB-rtcp", sess.Pub.PC, pushKeyframeOnPLI)

	go func() {
		for i, delay := range []time.Duration{3 * time.Second, 8 * time.Second, 15 * time.Second} {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				sess.RebindSlots(ctx, 4+i)
			}
		}
	}()

	dt := wgrelay.New(cameraSender, merged, lg)
	joiner := wgrelay.NewJoiner(cfg.ListenAddr, dt, lg)

	// runCtx — derived от outer ctx, чтобы watchdog мог принудительно
	// прибить именно текущую попытку tunnel'я, не убивая весь supervise().
	// При нормальном завершении joiner.Run возвращается, defer cancel
	// гасит и watchdog, и dt.Run.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go dt.Run(runCtx)
	go wgrelay.RunRxStallWatchdogDefault(runCtx, runCancel, dt, lg)

	lg.Printf("✓ goloom-wg-client ready — now activate your WireGuard tunnel")
	lg.Printf("  WG should point Endpoint at %s", cfg.ListenAddr)

	err = joiner.Run(runCtx)

	// Watchdog мог сорваться раньше joiner.Run, тогда runCtx уже cancelled
	// и joiner вернёт ctx.Err(). Превращаем это в специфичный ErrRxStall
	// чтобы supervise() выбрал быстрый retry (а не общий exponential
	// backoff как при unknown crash).
	if dt.WasRxStalled() {
		return wgrelay.ErrRxStall
	}
	if errors.Is(err, wgrelay.ErrPeerRehandshake) {
		return err // surface up to supervise() for fast retry
	}
	if err != nil && !errors.Is(err, wgrelay.ErrTunnelClosed) {
		return fmt.Errorf("joiner: %w", err)
	}
	return nil
}


func resolveTelemostIPs(meetingURL string) ([]net.IP, error) {
	var allIPs []net.IP
	hosts := []string{
		"cloud-api.yandex.ru",
		"telemost.yandex.ru",
	}

	u, err := url.Parse(meetingURL)
	if err == nil && u.Host != "" && u.Host != "telemost.yandex.ru" {
		hosts = append(hosts, u.Host)
	}

	sfuHosts := []string{
		"goloom.strm.yandex.net",
		"strm.yandex.net",
	}
	hosts = append(hosts, sfuHosts...)

	for _, host := range hosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no IPs resolved for Telemost hosts")
	}
	return allIPs, nil
}

func extractHost(rawURL string) string {
	for _, prefix := range []string{"turn:", "turns:", "stun:", "stuns:"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			if idx := strings.Index(rest, "?"); idx >= 0 {
				rest = rest[:idx]
			}
			host, _, err := net.SplitHostPort(rest)
			if err == nil && host != "" {
				return host
			}
			return rest
		}
	}

	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host, _, _ := net.SplitHostPort(u.Host)
		if host != "" {
			return host
		}
		return u.Host
	}
	return ""
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}
