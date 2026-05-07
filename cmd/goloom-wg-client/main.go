// goloom-wg-client connects to a Goloom inbound and exposes a local
// UDP listener for the system WireGuard userspace to dial. Thin shell
// over [github.com/Pinnss/goloom-server/pkg/wgclient] — all transport
// + supervisor logic lives there so the GUI binary can reuse it.
//
// Connstr currently carries Telemost meeting URLs only. WB Stream
// inbounds will land once the long-lived credential bundle ships in
// connstr (or via -config).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Pinnss/goloom-server/pkg/wgclient"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	connectStr := flag.String("connect", "", "connection string (goloom://...)")
	listenAddr := flag.String("listen", "", "override UDP listen address (default 127.0.0.1:51820)")
	flag.Parse()

	bootLg := log.New(os.Stdout, "[goloom-wg-boot] ", log.LstdFlags|log.Lmicroseconds)

	cfg, err := loadConfig(*connectStr, *configPath, bootLg)
	if err != nil {
		bootLg.Fatalf("CONFIG: %v", err)
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	bootLg.Printf("config loaded: transport=%s meeting=%s listen=%s",
		cfg.Transport, cfg.Meeting, cfg.ListenAddr)

	if !isAdmin() {
		bootLg.Fatalf("goloom-wg-client must run as Administrator (route management for SFU IP exclusion)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	svc := wgclient.New()

	// Tee captured log lines to stdout so the CLI experience stays
	// "what you printed is what you see". The GUI gets the same lines
	// over the event channel — no duplicate sink there.
	events, unsubscribe := svc.Subscribe()
	defer unsubscribe()
	go func() {
		for ev := range events {
			if ev.Kind == wgclient.EventLog && ev.Log != nil {
				os.Stdout.WriteString(ev.Log.Text + "\n")
			}
		}
	}()

	if err := svc.Start(ctx, cfg); err != nil {
		bootLg.Fatalf("START: %v", err)
	}
	<-ctx.Done()
	svc.Stop()
}

// loadConfig resolves the wgclient.Config from -connect, -config, or
// the implicit default goloom-wg-client.yaml in the working directory.
// Returns a usage error if none of those is satisfied.
func loadConfig(connectStr, configPath string, lg *log.Logger) (wgclient.Config, error) {
	switch {
	case connectStr != "":
		return wgclient.FromConnStr(connectStr)
	case configPath != "":
		return loadYAMLConfig(configPath)
	default:
		if _, err := os.Stat("goloom-wg-client.yaml"); err == nil {
			return loadYAMLConfig("goloom-wg-client.yaml")
		}
		return wgclient.Config{}, errUsage
	}
}
