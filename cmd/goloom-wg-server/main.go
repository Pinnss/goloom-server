package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Pinnss/goloom-server/internal/inbound"

	// Side-effect imports — register relay impls into [relay.Get].
	// Without these, inbound.Spec.Transport="vk-turn" would fail at
	// resolve time. Sister directory to internal/sfu/{telemost,vkcalls,livekit}
	// pattern, which are pulled in by internal/inbound itself.
	_ "github.com/Pinnss/goloom-server/internal/relay/vkturn"
)

func main() {
	configPath := flag.String("config", "goloom-wg-server.yaml", "path to YAML config file")
	flag.Parse()

	lg := log.New(os.Stdout, "[goloom-wg-server] ", log.LstdFlags|log.Lmicroseconds)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		lg.Fatalf("CONFIG: %v", err)
	}
	lg.Printf("config loaded: %d inbound(s), admin=%s", len(cfg.Inbounds), cfg.Admin.Listen)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mgr := inbound.NewManager(lg)
	mgr.Start(ctx)
	mgr.SetOnChange(func() {
		cfg.SetInbounds(mgr.List())
		if err := cfg.Save(); err != nil {
			lg.Printf("save config: %v", err)
		}
	})

	for _, spec := range cfg.Inbounds {
		if err := mgr.Add(ctx, spec); err != nil {
			lg.Printf("add inbound %s: %v", spec.Tag, err)
		}
	}

	adminSrv, err := newAdminServer(cfg, mgr, lg)
	if err != nil {
		lg.Fatalf("admin server: %v", err)
	}

	lg.Printf("✓ goloom-wg-server ready")

	go func() {
		if err := adminSrv.Run(ctx); err != nil {
			lg.Printf("admin server: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	lg.Printf("shutting down...")
	mgr.StopAll()
}
