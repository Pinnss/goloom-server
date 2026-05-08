package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	"github.com/Pinnss/goloom-server/internal/admin"
	"github.com/Pinnss/goloom-server/internal/inbound"
	"github.com/Pinnss/goloom-server/internal/wgprovision"
)

type adminServer struct {
	srv *admin.Server
}

func newAdminServer(cfg *Config, mgr *inbound.Manager, lg *log.Logger) (*adminServer, error) {
	prov, err := wgprovision.NewProvisioner(
		cfg.Network.WGSubnetBase,
		cfg.Network.WGPortBase,
		cfg.Network.ExternalIface,
	)
	if err != nil {
		lg.Printf("WARN: WG provisioner unavailable (%v); admin panel will only allow manual WG endpoints", err)
		prov = nil
	}

	if prov != nil {
		for _, spec := range cfg.Inbounds {
			if spec.WGInterface != "" {
				prov.Reserve(spec.WGSubnet, spec.WGInterface, portFromEndpoint(spec.WGEndpoint))
			}
		}
	}

	if cfg.Admin.Token != "" {
		lg.Printf("WARN: admin.token is deprecated — auth теперь логин/пароль (см. admin.json). Удали поле из yaml.")
	}
	credsPath := cfg.Admin.CredentialsPath
	if credsPath == "" {
		credsPath = filepath.Join(filepath.Dir(cfg.path), "admin.json")
	}
	creds, defaultPw, err := admin.LoadOrInit(credsPath)
	if err != nil {
		return nil, fmt.Errorf("admin credentials: %w", err)
	}
	if defaultPw != "" {
		// Печатаем дефолтный пароль ОДИН раз — потом он только в bcrypt-хеше.
		// Оператор должен сменить через панель; до тех пор UI висит баннер.
		lg.Printf("ADMIN bootstrap credentials → username=admin  password=%s", defaultPw)
		lg.Printf("ADMIN credentials saved at %s — change password from the dashboard ASAP", credsPath)
	}

	// Captcha broker is shared between the admin HTTP surface (where
	// the operator's browser hits /captcha-proxy/<id>) and the
	// inbound Manager (where VK Calls inbounds delegate captcha
	// solving). Mounting both ends of the bridge here keeps cmd-level
	// wiring honest about the shared state.
	captchaBroker := admin.NewCaptchaBroker()
	mgr.SetCaptchaBroker(captchaBroker)

	srv, err := admin.New(admin.Options{
		Listen:         cfg.Admin.Listen,
		Credentials:    creds,
		TLSCert:        cfg.Admin.TLS.Cert,
		TLSKey:         cfg.Admin.TLS.Key,
		AutoSelfSigned: cfg.Admin.TLS.AutoSelfSigned,
		Manager:        mgr,
		Provisioner:    prov,
		Logger:         lg,
		CaptchaBroker:  captchaBroker,
	})
	if err != nil {
		return nil, err
	}
	return &adminServer{srv: srv}, nil
}

func (a *adminServer) Run(ctx context.Context) error {
	return a.srv.Run(ctx)
}

func portFromEndpoint(endpoint string) int {
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			port := 0
			for _, c := range endpoint[i+1:] {
				if c < '0' || c > '9' {
					return 0
				}
				port = port*10 + int(c-'0')
			}
			return port
		}
	}
	return 0
}
