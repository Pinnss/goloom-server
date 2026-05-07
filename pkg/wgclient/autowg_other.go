// Stub implementation of auto-WG for non-Windows builds. The real
// path uses wintun + wireguard-go and is Windows-only today; if the
// stack ever ports to Linux/macOS we'll add platform-specific
// implementations alongside this file.

//go:build !windows

package wgclient

import (
	"context"
	"errors"
	"log"

	"github.com/Pinnss/goloom-server/internal/tun"
)

type autoWG struct{}

func startAutoWG(ctx context.Context, lg *log.Logger, cfg WGParams, listenAddr string, rm *tun.RouteManager, svc *Service) (*autoWG, error) {
	return nil, errors.New("auto-WG is only implemented on Windows today")
}

func (a *autoWG) Stop() {}
