package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// hiddenCmd builds an exec.Cmd whose console subprocess is created
// with CREATE_NO_WINDOW so it doesn't flash a black cmd box at the
// user. We invoke route.exe many times during a single connect
// (1 × `route print` + N × `route add` per excluded IP), so without
// this every connect would strobe the screen.
//
// Lives in routes_windows.go because syscall.SysProcAttr.HideWindow
// is Windows-only.
func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

type RouteManager struct {
	origGateway string
	origIfIndex string
	logger      *log.Logger

	mu     sync.Mutex
	routes []addedRoute
}

type addedRoute struct {
	dest    string
	mask    string
	gw      string
	ifIndex int
}

// NewRouteManager constructs an empty route manager. Call
// SaveOriginalState before any Exclude* / SetDefaultRoute call so we
// know the upstream gateway to send excluded traffic through.
//
// The TUN-side gateway and ifIndex used to route the tunnel default
// pass to SetDefaultRoute as arguments — they aren't known at
// construction time (the wintun adapter is created later).
func NewRouteManager(lg *log.Logger) *RouteManager {
	return &RouteManager{logger: lg}
}

func (rm *RouteManager) SaveOriginalState() error {
	out, err := hiddenCmd("route", "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("route print: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0.0.0.0") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "0.0.0.0" {
			rm.origGateway = fields[2]
			if len(fields) >= 5 {
				rm.origIfIndex = fields[4]
			}
			rm.logger.Printf("ROUTES original gateway=%s ifIdx=%s", rm.origGateway, rm.origIfIndex)
			return nil
		}
	}
	return fmt.Errorf("could not detect original default gateway")
}

func (rm *RouteManager) OriginalGateway() string { return rm.origGateway }

func (rm *RouteManager) ExcludeIPs(ips []net.IP) error {
	for _, ip := range ips {
		if err := rm.addRoute(ip.String(), "255.255.255.255", rm.origGateway); err != nil {
			rm.logger.Printf("ROUTES exclude %s: %v", ip, err)
		}
	}
	return nil
}

func (rm *RouteManager) ExcludeCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		mask := net.IP(ipNet.Mask).String()
		if err := rm.addRoute(ip.String(), mask, rm.origGateway); err != nil {
			rm.logger.Printf("ROUTES exclude CIDR %s: %v", cidr, err)
		}
	}
	return nil
}

// SetDefaultRoute installs a /1-pair (0.0.0.0/1 + 128.0.0.0/1) via
// the TUN's gateway. Choosing two halves of the address space rather
// than 0.0.0.0/0 lets the original default route stay in place — its
// /0 is dominated by the more-specific /1 routes for tunnel traffic,
// while excluded IPs (added by ExcludeIPs) keep going via the
// upstream gateway through their /32 routes.
func (rm *RouteManager) SetDefaultRoute(tunGateway net.IP, tunIfIndex int) error {
	gw := tunGateway.String()
	if err := rm.addRouteIF("0.0.0.0", "128.0.0.0", gw, tunIfIndex); err != nil {
		return fmt.Errorf("add 0.0.0.0/1: %w", err)
	}
	if err := rm.addRouteIF("128.0.0.0", "128.0.0.0", gw, tunIfIndex); err != nil {
		return fmt.Errorf("add 128.0.0.0/1: %w", err)
	}
	rm.logger.Printf("ROUTES default route set via TUN gateway %s IF %d", gw, tunIfIndex)
	return nil
}

func (rm *RouteManager) addRoute(dest, mask, gw string) error {
	return rm.addRouteIF(dest, mask, gw, 0)
}

func (rm *RouteManager) addRouteIF(dest, mask, gw string, ifIndex int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	args := []string{"add", dest, "mask", mask, gw, "metric", "5"}
	if ifIndex > 0 {
		args = append(args, "IF", fmt.Sprintf("%d", ifIndex))
	}
	out, err := hiddenCmd("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add %s mask %s %s: %w (%s)", dest, mask, gw, err, strings.TrimSpace(string(out)))
	}
	rm.routes = append(rm.routes, addedRoute{dest, mask, gw, ifIndex})
	if ifIndex > 0 {
		rm.logger.Printf("ROUTES + %s mask %s via %s IF %d", dest, mask, gw, ifIndex)
	} else {
		rm.logger.Printf("ROUTES + %s mask %s via %s", dest, mask, gw)
	}
	return nil
}

func (rm *RouteManager) Restore() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i := len(rm.routes) - 1; i >= 0; i-- {
		r := rm.routes[i]
		args := []string{"delete", r.dest, "mask", r.mask, r.gw}
		if r.ifIndex > 0 {
			args = append(args, "IF", fmt.Sprintf("%d", r.ifIndex))
		}
		out, err := hiddenCmd("route", args...).CombinedOutput()
		if err != nil {
			rm.logger.Printf("ROUTES restore delete %s: %v (%s)", r.dest, err, strings.TrimSpace(string(out)))
		} else {
			rm.logger.Printf("ROUTES - %s mask %s via %s", r.dest, r.mask, r.gw)
		}
	}
	rm.routes = nil
}
