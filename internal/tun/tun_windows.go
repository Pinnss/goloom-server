package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	Dev       tun.Device
	Name      string
	CIDR      string
	IP        net.IP
	IPNet     *net.IPNet
	MTU       int
	DNS       []string
	IfIndex   int
	Logger    *log.Logger
}

func CreateTUN(name string, cidr string, mtu int, dns []string, lg *log.Logger) (*Device, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}

	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("get TUN name: %w", err)
	}
	lg.Printf("TUN created: %s (mtu=%d)", realName, mtu)

	d := &Device{
		Dev:    dev,
		Name:   realName,
		CIDR:   cidr,
		IP:     ip,
		IPNet:  ipNet,
		MTU:    mtu,
		DNS:    dns,
		Logger: lg,
	}

	if err := d.configure(); err != nil {
		dev.Close()
		return nil, err
	}

	if idx, err := d.lookupIfIndex(); err != nil {
		lg.Printf("TUN WARN: ifIndex lookup: %v", err)
	} else {
		d.IfIndex = idx
		lg.Printf("TUN ifIndex=%d", idx)
	}

	return d, nil
}

func (d *Device) configure() error {
	mask := net.IP(d.IPNet.Mask).String()
	out, err := hiddenCmd("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", d.Name), "static", d.IP.String(), mask,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set address: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	d.Logger.Printf("TUN address set: %s/%s", d.IP, mask)

	for i, dns := range d.DNS {
		verb := "set"
		if i > 0 {
			verb = "add"
		}
		args := []string{"interface", "ip", verb, "dns", fmt.Sprintf("name=%s", d.Name)}
		if verb == "set" {
			args = append(args, "static", dns)
		} else {
			args = append(args, dns, fmt.Sprintf("index=%d", i+1))
		}
		out, err := hiddenCmd("netsh", args...).CombinedOutput()
		if err != nil {
			d.Logger.Printf("TUN dns %s: %v (%s)", dns, err, strings.TrimSpace(string(out)))
		}
	}
	if len(d.DNS) > 0 {
		d.Logger.Printf("TUN DNS set: %v", d.DNS)
	}

	return nil
}

func (d *Device) lookupIfIndex() (int, error) {
	iface, err := net.InterfaceByName(d.Name)
	if err != nil {
		out, err2 := hiddenCmd("netsh", "interface", "ip", "show", "config", fmt.Sprintf("name=%s", d.Name)).CombinedOutput()
		if err2 != nil {
			return 0, fmt.Errorf("net.InterfaceByName: %w; netsh fallback: %w", err, err2)
		}
		_ = out
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			if strings.EqualFold(i.Name, d.Name) {
				return i.Index, nil
			}
		}
		return 0, fmt.Errorf("interface %q not found", d.Name)
	}
	return iface.Index, nil
}

func (d *Device) Close() error {
	return d.Dev.Close()
}

func (d *Device) GatewayIP() net.IP {
	gw := make(net.IP, len(d.IP))
	copy(gw, d.IP)
	gw[len(gw)-1] = 1
	return gw
}

func (d *Device) RunPacketPump(ctx context.Context, toStack chan<- []byte, fromStack <-chan []byte) {
	go func() {
		bufs := make([][]byte, 1)
		sizes := make([]int, 1)
		bufs[0] = make([]byte, d.MTU+100)
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := d.Dev.Read(bufs, sizes, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				d.Logger.Printf("TUN read err: %v", err)
				return
			}
			if n == 0 || sizes[0] == 0 {
				continue
			}
			pkt := make([]byte, sizes[0])
			copy(pkt, bufs[0][:sizes[0]])
			select {
			case toStack <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-fromStack:
				bufs := [][]byte{pkt}
				if _, err := d.Dev.Write(bufs, 0); err != nil {
					if ctx.Err() != nil {
						return
					}
					d.Logger.Printf("TUN write err: %v", err)
				}
			}
		}
	}()
}
