package wgprovision

import (
	"encoding/binary"
	"fmt"
	"net"
)

// SubnetAllocator hands out non-overlapping /24 subnets from a /16 (or
// larger) pool. Tracks which /24 indexes are in use so removed inbounds
// can give them back.
type SubnetAllocator struct {
	base  *net.IPNet
	used  map[int]bool
}

func NewSubnetAllocator(baseCIDR string) (*SubnetAllocator, error) {
	_, ipnet, err := net.ParseCIDR(baseCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", baseCIDR, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 24 {
		return nil, fmt.Errorf("base CIDR must be IPv4 and at least /16, got /%d", ones)
	}
	return &SubnetAllocator{base: ipnet, used: make(map[int]bool)}, nil
}

// Reserve marks the given /24 inside the pool as used. Used at startup
// when reading existing inbounds back from config.
func (a *SubnetAllocator) Reserve(cidr string) error {
	idx, err := a.indexOf(cidr)
	if err != nil {
		return err
	}
	a.used[idx] = true
	return nil
}

// Allocate returns the next free /24 inside the pool.
func (a *SubnetAllocator) Allocate() (string, error) {
	ones, _ := a.base.Mask.Size()
	maxIdx := 1 << (24 - ones)
	for i := 1; i < maxIdx; i++ {
		if !a.used[i] {
			a.used[i] = true
			return a.cidrFor(i), nil
		}
	}
	return "", fmt.Errorf("subnet pool exhausted")
}

// Release frees a previously allocated /24 so it can be re-handed.
func (a *SubnetAllocator) Release(cidr string) {
	idx, err := a.indexOf(cidr)
	if err != nil {
		return
	}
	delete(a.used, idx)
}

func (a *SubnetAllocator) indexOf(cidr string) (int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ones, _ := ipnet.Mask.Size()
	if ones != 24 {
		return 0, fmt.Errorf("expected /24, got /%d", ones)
	}
	baseInt := binary.BigEndian.Uint32(a.base.IP.To4())
	cidrInt := binary.BigEndian.Uint32(ipnet.IP.To4())
	if cidrInt < baseInt {
		return 0, fmt.Errorf("subnet %s outside pool %s", cidr, a.base)
	}
	idx := int((cidrInt - baseInt) >> 8)
	return idx, nil
}

func (a *SubnetAllocator) cidrFor(idx int) string {
	baseInt := binary.BigEndian.Uint32(a.base.IP.To4())
	subnetInt := baseInt + uint32(idx<<8)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, subnetInt)
	return fmt.Sprintf("%s/24", ip)
}

// PortAllocator hands out unique UDP ports for WG endpoints.
type PortAllocator struct {
	base int
	used map[int]bool
}

func NewPortAllocator(base int) *PortAllocator {
	return &PortAllocator{base: base, used: make(map[int]bool)}
}

func (p *PortAllocator) Reserve(port int) {
	p.used[port] = true
}

func (p *PortAllocator) Allocate() (int, error) {
	for i := 0; i < 1000; i++ {
		port := p.base + i
		if !p.used[port] {
			p.used[port] = true
			return port, nil
		}
	}
	return 0, fmt.Errorf("port pool exhausted")
}

func (p *PortAllocator) Release(port int) { delete(p.used, port) }

// IfaceFor returns the conventional wgN interface name for a given index.
func IfaceFor(idx int) string { return fmt.Sprintf("wg%d", idx) }
