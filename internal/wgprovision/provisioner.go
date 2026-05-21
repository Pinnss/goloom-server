package wgprovision

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Provisioner is the high-level API the admin panel uses.
//
// CreateInbound:
//   1. allocates a /24 + UDP port + wgN name
//   2. generates server+client keypairs
//   3. writes /etc/wireguard/wgN.conf
//   4. systemctl start wg-quick@wgN
//
// DeleteInbound undoes all of that.
//
// All file/system operations are gated behind a sync.Mutex because
// multiple admin requests can race.
type Provisioner struct {
	subnets       *SubnetAllocator
	ports         *PortAllocator
	usedIfaces    map[int]bool
	externalIface string
	configDir     string

	mu sync.Mutex
}

func NewProvisioner(subnetBase string, portBase int, externalIface string) (*Provisioner, error) {
	sa, err := NewSubnetAllocator(subnetBase)
	if err != nil {
		return nil, err
	}
	if externalIface == "" {
		externalIface, _ = detectDefaultIface()
	}
	p := &Provisioner{
		subnets:       sa,
		ports:         NewPortAllocator(portBase),
		usedIfaces:    make(map[int]bool),
		externalIface: externalIface,
		configDir:     "/etc/wireguard",
	}

	// Reserve any wgN interfaces that already exist on the system, so we
	// don't clobber an out-of-band manual setup (or our own from a
	// previous deploy that wasn't tracked in config).
	for _, idx := range existingWGIfaces() {
		p.usedIfaces[idx] = true
	}
	for _, port := range existingWGPorts() {
		p.ports.Reserve(port)
	}

	return p, nil
}

// ExternalIface returns the egress interface name MASQUERADE rules use.
func (p *Provisioner) ExternalIface() string { return p.externalIface }

// Reserve marks an existing inbound's resources as in-use. Called at
// startup once for each inbound loaded from disk.
func (p *Provisioner) Reserve(subnet, iface string, port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if subnet != "" {
		_ = p.subnets.Reserve(subnet)
	}
	if port > 0 {
		p.ports.Reserve(port)
	}
	if idx, ok := ifaceIndex(iface); ok {
		p.usedIfaces[idx] = true
	}
}

// Allocation describes one freshly-provisioned WG endpoint.
type Allocation struct {
	Iface      string  // "wg1"
	IfaceIndex int     // 1
	Subnet     string  // "10.66.66.0/24"
	ServerIP   net.IP  // 10.66.66.1
	ClientIP   net.IP  // 10.66.66.2
	Port       int     // 51820
	Server     KeyPair
	Client     KeyPair

	// PresharedKey — optional 32-byte base64 PSK. Empty by default;
	// caller (e.g. admin handler for vk-turn inbounds) may set this
	// before [CreateInterface] to bake `PresharedKey = …` into the
	// peer section of the wg-quick config.
	PresharedKey string
}

// Allocate reserves the next free (subnet, port, iface) triple WITHOUT
// touching the filesystem yet. CreateInbound persists it.
func (p *Provisioner) Allocate() (*Allocation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	subnet, err := p.subnets.Allocate()
	if err != nil {
		return nil, err
	}
	port, err := p.ports.Allocate()
	if err != nil {
		p.subnets.Release(subnet)
		return nil, err
	}

	idx := -1
	for i := 0; i < 1000; i++ {
		if !p.usedIfaces[i] {
			idx = i
			break
		}
	}
	if idx < 0 {
		p.subnets.Release(subnet)
		p.ports.Release(port)
		return nil, fmt.Errorf("interface pool exhausted")
	}
	p.usedIfaces[idx] = true

	server, err := GenerateKeyPair()
	if err != nil {
		p.subnets.Release(subnet)
		p.ports.Release(port)
		delete(p.usedIfaces, idx)
		return nil, err
	}
	client, err := GenerateKeyPair()
	if err != nil {
		p.subnets.Release(subnet)
		p.ports.Release(port)
		delete(p.usedIfaces, idx)
		return nil, err
	}

	_, ipnet, _ := net.ParseCIDR(subnet)
	serverIP := ipFromSubnet(ipnet, 1)
	clientIP := ipFromSubnet(ipnet, 2)

	return &Allocation{
		Iface:      IfaceFor(idx),
		IfaceIndex: idx,
		Subnet:     subnet,
		ServerIP:   serverIP,
		ClientIP:   clientIP,
		Port:       port,
		Server:     server,
		Client:     client,
	}, nil
}

// CreateInterface writes /etc/wireguard/<iface>.conf and brings the
// interface up. The MASQUERADE rule covers only the inbound's /24.
func (p *Provisioner) CreateInterface(a *Allocation) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
ListenPort = %d
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE
PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE

[Peer]
PublicKey = %s
AllowedIPs = %s/32
%s`,
		a.Server.Private,
		a.ServerIP.String(),
		a.Port,
		a.Subnet, p.externalIface,
		a.Subnet, p.externalIface,
		a.Client.Public,
		a.ClientIP.String(),
		presharedKeyLine(a.PresharedKey),
	)

	path := filepath.Join(p.configDir, a.Iface+".conf")
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	out, err := exec.Command("systemctl", "start", "wg-quick@"+a.Iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start wg-quick@%s: %w (%s)", a.Iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DestroyInterface stops the interface and removes its config file.
// Releases pool resources so the next inbound can reuse them.
func (p *Provisioner) DestroyInterface(iface, subnet string, port int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	out, err := exec.Command("systemctl", "stop", "wg-quick@"+iface).CombinedOutput()
	if err != nil {
		// best-effort — interface may already be down
		_ = out
	}

	path := filepath.Join(p.configDir, iface+".conf")
	_ = os.Remove(path)

	if subnet != "" {
		p.subnets.Release(subnet)
	}
	if port > 0 {
		p.ports.Release(port)
	}
	if idx, ok := ifaceIndex(iface); ok {
		delete(p.usedIfaces, idx)
	}
	return nil
}

// ClientConfig builds a wg-client.conf the user pastes into their
// WireGuard app. publicEndpoint is what the user's WG dials — for the
// goloom architecture this is "127.0.0.1:51820" because they run the
// joiner locally; for a direct WG setup it'd be "<vps_public_ip>:port".
func (p *Provisioner) ClientConfig(a *Allocation, dns []string, publicEndpoint string) string {
	dnsLine := ""
	if len(dns) > 0 {
		dnsLine = fmt.Sprintf("DNS = %s\n", strings.Join(dns, ", "))
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
%s
[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
PersistentKeepalive = 25
%s`,
		a.Client.Private,
		a.ClientIP.String(),
		dnsLine,
		a.Server.Public,
		publicEndpoint,
		presharedKeyLine(a.PresharedKey),
	)
}

// presharedKeyLine returns "PresharedKey = …\n" when psk is non-empty
// or "" otherwise — pasted into the wg-quick peer section.
func presharedKeyLine(psk string) string {
	if psk == "" {
		return ""
	}
	return fmt.Sprintf("PresharedKey = %s\n", psk)
}

func ipFromSubnet(ipnet *net.IPNet, host byte) net.IP {
	ip := ipnet.IP.To4()
	out := make(net.IP, 4)
	copy(out, ip)
	out[3] = host
	return out
}

func ifaceIndex(name string) (int, bool) {
	if !strings.HasPrefix(name, "wg") {
		return 0, false
	}
	rest := name[2:]
	idx := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			return 0, false
		}
		idx = idx*10 + int(c-'0')
	}
	return idx, true
}

// existingWGPorts asks `wg show all listen-port` for every active WG
// interface and returns the set of ports already in use.
func existingWGPorts() []int {
	out, err := exec.Command("wg", "show", "all", "listen-port").CombinedOutput()
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		port := 0
		for _, c := range fields[1] {
			if c < '0' || c > '9' {
				port = 0
				break
			}
			port = port*10 + int(c-'0')
		}
		if port > 0 {
			ports = append(ports, port)
		}
	}
	return ports
}

// existingWGIfaces returns the indexes of every wgN interface currently
// present on the system (whether up or down). Used to avoid clobbering
// pre-existing setups.
func existingWGIfaces() []int {
	out, err := exec.Command("ip", "-br", "link", "show").CombinedOutput()
	if err != nil {
		return nil
	}
	var idxs []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.SplitN(fields[0], "@", 2)[0]
		if idx, ok := ifaceIndex(name); ok {
			idxs = append(idxs, idx)
		}
	}
	return idxs
}

func detectDefaultIface() (string, error) {
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").CombinedOutput()
	if err != nil {
		return "", err
	}
	// "8.8.8.8 via 192.168.1.1 dev ens3 src ..."
	parts := strings.Fields(string(out))
	for i, p := range parts {
		if p == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("could not detect default interface")
}
