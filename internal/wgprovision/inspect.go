package wgprovision

import (
	"os/exec"
	"strconv"
	"strings"
)

// InterfaceInfo describes one wgN interface as seen by `wg show`.
type InterfaceInfo struct {
	Name        string `json:"name"`
	ListenPort  int    `json:"listen_port"`
	PublicKey   string `json:"public_key"`
	NumPeers    int    `json:"num_peers"`
	UpSeconds   int    `json:"up_seconds"`
	HasConfFile bool   `json:"has_conf_file"`
}

// InspectInterfaces shells out to `wg show all dump` and returns one entry
// per active WG interface. Lightweight enough to call on every panel
// refresh without blowing up CPU.
func InspectInterfaces() []InterfaceInfo {
	out, err := exec.Command("wg", "show", "all", "dump").CombinedOutput()
	if err != nil {
		return nil
	}

	// Output format from `wg show all dump`:
	//
	//   <iface>\t<priv>\t<pub>\t<listen_port>\t<fwmark>            (interface row)
	//   <iface>\t<peer_pub>\t<psk>\t<endpoint>\t<allowed_ips>\t<latest_handshake>\t<rx>\t<tx>\t<keepalive>  (peer row)
	//
	// We aggregate per interface.
	byName := make(map[string]*InterfaceInfo)

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		name := fields[0]
		entry, ok := byName[name]
		if !ok {
			entry = &InterfaceInfo{Name: name}
			byName[name] = entry
		}
		// Heuristic: interface row has 5 fields, peer row has 9.
		if len(fields) == 5 {
			entry.PublicKey = fields[2]
			port, _ := strconv.Atoi(fields[3])
			entry.ListenPort = port
		} else {
			entry.NumPeers++
		}
	}

	out2 := make([]InterfaceInfo, 0, len(byName))
	for _, info := range byName {
		out2 = append(out2, *info)
	}
	return out2
}
