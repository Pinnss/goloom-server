// Package inbound represents a single configured "tunnel into a Telemost
// meeting" on the goloom-wg-server. Each Inbound owns:
//
//   - one Telemost session (its own peer in the call)
//   - one Sender for outbound VP8 frames + receivers for incoming
//   - one wgrelay.WGCreator that bridges the tunnel to a local WG endpoint
//
// Multiple Inbounds run independently in goroutines; the Manager (manager.go)
// supervises them so a failure in one doesn't take down the others.
package inbound

import "time"

// Spec is the persistent description of an inbound — what gets serialised
// to the server's YAML / JSON state.
type Spec struct {
	ID          string `yaml:"id" json:"id"`
	Tag         string `yaml:"tag" json:"tag"`
	Meeting     string `yaml:"meeting" json:"meeting"`
	DisplayName string `yaml:"display_name" json:"display_name"`

	// WGEndpoint is the local UDP address the relay forwards decrypted
	// tunnel frames to (typically 127.0.0.1:51820 for wg0, +1 for wg1, etc.).
	WGEndpoint string `yaml:"wg_endpoint" json:"wg_endpoint"`

	// WGInterface is the wireguard interface name this inbound is bound to.
	// Empty if the operator manages WG out-of-band; populated when the admin
	// panel provisioned the interface itself.
	WGInterface string `yaml:"wg_iface,omitempty" json:"wg_iface,omitempty"`

	// WGSubnet is the /24 the WG interface owns (e.g. "10.66.66.0/24").
	// Stored so the Manager can free it when the inbound is removed.
	WGSubnet string `yaml:"wg_subnet,omitempty" json:"wg_subnet,omitempty"`

	// ClientWGPrivateKey is the client-side WG private key, kept here so
	// the panel can re-render the client config / QR on demand without
	// asking the operator to upload it again. Server pubkey is derived.
	ClientWGPrivateKey string `yaml:"client_wg_private_key,omitempty" json:"-"`
	ClientWGPublicKey  string `yaml:"client_wg_public_key,omitempty" json:"client_wg_public_key,omitempty"`
	ServerWGPrivateKey string `yaml:"server_wg_private_key,omitempty" json:"-"`
	ServerWGPublicKey  string `yaml:"server_wg_public_key,omitempty" json:"server_wg_public_key,omitempty"`

	Enabled bool `yaml:"enabled" json:"enabled"`

	CreatedAt time.Time `yaml:"created_at" json:"created_at"`
}

// Status is the live snapshot the admin panel renders. Not persisted.
type Status struct {
	ID         string    `json:"id"`
	Tag        string    `json:"tag"`
	Enabled    bool      `json:"enabled"`
	Running    bool      `json:"running"`
	Phase      string    `json:"phase"` // "starting" | "waiting_peer" | "handshaking" | "relaying" | "stopped" | "error"
	LastError  string    `json:"last_error,omitempty"`
	Meeting    string    `json:"meeting"`
	WGEndpoint string    `json:"wg_endpoint"`
	WGIface    string    `json:"wg_iface,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`

	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
}
