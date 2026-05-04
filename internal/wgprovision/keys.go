// Package wgprovision provisions WireGuard interfaces from goloom-wg-server:
// generates keypairs, allocates subnets/ports from a pool, writes wgN.conf
// files, and brings interfaces up via wg-quick. Linux-only — Windows just
// uses the existing official client.
//
// This is the engine behind the admin panel's "Add Inbound" flow: instead
// of asking the operator to manually run `wg genkey`, edit /etc/wireguard,
// `systemctl start wg-quick@wg1`, etc., they click a button and we do it.
package wgprovision

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// KeyPair holds a Curve25519 keypair in the same base64 form WireGuard
// uses on the wire (wg pubkey output).
type KeyPair struct {
	Private string
	Public  string
}

// GenerateKeyPair produces a fresh WireGuard-compatible keypair.
// Equivalent to `wg genkey | tee priv | wg pubkey` but pure-Go so we
// don't shell out for every inbound creation.
func GenerateKeyPair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	// Curve25519 clamping per RFC 7748 §5
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}
