// WRAP layer for vkturn: ChaCha20-XOR-with-random-nonce obfuscation of
// DTLS packets before they hit the wire. Defeats DPI that signatures
// the plaintext DTLS handshake — without the shared key, the bytes
// look like noise.
//
// Verbatim port of Moroka8/vk-turn-proxy server/wrap.go (PR #162).
// Same wire format, so a goloom-wg-server compiled with vkturn can
// talk to any Moroka8 client and vice versa.

package vkturn

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
	"golang.org/x/crypto/chacha20"
)

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

// listenWrapped binds a UDP socket and returns a DTLS-compatible
// packet listener whose Accept() yields ChaCha20-XOR-obfuscated
// PacketConns. Clients must use the same key to decode.
func listenWrapped(addr *net.UDPAddr, key []byte) (dtlsnet.PacketListener, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("vkturn: wrap key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	inner, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("vkturn: wrap udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		key:   key,
	}, nil
}

type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	key   []byte
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &wrapPacketConn{inner: pc, key: l.key}, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

type wrapPacketConn struct {
	inner net.PacketConn
	key   []byte
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+wrapNonceLen)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < wrapNonceLen {
		return 0, addr, errors.New("vkturn: wrap short packet (no nonce)")
	}
	nonce := buf[:wrapNonceLen]
	ciphertext := buf[wrapNonceLen:n]
	if len(ciphertext) > len(p) {
		return 0, addr, errors.New("vkturn: wrap read buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, nonce)
	if err != nil {
		return 0, addr, fmt.Errorf("vkturn: wrap cipher init: %w", err)
	}
	cipher.XORKeyStream(p[:len(ciphertext)], ciphertext)
	return len(ciphertext), addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, wrapNonceLen+len(p))
	if _, err := rand.Read(out[:wrapNonceLen]); err != nil {
		return 0, fmt.Errorf("vkturn: wrap nonce gen: %w", err)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, out[:wrapNonceLen])
	if err != nil {
		return 0, fmt.Errorf("vkturn: wrap cipher init: %w", err)
	}
	cipher.XORKeyStream(out[wrapNonceLen:], p)
	if _, err := c.inner.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
