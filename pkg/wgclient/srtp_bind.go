// conn.Bind adapter that lets wireguard-go talk through a
// vkturnsrtp.Client wrapped session as if it were a UDP socket.
//
// Mirrors the anton48/vk-turn-proxy turnbind.TURNBind shape:
//
//   ┌─────────────────┐    Send(bufs)            ┌──────────────────┐
//   │ wireguard-go    │ ───────────────────────▶ │ srtpBind         │
//   │ userspace stack │                          │   .Write(buf)    │
//   │                 │ ◀─── ReceiveFunc ─────── │   .Read() → buf  │
//   └─────────────────┘                          └──────────────────┘
//                                                       │
//                                                       │ vkturnsrtp.wrappedConn:
//                                                       │   RTP+SRTP encrypt
//                                                       │   relay.WriteTo(peerAddr)
//                                                       ▼
//                                                  [TURN relay]
//                                                       │
//                                                       ▼
//                                            [goloom-wg-server :56001]

package wgclient

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// srtpBind implements [conn.Bind]. One per session. Single endpoint
// — all WG traffic flows through the SRTP-wrapped conn to the goloom
// server, regardless of which peer endpoint WG thinks it's talking to.
type srtpBind struct {
	mu     sync.Mutex
	open   bool
	closed chan struct{}

	srtpConn net.Conn // returned by vkturnsrtp.Client(...)
}

// newSRTPBind takes ownership of srtpConn — Close() will close it.
func newSRTPBind(srtpConn net.Conn) *srtpBind {
	return &srtpBind{srtpConn: srtpConn, closed: make(chan struct{})}
}

func (b *srtpBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, errors.New("srtpBind: already open")
	}
	b.open = true
	// One ReceiveFunc — single-conn, no v4/v6 split because the
	// SRTP-wrapped session has no concept of IP family.
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		n, err := b.srtpConn.Read(packets[0])
		if err != nil {
			select {
			case <-b.closed:
				return 0, net.ErrClosed
			default:
			}
			return 0, &net.OpError{Op: "read", Net: "srtp", Err: err}
		}
		sizes[0] = n
		eps[0] = srtpEndpoint{}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

func (b *srtpBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	b.open = false
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return b.srtpConn.Close()
}

func (b *srtpBind) SetMark(uint32) error { return nil }

func (b *srtpBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		if _, err := b.srtpConn.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint accepts whatever WG passes (the user's wg-quick
// "Endpoint=" value, typically the loopback we hand it) and returns
// a stub endpoint — the bind ignores it because there's only one
// destination.
func (b *srtpBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return srtpEndpoint{}, nil
}

func (b *srtpBind) BatchSize() int { return 1 }

// srtpEndpoint is the single-instance Endpoint returned to wg by
// both ReceiveFunc and ParseEndpoint. wg uses it only to track
// "which peer sent this packet" — we have one peer, so the
// implementation is trivial.
type srtpEndpoint struct{}

func (srtpEndpoint) ClearSrc()                {}
func (srtpEndpoint) SrcToString() string      { return "" }
func (srtpEndpoint) DstToString() string      { return "srtp-relay" }
func (srtpEndpoint) DstToBytes() []byte       { return []byte{0, 0, 0, 0} }
func (srtpEndpoint) DstIP() netip.Addr        { return netip.Addr{} }
func (srtpEndpoint) SrcIP() netip.Addr        { return netip.Addr{} }
