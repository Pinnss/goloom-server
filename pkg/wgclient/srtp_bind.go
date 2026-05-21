// conn.Bind adapter that lets wireguard-go talk through a pool of
// vkturnsrtp.Client wrapped sessions as if it were a single UDP
// socket.
//
// Why a pool: VK shapes per-allocation TURN traffic; spreading the
// load over many parallel allocations multiplies tunnel throughput
// roughly N× (anton48 build125 ships 10 by default, the same value
// we use here unless the caller overrides). On the send side we
// round-robin packets; on the receive side every per-conn read
// goroutine fans its packets into a single channel which the
// ReceiveFunc drains. WG userspace sees one stream of bytes — it
// has no idea there's a 10-way carrier swap going on underneath.
//
// Single-conn behaviour is preserved when N==1 — the pool degrades
// to the original direct-write / direct-read path with no extra
// goroutines or channel hops.

package wgclient

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// srtpBind implements [conn.Bind] over one-or-many SRTP-wrapped conns.
type srtpBind struct {
	mu     sync.Mutex
	open   bool
	closed chan struct{}

	conns []net.Conn // owned — Close() closes all

	// Round-robin send counter. Atomic so Send is safe from any goroutine.
	rrNext atomic.Uint64

	// Fan-in: per-conn goroutines push received packets here, the
	// ReceiveFunc drains. Buffered enough to ride out a brief WG-side
	// stall without blocking the readers.
	rxCh   chan rxPacket
	rxWG   sync.WaitGroup // reader goroutines, drained on Close
	rxOnce sync.Once      // start reader goroutines lazily on first Open
}

type rxPacket struct {
	data []byte
}

const srtpBindRxBufSize = 256

// newSRTPBind takes ownership of conns — Close() will close them all.
// Empty or nil slice is a programmer error.
func newSRTPBind(conns []net.Conn) *srtpBind {
	if len(conns) == 0 {
		// Make Bind methods safely return errors instead of panicking.
		conns = nil
	}
	return &srtpBind{
		conns:  conns,
		closed: make(chan struct{}),
		rxCh:   make(chan rxPacket, srtpBindRxBufSize),
	}
}

func (b *srtpBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, errors.New("srtpBind: already open")
	}
	if len(b.conns) == 0 {
		return nil, 0, errors.New("srtpBind: no SRTP conns")
	}
	b.open = true

	// Spawn one reader per conn. Each reader allocates its own buffer
	// to avoid concurrent writes to a shared slice.
	b.rxOnce.Do(func() {
		for _, c := range b.conns {
			b.rxWG.Add(1)
			go b.readerLoop(c)
		}
	})

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		select {
		case pkt, ok := <-b.rxCh:
			if !ok {
				return 0, net.ErrClosed
			}
			n := copy(packets[0], pkt.data)
			sizes[0] = n
			eps[0] = srtpEndpoint{}
			return 1, nil
		case <-b.closed:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

// readerLoop pulls packets off one SRTP conn and pushes them into the
// shared fan-in channel. Exits when the conn closes (Read returns
// non-nil error) or the bind closes (rxCh push selected closed).
func (b *srtpBind) readerLoop(c net.Conn) {
	defer b.rxWG.Done()
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		// Copy to a per-packet slice so the next Read can re-use buf.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case b.rxCh <- rxPacket{data: pkt}:
		case <-b.closed:
			return
		}
	}
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
	var firstErr error
	for _, c := range b.conns {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.rxWG.Wait()
	close(b.rxCh)
	return firstErr
}

func (b *srtpBind) SetMark(uint32) error { return nil }

// Send writes each buf through one of the conns, round-robining
// across the pool. A per-conn write error is non-fatal at the bind
// level — WG handshake retry will retry through whichever conns
// are still alive. We do propagate the error to WG so it can
// schedule that retry. The next Send picks a different conn.
func (b *srtpBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	if len(b.conns) == 0 {
		return net.ErrClosed
	}
	n := uint64(len(b.conns))
	for _, buf := range bufs {
		idx := b.rrNext.Add(1) % n
		if _, err := b.conns[idx].Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *srtpBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return srtpEndpoint{}, nil
}

func (b *srtpBind) BatchSize() int { return 1 }

type srtpEndpoint struct{}

func (srtpEndpoint) ClearSrc()           {}
func (srtpEndpoint) SrcToString() string { return "" }
func (srtpEndpoint) DstToString() string { return "srtp-pool" }
func (srtpEndpoint) DstToBytes() []byte  { return []byte{0, 0, 0, 0} }
func (srtpEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (srtpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
