package tunnel

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelPacketConn adapts a Sender + incoming frame channel into a
// net.PacketConn that KCP can read/write through. KCP sees this as a
// UDP-like socket; under the hood every WriteTo becomes a tunnel frame
// with FlagKCP, and every ReadFrom pulls from the dispatcher's channel.
type TunnelPacketConn struct {
	sender *Sender
	in     chan []byte // dispatcher pushes raw KCP payloads here

	closed   atomic.Bool
	closedCh chan struct{}

	mu          sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewPacketConn returns a PacketConn backed by sender for writes and in for
// reads. The caller must feed KCP-flagged frame payloads into in (see
// Dispatcher). bufSize controls backpressure on the read side.
func NewPacketConn(sender *Sender, bufSize int) *TunnelPacketConn {
	return &TunnelPacketConn{
		sender:   sender,
		in:       make(chan []byte, bufSize),
		closedCh: make(chan struct{}),
	}
}

// Deliver pushes a raw KCP payload (already stripped of the tunnel header)
// into the read buffer. Called by the dispatcher. Returns false if closed.
func (c *TunnelPacketConn) Deliver(payload []byte) bool {
	if c.closed.Load() {
		return false
	}
	select {
	case c.in <- payload:
		return true
	case <-c.closedCh:
		return false
	}
}

var tunnelAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

// ReadFrom blocks until a KCP datagram arrives or the deadline expires.
// The addr is a fixed dummy — KCP doesn't use it for anything meaningful
// since we have exactly one peer per PacketConn.
func (c *TunnelPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.readDeadline
	c.mu.Unlock()

	var timer *time.Timer
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, tunnelAddr, &timeoutError{}
		}
		timer = time.NewTimer(d)
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case buf, ok := <-c.in:
		if !ok {
			return 0, tunnelAddr, net.ErrClosed
		}
		n := copy(p, buf)
		return n, tunnelAddr, nil
	case <-timeout:
		return 0, tunnelAddr, &timeoutError{}
	case <-c.closedCh:
		return 0, tunnelAddr, net.ErrClosed
	}
}

// WriteTo sends a KCP datagram as a tunnel frame with FlagKCP.
// The addr is ignored — we always send to the single tunnel peer.
func (c *TunnelPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	if _, err := c.sender.Send(FlagKCP, cp); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *TunnelPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closedCh)
	}
	return nil
}

func (c *TunnelPacketConn) LocalAddr() net.Addr { return tunnelAddr }

func (c *TunnelPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *TunnelPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *TunnelPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "tunnel: i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
