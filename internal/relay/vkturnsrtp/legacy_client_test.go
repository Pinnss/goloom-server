package vkturnsrtp

import (
	"bytes"
	"context"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay"
)

// scriptedSRTPConn plays a client's packets into forwardUDP and records what is
// written back to it.
type scriptedSRTPConn struct {
	mu      sync.Mutex
	inbox   [][]byte
	at      int
	writes  [][]byte
	closed  bool
	drained chan struct{}
	once    sync.Once
}

func newScriptedSRTPConn(pkts ...[]byte) *scriptedSRTPConn {
	return &scriptedSRTPConn{inbox: pkts, drained: make(chan struct{})}
}

func (c *scriptedSRTPConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if c.at < len(c.inbox) {
			p := c.inbox[c.at]
			c.at++
			n := copy(b, p)
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		c.once.Do(func() { close(c.drained) })
		time.Sleep(time.Millisecond) // park like a real idle conn
	}
}

func (c *scriptedSRTPConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *scriptedSRTPConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func (c *scriptedSRTPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *scriptedSRTPConn) LocalAddr() net.Addr                { return fakeSRTPAddr{} }
func (c *scriptedSRTPConn) RemoteAddr() net.Addr               { return fakeSRTPAddr{} }
func (c *scriptedSRTPConn) SetDeadline(time.Time) error        { return nil }
func (c *scriptedSRTPConn) SetReadDeadline(time.Time) error    { return nil }
func (c *scriptedSRTPConn) SetWriteDeadline(_ time.Time) error { return nil }

// A client built before grouping existed never sends a group hello. The server
// must still carry its traffic — anything else is an outage for everyone who
// has not updated, which on the live box is everyone.
//
// This drives forwardUDP itself, because the group tests do not: when the
// grouping rewrite shipped a bug that killed every session milliseconds after
// the first packet, all seven of them still passed.
func TestLegacyClientWithoutGroupHelloStillRelays(t *testing.T) {
	// Stand in for the local WireGuard: whatever the relay forwards lands here.
	wg, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &listener{
		cfg:    relay.Config{ConnectAddr: wg.LocalAddr().String()},
		log:    log.New(&bytes.Buffer{}, "", 0),
		ctx:    ctx,
		groups: newGroupRegistry(),
	}

	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	// The liveness sentinel the client has always sent: 0xff 'P' 'N' 'G' + seq.
	probe := []byte{0xff, 'P', 'N', 'G', 0, 0, 0, 0, 0, 0, 0, 7}
	conn := newScriptedSRTPConn(payload, probe)

	done := make(chan struct{})
	go func() { defer close(done); l.forwardUDP(conn) }()

	// 1. the data packet must reach WireGuard
	_ = wg.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := wg.ReadFrom(buf)
	if err != nil {
		t.Fatalf("nothing reached WireGuard from a client that sent no hello: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("WireGuard got %v, want %v", buf[:n], payload)
	}

	// 2. the probe must be echoed back, not forwarded
	deadline := time.Now().Add(5 * time.Second)
	var echoed bool
	for time.Now().Before(deadline) && !echoed {
		for _, w := range conn.written() {
			if bytes.Equal(w, probe) {
				echoed = true
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !echoed {
		t.Error("liveness probe was not echoed; the client's watchdog would kill the conn")
	}

	// 3. the session must still be alive — the grouping bug killed it here
	select {
	case <-done:
		t.Fatal("forwardUDP returned while the client was still connected")
	default:
	}

	// 4. and it must have been given a group of one, so a downlink pump exists
	l.groups.mu.Lock()
	groups := len(l.groups.groups)
	l.groups.mu.Unlock()
	if groups != 1 {
		t.Errorf("registry holds %d groups, want exactly 1 group-of-one", groups)
	}

	cancel()
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("forwardUDP did not exit after teardown")
	}
}

// The downlink has to reach a legacy client too: its group has one member, so
// everything WireGuard sends back goes to it.
func TestLegacyClientReceivesDownlink(t *testing.T) {
	wg, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &listener{
		cfg:    relay.Config{ConnectAddr: wg.LocalAddr().String()},
		log:    log.New(&bytes.Buffer{}, "", 0),
		ctx:    ctx,
		groups: newGroupRegistry(),
	}

	conn := newScriptedSRTPConn([]byte{0x11, 0x22, 0x33})
	done := make(chan struct{})
	go func() { defer close(done); l.forwardUDP(conn) }()

	_ = wg.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	_, from, err := wg.ReadFrom(buf)
	if err != nil {
		t.Fatalf("uplink never arrived: %v", err)
	}

	reply := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	if _, err := wg.WriteTo(reply, from); err != nil {
		t.Fatalf("reply: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, w := range conn.written() {
			if bytes.Equal(w, reply) {
				cancel()
				_ = conn.Close()
				<-done
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the reply never reached the legacy client — its tunnel would be one-way")
}
