package wgclient

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a net.Conn whose reads block until it is closed and whose writes
// either succeed or fail on demand — enough to drive the bind's round-robin and
// its watchdog.
type fakeConn struct {
	id       int
	closed   chan struct{}
	once     sync.Once
	writeErr atomic.Bool
	writes   atomic.Uint64
}

func newFakeConn(id int) *fakeConn { return &fakeConn{id: id, closed: make(chan struct{})} }

func (f *fakeConn) Read([]byte) (int, error) {
	<-f.closed
	return 0, io.EOF
}

func (f *fakeConn) Write(b []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	if f.writeErr.Load() {
		return 0, errors.New("fake write failure")
	}
	f.writes.Add(1)
	return len(b), nil
}

func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeConn) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

func (f *fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (f *fakeConn) SetDeadline(time.Time) error        { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error    { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "srtp" }
func (fakeAddr) String() string  { return "srtp" }

// A slot whose write fails is marked dead and must be REBUILT, not merely
// retired. Before Redial existed the pool shrank with every dead allocation
// until nothing was left, while the UI still reported a live tunnel.
func TestBindReplacesDeadSlot(t *testing.T) {
	c0, c1 := newFakeConn(0), newFakeConn(1)
	b := NewSRTPBind([]net.Conn{c0, c1})
	defer b.Close()

	var redials atomic.Int64
	replacement := newFakeConn(99)
	b.Redial = func(idx int) (net.Conn, error) {
		redials.Add(1)
		return replacement, nil
	}

	// Kill slot 0 the way a real write failure does.
	c0.writeErr.Store(true)
	// Two buffers guarantee the round-robin visits slot 0 whatever the counter
	// happens to be.
	if err := b.Send([][]byte{{1, 2, 3}, {4, 5, 6}}, nil); err != nil {
		t.Fatalf("Send should fall through to the healthy slot: %v", err)
	}
	if !b.dead[0].Load() {
		t.Fatal("failed write did not mark the slot dead")
	}

	b.tryRedial(0, time.Now().Unix())

	if redials.Load() != 1 {
		t.Fatalf("Redial called %d times, want 1", redials.Load())
	}
	if b.dead[0].Load() {
		t.Error("replaced slot is still marked dead")
	}
	if box := b.slots[0].Load(); box == nil || box.c != replacement {
		t.Error("slot 0 does not hold the replacement conn")
	}
	if !c0.isClosed() {
		t.Error("the old conn was not closed on replacement")
	}

	// The replaced slot must carry traffic again.
	before := replacement.writes.Load()
	for i := 0; i < 8; i++ {
		_ = b.Send([][]byte{{9}}, nil)
	}
	if replacement.writes.Load() == before {
		t.Error("replacement conn never selected by the round-robin")
	}
}

// Replacement attempts must be throttled per slot: VK rate-limits allocates and
// answers 486 past ten per credential, so a relay outage must not become a
// storm.
func TestBindRedialBackoff(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	defer b.Close()

	var redials atomic.Int64
	b.Redial = func(int) (net.Conn, error) {
		redials.Add(1)
		return newFakeConn(7), nil
	}
	now := time.Now().Unix()
	b.dead[0].Store(true)
	b.tryRedial(0, now)
	b.tryRedial(0, now)
	b.tryRedial(0, now+1)
	if got := redials.Load(); got != 1 {
		t.Fatalf("Redial called %d times within the backoff, want 1", got)
	}
	b.tryRedial(0, now+int64(redialBackoff/time.Second)+1)
	if got := redials.Load(); got != 2 {
		t.Fatalf("Redial called %d times after the backoff elapsed, want 2", got)
	}
}

// A failing Redial must leave the slot dead and retriable, not panic or wedge.
func TestBindRedialFailureKeepsSlotDead(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	defer b.Close()

	b.Redial = func(int) (net.Conn, error) { return nil, errors.New("TURN allocate refused") }
	b.dead[0].Store(true)
	b.tryRedial(0, time.Now().Unix())
	if !b.dead[0].Load() {
		t.Error("slot cleared its dead flag despite a failed redial")
	}
	if box := b.slots[0].Load(); box == nil || box.c != c0 {
		t.Error("failed redial disturbed the existing conn")
	}
}

// After Close, a redial must not resurrect a slot or leak the fresh conn.
func TestBindRedialAfterCloseIsNoOp(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	fresh := newFakeConn(5)
	b.Redial = func(int) (net.Conn, error) { return fresh, nil }
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b.tryRedial(0, time.Now().Unix())
	if box := b.slots[0].Load(); box != nil {
		t.Error("slot repopulated after Close")
	}
}

// Send must account bytes so the UI can tell a stalled tunnel from an idle one.
func TestBindCountsBytes(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	defer b.Close()
	if err := b.Send([][]byte{{1, 2, 3, 4, 5}}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := b.TxBytes.Load(); got != 5 {
		t.Errorf("TxBytes = %d, want 5", got)
	}
}
