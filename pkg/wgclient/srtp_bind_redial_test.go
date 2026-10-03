package wgclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
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
	defer b.Shutdown()

	var redials atomic.Int64
	replacement := newFakeConn(99)
	b.Redial = func(_ context.Context, idx int) (net.Conn, error) {
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
	defer b.Shutdown()

	var redials atomic.Int64
	b.Redial = func(context.Context, int) (net.Conn, error) {
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
	defer b.Shutdown()

	b.Redial = func(context.Context, int) (net.Conn, error) { return nil, errors.New("TURN allocate refused") }
	b.dead[0].Store(true)
	b.tryRedial(0, time.Now().Unix())
	if !b.dead[0].Load() {
		t.Error("slot cleared its dead flag despite a failed redial")
	}
	if box := b.slots[0].Load(); box == nil || box.c != c0 {
		t.Error("failed redial disturbed the existing conn")
	}
}

// After Shutdown, a redial must not resurrect a slot or leak the fresh conn.
func TestBindRedialAfterShutdownIsNoOp(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	fresh := newFakeConn(5)
	b.Redial = func(context.Context, int) (net.Conn, error) { return fresh, nil }
	if err := b.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	b.tryRedial(0, time.Now().Unix())
	if box := b.slots[0].Load(); box != nil {
		t.Error("slot repopulated after Shutdown")
	}
	if fresh.isClosed() {
		t.Error("Redial was invoked at all after Shutdown")
	}
}

// A Redial already in flight when Shutdown lands must not install its conn —
// the slot is gone and the fresh TURN allocation behind it would leak, and VK
// answers 486 past ten allocations per credential.
func TestBindRedialLandingAfterShutdownClosesItsConn(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	fresh := newFakeConn(5)
	b.Redial = func(context.Context, int) (net.Conn, error) {
		// Shutdown wins the race while this dial is "in flight".
		_ = b.Shutdown()
		return fresh, nil
	}
	b.dead[0].Store(true)
	b.tryRedial(0, time.Now().Unix())

	if box := b.slots[0].Load(); box != nil {
		t.Error("a redial that landed after Shutdown repopulated the slot")
	}
	if !fresh.isClosed() {
		t.Error("a redial that landed after Shutdown leaked its conn")
	}
}

// wireguard-go cycles the bind on the way UP: device.Up() calls BindUpdate,
// which does bind.Close() and then bind.Open(). Close must therefore NOT touch
// the SRTP conns — when it did, all ten TURN allocations died ~14 ms before the
// first handshake, every Send returned "use of closed network connection", the
// watchdog was wedged by the shutdown flag, and the tunnel still reported
// "ready" while unable to move a byte.
func TestBindSurvivesWireguardCloseOpenCycle(t *testing.T) {
	c0, c1 := newFakeConn(0), newFakeConn(1)
	b := NewSRTPBind([]net.Conn{c0, c1})
	defer b.Shutdown()

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// What BindUpdate does, in order.
	if err := b.Close(); err != nil {
		t.Fatalf("Close must not fail — BindUpdate aborts the bring-up: %v", err)
	}
	if c0.isClosed() || c1.isClosed() {
		t.Fatal("Close released the SRTP conns; they belong to the pool and must outlive it")
	}
	recv, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	if len(recv) == 0 {
		t.Fatal("reopen returned no ReceiveFunc")
	}
	for i := range b.slots {
		if box := b.slots[i].Load(); box == nil {
			t.Fatalf("slot %d was emptied by the Close/Open cycle", i)
		}
	}
	if err := b.Send([][]byte{{1, 2, 3}}, nil); err != nil {
		t.Fatalf("Send after the cycle: %v", err)
	}
	if b.TxBytes.Load() != 3 {
		t.Errorf("TxBytes = %d after the cycle, want 3", b.TxBytes.Load())
	}

	// Drive the reopened ReceiveFunc, not just the send side. A recv closure
	// still watching the PREVIOUS Open's stop channel returns ErrClosed here,
	// which is the other half of the same failure: a bind that reports ready
	// and never delivers a packet.
	payload := []byte{9, 8, 7}
	pkt := bindPktPoolGet(len(payload))
	copy(pkt, payload)
	b.rxCh <- rxPacket{data: pkt}

	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := recv[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("recv after the cycle: %v", err)
	}
	if n != 1 {
		t.Fatalf("recv returned %d packets after the cycle, want 1", n)
	}
	if !bytes.Equal(bufs[0][:sizes[0]], payload) {
		t.Errorf("recv delivered %v, want %v", bufs[0][:sizes[0]], payload)
	}
}

// Shutdown is what actually releases the conns, whether or not Open ever ran.
func TestBindShutdownReleasesConns(t *testing.T) {
	c0, c1 := newFakeConn(0), newFakeConn(1)
	b := NewSRTPBind([]net.Conn{c0, c1})
	if err := b.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !c0.isClosed() || !c1.isClosed() {
		t.Error("Shutdown left SRTP conns open — the TURN allocations behind them leak")
	}
	if err := b.Shutdown(); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
	if err := b.Send([][]byte{{1}}, nil); err == nil {
		t.Error("Send succeeded after Shutdown")
	}
}

// Send must account bytes so the UI can tell a stalled tunnel from an idle one.
func TestBindCountsBytes(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	defer b.Shutdown()
	if err := b.Send([][]byte{{1, 2, 3, 4, 5}}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := b.TxBytes.Load(); got != 5 {
		t.Errorf("TxBytes = %d, want 5", got)
	}
}

// Teardown must not deadlock against a redial that lands while it runs.
// tryRedial dials outside b.mu and then takes it to install the conn, and the
// goroutine driving it is the watchdog, which rxWG counts — so a Shutdown that
// held b.mu across rxWG.Wait() waited for a goroutine blocked on the very lock
// it was holding. On the phone that is Disconnect hanging forever.
func TestBindShutdownDoesNotDeadlockAgainstLandingRedial(t *testing.T) {
	c0 := newFakeConn(0)
	b := NewSRTPBind([]net.Conn{c0})
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}

	dialing := make(chan struct{})
	release := make(chan struct{})
	fresh := newFakeConn(5)
	b.Redial = func(context.Context, int) (net.Conn, error) {
		close(dialing)
		<-release // hold the dial open until Shutdown is under way
		return fresh, nil
	}
	b.dead[0].Store(true)

	// Drive tryRedial from a goroutine rxWG counts, standing in for
	// zombieWatchdog — which is the real caller, but only ticks every
	// probeInterval/3, so driving it directly would cost the suite 10 s for the
	// same interleaving.
	b.rxWG.Add(1)
	go func() {
		defer b.rxWG.Done()
		b.tryRedial(0, time.Now().Unix())
	}()
	<-dialing

	done := make(chan error, 1)
	go func() { done <- b.Shutdown() }()
	// Let Shutdown take b.mu and reach its wait, THEN let the dial land so it
	// blocks on b.mu — the exact interleaving that used to wedge.
	time.Sleep(150 * time.Millisecond)
	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown deadlocked against a redial landing during teardown")
	}
	if !fresh.isClosed() {
		t.Error("the conn that landed during teardown was leaked")
	}
}

// A bind that has been shut down must refuse to reopen rather than hand
// wireguard-go a bind with no slots that reports ready and cannot send.
func TestBindOpenAfterShutdownFails(t *testing.T) {
	b := NewSRTPBind([]net.Conn{newFakeConn(0)})
	if err := b.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, _, err := b.Open(0); err == nil {
		t.Error("Open succeeded on a bind that was shut down")
	}
}

// VK caps concurrent allocations per credential (20, measured against the live
// service in October 2026). Every slot above that is born dead, and the
// watchdog used to ask for all of them again every redialBackoff — ~30 doomed
// allocate requests every 15 s, forever. VK throttles a credential that asks
// too often, so the retries endangered the allocations that WERE up.
func TestBindBacksOffHardWhenVKIsOutOfQuota(t *testing.T) {
	b := NewSRTPBind([]net.Conn{nil})
	defer b.Shutdown()

	var calls atomic.Int64
	b.Redial = func(context.Context, int) (net.Conn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("TURN allocate via relay: %w", ErrTURNQuota)
	}
	b.dead[0].Store(true)

	now := time.Now().Unix()
	b.tryRedial(0, now)
	if calls.Load() != 1 {
		t.Fatalf("Redial called %d times, want 1", calls.Load())
	}

	// A slot refused for quota must stay quiet well past the ordinary backoff.
	b.tryRedial(0, now+int64(redialBackoff/time.Second)+1)
	if got := calls.Load(); got != 1 {
		t.Errorf("Redial called %d times one ordinary backoff later; a quota refusal must hold much longer", got)
	}
	b.tryRedial(0, now+int64(quotaRedialBackoff/time.Second)+1)
	if got := calls.Load(); got != 2 {
		t.Errorf("Redial called %d times after the quota backoff elapsed, want 2", got)
	}
}

// A non-quota failure keeps the ordinary, eager backoff: those are transient
// and the slot should come back quickly.
func TestBindKeepsShortBackoffForOrdinaryFailures(t *testing.T) {
	b := NewSRTPBind([]net.Conn{nil})
	defer b.Shutdown()

	var calls atomic.Int64
	b.Redial = func(context.Context, int) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("TURN allocate via relay: connection reset")
	}
	b.dead[0].Store(true)

	now := time.Now().Unix()
	b.tryRedial(0, now)
	b.tryRedial(0, now+int64(redialBackoff/time.Second)+1)
	if got := calls.Load(); got != 2 {
		t.Errorf("Redial called %d times across two ordinary backoffs, want 2", got)
	}
}

// quotaErr must recognise a refusal from the message text pion gives us — by
// code and by reason phrase — and must not mislabel anything else.
func TestQuotaErrClassification(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		quota bool
	}{
		{"pion wording", errors.New("turn Allocate: Allocate error response (error 486: Allocation Quota Reached)"), true},
		{"code only", errors.New("stun error 486"), true},
		{"reason only", errors.New("Allocation Quota Reached"), true},
		{"unrelated", errors.New("dial udp: i/o timeout"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quotaErr(tc.err)
			if errors.Is(got, ErrTURNQuota) != tc.quota {
				t.Errorf("quotaErr(%v) quota=%v, want %v", tc.err, !tc.quota, tc.quota)
			}
			if tc.err != nil && !strings.Contains(got.Error(), tc.err.Error()) {
				t.Errorf("quotaErr dropped the original message: %v", got)
			}
		})
	}
}
