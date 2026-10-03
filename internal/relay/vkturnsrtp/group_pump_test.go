package vkturnsrtp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// scriptedWGConn stands in for the shared socket to the local WireGuard. Reads
// return whatever the script says, in order, so a test can hand the pump an
// idle timeout and then real data.
type scriptedWGConn struct {
	mu     sync.Mutex
	steps  []wgStep
	at     int
	closed bool
	reads  int
}

type wgStep struct {
	payload []byte
	err     error
	block   bool // park until the conn is closed
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (c *scriptedWGConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	var st wgStep
	if c.at < len(c.steps) {
		st = c.steps[c.at]
		c.at++
	} else {
		st = wgStep{block: true}
	}
	c.reads++
	c.mu.Unlock()

	if st.block {
		for {
			c.mu.Lock()
			done := c.closed
			c.mu.Unlock()
			if done {
				return 0, net.ErrClosed
			}
			time.Sleep(time.Millisecond)
		}
	}
	if st.err != nil {
		return 0, st.err
	}
	return copy(b, st.payload), nil
}

func (c *scriptedWGConn) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *scriptedWGConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *scriptedWGConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *scriptedWGConn) Close() error                       { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *scriptedWGConn) LocalAddr() net.Addr                { return fakeSRTPAddr{} }
func (c *scriptedWGConn) RemoteAddr() net.Addr               { return fakeSRTPAddr{} }
func (c *scriptedWGConn) SetDeadline(time.Time) error        { return nil }
func (c *scriptedWGConn) SetReadDeadline(time.Time) error    { return nil }
func (c *scriptedWGConn) SetWriteDeadline(_ time.Time) error { return nil }

// An idle period must not kill the downlink. The pump is started only by
// groupRegistry.join, which runs only when a NEW conn arrives, so a pump that
// returns while members remain leaves the group receiving nothing — silently,
// and with no way back. A read deadline expiring means "quiet", not "dead".
func TestGroupPumpSurvivesIdleReadTimeout(t *testing.T) {
	member := newFakeSRTPConn()
	wg := &scriptedWGConn{steps: []wgStep{
		{err: timeoutErr{}},           // quiet stretch
		{err: timeoutErr{}},           // still quiet
		{payload: []byte{1, 2, 3, 4}}, // traffic resumes
	}}
	reg := newGroupRegistry()
	var id [groupIDLen]byte
	id[0] = 0xab
	g, needPump, err := reg.join(id, member, func() (net.Conn, error) { return wg, nil }, nil)
	if err != nil || !needPump {
		t.Fatalf("join: err=%v needPump=%v", err, needPump)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); g.runDownlink(ctx, func(string, error) {}) }()

	deadline := time.Now().Add(3 * time.Second)
	for member.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if member.count() == 0 {
		t.Fatal("the packet after the idle stretch was never delivered — the pump died on a timeout")
	}
	if wg.isClosed() {
		t.Error("an idle timeout retired the group")
	}
	select {
	case <-done:
		t.Error("pump exited although the group still has a member")
	default:
	}
	// Closing the shared socket is what unblocks a parked Read — the pump cannot
	// see ctx while inside it, which is exactly what leave() does in production.
	cancel()
	_ = wg.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pump did not exit after the shared socket closed")
	}
}

// A genuinely broken shared socket must retire the group: its members cannot be
// served, so they have to be closed and let each client's watchdog rebuild the
// slot. Leaving them attached keeps a tunnel that looks healthy and receives
// nothing.
func TestGroupRetiresOnDeadSharedSocket(t *testing.T) {
	member := newFakeSRTPConn()
	wg := &scriptedWGConn{steps: []wgStep{{err: net.ErrClosed}}}
	reg := newGroupRegistry()
	var id [groupIDLen]byte
	id[0] = 0xcd
	g, _, err := reg.join(id, member, func() (net.Conn, error) { return wg, nil }, nil)
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	var gotErr string
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.runDownlink(context.Background(), func(what string, _ error) {
			mu.Lock()
			gotErr = what
			mu.Unlock()
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pump did not exit on a dead socket")
	}

	mu.Lock()
	reported := gotErr
	mu.Unlock()
	if reported != "group wg read" {
		t.Errorf("error reported as %q, want \"group wg read\"", reported)
	}
	member.mu.Lock()
	memberClosed := member.closed
	member.mu.Unlock()
	if !memberClosed {
		t.Error("retire left the member attached to a group that cannot serve it")
	}
	if !wg.isClosed() {
		t.Error("retire left the shared socket open")
	}
	reg.mu.Lock()
	_, still := reg.groups[id]
	reg.mu.Unlock()
	if still {
		t.Error("a retired group is still in the registry, so a rejoin would reuse the dead socket")
	}
}
