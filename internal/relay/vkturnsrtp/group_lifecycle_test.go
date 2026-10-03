package vkturnsrtp

import (
	"context"
	"log"
	"net"
	"testing"
	"time"
)

// newTestRegistry gives a registry whose groups dial a loopback UDP socket, so
// the pump has something real to read from without a WireGuard on the far side.
func newTestRegistry(t *testing.T) (*groupRegistry, func() (net.Conn, error), *net.UDPConn) {
	t.Helper()
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	dial := func() (net.Conn, error) { return net.Dial("udp", backend.LocalAddr().String()) }
	return newGroupRegistry(), dial, backend
}

// The pump must belong to the GROUP. An earlier design started it under the
// joining member's session context, so when that member left — while others
// were still attached — the group's downlink went silent for good: pumping
// stayed true, so no later join could restart it.
func TestGroupPumpSurvivesItsCreatorLeaving(t *testing.T) {
	reg, dial, _ := newTestRegistry(t)
	id := [groupIDLen]byte{1}
	lg := log.New(&testWriter{t}, "", 0)

	creator, second := newFakeSRTPConn(), newFakeSRTPConn()

	g, needPump, err := reg.join(id, creator, dial, lg)
	if err != nil || !needPump {
		t.Fatalf("first join: needPump=%v err=%v", needPump, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.runDownlink(ctx, func(string, error) {})

	if _, needPump, err = reg.join(id, second, dial, lg); err != nil || needPump {
		t.Fatalf("second join: needPump=%v err=%v (the running pump must be reused)", needPump, err)
	}

	// The creator goes away; the group still has a member.
	reg.leave(g, creator)

	g.mu.Lock()
	members, pumping, closed := len(g.members), g.pumping, g.closed
	g.mu.Unlock()
	if members != 1 || closed {
		t.Fatalf("group has %d members, closed=%v — it must survive", members, closed)
	}
	if !pumping {
		t.Fatal("group lost its pump when the creator left")
	}
}

// When the pump does exit, the group must be able to get another one rather
// than staying member-ful and deaf.
func TestGroupPumpIsRestartable(t *testing.T) {
	reg, dial, _ := newTestRegistry(t)
	id := [groupIDLen]byte{2}

	g, needPump, err := reg.join(id, newFakeSRTPConn(), dial, nil)
	if err != nil || !needPump {
		t.Fatalf("join: %v %v", needPump, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go g.runDownlink(ctx, func(string, error) {})
	cancel() // pump exits

	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		pumping := g.pumping
		g.mu.Unlock()
		if !pumping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pump did not clear its flag on exit, so nothing can restart it")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, needPump, err = reg.join(id, newFakeSRTPConn(), dial, nil); err != nil || !needPump {
		t.Fatalf("rejoin after the pump exited: needPump=%v err=%v — want a restart", needPump, err)
	}
}

// A member that cannot be written to must leave the rotation at once. Left in,
// it keeps drawing its 1/N share of the downlink into a black hole until its
// session times out, which can take half an hour.
func TestDownlinkDropsUnwritableMember(t *testing.T) {
	reg, dial, backend := newTestRegistry(t)
	id := [groupIDLen]byte{3}
	good, bad := newFakeSRTPConn(), newFakeSRTPConn()
	_ = bad.Close() // writes now fail

	g, _, err := reg.join(id, bad, dial, nil)
	if err != nil {
		t.Fatalf("join bad: %v", err)
	}
	if _, _, err = reg.join(id, good, dial, nil); err != nil {
		t.Fatalf("join good: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.runDownlink(ctx, func(string, error) {})

	// The group's socket is CONNECTED to the backend, so only the backend can
	// reach it. Send an uplink first so the backend learns the address, then
	// reply from there.
	if err := g.writeUplink([]byte("uplink")); err != nil {
		t.Fatalf("uplink: %v", err)
	}
	rbuf := make([]byte, 64)
	_ = backend.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, from, err := backend.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("backend never saw the uplink: %v", err)
	}

	// Keep feeding until the round-robin has visited both members: the bad one
	// must be dropped, the good one must keep receiving.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		members := len(g.members)
		g.mu.Unlock()
		if members == 1 && good.count() > 0 {
			return // dropped the dead member, still delivering to the live one
		}
		_, _ = backend.WriteTo([]byte("downlink"), from)
		time.Sleep(10 * time.Millisecond)
	}
	g.mu.Lock()
	members := len(g.members)
	g.mu.Unlock()
	t.Fatalf("after 3 s: %d members left (want 1), %d packets delivered to the healthy one (want >0)",
		members, good.count())
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
