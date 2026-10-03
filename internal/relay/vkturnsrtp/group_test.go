package vkturnsrtp

import (
	"testing"
	"time"
)

func TestGroupHelloRoundTrip(t *testing.T) {
	id := [groupIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	got, ok := ParseGroupHello(GroupHello(id))
	if !ok || got != id {
		t.Fatalf("round trip gave (%x, %v)", got, ok)
	}
}

// A hello must be distinguishable from the liveness probe and from WireGuard
// traffic — misreading either would forward a sentinel into WireGuard or eat a
// real packet.
func TestGroupHelloRejectsOtherTraffic(t *testing.T) {
	cases := map[string][]byte{
		"liveness probe":  {0xff, 'P', 'N', 'G', 0, 0, 0, 0, 0, 0, 0, 1},
		"truncated hello": append([]byte{0xff, 'G', 'R', 'P'}, make([]byte, groupIDLen-1)...),
		"wg handshake":    {1, 0, 0, 0, 9, 9, 9, 9},
		"empty":           {},
	}
	for name, p := range cases {
		if _, ok := ParseGroupHello(p); ok {
			t.Errorf("%s parsed as a group hello", name)
		}
	}
	if isProbePacket(GroupHello([groupIDLen]byte{})) {
		t.Error("group hello parsed as a liveness probe")
	}
}

func TestTokenBucketPacesAndRefills(t *testing.T) {
	b := newTokenBucket(1000, 2000) // 1000 B/s, 2000 B burst
	if !b.take(2000) {
		t.Fatal("burst should be spendable immediately")
	}
	if b.take(1) {
		t.Fatal("bucket should be empty right after the burst")
	}
	// Refill is time-based; rewind lastFill rather than sleeping a whole second.
	b.mu.Lock()
	b.lastFill = b.lastFill.Add(-500 * time.Millisecond)
	b.mu.Unlock()
	if !b.take(400) {
		t.Error("500 ms at 1000 B/s should afford 400 B")
	}
	if b.take(400) {
		t.Error("only ~500 B was earned; a second 400 B take must fail")
	}
}

func TestTokenBucketCapsAtBurst(t *testing.T) {
	b := newTokenBucket(1000, 500)
	b.mu.Lock()
	b.lastFill = b.lastFill.Add(-time.Hour)
	b.mu.Unlock()
	if !b.take(500) {
		t.Fatal("full burst must be available")
	}
	if b.take(1) {
		t.Error("tokens accumulated beyond the burst cap")
	}
}

// The downlink must round-robin: one member cannot be starved while another
// carries everything, which was the whole point of the endpoint-roaming fix.
func TestPickMemberRoundRobins(t *testing.T) {
	g := &connGroup{done: make(chan struct{})}
	for i := 0; i < 3; i++ {
		g.members = append(g.members, &groupMember{
			conn:   newFakeSRTPConn(),
			bucket: newTokenBucket(1e9, 1e9),
		})
	}
	seen := map[*groupMember]int{}
	cursor := 0
	for i := 0; i < 9; i++ {
		m := g.pickMember(&cursor, 100)
		if m == nil {
			t.Fatal("no member picked despite full buckets")
		}
		seen[m]++
	}
	if len(seen) != 3 {
		t.Fatalf("used %d of 3 members", len(seen))
	}
	for m, n := range seen {
		if n != 3 {
			t.Errorf("member %p got %d packets, want an even 3", m, n)
		}
	}
}

// When every member is out of budget the picker must report that rather than
// overshooting VK's per-allocation limit.
func TestPickMemberRefusesWhenAllSaturated(t *testing.T) {
	g := &connGroup{done: make(chan struct{})}
	for i := 0; i < 2; i++ {
		g.members = append(g.members, &groupMember{
			conn:   newFakeSRTPConn(),
			bucket: newTokenBucket(1, 10), // 10 B burst, refills at 1 B/s
		})
	}
	cursor := 0
	if m := g.pickMember(&cursor, 1000); m != nil {
		t.Fatal("picked a member that cannot afford the packet")
	}
}

func TestPickMemberEmptyGroup(t *testing.T) {
	g := &connGroup{done: make(chan struct{})}
	cursor := 0
	if m := g.pickMember(&cursor, 1); m != nil {
		t.Fatal("picked a member from an empty group")
	}
}
