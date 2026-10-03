package vkturnsrtp

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A client opens N TURN allocations and spreads WireGuard datagrams across all
// of them. Each allocation arrives here as its own SRTP session, and each used
// to dial its OWN UDP socket towards the local WireGuard. That is what kept the
// downlink slow:
//
// kernel WireGuard tracks one endpoint per peer. With N sockets it saw N source
// addresses for the same peer and roamed the endpoint to whichever one it had
// authenticated last, so EVERY reply went out through a single allocation while
// the other N-1 sat idle — and one allocation is policed by VK at roughly
// 247 KiB/s. The roaming also flipped with each uplink packet, so replies
// arrived in bursts from alternating paths.
//
// A group fixes both halves. Members that announce the same id share ONE socket
// to WireGuard, so the peer endpoint is stable, and the replies coming back are
// then ours to spread: the pump round-robins them across members, each paced by
// its own token bucket so no single allocation is pushed past what VK will
// forward. Upstream measured this design going from 22.5 to 103 Mbit/s at 60
// allocations.
//
// Clients that never send a group hello keep the old behaviour — a group of one
// — so an older build still works, just without the spreading.

// Group hello: 0xff 'G' 'R' 'P' followed by a 16-byte group id, sent by the
// client on each SRTP conn right after its handshake. Same sentinel family as
// the liveness probe (0xff 'P' 'N' 'G') and, like it, never forwarded to
// WireGuard.
const (
	groupIDLen    = 16
	groupHelloLen = 4 + groupIDLen

	// groupPacePerSec is the per-allocation payload budget VK will actually
	// forward; groupPaceOnWire is the per-packet overhead counted against it.
	// Upstream measured delivery falling to ~98% at 260 KiB/s, so this sits
	// just under that knee.
	groupPacePerSec = 247 * 1024
	groupPaceBurst  = 16 * 1024
	groupPaceOnWire = 30

	// groupPaceWait / groupPaceWaitTries bound how long a reply waits for a
	// member to have budget before it is dropped: ~40 ms total, well inside
	// WireGuard's tolerance and far cheaper than an inner-TCP retransmit.
	groupPaceWait      = 4 * time.Millisecond
	groupPaceWaitTries = 10

	groupWriteTimeout = 5 * time.Second
)

var groupHelloMagic = [4]byte{0xff, 'G', 'R', 'P'}

// GroupHello builds the hello a client sends to join id.
func GroupHello(id [groupIDLen]byte) []byte {
	out := make([]byte, 0, groupHelloLen)
	out = append(out, groupHelloMagic[:]...)
	return append(out, id[:]...)
}

// ParseGroupHello returns the group id carried by p, if p is a group hello.
func ParseGroupHello(p []byte) ([groupIDLen]byte, bool) {
	var id [groupIDLen]byte
	if len(p) < groupHelloLen {
		return id, false
	}
	for i, b := range groupHelloMagic {
		if p[i] != b {
			return id, false
		}
	}
	copy(id[:], p[4:groupHelloLen])
	return id, true
}

// tokenBucket paces one member. Tokens are bytes, refilled at rate and capped
// at burst.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	burst    float64
	rate     float64
	lastFill time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, burst: burst, rate: rate, lastFill: time.Now()}
}

// take removes n bytes if they are available, reporting whether it could.
func (t *tokenBucket) take(n int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if el := now.Sub(t.lastFill).Seconds(); el > 0 {
		t.tokens += el * t.rate
		if t.tokens > t.burst {
			t.tokens = t.burst
		}
		t.lastFill = now
	}
	want := float64(n)
	if t.tokens < want {
		return false
	}
	t.tokens -= want
	return true
}

// connGroup is one client's set of SRTP conns plus the single socket they share
// towards the local WireGuard.
type connGroup struct {
	id  [groupIDLen]byte
	log *log.Logger
	reg *groupRegistry // so a pump that cannot recover can retire the group

	// wgConn is the shared socket: every member writes uplink into it, and one
	// pump goroutine reads the downlink out of it.
	wgConn net.Conn

	mu      sync.Mutex
	members []*groupMember
	pumping bool
	closed  bool
	done    chan struct{} // closed when the group is torn down

	Delivered atomic.Uint64 // downlink packets handed to a member
	Dropped   atomic.Uint64 // downlink packets no member could take in time
}

type groupMember struct {
	conn   net.Conn
	bucket *tokenBucket
}

// groupRegistry keeps the live groups for one listener.
type groupRegistry struct {
	mu     sync.Mutex
	groups map[[groupIDLen]byte]*connGroup
}

func newGroupRegistry() *groupRegistry {
	return &groupRegistry{groups: make(map[[groupIDLen]byte]*connGroup)}
}

// join adds conn to the group named id, creating the group (and its shared
// socket, via dial) on first use. It reports whether the caller must start the
// downlink pump — which is true both for a brand-new group and for one whose
// pump has exited while members remain. The pump must NOT be tied to the
// joining member's lifetime: it serves the whole group, and an earlier design
// that let the creating member's teardown cancel it left groups with members
// and no downlink at all.
func (r *groupRegistry) join(id [groupIDLen]byte, conn net.Conn, dial func() (net.Conn, error), lg *log.Logger) (*connGroup, bool, error) {
	r.mu.Lock()
	g, ok := r.groups[id]
	if !ok {
		wgConn, err := dial()
		if err != nil {
			r.mu.Unlock()
			return nil, false, err
		}
		g = &connGroup{id: id, log: lg, reg: r, wgConn: wgConn, done: make(chan struct{})}
		r.groups[id] = g
	}
	r.mu.Unlock()

	g.mu.Lock()
	if g.closed {
		// Raced with the last member leaving; the caller retries with a fresh
		// group rather than joining a corpse.
		g.mu.Unlock()
		return nil, false, net.ErrClosed
	}
	g.members = append(g.members, &groupMember{
		conn:   conn,
		bucket: newTokenBucket(groupPacePerSec, groupPaceBurst),
	})
	needPump := !g.pumping
	g.pumping = needPump || g.pumping
	n := len(g.members)
	g.mu.Unlock()

	if lg != nil {
		lg.Printf("vkturnsrtp: group %x: %d member(s) after join", id[:4], n)
	}
	return g, needPump, nil
}

// pumpStopped marks the group as needing a pump again. Called by runDownlink on
// its way out so a later join can restart it instead of the group going deaf.
func (g *connGroup) pumpStopped() {
	g.mu.Lock()
	if !g.closed {
		g.pumping = false
	}
	g.mu.Unlock()
}

// dropMember removes one member, e.g. after a write to it failed. Leaving a
// dead member in the rotation black-holes its 1/N share of the downlink until
// its session times out, which can be half an hour.
func (g *connGroup) dropMember(conn net.Conn) {
	g.mu.Lock()
	for i, m := range g.members {
		if m.conn == conn {
			g.members = append(g.members[:i], g.members[i+1:]...)
			break
		}
	}
	left := len(g.members)
	g.mu.Unlock()
	if g.log != nil {
		g.log.Printf("vkturnsrtp: group %x: dropped an unwritable member, %d left", g.id[:4], left)
	}
}

// retire takes a group out of service after its shared socket failed, closing
// the members so the clients notice and rebuild. Unlike leave it does not wait
// for the group to empty — the point is that the members cannot be served.
func (g *connGroup) retire() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	g.pumping = false
	close(g.done)
	members := g.members
	g.members = nil
	g.mu.Unlock()

	if g.reg != nil {
		g.reg.mu.Lock()
		if cur, ok := g.reg.groups[g.id]; ok && cur == g {
			delete(g.reg.groups, g.id)
		}
		g.reg.mu.Unlock()
	}
	_ = g.wgConn.Close()
	for _, m := range members {
		_ = m.conn.Close()
	}
	if g.log != nil {
		g.log.Printf("vkturnsrtp: group %x retired after a shared-socket failure (%d member(s) dropped, delivered=%d dropped=%d)",
			g.id[:4], len(members), g.Delivered.Load(), g.Dropped.Load())
	}
}

// leave removes conn from the group and tears the group down once empty.
func (r *groupRegistry) leave(g *connGroup, conn net.Conn) {
	g.mu.Lock()
	for i, m := range g.members {
		if m.conn == conn {
			g.members = append(g.members[:i], g.members[i+1:]...)
			break
		}
	}
	if len(g.members) > 0 || g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	g.pumping = false
	close(g.done)
	g.mu.Unlock()

	r.mu.Lock()
	if cur, ok := r.groups[g.id]; ok && cur == g {
		delete(r.groups, g.id)
	}
	r.mu.Unlock()

	_ = g.wgConn.Close()
	if g.log != nil {
		g.log.Printf("vkturnsrtp: group %x closed (delivered=%d dropped=%d)",
			g.id[:4], g.Delivered.Load(), g.Dropped.Load())
	}
}

// writeUplink forwards one client packet into the shared WireGuard socket.
func (g *connGroup) writeUplink(b []byte) error {
	if err := g.wgConn.SetWriteDeadline(time.Now().Add(srtpIdleDeadline)); err != nil {
		return err
	}
	_, err := g.wgConn.Write(b)
	return err
}

// pickMember returns the next member that can afford n bytes, round-robining
// from cursor so no member is favoured.
func (g *connGroup) pickMember(cursor *int, n int) *groupMember {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.members) == 0 {
		return nil
	}
	for i := 0; i < len(g.members); i++ {
		*cursor = (*cursor + 1) % len(g.members)
		if m := g.members[*cursor]; m.bucket.take(n + groupPaceOnWire) {
			return m
		}
	}
	return nil
}

// runDownlink reads replies from the shared WireGuard socket and spreads them
// across the group's members. One goroutine per group.
func (g *connGroup) runDownlink(ctx context.Context, onErr func(string, error)) {
	defer g.pumpStopped()
	buf := make([]byte, 1600)
	cursor := 0
	var lastDeadline time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.done:
			return
		default:
		}
		if time.Since(lastDeadline) > srtpDeadlineRearm {
			if err := g.wgConn.SetReadDeadline(time.Now().Add(srtpIdleDeadline)); err != nil {
				onErr("set group wg read deadline", err)
				return
			}
			lastDeadline = time.Now()
		}
		n, err := g.wgConn.Read(buf)
		if err != nil {
			// A read deadline expiring means the tunnel was quiet, not that the
			// socket died — and the pump is irreplaceable while members remain:
			// it is started only by groupRegistry.join, which only runs when a
			// NEW conn arrives, so returning here left the whole group with
			// members and no downlink at all, silently and forever.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				lastDeadline = time.Time{} // force a re-arm and keep serving
				continue
			}
			onErr("group wg read", err)
			// The shared socket is genuinely gone. Retire the group so the
			// members' next write fails and each client's watchdog rebuilds its
			// slot — which re-joins and dials a working socket. Staying up would
			// keep a tunnel that looks healthy and receives nothing.
			g.retire()
			return
		}

		// Every member saturated: hold briefly rather than dropping on the
		// first try — the buckets refill continuously.
		var m *groupMember
		for attempt := 0; attempt < groupPaceWaitTries; attempt++ {
			if m = g.pickMember(&cursor, n); m != nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-g.done:
				return
			case <-time.After(groupPaceWait):
			}
		}
		if m == nil {
			g.Dropped.Add(1)
			continue
		}
		if err := m.conn.SetWriteDeadline(time.Now().Add(groupWriteTimeout)); err != nil {
			onErr("set group member write deadline", err)
			g.dropMember(m.conn)
			g.Dropped.Add(1)
			continue
		}
		if _, err := m.conn.Write(buf[:n]); err != nil {
			onErr("group member write", err)
			g.dropMember(m.conn)
			g.Dropped.Add(1)
			continue
		}
		g.Delivered.Add(1)
	}
}
