package wgclient

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay/vkturnsrtp"
)

// srtpHandshakeTimeout bounds one TURN allocate plus its DTLS-SRTP handshake.
const srtpHandshakeTimeout = 15 * time.Second

// SRTPPool owns the TURN allocations behind an [SRTPBind]'s slots and can
// rebuild any one of them on demand.
//
// It exists because a dead allocation used to stay dead: the bind's watchdog
// killed the conn, dropped it from the round-robin, and nothing ever replaced
// it. Allocations die for ordinary reasons — the phone sleeps, a NAT mapping
// expires, VK resets a relay, the server is redeployed — so over hours the pool
// shrank towards zero while the UI still reported a healthy tunnel. Wiring
// Pool.Redial into SRTPBind.Redial lets the watchdog heal instead of only
// diagnose.
type SRTPPool struct {
	// groupID ties every conn in this pool together for the server, which then
	// feeds them all from ONE socket to WireGuard and spreads the downlink
	// across them. Without it the kernel roams the peer endpoint to whichever
	// allocation spoke last, so the whole downlink rides a single one at VK's
	// ~247 KiB/s per-allocation budget. See internal/relay/vkturnsrtp/group.go.
	groupID [16]byte

	endpoints []string
	peerAddr  string
	creds     TURNCreds
	logger    *log.Logger

	mu     sync.Mutex
	allocs []*TURNAllocation // one per slot; nil once closed
	closed bool
}

// NewSRTPPool allocates n slots, round-robining over endpoints. It returns the
// pool and a slice of EXACTLY n conns, nil where a slot failed, so slot indices
// line up with the bind's — a redial for index i must rebuild the same
// allocation the bind thinks lives at i, and a compacted slice would silently
// shift them and tear down a healthy one. It errors only when NOT A SINGLE slot
// came up; partial success is normal and the bind's watchdog fills the nil gaps.
func NewSRTPPool(ctx context.Context, endpoints []string, peerAddr string, creds TURNCreds, n int, lg *log.Logger) (*SRTPPool, []net.Conn, error) {
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("srtp pool: no TURN endpoints")
	}
	if n <= 0 {
		return nil, nil, fmt.Errorf("srtp pool: n must be positive, got %d", n)
	}
	p := &SRTPPool{
		endpoints: endpoints,
		peerAddr:  peerAddr,
		creds:     creds,
		logger:    lg,
		allocs:    make([]*TURNAllocation, n),
	}
	if _, err := rand.Read(p.groupID[:]); err != nil {
		return nil, nil, fmt.Errorf("srtp pool: group id: %w", err)
	}
	conns := make([]net.Conn, n)
	up := 0
	for i := 0; i < n; i++ {
		c, err := p.dial(ctx, i)
		if err != nil {
			p.logf("srtp pool: slot %d/%d: %v", i+1, n, err)
			continue
		}
		conns[i] = c
		up++
	}
	if up == 0 {
		p.Close()
		return nil, nil, fmt.Errorf("srtp pool: every TURN allocate / DTLS handshake failed")
	}
	return p, conns, nil
}

// GroupHello is the hello every conn in this pool announces, for
// [SRTPBind.GroupHello] to repeat.
func (p *SRTPPool) GroupHello() []byte { return vkturnsrtp.GroupHello(p.groupID) }

// Redial rebuilds one slot. Suitable as [SRTPBind.Redial]. The context lets a
// teardown abort a dial in progress — a TURN allocate plus DTLS handshake can
// take the better part of 20 s, and Close used to wait it out.
func (p *SRTPPool) Redial(ctx context.Context, idx int) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, srtpHandshakeTimeout)
	defer cancel()
	return p.dial(dialCtx, idx)
}

// dial establishes slot idx, replacing whatever allocation it held.
func (p *SRTPPool) dial(ctx context.Context, idx int) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	if idx < 0 || idx >= len(p.allocs) {
		p.mu.Unlock()
		return nil, fmt.Errorf("srtp pool: slot %d out of range", idx)
	}
	endpoint := p.endpoints[idx%len(p.endpoints)]
	peerAddr, creds := p.peerAddr, p.creds
	p.mu.Unlock()

	alloc, err := AllocateTURN(ctx, endpoint, peerAddr, creds)
	if err != nil {
		return nil, fmt.Errorf("TURN allocate via %s: %w", endpoint, err)
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, srtpHandshakeTimeout)
	conn, err := vkturnsrtp.Client(hsCtx, alloc.Relay(), alloc.PeerAddr())
	hsCancel()
	if err != nil {
		alloc.Close()
		return nil, fmt.Errorf("DTLS-SRTP handshake via %s: %w", endpoint, err)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		alloc.Close()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	old := p.allocs[idx]
	p.allocs[idx] = alloc
	p.mu.Unlock()
	if old != nil {
		old.Close()
	}

	// Announce the group before any WireGuard traffic, and again on every
	// replacement conn, so a rebuilt slot rejoins the same shared socket instead
	// of splitting the peer endpoint off on its own.
	if err := conn.SetWriteDeadline(time.Now().Add(srtpHandshakeTimeout)); err == nil {
		if _, err := conn.Write(vkturnsrtp.GroupHello(p.groupID)); err != nil {
			p.logf("srtp pool: slot %d group hello: %v", idx, err)
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	p.logf("srtp pool: slot %d up via %s (group %x)", idx, endpoint, p.groupID[:4])
	return conn, nil
}

// Close releases every allocation. The conns themselves belong to the
// SRTPBind, which closes them on its own Close.
func (p *SRTPPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	allocs := p.allocs
	p.allocs = nil
	p.mu.Unlock()
	for _, a := range allocs {
		if a != nil {
			a.Close()
		}
	}
}

func (p *SRTPPool) logf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}
