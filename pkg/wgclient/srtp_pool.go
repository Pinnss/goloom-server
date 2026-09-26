package wgclient

import (
	"context"
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
	endpoints []string
	peerAddr  string
	creds     TURNCreds
	logger    *log.Logger

	mu     sync.Mutex
	allocs []*TURNAllocation // one per slot; nil once closed
	closed bool
}

// NewSRTPPool allocates up to n slots, round-robining over endpoints. It
// returns the pool, the conns that came up (in slot order) and an error only
// when NOT A SINGLE slot could be established. Partial success is normal and
// the caller should carry on with fewer conns; once Redial is wired in, the
// bind's watchdog fills the gaps.
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
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := p.dial(ctx, i)
		if err != nil {
			p.logf("srtp pool: slot %d/%d: %v", i+1, n, err)
			continue
		}
		conns = append(conns, c)
	}
	if len(conns) == 0 {
		p.Close()
		return nil, nil, fmt.Errorf("srtp pool: every TURN allocate / DTLS handshake failed")
	}
	return p, conns, nil
}

// Redial rebuilds one slot. Suitable as [SRTPBind.Redial].
func (p *SRTPPool) Redial(idx int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), srtpHandshakeTimeout)
	defer cancel()
	return p.dial(ctx, idx)
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
	p.logf("srtp pool: slot %d up via %s", idx, endpoint)
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
