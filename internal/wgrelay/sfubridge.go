package wgrelay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

// SFUBridge dials a local WireGuard endpoint and shuttles datagrams
// between it and an [sfu.Session]. Replaces [WGCreator] / [Joiner] for
// callers that have already abstracted their transport behind sfu.
//
// One bridge corresponds to one WG endpoint binding (server-side: the
// VPS-local wgN UDP port; client-side: a localhost listener that the
// system WG userspace dials). The bridge owns the UDP socket lifecycle.
type SFUBridge struct {
	endpoint string
	sess     sfu.Session
	logger   *log.Logger

	// Mode controls dial vs listen.
	mode bridgeMode

	udp *net.UDPConn
	// remote is the latest peer address seen from a "listen" mode UDP
	// socket — set on first packet, used as the destination for
	// outgoing frames pulled off sess.Frames().
	remote   atomic.Pointer[net.UDPAddr]
	closeOnce sync.Once

	TxPackets atomic.Uint64
	TxBytes   atomic.Uint64
	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64

	// stalled is set by [RunRxStallWatchdog] when it forces a cancel.
	stalled atomic.Bool
}

type bridgeMode int

const (
	bridgeDial   bridgeMode = iota // server-side: dial the local WG UDP port
	bridgeListen                   // client-side: listen on localhost so WG dials us
)

// NewServerBridge runs as the server side of the relay: dials a local
// WG endpoint (e.g. 127.0.0.1:51820) and shuttles inbound tunnel
// frames to it / outbound UDP back into the tunnel.
func NewServerBridge(endpoint string, sess sfu.Session, lg *log.Logger) *SFUBridge {
	return &SFUBridge{
		endpoint: endpoint,
		sess:     sess,
		logger:   lg,
		mode:     bridgeDial,
	}
}

// NewClientBridge runs as the client side: listens on a local UDP
// socket so the system WireGuard userspace can dial in. Outbound
// datagrams pulled off the tunnel are written to whatever remote
// address last sent us a packet.
func NewClientBridge(listenAddr string, sess sfu.Session, lg *log.Logger) *SFUBridge {
	return &SFUBridge{
		endpoint: listenAddr,
		sess:     sess,
		logger:   lg,
		mode:     bridgeListen,
	}
}

// Run blocks pumping data both directions until ctx is cancelled or
// sess closes (peer disconnect / rehandshake). The returned error
// surfaces sfu.ErrPeerRehandshake when applicable so the supervisor
// can fast-retry.
func (b *SFUBridge) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", b.endpoint)
	if err != nil {
		return fmt.Errorf("wgrelay: resolve %q: %w", b.endpoint, err)
	}

	switch b.mode {
	case bridgeDial:
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return fmt.Errorf("wgrelay: dial %q: %w", b.endpoint, err)
		}
		b.udp = conn
		b.logger.Printf("WG-BRIDGE dial %s (local=%s)", conn.RemoteAddr(), conn.LocalAddr())
	case bridgeListen:
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("wgrelay: listen %q: %w", b.endpoint, err)
		}
		b.udp = conn
		b.logger.Printf("WG-BRIDGE listen %s", conn.LocalAddr())
	}
	defer b.close()

	go b.udpReadLoop(ctx)
	go b.tunnelReadLoop(ctx)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.sess.Done():
		if err := b.sess.Err(); err != nil {
			if errors.Is(err, sfu.ErrPeerRehandshake) {
				return sfu.ErrPeerRehandshake
			}
			return err
		}
		return ErrTunnelClosed
	}
}

// udpReadLoop pulls datagrams off the local UDP socket and feeds them
// into the SFU session.
func (b *SFUBridge) udpReadLoop(ctx context.Context) {
	buf := make([]byte, udpReadBuf)
	for {
		if ctx.Err() != nil {
			return
		}
		n, peer, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-b.sess.Done():
				return
			default:
			}
			b.logger.Printf("WG-BRIDGE UDP read err: %v", err)
			return
		}
		// In listen mode, remember the latest peer so we can write
		// back to them. In dial mode this is a no-op.
		if b.mode == bridgeListen && peer != nil {
			b.remote.Store(peer)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := b.sess.Send(pkt); err != nil {
			if errors.Is(err, sfu.ErrSessionClosed) {
				return
			}
			b.logger.Printf("WG-BRIDGE tunnel send err: %v", err)
			continue
		}
		count := b.RxPackets.Add(1)
		b.RxBytes.Add(uint64(n))
		if count <= 5 || count%200 == 0 {
			b.logger.Printf("WG-BRIDGE ↑ pkt #%d (from local WG) len=%d", count, n)
		}
	}
}

// tunnelReadLoop pulls datagrams off the SFU session and writes them
// to the local UDP endpoint.
func (b *SFUBridge) tunnelReadLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-b.sess.Frames():
			if !ok {
				return
			}
			var (
				n   int
				err error
			)
			switch b.mode {
			case bridgeDial:
				n, err = b.udp.Write(data)
			case bridgeListen:
				dst := b.remote.Load()
				if dst == nil {
					// We haven't seen the local WG userspace dial us
					// yet — drop. Once it does, subsequent frames flow
					// normally.
					continue
				}
				n, err = b.udp.WriteToUDP(data, dst)
			}
			if err != nil {
				b.logger.Printf("WG-BRIDGE UDP write err: %v", err)
				return
			}
			count := b.TxPackets.Add(1)
			b.TxBytes.Add(uint64(n))
			if count <= 5 || count%200 == 0 {
				b.logger.Printf("WG-BRIDGE ↓ pkt #%d (to local WG) len=%d", count, n)
			}
		}
	}
}

func (b *SFUBridge) close() {
	b.closeOnce.Do(func() {
		if b.udp != nil {
			b.udp.Close()
		}
	})
}

// RunRxStallWatchdog watches the RxBytes counter on the bridge and
// fires `cancel()` if the counter doesn't advance for `rxStallTimeout`
// after handshake (first non-zero rx). Mirrors the legacy DataTunnel
// watchdog but operates on SFUBridge stats so it works for any
// transport.
//
// Tick / timeout defaults match RunRxStallWatchdogDefault for the
// legacy path: 30 sec tick, 2 minute stall timeout.
//
// Caller is expected to wrap the bridge's Run in a derived ctx —
// when cancel() fires the bridge unwinds, Run returns, and the
// supervise loop restarts. ErrRxStall is exposed via Stalled()
// for callers who want to distinguish stall from a clean cancel.
func (b *SFUBridge) RunRxStallWatchdog(
	ctx context.Context,
	cancel context.CancelFunc,
	logger *log.Logger,
	tick time.Duration,
	rxStallTimeout time.Duration,
) {
	if tick <= 0 {
		tick = 30 * time.Second
	}
	if rxStallTimeout <= 0 {
		rxStallTimeout = 2 * time.Minute
	}

	t := time.NewTicker(tick)
	defer t.Stop()

	var (
		lastRx     uint64
		lastChange = time.Now()
		wasReady   bool
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rx := b.RxBytes.Load()
			ready := rx > 0
			if !ready {
				lastRx = 0
				lastChange = time.Now()
				wasReady = false
				continue
			}
			if !wasReady {
				wasReady = true
				lastRx = rx
				lastChange = time.Now()
				continue
			}
			if rx != lastRx {
				lastRx = rx
				lastChange = time.Now()
				continue
			}
			if time.Since(lastChange) > rxStallTimeout {
				if logger != nil {
					logger.Printf("WG-BRIDGE WATCHDOG no rx for %s after handshake — forcing reconnect", rxStallTimeout)
				}
				b.stalled.Store(true)
				cancel()
				return
			}
		}
	}
}

// Stalled reports whether the rx-stall watchdog fired during the
// bridge's lifetime. Read after Run returns to distinguish stall from
// a clean cancel / context done.
func (b *SFUBridge) Stalled() bool {
	return b.stalled.Load()
}
