package wgrelay

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// udpReadBuf is sized for max plausible WG datagram. WG control packets
// are tiny but data can hit path MTU (~1420 typical).
const udpReadBuf = 2048

type peerAddr struct {
	v atomic.Pointer[net.UDPAddr]
}

func (p *peerAddr) store(a *net.UDPAddr) { p.v.Store(a) }
func (p *peerAddr) load() *net.UDPAddr   { return p.v.Load() }

// WGJoiner is the client-side relay. It owns a local UDP socket that
// the user's WireGuard interface points at. Forwards the user's WG
// datagrams to the tunnel and writes tunnel frames back to the last-seen
// WG client source address.
type WGJoiner struct {
	listenAddr string
	tun        *DataTunnel
	logger     *log.Logger

	udp  *net.UDPConn
	peer peerAddr

	closeOnce sync.Once
	tunDown   chan struct{}

	TxPackets atomic.Uint64
	TxBytes   atomic.Uint64
	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64
}

var ErrTunnelClosed = errors.New("wgrelay: tunnel closed")

func NewJoiner(listenAddr string, tun *DataTunnel, lg *log.Logger) *WGJoiner {
	return &WGJoiner{
		listenAddr: listenAddr,
		tun:        tun,
		logger:     lg,
		tunDown:    make(chan struct{}),
	}
}

// Run binds the UDP listener and blocks until ctx is cancelled or the
// underlying tunnel closes.
func (j *WGJoiner) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", j.listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	j.udp = conn
	j.logger.Printf("WG-JOINER listening UDP on %s", conn.LocalAddr())

	j.tun.SetOnData(j.onTunnelFrame)
	j.tun.SetOnClose(j.signalTunDown)

	go j.readLoop(ctx)

	select {
	case <-ctx.Done():
		j.close()
		return ctx.Err()
	case <-j.tunDown:
		j.close()
		if j.tun.NeedsRehandshake() {
			return ErrPeerRehandshake
		}
		return ErrTunnelClosed
	}
}

func (j *WGJoiner) signalTunDown() {
	select {
	case <-j.tunDown:
	default:
		close(j.tunDown)
	}
}

func (j *WGJoiner) readLoop(ctx context.Context) {
	buf := make([]byte, udpReadBuf)
	for {
		if ctx.Err() != nil {
			return
		}
		n, src, err := j.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			j.logger.Printf("WG-JOINER UDP read err: %v", err)
			return
		}
		j.peer.store(src)
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := j.tun.Send(pkt); err != nil {
			j.logger.Printf("WG-JOINER tunnel send err: %v", err)
			continue
		}
		count := j.TxPackets.Add(1)
		j.TxBytes.Add(uint64(n))
		if count <= 5 || count%200 == 0 {
			j.logger.Printf("WG-JOINER ↑ pkt #%d src=%s len=%d", count, src, n)
		}
	}
}

func (j *WGJoiner) onTunnelFrame(data []byte) {
	dst := j.peer.load()
	if dst == nil {
		j.logger.Printf("WG-JOINER ↓ frame received but no peer addr known yet (len=%d)", len(data))
		return
	}
	n, err := j.udp.WriteToUDP(data, dst)
	if err != nil {
		j.logger.Printf("WG-JOINER UDP write err: %v", err)
		return
	}
	count := j.RxPackets.Add(1)
	j.RxBytes.Add(uint64(n))
	if count <= 5 || count%200 == 0 {
		j.logger.Printf("WG-JOINER ↓ pkt #%d dst=%s len=%d", count, dst, n)
	}
}

func (j *WGJoiner) close() {
	j.closeOnce.Do(func() {
		if j.udp != nil {
			j.udp.Close()
		}
	})
}
