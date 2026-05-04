package wgrelay

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// WGCreator is the server-side relay. It dials the configured local
// WireGuard server endpoint and shuttles datagrams between the tunnel
// and that UDP socket.
type WGCreator struct {
	wgEndpoint string
	tun        *DataTunnel
	logger     *log.Logger

	udp *net.UDPConn

	closeOnce sync.Once
	tunDown   chan struct{}

	TxPackets atomic.Uint64
	TxBytes   atomic.Uint64
	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64
}

func NewCreator(wgEndpoint string, tun *DataTunnel, lg *log.Logger) *WGCreator {
	return &WGCreator{
		wgEndpoint: wgEndpoint,
		tun:        tun,
		logger:     lg,
		tunDown:    make(chan struct{}),
	}
}

// Run dials the WG server endpoint and blocks until ctx is cancelled or
// the tunnel closes.
func (c *WGCreator) Run(ctx context.Context) error {
	dst, err := net.ResolveUDPAddr("udp", c.wgEndpoint)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return err
	}
	c.udp = conn
	c.logger.Printf("WG-CREATOR dialing UDP %s (local=%s)", conn.RemoteAddr(), conn.LocalAddr())

	c.tun.SetOnData(c.onTunnelFrame)
	c.tun.SetOnClose(c.signalTunDown)

	go c.readLoop(ctx)

	select {
	case <-ctx.Done():
		c.close()
		return ctx.Err()
	case <-c.tunDown:
		c.close()
		if c.tun.NeedsRehandshake() {
			return ErrPeerRehandshake
		}
		return ErrTunnelClosed
	}
}

func (c *WGCreator) signalTunDown() {
	select {
	case <-c.tunDown:
	default:
		close(c.tunDown)
	}
}

func (c *WGCreator) readLoop(ctx context.Context) {
	buf := make([]byte, udpReadBuf)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Printf("WG-CREATOR UDP read err: %v", err)
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := c.tun.Send(pkt); err != nil {
			c.logger.Printf("WG-CREATOR tunnel send err: %v", err)
			continue
		}
		count := c.RxPackets.Add(1)
		c.RxBytes.Add(uint64(n))
		if count <= 5 || count%200 == 0 {
			c.logger.Printf("WG-CREATOR ↑ pkt #%d (from local WG) len=%d", count, n)
		}
	}
}

func (c *WGCreator) onTunnelFrame(data []byte) {
	n, err := c.udp.Write(data)
	if err != nil {
		c.logger.Printf("WG-CREATOR UDP write err: %v", err)
		return
	}
	count := c.TxPackets.Add(1)
	c.TxBytes.Add(uint64(n))
	if count <= 5 || count%200 == 0 {
		c.logger.Printf("WG-CREATOR ↓ pkt #%d (to local WG) len=%d", count, n)
	}
}

func (c *WGCreator) close() {
	c.closeOnce.Do(func() {
		if c.udp != nil {
			c.udp.Close()
		}
	})
}
