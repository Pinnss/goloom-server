package tun

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sv9toslavPinigin/goloom-server/internal/tunnel"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Stack struct {
	s       *stack.Stack
	ep      *channel.Endpoint
	sm      *tunnel.StreamManager
	logger  *log.Logger
	tunAddr tcpip.Address
	cancel  context.CancelFunc

	ActiveConns atomic.Int64
	TotalConns  atomic.Int64
}

func NewStack(ctx context.Context, sm *tunnel.StreamManager, tunIP net.IP, mtu int, lg *log.Logger) (*Stack, error) {
	ctx, cancel := context.WithCancel(ctx)

	ep := channel.New(512, uint32(mtu), "")

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		cancel()
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	addr := tcpip.AddrFrom4([4]byte(tunIP.To4()))
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		cancel()
		return nil, fmt.Errorf("add address: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	st := &Stack{
		s:       s,
		ep:      ep,
		sm:      sm,
		logger:  lg,
		tunAddr: addr,
		cancel:  cancel,
	}

	st.setupTCPForwarder(ctx)
	st.setupUDPForwarder(ctx)

	return st, nil
}

func (st *Stack) InjectPacket(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	version := pkt[0] >> 4
	var proto tcpip.NetworkProtocolNumber
	switch version {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	st.ep.InjectInbound(proto, pkb)
	pkb.DecRef()
}

func (st *Stack) ReadPacket() ([]byte, bool) {
	pkb := st.ep.Read()
	if pkb == nil {
		return nil, false
	}
	defer pkb.DecRef()
	view := pkb.ToView()
	data := view.AsSlice()
	out := make([]byte, len(data))
	copy(out, data)
	return out, true
}

func (st *Stack) Close() {
	st.cancel()
	st.s.Close()
}

func (st *Stack) setupTCPForwarder(ctx context.Context) {
	fwd := tcp.NewForwarder(st.s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		target := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			st.logger.Printf("TCP-FWD create endpoint for %s: %v", target, err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		st.TotalConns.Add(1)
		st.ActiveConns.Add(1)
		connID := st.TotalConns.Load()

		go st.handleTCPConn(ctx, conn, target, connID)
	})
	st.s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

func (st *Stack) handleTCPConn(ctx context.Context, conn *gonet.TCPConn, target string, connID int64) {
	defer conn.Close()
	defer st.ActiveConns.Add(-1)

	st.logger.Printf("TCP-FWD [%d] → %s", connID, target)

	stream, err := st.sm.OpenStream()
	if err != nil {
		st.logger.Printf("TCP-FWD [%d] open stream: %v", connID, err)
		return
	}
	defer stream.Close()

	if _, err := fmt.Fprintf(stream, "%s\n", target); err != nil {
		st.logger.Printf("TCP-FWD [%d] send target: %v", connID, err)
		return
	}

	stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(stream)
	resp, err := reader.ReadString('\n')
	if err != nil {
		st.logger.Printf("TCP-FWD [%d] server response: %v", connID, err)
		return
	}
	stream.SetReadDeadline(time.Time{})
	resp = strings.TrimSpace(resp)

	if resp != "OK" {
		st.logger.Printf("TCP-FWD [%d] server rejected %s: %s", connID, target, resp)
		return
	}

	st.logger.Printf("TCP-FWD [%d] connected %s — relaying", connID, target)
	relayConns(conn, stream)
	st.logger.Printf("TCP-FWD [%d] done %s", connID, target)
}

func (st *Stack) setupUDPForwarder(ctx context.Context) {
	fwd := udp.NewForwarder(st.s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		if id.LocalPort != 53 {
			return
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		conn := gonet.NewUDPConn(&wq, ep)
		go st.handleDNS(ctx, conn, id.LocalAddress.String())
	})
	st.s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func (st *Stack) handleDNS(ctx context.Context, conn *gonet.UDPConn, dnsServer string) {
	defer conn.Close()

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	query := buf[:n]

	target := fmt.Sprintf("%s:53", dnsServer)
	stream, err := st.sm.OpenStream()
	if err != nil {
		st.logger.Printf("DNS-FWD open stream: %v", err)
		return
	}
	defer stream.Close()

	if _, err := fmt.Fprintf(stream, "%s\n", target); err != nil {
		return
	}
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(stream)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	if strings.TrimSpace(resp) != "OK" {
		return
	}

	tcpQuery := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpQuery[:2], uint16(len(query)))
	copy(tcpQuery[2:], query)
	if _, err := stream.Write(tcpQuery); err != nil {
		return
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
		return
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen > 4096 {
		return
	}
	dnsResp := make([]byte, respLen)
	if _, err := io.ReadFull(reader, dnsResp); err != nil {
		return
	}

	conn.Write(dnsResp)
}

func relayConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.SetWriteDeadline(time.Now())
		src.SetReadDeadline(time.Now())
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func (st *Stack) Endpoint() *channel.Endpoint { return st.ep }
