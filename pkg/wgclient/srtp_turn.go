// TURN allocation helper for the SRTP client path.
//
// We use pion/turn/v5 in client mode: dial a UDP connection to one of
// the VK TURN nodes, authenticate with the long-term username/password
// pair obtained from the VK Calls anonymous-auth flow, allocate a
// relayed transport address, and hand the resulting net.PacketConn
// back to the caller (who will wrap it with vkturnsrtp.Client).
//
// The packet flow once allocated:
//
//   client send: relayConn.WriteTo(payload, peerAddr)
//                  → wraps in TURN ChannelData / SendIndication
//                  → UDP datagram out to the VK TURN node
//                  → relay forwards plaintext to peerAddr (our server)
//
//   client recv: relayConn.ReadFrom(buf)
//                  → reads UDP from the VK TURN node
//                  → unwraps TURN ChannelData
//                  → returns the inner payload + source addr
//
// peerAddr in the goloom case is the goloom server's
// vk-turn-srtp listener (host:port from the inbound spec).

package wgclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// TURNAllocation owns the underlying TURN client + the conn it runs
// over (UDP or TCP, see TURNCreds.UseTCP). Closing it tears both
// down in the right order.
type TURNAllocation struct {
	client    *turn.Client
	relay     net.PacketConn
	udpConn   *net.UDPConn // non-nil when control channel is UDP
	tcpConn   net.Conn     // non-nil when control channel is TCP
	peerAddr  *net.UDPAddr
	closeOnce sync.Once
}

// PeerAddr is the resolved goloom-server address that wrapped
// senders should target via relay.WriteTo.
func (a *TURNAllocation) PeerAddr() *net.UDPAddr { return a.peerAddr }

// Relay is the TURN-relayed net.PacketConn. Reads return packets
// already de-framed (no ChannelData header); writes need a
// destination addr — typically [PeerAddr] for the production path.
func (a *TURNAllocation) Relay() net.PacketConn { return a.relay }

func (a *TURNAllocation) Close() {
	a.closeOnce.Do(func() {
		if a.relay != nil {
			_ = a.relay.Close()
		}
		if a.client != nil {
			a.client.Close()
		}
		if a.udpConn != nil {
			_ = a.udpConn.Close()
		}
		if a.tcpConn != nil {
			_ = a.tcpConn.Close()
		}
	})
}

// TURNCreds is the long-term auth bundle returned by VK's
// calls.getAnonymousToken + joinConversationByLink chain.
//
// UseTCP selects the iOS↔TURN-relay control transport. TCP is the
// anton48 build128+ default and is strongly recommended: empirically
// VK applies a per-credential allocation-rate throttle that hits
// 36-58% of UDP allocate attempts but ~0% on TCP (introduced
// 2026-05-18). UDP path is kept as an escape hatch for networks
// that block TCP-to-relay altogether.
type TURNCreds struct {
	Username string
	Password string
	UseTCP   bool
}

// AllocateTURN dials turnAddr, runs the TURN ALLOCATE handshake using
// creds, and returns a handle whose Relay() can be wrapped by
// vkturnsrtp.Client. peerAddrStr is resolved up front so wrappers
// downstream don't have to.
//
// ctx bounds the dial + handshake setup; once the returned handle
// is in hand, its lifetime is decoupled from ctx (call Close()).
//
// Transport (UDP vs TCP) is taken from creds.UseTCP.
func AllocateTURN(ctx context.Context, turnAddr, peerAddrStr string, creds TURNCreds) (*TURNAllocation, error) {
	turnUDP, err := net.ResolveUDPAddr("udp", turnAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve TURN %s: %w", turnAddr, err)
	}
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddrStr)
	if err != nil {
		return nil, fmt.Errorf("resolve peer %s: %w", peerAddrStr, err)
	}

	var (
		conn    net.PacketConn
		udpConn *net.UDPConn
		tcpConn net.Conn
	)
	if creds.UseTCP {
		// TCP control channel. pion/turn ships turn.NewSTUNConn to
		// adapt a TCP connection into a net.PacketConn so the same
		// client.Allocate flow works on either transport.
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", turnAddr)
		cancel()
		if dialErr != nil {
			return nil, fmt.Errorf("dial TURN TCP %s: %w", turnAddr, dialErr)
		}
		tcpConn = raw
		conn = turn.NewSTUNConn(raw)
	} else {
		// UDP control channel. DialUDP so the OS picks a source port;
		// connectedUDPConn ignores per-write destination since the
		// underlying socket is already pinned to turnAddr. Matches
		// anton48's connectedUDPConn pattern.
		raw, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", turnAddr)
		if dialErr != nil {
			return nil, fmt.Errorf("dial TURN UDP %s: %w", turnAddr, dialErr)
		}
		uc, ok := raw.(*net.UDPConn)
		if !ok {
			_ = raw.Close()
			return nil, fmt.Errorf("dial returned non-UDPConn %T", raw)
		}
		udpConn = uc
		conn = &connectedUDPConn{UDPConn: uc, turnAddr: turnUDP}
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           conn,
		Username:       creds.Username,
		Password:       creds.Password,
		Realm:          "",
		LoggerFactory:  &logging.DefaultLoggerFactory{Writer: discardLogWriter{}},
	}

	closeUnderlay := func() {
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if tcpConn != nil {
			_ = tcpConn.Close()
		}
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		closeUnderlay()
		return nil, fmt.Errorf("turn.NewClient: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		closeUnderlay()
		return nil, fmt.Errorf("turn client Listen: %w", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		closeUnderlay()
		return nil, fmt.Errorf("turn Allocate: %w", err)
	}

	// CreatePermission for the peer so the TURN relay forwards
	// inbound packets from peerAddr back to us. pion/turn does this
	// automatically on first WriteTo, but we do it eagerly to fail
	// fast (and to populate the relay's permission table before the
	// DTLS handshake's first ClientHello).
	if err := relayConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
		_, _ = relayConn.WriteTo([]byte{0}, peerUDP)
	}

	return &TURNAllocation{
		client:   client,
		relay:    relayConn,
		udpConn:  udpConn,
		tcpConn:  tcpConn,
		peerAddr: peerUDP,
	}, nil
}

// connectedUDPConn adapts a connected *net.UDPConn (from DialUDP) to
// net.PacketConn by ignoring the per-write destination addr (the
// connection's already pinned to one). Mirrors the anton48
// connectedUDPConn pattern used in their proxy.runTURN.
type connectedUDPConn struct {
	*net.UDPConn
	turnAddr *net.UDPAddr
}

func (c *connectedUDPConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.UDPConn.Write(b)
}

func (c *connectedUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.UDPConn.Read(b)
	return n, c.turnAddr, err
}

// discardLogWriter silences pion's verbose TURN-client chatter. We
// surface failures via the typed errors above; line-noise
// "Authentication failed (X-Pion-Diag-Id ...)" would just fill the
// goloom log without adding signal.
type discardLogWriter struct{}

func (discardLogWriter) Write(p []byte) (int, error) { return len(p), nil }
