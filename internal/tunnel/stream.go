package tunnel

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	kcp "github.com/xtaci/kcp-go/v5"
)

// StreamManager holds the full reliable-stream stack:
//
//	TunnelPacketConn → KCP (reliable, ordered bytes) → yamux (multiplexed streams)
//
// The initiator calls Listen/Accept; the echoer calls Dial/Open.
type StreamManager struct {
	PacketConn *TunnelPacketConn
	KCPConn    net.Conn       // the single KCP session (as net.Conn)
	KCPSession *kcp.UDPSession
	Mux        *yamux.Session
	Logger     *log.Logger
	IsServer   bool
}

// KCP tuning parameters — optimized for high-latency WebRTC relay (~1-2s RTT).
const (
	kcpMTU       = 900  // well under single-RTP-packet limit for camera path
	kcpSndWnd    = 256
	kcpRcvWnd    = 256
	kcpNoDelay   = 1    // enable nodelay mode
	kcpInterval  = 20   // internal update timer (ms)
	kcpResend    = 2    // fast resend trigger (ack skip count)
	kcpNC        = 1    // disable congestion control (tunnel is capacity-limited by SFU, not network)
	kcpMinRTO    = 1500 // ms — WebRTC relay adds ~1s, don't retransmit prematurely
)

// NewStreamManager creates the full KCP+yamux stack over the given
// TunnelPacketConn. isServer should be true for the initiator (screen-sharer)
// who accepts yamux streams, false for the echoer who opens them.
func NewStreamManager(pc *TunnelPacketConn, isServer bool, lg *log.Logger) (*StreamManager, error) {
	sm := &StreamManager{
		PacketConn: pc,
		IsServer:   isServer,
		Logger:     lg,
	}

	// KCP operates on a net.PacketConn. We use NewConn3 which wraps an
	// existing PacketConn — no real UDP socket needed.
	block, _ := kcp.NewNoneBlockCrypt(nil)
	sess, err := kcp.NewConn3(0, tunnelAddr, block, 0, 0, pc)
	if err != nil {
		return nil, fmt.Errorf("kcp.NewConn3: %w", err)
	}
	sm.KCPSession = sess
	sm.KCPConn = sess

	sess.SetMtu(kcpMTU)
	sess.SetWindowSize(kcpSndWnd, kcpRcvWnd)
	sess.SetNoDelay(kcpNoDelay, kcpInterval, kcpResend, kcpNC)
	sess.SetStreamMode(true)
	sess.SetACKNoDelay(true)

	// yamux on top of the KCP connection
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.MaxStreamWindowSize = 256 * 1024
	yamuxCfg.KeepAliveInterval = 10 * time.Second
	yamuxCfg.ConnectionWriteTimeout = 30 * time.Second
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.LogOutput = io.Discard

	if isServer {
		sm.Mux, err = yamux.Server(sess, yamuxCfg)
	} else {
		sm.Mux, err = yamux.Client(sess, yamuxCfg)
	}
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("yamux init: %w", err)
	}

	lg.Printf("STREAM ✓ KCP+yamux ready (server=%v mtu=%d sndwnd=%d rcvwnd=%d minrto=%dms)",
		isServer, kcpMTU, kcpSndWnd, kcpRcvWnd, kcpMinRTO)
	return sm, nil
}

// AcceptStream blocks until a peer opens a new yamux stream. Server-side only.
func (sm *StreamManager) AcceptStream() (net.Conn, error) {
	return sm.Mux.Accept()
}

// OpenStream opens a new yamux stream to the peer. Client-side.
func (sm *StreamManager) OpenStream() (net.Conn, error) {
	return sm.Mux.Open()
}

// Close tears down yamux, KCP, and the underlying PacketConn.
func (sm *StreamManager) Close() error {
	if sm.Mux != nil {
		sm.Mux.Close()
	}
	if sm.KCPSession != nil {
		sm.KCPSession.Close()
	}
	if sm.PacketConn != nil {
		sm.PacketConn.Close()
	}
	return nil
}
