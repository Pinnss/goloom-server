package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sv9toslavPinigin/goloom-server/internal/tunnel"
)

// SOCKS5 server that listens locally and forwards connections through the
// tunnel via yamux streams. Runs on the client (PC) side.
type SOCKS5Server struct {
	SM       *tunnel.StreamManager
	Logger   *log.Logger
	Listener net.Listener

	ActiveConns atomic.Int64
	TotalConns  atomic.Int64
}

// ListenAndServe binds to addr (e.g. "127.0.0.1:1080") and accepts SOCKS5
// connections until ctx is done.
func (s *SOCKS5Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.Listener = ln
	s.Logger.Printf("SOCKS5 listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.TotalConns.Add(1)
		s.ActiveConns.Add(1)
		go s.handleConn(ctx, conn)
	}
}

func (s *SOCKS5Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer s.ActiveConns.Add(-1)
	connID := s.TotalConns.Load()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// --- SOCKS5 handshake (RFC 1928) ---
	// Client greeting: VER NMETHODS METHODS
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		s.Logger.Printf("SOCKS5 [%d] greeting read: %v", connID, err)
		return
	}
	if header[0] != 0x05 {
		s.Logger.Printf("SOCKS5 [%d] unsupported version %d", connID, header[0])
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		s.Logger.Printf("SOCKS5 [%d] methods read: %v", connID, err)
		return
	}

	// No auth required (0x00). If client doesn't offer it, reject.
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// --- SOCKS5 request ---
	// VER CMD RSV ATYP DST.ADDR DST.PORT
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		s.Logger.Printf("SOCKS5 [%d] request read: %v", connID, err)
		return
	}
	if req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		s.socksReply(conn, 0x07) // command not supported
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		s.socksReply(conn, 0x08) // address type not supported
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := fmt.Sprintf("%s:%d", host, port)

	s.Logger.Printf("SOCKS5 [%d] CONNECT %s", connID, target)

	// Open yamux stream to tunnel server
	stream, err := s.SM.OpenStream()
	if err != nil {
		s.Logger.Printf("SOCKS5 [%d] open stream: %v", connID, err)
		s.socksReply(conn, 0x01) // general failure
		return
	}
	defer stream.Close()

	// Send target to server
	if _, err := fmt.Fprintf(stream, "%s\n", target); err != nil {
		s.Logger.Printf("SOCKS5 [%d] send target: %v", connID, err)
		s.socksReply(conn, 0x01)
		return
	}

	// Wait for server response
	stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(stream)
	resp, err := reader.ReadString('\n')
	if err != nil {
		s.Logger.Printf("SOCKS5 [%d] server response: %v", connID, err)
		s.socksReply(conn, 0x01)
		return
	}
	stream.SetReadDeadline(time.Time{})
	resp = strings.TrimSpace(resp)

	if resp != "OK" {
		s.Logger.Printf("SOCKS5 [%d] server rejected: %s", connID, resp)
		s.socksReply(conn, 0x05) // connection refused
		return
	}

	// Success — tell SOCKS5 client we're connected
	s.socksReply(conn, 0x00)
	conn.SetDeadline(time.Time{})

	s.Logger.Printf("SOCKS5 [%d] connected %s — relaying", connID, target)
	stats := &RelayStats{}
	Relay(conn, stream, stats)
	s.Logger.Printf("SOCKS5 [%d] done %s (up=%d down=%d)", connID, target,
		stats.BytesUp.Load(), stats.BytesDown.Load())
}

func (s *SOCKS5Server) socksReply(conn net.Conn, rep byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
