package proxy

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sv9toslavPinigin/goloom-server/internal/tunnel"
)

// Server accepts yamux streams from the tunnel and dials the requested
// target on the open internet. Runs on the VPS side.
type Server struct {
	SM     *tunnel.StreamManager
	Logger *log.Logger

	ActiveConns atomic.Int64
	TotalConns  atomic.Int64
}

func (s *Server) Run(ctx context.Context) error {
	s.Logger.Printf("PROXY-SERVER listening for yamux streams")
	for {
		stream, err := s.SM.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.TotalConns.Add(1)
		s.ActiveConns.Add(1)
		go s.handleStream(ctx, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, stream net.Conn) {
	defer stream.Close()
	defer s.ActiveConns.Add(-1)
	connID := s.TotalConns.Load()

	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		s.Logger.Printf("PROXY-SERVER [%d] read target: %v", connID, err)
		fmt.Fprintf(stream, "ERR: %v\n", err)
		return
	}
	target := strings.TrimSpace(line)
	stream.SetReadDeadline(time.Time{})

	if target == "" {
		s.Logger.Printf("PROXY-SERVER [%d] empty target", connID)
		fmt.Fprintf(stream, "ERR: empty target\n")
		return
	}

	s.Logger.Printf("PROXY-SERVER [%d] → dialing %s", connID, target)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	remote, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		s.Logger.Printf("PROXY-SERVER [%d] dial %s: %v", connID, target, err)
		fmt.Fprintf(stream, "ERR: %v\n", err)
		return
	}
	defer remote.Close()

	if _, err := fmt.Fprintf(stream, "OK\n"); err != nil {
		s.Logger.Printf("PROXY-SERVER [%d] write OK: %v", connID, err)
		return
	}

	s.Logger.Printf("PROXY-SERVER [%d] connected to %s — relaying", connID, target)
	stats := &RelayStats{}
	Relay(stream, remote, stats)
	s.Logger.Printf("PROXY-SERVER [%d] done %s (up=%d down=%d)", connID, target,
		stats.BytesUp.Load(), stats.BytesDown.Load())
}
