// SRTP-framed listener implementing [relay.Handle]. Each accepted
// session arrives as a [net.Conn] from the srtp.go demux+handshake
// machinery; this file dials the local WG endpoint and pumps bytes
// in both directions, plus echoes liveness-probe sentinels back to
// the client (parity with anton48 server pumpBidirectional).

package vkturnsrtp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay"
)

// listener implements [relay.Handle] over the SRTP Server.
type listener struct {
	cfg relay.Config
	log *log.Logger

	srv    *Server
	ctx    context.Context
	cancel context.CancelFunc

	wg sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	active        atomic.Uint64
	totalAccepted atomic.Uint64
	lastErr       atomic.Pointer[string]
}

func newListener(setupCtx context.Context, cfg relay.Config) (*listener, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("vkturnsrtp: Config.ListenAddr is empty")
	}
	if cfg.ConnectAddr == "" {
		return nil, errors.New("vkturnsrtp: Config.ConnectAddr is empty")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(discardWriter{}, "", 0)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("vkturnsrtp: resolve %s: %w", cfg.ListenAddr, err)
	}
	_ = setupCtx // currently unused; reserved for forward-compat with cert-pinning hooks

	srv, err := Listen(udpAddr)
	if err != nil {
		return nil, fmt.Errorf("vkturnsrtp: listen: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	l := &listener{
		cfg:    cfg,
		log:    logger,
		srv:    srv,
		ctx:    runCtx,
		cancel: cancel,
	}

	l.wg.Add(1)
	go l.acceptLoop()

	logger.Printf("vkturnsrtp: listening on %s → %s", cfg.ListenAddr, cfg.ConnectAddr)
	return l, nil
}

func (l *listener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.srv.Accept(l.ctx)
		if err != nil {
			select {
			case <-l.ctx.Done():
				return
			default:
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			l.recordErr(err)
			l.log.Printf("vkturnsrtp: accept: %v", err)
			// Same posture as vkturn: srtp.Server keeps the listening
			// socket alive across individual handshake failures, so we
			// loop and let it yield the next conn.
			continue
		}
		l.totalAccepted.Add(1)
		l.wg.Add(1)
		go l.handle(conn)
	}
}

func (l *listener) handle(conn net.Conn) {
	defer l.wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			l.log.Printf("vkturnsrtp: close incoming %s: %v", conn.RemoteAddr(), err)
		}
	}()

	l.active.Add(1)
	defer l.active.Add(^uint64(0))

	l.log.Printf("vkturnsrtp: session up from %s", conn.RemoteAddr())
	l.forwardUDP(conn)
	l.log.Printf("vkturnsrtp: session closed: %s", conn.RemoteAddr())
}

// forwardUDP pumps bytes bidirectionally between the SRTP-wrapped
// session and a fresh local UDP socket dialled to ConnectAddr.
// Includes the probe-echo gate from anton48: a sentinel packet
// (0xff 'P' 'N' 'G' + 8-byte BE seq) goes BACK to the client
// verbatim rather than being forwarded to WG. Without this echo
// the client's zombie-detection (post-iOS-wake) stays dormant.
func (l *listener) forwardUDP(conn net.Conn) {
	serverConn, err := net.Dial("udp", l.cfg.ConnectAddr)
	if err != nil {
		l.recordErr(err)
		l.log.Printf("vkturnsrtp: dial backend %s: %v", l.cfg.ConnectAddr, err)
		return
	}
	defer func() {
		if err := serverConn.Close(); err != nil {
			l.log.Printf("vkturnsrtp: close backend conn: %v", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	sessCtx, sessCancel := context.WithCancel(l.ctx)
	defer sessCancel()

	context.AfterFunc(sessCtx, func() {
		_ = conn.SetDeadline(time.Now())
		_ = serverConn.SetDeadline(time.Now())
	})

	logIOErr := func(stage string, err error) {
		if isExpectedShutdownErr(sessCtx, err) {
			return
		}
		l.log.Printf("vkturnsrtp: %s: %v", stage, err)
	}

	// client → backend (with probe-echo gate)
	go func() {
		defer wg.Done()
		defer sessCancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-sessCtx.Done():
				return
			default:
			}
			if err := conn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				logIOErr("set srtp read deadline", err)
				return
			}
			n, err := conn.Read(buf)
			if err != nil {
				logIOErr("srtp read", err)
				return
			}
			if isProbePacket(buf[:n]) {
				// Echo verbatim back through the SRTP conn instead of
				// forwarding to local WG (where it would be dropped as
				// an invalid wg message type, leaving the client's
				// liveness check dormant).
				if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					logIOErr("set srtp probe-echo deadline", err)
					return
				}
				if _, err := conn.Write(buf[:n]); err != nil {
					logIOErr("srtp probe-echo write", err)
					return
				}
				continue
			}
			if err := serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				logIOErr("set backend write deadline", err)
				return
			}
			if _, err := serverConn.Write(buf[:n]); err != nil {
				logIOErr("backend write", err)
				return
			}
		}
	}()
	// backend → client
	go func() {
		defer wg.Done()
		defer sessCancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-sessCtx.Done():
				return
			default:
			}
			if err := serverConn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				logIOErr("set backend read deadline", err)
				return
			}
			n, err := serverConn.Read(buf)
			if err != nil {
				logIOErr("backend read", err)
				return
			}
			if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				logIOErr("set srtp write deadline", err)
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				logIOErr("srtp write", err)
				return
			}
		}
	}()
	wg.Wait()
}

func (l *listener) Status() relay.Status {
	st := relay.Status{
		Running:           true,
		ListenAddr:        l.cfg.ListenAddr,
		ActiveConnections: l.active.Load(),
		TotalAccepted:     l.totalAccepted.Load(),
	}
	select {
	case <-l.ctx.Done():
		st.Running = false
	default:
	}
	if e := l.lastErr.Load(); e != nil {
		st.LastErr = *e
	}
	return st
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		l.closeErr = l.srv.Close()
		l.wg.Wait()
	})
	return l.closeErr
}

func (l *listener) recordErr(err error) {
	if err == nil {
		return
	}
	s := err.Error()
	l.lastErr.Store(&s)
}

// isProbePacket reports whether the payload is a client liveness probe
// (12-byte sentinel `0xff 'P' 'N' 'G' + 8-byte BE seq`). The leading
// 4 bytes are sufficient to recognise it; the seq bytes that follow
// are echoed verbatim so the client can correlate.
func isProbePacket(p []byte) bool {
	return len(p) >= 4 && p[0] == 0xff && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
}

// isExpectedShutdownErr is the same fact-check as the vkturn listener's
// version: silence the per-session goroutine log spam from
// SetDeadline(now)-poked Read/Write returns or peer-initiated EOF.
// Duplicated here to keep vkturnsrtp independent of vkturn.
func isExpectedShutdownErr(sessCtx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if sessCtx.Err() != nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// discardWriter satisfies io.Writer for the nil-Logger fallback.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
