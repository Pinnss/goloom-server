// SRTP-framed listener implementing [relay.Handle]. Each accepted
// session arrives as a [net.Conn] from the srtp.go demux+handshake
// machinery; this file pumps bytes between each SRTP conn and the
// WireGuard socket its group shares (see group.go), echoes
// liveness-probe sentinels back to the client, and gates group hellos.

package vkturnsrtp

import (
	"context"
	"crypto/rand"
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

	// groups maps a client's group id to the shared WireGuard socket its
	// allocations feed. See group.go for why one socket per client matters.
	groups *groupRegistry

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
		groups: newGroupRegistry(),
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

// srtpIdleDeadline is how long a relayed SRTP conn may sit silent before its
// read fails; srtpDeadlineRearm is how often we bother pushing that deadline
// forward. The gap between them is what keeps the timer churn bounded.
const (
	srtpIdleDeadline  = 30 * time.Minute
	srtpDeadlineRearm = 1 * time.Minute
)

// forwardUDP pumps bytes bidirectionally between the SRTP-wrapped
// session and a fresh local UDP socket dialled to ConnectAddr.
// Includes the probe-echo gate from anton48: a sentinel packet
// (0xff 'P' 'N' 'G' + 8-byte BE seq) goes BACK to the client
// verbatim rather than being forwarded to WG. Without this echo
// the client's zombie-detection (post-iOS-wake) stays dormant.
func (l *listener) forwardUDP(conn net.Conn) {
	sessCtx, sessCancel := context.WithCancel(l.ctx)
	defer sessCancel()

	logIOErr := func(stage string, err error) {
		if isExpectedShutdownErr(sessCtx, err) {
			return
		}
		l.log.Printf("vkturnsrtp: %s: %v", stage, err)
	}
	dialWG := func() (net.Conn, error) {
		c, err := net.Dial("udp", l.cfg.ConnectAddr)
		if err != nil {
			l.recordErr(err)
			l.log.Printf("vkturnsrtp: dial backend %s: %v", l.cfg.ConnectAddr, err)
			return nil, err
		}
		return c, nil
	}

	// The group stays UNKNOWN until the client announces one. Joining a
	// throwaway group up front was a total-outage bug: the client's first packet
	// is its hello, moving to the real group emptied the throwaway, and tearing
	// that down killed the session that had just joined.
	var (
		group   *connGroup
		groupID [groupIDLen]byte
	)
	join := func(id [groupIDLen]byte) bool {
		// A group caught mid-teardown is transient — retry, which creates a
		// fresh one — rather than dropping the session.
		var g *connGroup
		var needPump bool
		for attempt := 0; attempt < 3; attempt++ {
			var err error
			g, needPump, err = l.groups.join(id, conn, dialWG, l.log)
			if err == nil {
				break
			}
			if !errors.Is(err, net.ErrClosed) {
				logIOErr("group join", err)
				return false
			}
			g = nil
		}
		if g == nil {
			logIOErr("group join", net.ErrClosed)
			return false
		}
		if group != nil {
			l.groups.leave(group, conn)
		}
		group, groupID = g, id
		if needPump {
			// The pump serves the GROUP, so it runs under the listener context,
			// never under this member's session: one member leaving must not
			// silence everyone else's downlink.
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				g.runDownlink(l.ctx, logIOErr)
			}()
		}
		return true
	}
	defer func() {
		if group != nil {
			l.groups.leave(group, conn)
		}
	}()

	context.AfterFunc(sessCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	// client → WireGuard, with the probe echo and the group hello gated out.
	buf := make([]byte, 1600)
	var lastDeadline time.Time
	for {
		select {
		case <-sessCtx.Done():
			return
		default:
		}
		// Re-arm the idle deadline sparingly, not per packet: it only has to be
		// in the future, and each call used to allocate a timer plus a channel
		// that lived for the full 30 minutes (see deadline.go).
		if time.Since(lastDeadline) > srtpDeadlineRearm {
			if err := conn.SetReadDeadline(time.Now().Add(srtpIdleDeadline)); err != nil {
				logIOErr("set srtp read deadline", err)
				return
			}
			lastDeadline = time.Now()
		}
		n, err := conn.Read(buf)
		if err != nil {
			logIOErr("srtp read", err)
			return
		}
		if isProbePacket(buf[:n]) {
			// Echo verbatim instead of forwarding to WireGuard, where it would
			// be dropped as an invalid message type and leave the client's
			// liveness check dormant.
			if err := conn.SetWriteDeadline(time.Now().Add(groupWriteTimeout)); err != nil {
				logIOErr("set srtp probe-echo deadline", err)
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				logIOErr("srtp probe-echo write", err)
				return
			}
			continue
		}
		if id, ok := ParseGroupHello(buf[:n]); ok {
			// Re-announcing the same id is a no-op — the client repeats the
			// hello alongside its liveness probe so a single lost datagram
			// cannot silently leave this allocation ungrouped. A different id
			// moves this conn, which is how a client rotates after a path change.
			if (group == nil || id != groupID) && !join(id) {
				return
			}
			continue
		}
		if group == nil {
			// No hello ever arrived: an older client. Give it a group of one,
			// keyed by a random id — the pre-grouping behaviour.
			if _, err := rand.Read(groupID[:]); err != nil {
				logIOErr("group id", err)
				return
			}
			if !join(groupID) {
				return
			}
		}
		if err := group.writeUplink(buf[:n]); err != nil {
			logIOErr("group wg write", err)
			return
		}
	}
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
