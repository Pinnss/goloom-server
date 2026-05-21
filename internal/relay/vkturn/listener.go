// DTLS-over-UDP listener that mirrors vk-turn-proxy server (see
// Moroka8/vk-turn-proxy PR #162). Binds a UDP socket, terminates DTLS
// (optionally wrapped in ChaCha20-XOR obfuscation), and forwards
// decrypted payload to a local UDP target — typically a kernel
// WireGuard instance.
//
// The wire protocol is identical to the upstream Moroka8 server, so a
// goloom-wg-server using this package is a drop-in replacement for
// running vk-turn-server as a separate systemd unit. Same flags map
// to the same fields:
//   -listen  → relay.Config.ListenAddr
//   -connect → relay.Config.ConnectAddr
//   -wrap    → Options.UseWrap
//   -wrap-key → Options.WrapKey (hex-decoded, 32 bytes)
//   -debug   → Options.Debug
//
// Not ported: -vless / -vless-bond. Those carry TCP for Xray/VLESS
// proxies, which is outside goloom's scope (WG = UDP).
package vkturn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/relay"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// listener is the running handle returned by [Transport.Start]. It
// implements [relay.Handle].
type listener struct {
	cfg  relay.Config
	opts Options
	log  *log.Logger

	netListener net.Listener
	ctx         context.Context
	cancel      context.CancelFunc

	wg sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	active        atomic.Uint64
	totalAccepted atomic.Uint64
	lastErr       atomic.Pointer[string]
}

// newListener binds the socket, sets up the DTLS server, kicks off
// the accept loop in a goroutine, and returns once the listener is
// ready to receive (i.e. binding succeeded). Bring-up failures
// surface as a non-nil error; no goroutine leaks on the error path.
func newListener(setupCtx context.Context, cfg relay.Config) (*listener, error) {
	opts, _ := cfg.Options.(Options)
	if opts.UseWrap && len(opts.WrapKey) != wrapKeyLen {
		return nil, fmt.Errorf("vkturn: UseWrap=true but WrapKey is %d bytes (need %d)", len(opts.WrapKey), wrapKeyLen)
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("vkturn: Config.ListenAddr is empty")
	}
	if cfg.ConnectAddr == "" {
		return nil, errors.New("vkturn: Config.ConnectAddr is empty")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(discardWriter{}, "", 0)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("vkturn: resolve %s: %w", cfg.ListenAddr, err)
	}

	// Self-signed cert per process lifetime — clients don't verify it
	// (DTLS here is for confidentiality + DPI obfuscation, not auth;
	// auth is the inner WireGuard handshake).
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("vkturn: generate self-signed cert: %w", err)
	}

	dtlsOpts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	}

	var netLn net.Listener
	if opts.UseWrap {
		logger.Printf("vkturn: WRAP enabled — clients without matching key will be rejected at DTLS handshake")
		wrapLn, werr := listenWrapped(udpAddr, opts.WrapKey)
		if werr != nil {
			return nil, fmt.Errorf("vkturn: bind wrap listener: %w", werr)
		}
		netLn, err = dtls.NewListenerWithOptions(wrapLn, dtlsOpts...)
	} else {
		netLn, err = dtls.ListenWithOptions("udp", udpAddr, dtlsOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("vkturn: dtls listen: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	_ = setupCtx // ctx only used for setup (not honoured for cancellation now — kept on signature for forward-compat)

	l := &listener{
		cfg:         cfg,
		opts:        opts,
		log:         logger,
		netListener: netLn,
		ctx:         runCtx,
		cancel:      cancel,
	}

	l.wg.Add(1)
	go l.acceptLoop()

	logger.Printf("vkturn: listening on %s → %s (wrap=%v debug=%v)", cfg.ListenAddr, cfg.ConnectAddr, opts.UseWrap, opts.Debug)
	return l, nil
}

func (l *listener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.netListener.Accept()
		if err != nil {
			// Net listener closed → expected on Close().
			select {
			case <-l.ctx.Done():
				return
			default:
			}
			l.recordErr(err)
			l.log.Printf("vkturn: accept: %v", err)
			// Transient accept errors shouldn't kill the loop —
			// the underlying UDP socket survives, and the DTLS
			// listener will yield the next connection. Match
			// upstream behaviour (`log.Println(err); continue`).
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
			l.log.Printf("vkturn: close incoming %s: %v", conn.RemoteAddr(), err)
		}
	}()

	l.active.Add(1)
	defer l.active.Add(^uint64(0)) // decrement

	// DTLS handshake with 30s deadline — matches upstream.
	hsCtx, hsCancel := context.WithTimeout(l.ctx, 30*time.Second)
	defer hsCancel()

	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		l.log.Printf("vkturn: accepted conn is not *dtls.Conn (got %T)", conn)
		return
	}
	if err := dtlsConn.HandshakeContext(hsCtx); err != nil {
		l.recordErr(err)
		l.log.Printf("vkturn: handshake from %s: %v", conn.RemoteAddr(), err)
		return
	}

	l.forwardUDP(conn)
}

// forwardUDP runs the bidirectional copy loop between an accepted DTLS
// connection and a fresh UDP socket dialled to ConnectAddr. Verbatim
// adaptation of upstream handleUDPConnection (PR #162 main.go ~L716)
// — same buffer sizes, same deadlines.
func (l *listener) forwardUDP(conn net.Conn) {
	serverConn, err := net.Dial("udp", l.cfg.ConnectAddr)
	if err != nil {
		l.recordErr(err)
		l.log.Printf("vkturn: dial backend %s: %v", l.cfg.ConnectAddr, err)
		return
	}
	defer func() {
		if err := serverConn.Close(); err != nil {
			l.log.Printf("vkturn: close backend conn: %v", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	sessCtx, sessCancel := context.WithCancel(l.ctx)
	defer sessCancel()

	stats := &throughputStats{}
	if l.opts.Debug {
		go stats.logEvery(sessCtx, l.log, fmt.Sprintf("[DTLS %s]", conn.RemoteAddr()), "dtls-to-backend", "backend-to-dtls")
	}

	// Cancellation propagation: when sessCtx fires, force both ends
	// to wake from their blocked reads via SetDeadline(time.Now()).
	context.AfterFunc(sessCtx, func() {
		_ = conn.SetDeadline(time.Now())
		_ = serverConn.SetDeadline(time.Now())
	})

	// dtls → backend
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
				l.log.Printf("vkturn: set dtls read deadline: %v", err)
				return
			}
			n, err := conn.Read(buf)
			if err != nil {
				l.log.Printf("vkturn: dtls read: %v", err)
				return
			}
			if err := serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				l.log.Printf("vkturn: set backend write deadline: %v", err)
				return
			}
			written, err := serverConn.Write(buf[:n])
			stats.addTx(written)
			if err != nil {
				l.log.Printf("vkturn: backend write: %v", err)
				return
			}
		}
	}()
	// backend → dtls
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
				l.log.Printf("vkturn: set backend read deadline: %v", err)
				return
			}
			n, err := serverConn.Read(buf)
			if err != nil {
				l.log.Printf("vkturn: backend read: %v", err)
				return
			}
			if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				l.log.Printf("vkturn: set dtls write deadline: %v", err)
				return
			}
			written, err := conn.Write(buf[:n])
			stats.addRx(written)
			if err != nil {
				l.log.Printf("vkturn: dtls write: %v", err)
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

// Close stops accepting new connections, force-closes the underlying
// listener so the accept goroutine exits, cancels per-session ctx, and
// waits for goroutines to drain. Idempotent and goroutine-safe.
func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()                              // signals accept loop + per-session loops
		l.closeErr = l.netListener.Close()      // unblocks Accept()
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

// discardWriter satisfies io.Writer for the nil-Logger fallback.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
