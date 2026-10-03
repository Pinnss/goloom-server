// conn.Bind adapter that lets wireguard-go talk through a pool of
// vkturnsrtp.Client wrapped sessions as if it were a single UDP
// socket.
//
// Why a pool: VK shapes per-allocation TURN traffic; spreading the
// load over many parallel allocations multiplies tunnel throughput
// roughly N× (anton48 build125 ships 10 by default, the same value
// we use here unless the caller overrides). On the send side we
// round-robin packets; on the receive side every per-conn read
// goroutine fans its packets into a single channel which the
// ReceiveFunc drains. WG userspace sees one stream of bytes — it
// has no idea there's a 10-way carrier swap going on underneath.
//
// Liveness: each conn runs a probe sender that emits a sentinel
// packet (magic 0xff 'P' 'N' 'G' + 8-byte BE seq) every probeInterval.
// The patched goloom server echoes those back; the read loop spots
// the magic and records the pong arrival time. A watchdog then kills
// any conn whose last pong is older than probeStaleThreshold (and at
// least one pong was seen at all, so we know the server is patched).
// Dead conns are dropped from the round-robin; if every conn dies
// the bind's Close fires, supervisor restarts the session.
//
// Single-conn behaviour is preserved when N==1 — the pool degrades
// to the original direct-write / direct-read path with no extra
// fan-in but the probe machinery still runs.

package wgclient

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// SRTPBind implements [conn.Bind] over one-or-many SRTP-wrapped conns.
type SRTPBind struct {
	// ctx is cancelled by Close so an in-flight Redial aborts.
	ctx       context.Context
	cancelCtx context.CancelFunc

	mu      sync.Mutex
	open    bool
	closing bool // set under mu before Shutdown waits, so tryRedial stops adding
	started bool // reader/probe/watchdog goroutines have been spawned

	// closed signals PERMANENT shutdown and is closed only by Shutdown. Every
	// long-lived goroutine (readers, probes, watchdog) keys off it, so they
	// survive the Close/Open cycling that wireguard-go does below.
	closed chan struct{}

	// stopRecv unblocks the CURRENT Open's ReceiveFunc and is replaced on each
	// Open. It exists because conn.Bind.Close does not mean "tear everything
	// down": device.Up() runs BindUpdate, which calls bind.Close() and then
	// bind.Open() on the way up. Close used to close the SRTP conns outright,
	// so every allocation died ~14 ms before the first handshake and the
	// tunnel reported "ready" while being unable to send a single byte. The
	// conns are owned by the caller's pool and cannot be rebuilt synchronously
	// inside Open, so Close now only stops the receive side; Shutdown is what
	// releases the conns.
	stopRecv chan struct{}

	// One slot per TURN allocation, read atomically: a slot's conn can be
	// swapped out by the watchdog while Send is running. Owned — Close()
	// closes whatever each slot currently holds.
	slots []atomic.Pointer[connBox]

	// Redial, when set, re-establishes the transport for one slot (a fresh
	// TURN allocation plus its DTLS-SRTP handshake). Without it a dead slot
	// stays dead for the life of the session, which is how the tunnel used to
	// rot: allocations died one by one and nothing replaced them, so the pool
	// silently shrank to zero while the UI still said "On".
	// The context is cancelled when the bind closes, so a teardown aborts a
	// TURN allocate plus DTLS handshake in progress instead of waiting out its
	// ~20 s budget.
	Redial func(ctx context.Context, idx int) (net.Conn, error)

	// GroupHello, when set, is re-sent on every conn alongside each liveness
	// probe. The server treats a repeat of the same id as a no-op, so this is
	// free insurance: the hello is a single datagram over a lossy relay, and
	// losing it silently leaves that allocation ungrouped — which quietly
	// restores the endpoint roaming the grouping exists to prevent.
	GroupHello []byte

	logger *log.Logger // optional; nil disables probe-loop logging

	// Round-robin send counter. Atomic so Send is safe from any goroutine.
	rrNext atomic.Uint64

	// Fan-in: per-conn goroutines push received packets here, the
	// ReceiveFunc drains. Buffered enough to ride out a brief WG-side
	// stall without blocking the readers.
	rxCh   chan rxPacket
	rxWG   sync.WaitGroup // reader goroutines, drained on Close
	rxOnce sync.Once      // start reader goroutines lazily on first Open

	// Per-conn liveness state. Indexed by the position in `conns` at
	// Open() time. lastPongUnix stores Unix seconds of the most recent
	// probe-echo for conn i; dead[i] is set when the watchdog gives up
	// on a conn (subsequent Send picks skip it).
	lastPongUnix  []atomic.Int64
	pingSeq       []atomic.Uint64
	dead          []atomic.Bool
	serverProbed  atomic.Bool // any pong ever seen → probes are armed
	quotaLogged   atomic.Bool // say "out of quota" once, not per slot per cycle
	expiredLogged atomic.Bool // likewise for expired credentials

	// nextRedialUnix[i] throttles slot i's replacement attempts, so a VK-side
	// outage cannot turn into an allocate storm.
	nextRedialUnix []atomic.Int64

	// TxBytes / RxBytes are the tunnel's real byte counters. They exist so the
	// UI can tell a stalled tunnel from an idle one; before this the SRTP path
	// reported zero forever and a dead tunnel looked exactly like a quiet one.
	TxBytes atomic.Uint64
	RxBytes atomic.Uint64
}

// connBox wraps a conn so it can live in an atomic.Pointer.
type connBox struct{ c net.Conn }

type rxPacket struct {
	data []byte
}

const (
	srtpBindRxBufSize = 256

	// probePingMagic / probeInterval / probeStaleThreshold mirror the
	// anton48/vk-turn-proxy-ios constants so wire-compat with their iOS
	// client is preserved. Server side (internal/relay/vkturn(srtp))
	// recognises the same magic and echoes verbatim — pre-PR-2 servers
	// just drop the packets and serverProbed stays false (zero-cost
	// degradation, behaviour identical to a pre-probe build).
	probeInterval       = 30 * time.Second
	probeStaleThreshold = 120 * time.Second

	// redialBackoff throttles per-slot replacement attempts so a VK-side
	// outage cannot turn into an allocate storm (VK rate-limits allocates and
	// answers 486 past 10 per credential).
	redialBackoff = 15 * time.Second

	// shutdownGrace bounds how long teardown waits for the bind's goroutines.
	// It exists because a TURN allocate ignores context cancellation.
	shutdownGrace = 2 * time.Second

	// quotaRedialBackoff throttles a slot VK refused for want of quota. The
	// ordinary backoff is far too eager for that: with numConnections set above
	// VK's per-credential ceiling (20, measured) every surplus slot is born
	// dead, so the watchdog asked for ~30 doomed allocations every 15 s,
	// forever. VK throttles a credential that asks too often, which puts the
	// allocations we DO hold at risk.
	quotaRedialBackoff = 10 * time.Minute
)

var probePingMagic = []byte{0xff, 'P', 'N', 'G'}

// bindPktPool recycles per-packet byte buffers between readerLoop
// (the producer that copies one packet's worth of bytes out of the
// underlying wrappedConn.Read scratch buffer) and the WG-bound recv
// closure (the consumer that copies into WG's destination slice and
// is then done with the buffer). Backports anton48 build133 GC-pressure
// fix to the goloom client side — same ~2400 pkts/s × ~5 MB/s of
// allocations get recycled instead of churning the heap.
//
// Pool stores *[]byte pointers to avoid the per-Put interface-boxing
// allocation that bare []byte values would incur.
var bindPktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

func bindPktPoolGet(n int) []byte {
	pp := bindPktPool.Get().(*[]byte)
	p := *pp
	if cap(p) < n {
		p = make([]byte, n)
	} else {
		p = p[:n]
	}
	return p
}

func bindPktPoolPut(b []byte) {
	if cap(b) < 2048 {
		return
	}
	b = b[:0]
	bindPktPool.Put(&b)
}

// NewSRTPBind takes ownership of conns — Close() will close them all.
// Empty or nil slice is a programmer error. logger may be nil (silent
// probe loop); usually you want to wire it to the session's *log.Logger.
func NewSRTPBind(conns []net.Conn) *SRTPBind {
	if len(conns) == 0 {
		conns = nil
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	b := &SRTPBind{
		ctx:            ctx,
		cancelCtx:      cancelCtx,
		closed:         make(chan struct{}),
		rxCh:           make(chan rxPacket, srtpBindRxBufSize),
		slots:          make([]atomic.Pointer[connBox], len(conns)),
		lastPongUnix:   make([]atomic.Int64, len(conns)),
		pingSeq:        make([]atomic.Uint64, len(conns)),
		dead:           make([]atomic.Bool, len(conns)),
		nextRedialUnix: make([]atomic.Int64, len(conns)),
	}
	for i, c := range conns {
		if c == nil {
			// A slot the pool could not establish. It keeps its index — the
			// bind and the pool must agree on what slot i means — and starts
			// dead so the watchdog redials it instead of Send picking it.
			b.dead[i].Store(true)
			continue
		}
		b.slots[i].Store(&connBox{c: c})
	}
	return b
}

// SetLogger optionally wires a logger for the probe loop. Call before
// Open() — once readers are running, switching the logger has no effect
// on existing goroutines.
func (b *SRTPBind) SetLogger(lg *log.Logger) {
	b.mu.Lock()
	b.logger = lg
	b.mu.Unlock()
}

func (b *SRTPBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, errors.New("SRTPBind: already open")
	}
	if len(b.slots) == 0 {
		return nil, 0, errors.New("SRTPBind: no SRTP conns")
	}
	select {
	case <-b.closed:
		// Shut down for good: every slot is empty and rxCh is closed, so an
		// "Open" here would hand wireguard-go a bind that reports ready and
		// cannot move a byte — exactly the failure this split exists to end.
		return nil, 0, net.ErrClosed
	default:
	}
	b.open = true
	b.stopRecv = make(chan struct{})
	stop := b.stopRecv

	// Reader + probe goroutines per conn. Reader allocates its own buf
	// to avoid concurrent writes; probe sender uses a tiny dedicated
	// buffer (12 bytes per ping). Watchdog runs once per bind.
	b.rxOnce.Do(func() {
		for i := range b.slots {
			box := b.slots[i].Load()
			if box == nil {
				continue
			}
			b.rxWG.Add(2)
			go b.readerLoop(i, box.c)
			go b.probeSenderLoop(i, box.c)
		}
		b.rxWG.Add(1)
		go b.zombieWatchdog()
		b.started = true
	})

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		select {
		case pkt, ok := <-b.rxCh:
			if !ok {
				return 0, net.ErrClosed
			}
			n := copy(packets[0], pkt.data)
			bindPktPoolPut(pkt.data)
			sizes[0] = n
			eps[0] = srtpEndpoint{}
			return 1, nil
		case <-stop:
			return 0, net.ErrClosed
		case <-b.closed:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recv}, 0, nil
}

// readerLoop drains one SRTP conn. Probe-echo packets (magic 0xff PNG)
// update b.lastPongUnix[i] and don't make it to WG. Everything else
// goes to the fan-in channel.
func (b *SRTPBind) readerLoop(idx int, c net.Conn) {
	defer b.rxWG.Done()
	// A replaced conn's reader ends when its conn is closed, which tryRedial
	// does — no generation check is needed here, but the slot must never be
	// judged by this conn again.
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if n >= 4 && buf[0] == 0xff && buf[1] == 'P' && buf[2] == 'N' && buf[3] == 'G' {
			b.lastPongUnix[idx].Store(time.Now().Unix())
			b.serverProbed.Store(true)
			continue // never deliver probe-echo to WG userspace
		}
		// Copy to a per-packet slice so the next Read can reuse buf.
		// Buffer is pulled from bindPktPool; recv closure Puts it back
		// after copying out to WG's destination.
		b.RxBytes.Add(uint64(n))
		pkt := bindPktPoolGet(n)
		copy(pkt, buf[:n])
		select {
		case b.rxCh <- rxPacket{data: pkt}:
		case <-b.closed:
			bindPktPoolPut(pkt)
			return
		}
	}
}

// probeSenderLoop emits one ping per probeInterval, indefinitely.
// Magic + 8-byte BE sequence number; server-side forwardUDP echoes
// the whole packet verbatim. We don't wait for an echo here — the
// pongUnix update happens asynchronously in the reader. The
// watchdog detects misses.
func (b *SRTPBind) probeSenderLoop(idx int, c net.Conn) {
	defer b.rxWG.Done()
	// Jitter the first ping per conn so 10 conns don't ping at the
	// same wall-clock moment (which would briefly steal a slot from
	// real WG handshake under load).
	startupDelay := time.Duration(idx) * 200 * time.Millisecond
	select {
	case <-time.After(startupDelay):
	case <-b.closed:
		return
	}
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	pkt := make([]byte, len(probePingMagic)+8)
	copy(pkt, probePingMagic)
	for {
		select {
		case <-b.closed:
			return
		case <-t.C:
			// Stop as soon as this conn is no longer the slot's: the loop used
			// to keep probing a replaced conn, whose writes then failed and
			// condemned the healthy successor — the slot flapped forever and
			// burned a fresh VK allocation every cycle.
			if cur := b.slots[idx].Load(); cur == nil || cur.c != c {
				return
			}
			if b.dead[idx].Load() {
				return
			}
			if hello := b.GroupHello; len(hello) > 0 {
				if _, err := c.Write(hello); err != nil {
					// Fall through: the probe write below reports the failure.
					_ = err
				}
			}
			seq := b.pingSeq[idx].Add(1)
			binary.BigEndian.PutUint64(pkt[len(probePingMagic):], seq)
			if _, err := c.Write(pkt); err != nil {
				// Write error → mark dead immediately, watchdog will
				// notice and skip from Send. Don't return — the
				// goroutine exits via b.closed when the bind closes.
				b.dead[idx].Store(true)
				if b.logger != nil {
					b.logger.Printf("srtp-bind: probe send failed on conn %d: %v (marking dead)", idx, err)
				}
			}
		}
	}
}

// zombieWatchdog kills conns whose last pong is older than
// probeStaleThreshold (but only after we've ever seen at least one
// pong — otherwise a pre-probe-aware server would have every conn
// killed within probeStaleThreshold of session start). Runs every
// probeInterval/3 so we don't oversleep a kill by half a probe cycle.
func (b *SRTPBind) zombieWatchdog() {
	defer b.rxWG.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-b.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	t := time.NewTicker(probeInterval / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// The serverProbed gate guards the stale-pong heuristic ONLY. It used
			// to skip the whole loop, so a slot that was dead from the start —
			// which the pool now reports as a nil conn whenever an allocate
			// fails — could never be rebuilt unless some OTHER slot happened to
			// pong first. With every slot born dead, nothing ever healed.
			probed := b.serverProbed.Load()
			now := time.Now().Unix()
			alive := 0
			for i := range b.slots {
				if b.dead[i].Load() || b.slots[i].Load() == nil {
					b.tryRedial(i, now)
					continue
				}
				if !probed {
					alive++
					continue
				}
				last := b.lastPongUnix[i].Load()
				if last > 0 && now-last > int64(probeStaleThreshold/time.Second) {
					b.dead[i].Store(true)
					if box := b.slots[i].Load(); box != nil {
						_ = box.c.Close() // wakes the reader
					}
					if b.logger != nil {
						b.logger.Printf("srtp-bind: conn %d zombie (last pong %ds ago) — killed", i, now-last)
					}
					b.tryRedial(i, now)
					continue
				}
				alive++
			}
			if alive == 0 && b.logger != nil {
				b.logger.Printf("srtp-bind: WARN — all %d conns are dead; replacing them (Redial set: %v)",
					len(b.slots), b.Redial != nil)
			}
		}
	}
}

// tryRedial replaces one dead slot's transport, at most once per
// redialBackoff seconds per slot. A replaced slot rejoins the round-robin
// immediately; if Redial is unset or fails, the slot simply stays dead and we
// try again after the backoff.
func (b *SRTPBind) tryRedial(idx int, nowUnix int64) {
	if b.Redial == nil {
		return
	}
	select {
	case <-b.closed:
		return
	default:
	}
	if next := b.nextRedialUnix[idx].Load(); next > nowUnix {
		return
	}
	b.nextRedialUnix[idx].Store(nowUnix + int64(redialBackoff/time.Second))

	// Dial OUTSIDE b.mu: it can take ~20 s, and Close must not queue behind it.
	// b.ctx is cancelled by Close, which aborts the dial instead of waiting.
	nc, err := b.Redial(b.ctx, idx)
	if err != nil {
		if errors.Is(err, ErrTURNCredentialExpired) {
			// Only a fresh VK authentication can fix this, and that needs the
			// user. Retrying on the ordinary backoff would hammer VK forever
			// with requests that cannot succeed.
			b.nextRedialUnix[idx].Store(nowUnix + int64(quotaRedialBackoff/time.Second))
			if b.logger != nil && !b.expiredLogged.Swap(true) {
				b.logger.Printf("srtp-bind: VK credentials have expired; the tunnel needs a reconnect to re-authenticate")
			}
			return
		}
		if errors.Is(err, ErrTURNQuota) {
			// Nothing changes until one of our own allocations goes away, so
			// stop asking for a while instead of every redialBackoff.
			b.nextRedialUnix[idx].Store(nowUnix + int64(quotaRedialBackoff/time.Second))
			if b.logger != nil && !b.quotaLogged.Swap(true) {
				b.logger.Printf("srtp-bind: VK is out of allocation quota; surplus slots paused for %s", quotaRedialBackoff)
			}
			return
		}
		if b.logger != nil {
			b.logger.Printf("srtp-bind: conn %d redial failed: %v", idx, err)
		}
		return
	}

	// Install under b.mu so the goroutine bookkeeping cannot race Close's
	// rxWG.Wait: an Add after Wait started is a WaitGroup misuse panic, and an
	// Add that sneaks in just before it deadlocks the teardown.
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		_ = nc.Close()
		return
	}
	old := b.slots[idx].Swap(&connBox{c: nc})
	b.lastPongUnix[idx].Store(nowUnix)
	b.dead[idx].Store(false)
	b.rxWG.Add(2)
	b.mu.Unlock()

	if old != nil {
		_ = old.c.Close()
	}
	go b.readerLoop(idx, nc)
	go b.probeSenderLoop(idx, nc)
	if b.logger != nil {
		b.logger.Printf("srtp-bind: conn %d replaced — back in the rotation", idx)
	}
}

// Close implements the [conn.Bind] half of the lifecycle: it stops the current
// receive side and nothing else. wireguard-go calls it on the way UP as well as
// down — device.Up() runs BindUpdate, which closes the bind and immediately
// reopens it — so closing the SRTP conns here killed every TURN allocation
// before the first handshake could use it. Releasing the conns is [Shutdown]'s
// job, and the owner calls that when the tunnel really goes away.
//
// It always reports success: BindUpdate aborts the whole bring-up if Close
// returns an error, and a failure to shut down a receive path is never a reason
// to refuse to start.
func (b *SRTPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	closeOnce(b.stopRecv)
	return nil
}

// Shutdown releases everything the bind owns: it signals permanent shutdown,
// aborts a Redial in flight, closes every SRTP conn, waits for the reader,
// probe and watchdog goroutines to exit, and closes the fan-in channel. The
// bind is unusable afterwards.
//
// It is independent of Open on purpose. A bind that was constructed but never
// opened — which happens on every setup path that fails between NewSRTPBind and
// wireguard-go bringing the device up — must still release its conns, or the
// TURN allocations behind them leak and VK answers 486 past ten per credential.
func (b *SRTPBind) Shutdown() error {
	b.mu.Lock()
	select {
	case <-b.closed:
		b.mu.Unlock()
		return nil // already shut down
	default:
		close(b.closed)
	}
	// Unblock the receive side too: a reader parked on the fan-in channel
	// leaves via b.closed, but wireguard-go may still be inside recv.
	closeOnce(b.stopRecv)
	started := b.started
	b.open = false
	b.closing = true
	// cancelCtx only reaches the socket dial: pion's client.Listen/Allocate
	// take no context (see srtp_turn.go), so a redial past that point runs to
	// completion regardless. The bounded wait below is what keeps teardown
	// from hanging on it.
	b.cancelCtx()
	var firstErr error
	for i := range b.slots {
		box := b.slots[i].Swap(nil)
		if box == nil {
			continue
		}
		if err := box.c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.mu.Unlock()

	// Wait with b.mu RELEASED. tryRedial dials outside the lock and then takes
	// it to install the conn, and the goroutine driving it is the watchdog —
	// which rxWG counts. Waiting for that goroutine while holding the lock it
	// needs deadlocks teardown, and cancelCtx does not save us once the dial
	// has already returned a conn. Releasing first is safe because b.closing is
	// set: a redial landing now closes its conn and adds nothing to rxWG.
	//
	// Wait only if goroutines were ever spawned; b.closed is already closed, so
	// a reader parked on a full rxCh takes that branch instead of wedging us.
	if started {
		done := make(chan struct{})
		go func() { b.rxWG.Wait(); close(done) }()
		select {
		case <-done:
			close(b.rxCh)
		case <-time.After(shutdownGrace):
			// A TURN allocate cannot be cancelled, so a redial in flight holds
			// its goroutine for the full budget. Returning without closing rxCh
			// leaves it to the GC — nothing writes to a closed channel, and the
			// alternative is Disconnect freezing the UI on the network.
			if b.logger != nil {
				b.logger.Printf("srtp-bind: teardown left a dial in flight after %s", shutdownGrace)
			}
		}
	} else {
		close(b.rxCh)
	}
	return firstErr
}

// closeOnce closes ch unless it is nil or already closed. Open has not
// necessarily run — BindUpdate's very first act on device.Up() is to call
// Close — so a nil channel is the normal case, not an error.
func closeOnce(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (b *SRTPBind) SetMark(uint32) error { return nil }

// Send round-robins each buf over the pool. Dead conns are skipped;
// if every conn is dead, returns net.ErrClosed so WG's retry loop
// surfaces it as a handshake failure (which the session supervisor
// then handles).
func (b *SRTPBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	if len(b.slots) == 0 {
		return net.ErrClosed
	}
	n := uint64(len(b.slots))
	for _, buf := range bufs {
		// Round-robin with up to N tries to skip dead conns. If every
		// slot is dead the loop returns net.ErrClosed.
		var lastErr error
		sent := false
		for attempt := uint64(0); attempt < n; attempt++ {
			idx := b.rrNext.Add(1) % n
			if b.dead[idx].Load() {
				lastErr = net.ErrClosed
				continue
			}
			box := b.slots[idx].Load()
			if box == nil {
				lastErr = net.ErrClosed
				continue
			}
			if _, err := box.c.Write(buf); err != nil {
				// Only retire the slot if it still holds the conn that failed:
				// a replacement may already have been installed, and marking
				// THAT dead would undo the repair.
				if b.slots[idx].Load() == box {
					b.dead[idx].Store(true)
				}
				lastErr = err
				continue
			}
			b.TxBytes.Add(uint64(len(buf)))
			sent = true
			break
		}
		if !sent {
			if lastErr == nil {
				lastErr = net.ErrClosed
			}
			return lastErr
		}
	}
	return nil
}

func (b *SRTPBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return srtpEndpoint{}, nil
}

func (b *SRTPBind) BatchSize() int { return 1 }

// LivenessSnapshot reports per-conn state — used by diagnostic
// callers (admin UI / Service status). All counters are read with
// atomic.Load so the snapshot is point-in-time consistent within
// each conn (no cross-conn ordering guarantee).
type LivenessSnapshot struct {
	NumConns      int
	Alive         int
	Dead          int
	ServerProbed  bool
	LastPongAgoMs []int64 // -1 = never pong'd
}

// Liveness returns a point-in-time snapshot of the probe state.
func (b *SRTPBind) Liveness() LivenessSnapshot {
	snap := LivenessSnapshot{
		NumConns:      len(b.slots),
		ServerProbed:  b.serverProbed.Load(),
		LastPongAgoMs: make([]int64, len(b.slots)),
	}
	now := time.Now().Unix()
	for i := range b.slots {
		if b.dead[i].Load() {
			snap.Dead++
			snap.LastPongAgoMs[i] = -1
			continue
		}
		snap.Alive++
		last := b.lastPongUnix[i].Load()
		if last == 0 {
			snap.LastPongAgoMs[i] = -1
		} else {
			snap.LastPongAgoMs[i] = (now - last) * 1000
		}
	}
	return snap
}

type srtpEndpoint struct{}

func (srtpEndpoint) ClearSrc()           {}
func (srtpEndpoint) SrcToString() string { return "" }
func (srtpEndpoint) DstToString() string { return "srtp-pool" }
func (srtpEndpoint) DstToBytes() []byte  { return []byte{0, 0, 0, 0} }
func (srtpEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (srtpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
