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
	mu     sync.Mutex
	open   bool
	closed chan struct{}

	conns []net.Conn // owned — Close() closes all

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
}

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
	return &SRTPBind{
		conns:        conns,
		closed:       make(chan struct{}),
		rxCh:         make(chan rxPacket, srtpBindRxBufSize),
		lastPongUnix: make([]atomic.Int64, len(conns)),
		pingSeq:      make([]atomic.Uint64, len(conns)),
		dead:         make([]atomic.Bool, len(conns)),
	}
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
	if len(b.conns) == 0 {
		return nil, 0, errors.New("SRTPBind: no SRTP conns")
	}
	b.open = true

	// Reader + probe goroutines per conn. Reader allocates its own buf
	// to avoid concurrent writes; probe sender uses a tiny dedicated
	// buffer (12 bytes per ping). Watchdog runs once per bind.
	b.rxOnce.Do(func() {
		for i, c := range b.conns {
			b.rxWG.Add(2)
			go b.readerLoop(i, c)
			go b.probeSenderLoop(i, c)
		}
		b.rxWG.Add(1)
		go b.zombieWatchdog()
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
			if b.dead[idx].Load() {
				return
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
			if !b.serverProbed.Load() {
				continue
			}
			now := time.Now().Unix()
			alive := 0
			for i := range b.conns {
				if b.dead[i].Load() {
					continue
				}
				last := b.lastPongUnix[i].Load()
				if last > 0 && now-last > int64(probeStaleThreshold/time.Second) {
					b.dead[i].Store(true)
					_ = b.conns[i].Close() // wakes the reader
					if b.logger != nil {
						b.logger.Printf("srtp-bind: conn %d zombie (last pong %ds ago) — killed", i, now-last)
					}
					continue
				}
				alive++
			}
			if alive == 0 && b.logger != nil {
				b.logger.Printf("srtp-bind: WARN — all %d conns zombie; supervisor should retry the session", len(b.conns))
			}
		}
	}
}

func (b *SRTPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	b.open = false
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	var firstErr error
	for _, c := range b.conns {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.rxWG.Wait()
	close(b.rxCh)
	return firstErr
}

func (b *SRTPBind) SetMark(uint32) error { return nil }

// Send round-robins each buf over the pool. Dead conns are skipped;
// if every conn is dead, returns net.ErrClosed so WG's retry loop
// surfaces it as a handshake failure (which the session supervisor
// then handles).
func (b *SRTPBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	if len(b.conns) == 0 {
		return net.ErrClosed
	}
	n := uint64(len(b.conns))
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
			if _, err := b.conns[idx].Write(buf); err != nil {
				b.dead[idx].Store(true)
				lastErr = err
				continue
			}
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
		NumConns:      len(b.conns),
		ServerProbed:  b.serverProbed.Load(),
		LastPongAgoMs: make([]int64, len(b.conns)),
	}
	now := time.Now().Unix()
	for i := range b.conns {
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
