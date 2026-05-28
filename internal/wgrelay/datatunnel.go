// Package wgrelay implements a WireGuard UDP transport-proxy on top of a
// goloom Sender/Receiver pair.
//
// Topology:
//
//	[wg-client]              [wg-server]
//	    │                         ▲
//	    │ UDP                     │ UDP
//	    ▼                         │
//	┌─────────┐               ┌─────────┐
//	│ Joiner  │ ─ Tunnel ───▶ │ Creator │
//	│ (client)│ ◀───────────  │ (server)│
//	└─────────┘               └─────────┘
//
// The tunnel carries raw WG datagrams as single-frame messages with
// FlagWGData. Joiner runs on the user's machine, listens on a local UDP
// socket that their WireGuard interface points at. Creator runs on the
// VPS, forwards datagrams to the locally running WG server.
//
// No KCP, no yamux, no streams — WG itself handles reliability,
// retransmission, and crypto. This is the minimum viable tunnel.
package wgrelay

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pinnss/goloom-server/internal/tunnel"
)

// ErrPeerRehandshake is signalled when the data tunnel observes a
// FlagHandshake frame after the initial handshake has completed —
// meaning the peer restarted and wants to renegotiate. Joiners and
// creators surface this so the supervisor restarts the whole stack.
var ErrPeerRehandshake = errors.New("wgrelay: peer initiated re-handshake")

// ErrRxStall is returned from the supervised run() when the rx-stall
// watchdog has fired — i.e. the tunnel completed handshake and was
// active, but no WG payload arrived for the configured timeout
// (default 2 min). Usually means Telemost SFU started shaping or
// dropped our media tracks while keeping the control channel alive.
// supervise() treats this like ErrPeerRehandshake — fast retry.
var ErrRxStall = errors.New("wgrelay: rx stalled after handshake")

// FlagWGData is set on tunnel frames carrying a WireGuard datagram.
// We reuse FlagTest's bit (0x01) since the test path is unused in
// production WG mode and the receiver only filters by flag value.
const FlagWGData = tunnel.FlagTest

// DataTunnel exposes a simple byte-stream over the Sender/Receiver pair.
// Send queues bytes for transmission; OnData fires for each received
// datagram. No reliability, no ordering — caller (WireGuard) handles it.
type DataTunnel struct {
	sender   *tunnel.Sender
	frameCh  <-chan tunnel.ReceivedFrame
	logger   *log.Logger

	mu      sync.RWMutex
	onData  func([]byte)
	onClose func()

	closed       bool
	closeCh      chan struct{}
	rehandshake  bool // set when we exit because the peer wanted to renegotiate

	// Atomic throughput counters — read by the supervisor's rx-stall
	// watchdog (clients) and by Status() for live UI/admin metrics.
	// Bytes only count WG-flagged payloads, not handshake/handshakeAck.
	rxBytes atomic.Int64
	txBytes atomic.Int64

	// Set the first time a WG payload arrives. The watchdog ignores
	// rx-stall before this point — pre-handshake the channel is
	// expected to be quiet, and treating that as a stall would cause
	// an immediate reconnect loop.
	gotFirstRx atomic.Bool

	// Set by the rx-stall watchdog when it fires. The supervised
	// caller checks this after the joiner exits to surface
	// ErrRxStall (vs a generic ctx-cancel) so the upstream retry
	// strategy can decide how aggressive to be.
	rxStalled atomic.Bool
}

func New(sender *tunnel.Sender, frames <-chan tunnel.ReceivedFrame, lg *log.Logger) *DataTunnel {
	return &DataTunnel{
		sender:  sender,
		frameCh: frames,
		logger:  lg,
		closeCh: make(chan struct{}),
	}
}

// Run blocks reading frames from the receive channel and dispatching
// WG-flagged payloads to the OnData callback. Returns when ctx is
// cancelled, the frame channel closes, or the peer sends a handshake
// frame post-handshake (meaning the peer restarted and wants to
// renegotiate — surfaced via NeedsRehandshake()).
func (t *DataTunnel) Run(ctx context.Context) {
	defer t.signalClose()
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-t.frameCh:
			if !ok {
				return
			}
			// A FlagHandshake/FlagHandshakeAck frame means "a peer is
			// (re)starting its handshake". Two cases, disambiguated by
			// whether real WG data has flowed yet (gotFirstRx):
			//
			//   1. BEFORE first WG data (gotFirstRx == false): these are
			//      leftover HELLOs/ACKs from the initial handshake. In pool
			//      mode the merged channel collects N HELLOs + N ACKs from N
			//      pool members while [session.Handshake] consumes only one
			//      of each; the rest land here. Tearing down on them would
			//      loop forever. → ignore.
			//
			//   2. AFTER data has flowed (gotFirstRx == true): the peer
			//      genuinely reconnected (new Telemost participant, fresh
			//      app session). The old session is dead. → tear down so the
			//      supervisor re-runs WaitForPeer + Handshake against the new
			//      peer. Without this, a reconnecting client hangs in
			//      handshake because our side stays stuck in the old relay.
			//
			// 2026-05-28: restored teardown (gated on gotFirstRx) after the
			// 2026-05-27 blanket-ignore regressed client reconnection.
			if f.Flags.Has(tunnel.FlagHandshake) || f.Flags.Has(tunnel.FlagHandshakeAck) {
				if !t.gotFirstRx.Load() {
					continue
				}
				t.mu.Lock()
				t.rehandshake = true
				t.mu.Unlock()
				t.logger.Printf("DT: peer re-handshake after active relay — tearing down for fresh session")
				return
			}
			if !f.Flags.Has(FlagWGData) {
				continue
			}
			t.rxBytes.Add(int64(len(f.Payload)))
			t.gotFirstRx.Store(true)
			t.mu.RLock()
			cb := t.onData
			t.mu.RUnlock()
			if cb != nil {
				cb(f.Payload)
			}
		}
	}
}

// NeedsRehandshake reports whether Run exited because the peer wanted
// to renegotiate (vs ctx-cancel or normal close). The supervisor uses
// this to decide whether to restart immediately vs back off.
func (t *DataTunnel) NeedsRehandshake() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rehandshake
}

// Send queues a WG datagram for transmission. Returns immediately;
// actual transmission happens on the Sender's background loop after
// batching/pacing.
func (t *DataTunnel) Send(data []byte) error {
	if t.isClosed() {
		return errors.New("wgrelay: tunnel closed")
	}
	_, err := t.sender.Send(FlagWGData, data)
	if err == nil {
		// Counted on best-effort: actual TX happens later in Sender's
		// loop, but for stall-detection we care about queued bytes
		// since that means the upper layer is trying to push data.
		t.txBytes.Add(int64(len(data)))
	}
	return err
}

// Stats returns running rx/tx byte counters and whether the tunnel has
// ever received a WG payload (i.e. handshake completed). The watchdog
// uses `ready=false` to defer stall detection during the handshake
// phase — see main.go::run().
func (t *DataTunnel) Stats() (rx, tx int64, ready bool) {
	return t.rxBytes.Load(), t.txBytes.Load(), t.gotFirstRx.Load()
}

// MarkRxStalled is called by RunRxStallWatchdog once it triggers.
// The supervised run() reads this via WasRxStalled() to surface
// ErrRxStall to its caller.
func (t *DataTunnel) MarkRxStalled() {
	t.rxStalled.Store(true)
}

// WasRxStalled reports whether the rx-stall watchdog fired during
// this DataTunnel's lifetime. Each new DataTunnel starts with this
// flag false, so the supervisor's per-attempt instance gives an
// honest answer per attempt.
func (t *DataTunnel) WasRxStalled() bool {
	return t.rxStalled.Load()
}

// Default rx-stall watchdog timing. Public so callers can tune them
// for tests; in production the defaults are fine on both Android and
// Windows clients.
var (
	// DefaultRxStallTick — как часто опрашиваем rx-counter.
	DefaultRxStallTick = 30 * time.Second
	// DefaultRxStallTimeout — сколько rx может стоять до forced reconnect.
	// 2 минуты выбраны под WG persistent-keepalive (25 сек) с запасом
	// на несколько потерянных пакетов. Меньше — false-positive'ы при
	// natural idle; больше — слишком долго жить с мёртвой сессией.
	DefaultRxStallTimeout = 2 * time.Minute
)

// RunRxStallWatchdog следит за свежестью rx-трафика на DataTunnel и
// зовёт cancel() когда обнаруживает stall. Идентичен по семантике
// серверному watchdog'у в internal/inbound/manager.go::watchdog().
//
// Алгоритм: раз в `tick` смотрим [DataTunnel.Stats]. Пока handshake не
// завершился (`ready==false`) — baseline'ы сбрасываются. После того
// как пошёл первый WG-payload, начинаем мерить промежутки между
// движениями rx-счётчика. Если за `rxStallTimeout` rx-байты не
// сдвинулись — считаем сессию мёртвой, [DataTunnel.MarkRxStalled] +
// cancel, выходим. Caller (run()/runSession) после возврата joiner'а
// проверит [DataTunnel.WasRxStalled] и вернёт [ErrRxStall].
//
// Зачем: Telemost SFU умеет тихо "шейпить" media-tracks при долгой
// сессии — control-channel (KCP keepalive/telemetry) остаётся живым,
// а WG-пакеты через video-track перестают доставляться. Без watchdog'а
// клиент висит в этом состоянии до перезапуска руками. Эта симметрия
// со server-watchdog'ом и есть весь fix/client-rx-stall-watchdog.
//
// Используется параметризированная сигнатура (tick/timeout аргументами,
// а не глобальными константами) только для тестов — в production
// callers зовут через RunRxStallWatchdogDefault.
func RunRxStallWatchdog(
	ctx context.Context,
	cancel context.CancelFunc,
	dt *DataTunnel,
	lg *log.Logger,
	tick time.Duration,
	rxStallTimeout time.Duration,
) {
	t := time.NewTicker(tick)
	defer t.Stop()

	var (
		lastRx     int64
		lastChange = time.Now()
		wasReady   bool
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rx, _, ready := dt.Stats()
			if !ready {
				lastRx = 0
				lastChange = time.Now()
				wasReady = false
				continue
			}
			if !wasReady {
				wasReady = true
				lastRx = rx
				lastChange = time.Now()
				continue
			}
			if rx != lastRx {
				lastRx = rx
				lastChange = time.Now()
				continue
			}
			if time.Since(lastChange) > rxStallTimeout {
				if lg != nil {
					lg.Printf("WATCHDOG no rx for %s after handshake — forcing reconnect", rxStallTimeout)
				}
				dt.MarkRxStalled()
				cancel()
				return
			}
		}
	}
}

// RunRxStallWatchdogDefault — same as [RunRxStallWatchdog] with
// production timings (DefaultRxStallTick / DefaultRxStallTimeout).
func RunRxStallWatchdogDefault(
	ctx context.Context,
	cancel context.CancelFunc,
	dt *DataTunnel,
	lg *log.Logger,
) {
	RunRxStallWatchdog(ctx, cancel, dt, lg, DefaultRxStallTick, DefaultRxStallTimeout)
}

func (t *DataTunnel) SetOnData(fn func([]byte)) {
	t.mu.Lock()
	t.onData = fn
	t.mu.Unlock()
}

func (t *DataTunnel) SetOnClose(fn func()) {
	t.mu.Lock()
	t.onClose = fn
	t.mu.Unlock()
}

func (t *DataTunnel) Close() error {
	t.signalClose()
	return nil
}

func (t *DataTunnel) signalClose() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.closeCh)
	cb := t.onClose
	t.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (t *DataTunnel) isClosed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.closed
}
