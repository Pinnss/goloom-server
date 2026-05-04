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

	"github.com/Pinnss/goloom-server/internal/tunnel"
)

// ErrPeerRehandshake is signalled when the data tunnel observes a
// FlagHandshake frame after the initial handshake has completed —
// meaning the peer restarted and wants to renegotiate. Joiners and
// creators surface this so the supervisor restarts the whole stack.
var ErrPeerRehandshake = errors.New("wgrelay: peer initiated re-handshake")

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
			// A FlagHandshake/FlagHandshakeAck frame after we've started
			// relaying means our peer just restarted (fresh server
			// instance, or client reconnected). Tear down so the
			// supervisor restarts both Sender state and any WG session.
			if f.Flags.Has(tunnel.FlagHandshake) || f.Flags.Has(tunnel.FlagHandshakeAck) {
				t.mu.Lock()
				t.rehandshake = true
				t.mu.Unlock()
				t.logger.Printf("DT: peer initiated re-handshake — tearing down for fresh session")
				return
			}
			if !f.Flags.Has(FlagWGData) {
				continue
			}
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
	return err
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
