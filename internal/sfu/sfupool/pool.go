// Package sfupool aggregates N parallel SFU sessions into one
// [sfu.Session] so a single logical inbound can spread WG traffic across
// multiple Telemost meeting participants. Yandex Telemost SFU caps each
// publisher track at ~3 Mbps regardless of capabilities/codec/SDP hints
// (verified 2026-05-27 with a battery of signalling-layer experiments
// that all came back negative). The cap is per-publisher, so N pool
// members in the same room give an aggregate ~N×3 Mbps download budget.
//
// Pairing topology: pool members do not need to pair with specific peers
// in the room. The SFU broadcasts every participant's track to every
// other participant; pool members on the same side filter out each
// others' frames via [internal/tunnel.FlagFromServer] / Receiver.DropFlag,
// stamped in [internal/tunnel.Sender.SideFlag]. So:
//
//   - Server pool publishes data D distributed round-robin across N tracks.
//   - Each client pool member receives ALL N server tracks; downloads
//     aggregate naturally because each track carries different bytes.
//   - Each server pool member receives the client's single (or N) tracks
//     and forwards to local WG. Upload duplicates land in WireGuard's
//     anti-replay window — silently dropped. CPU waste but functional.
//
// Done semantics: PooledSession's Done channel closes when ANY child
// session closes. This is conservative: a half-dead pool is hard to
// reason about, so the supervising runner restarts the whole pool on
// any child failure.
package sfupool

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/Pinnss/goloom-server/internal/sfu"
)

// PooledSession aggregates N child [sfu.Session] into one. Implements
// both [sfu.Session] and [sfu.ICEHostsProvider].
type PooledSession struct {
	children []sfu.Session
	logger   *log.Logger

	incoming chan []byte
	nextSend atomic.Uint64 // round-robin counter; modulo len(children)

	closeOnce sync.Once
	closed    atomic.Bool
	doneCh    chan struct{}
	doneOnce  sync.Once

	errMu sync.Mutex
	err   error
}

// Connect dials `size` child sessions in parallel via the given transport
// and returns one PooledSession aggregating them. On any child connect
// failure, all successful children are torn down and the original error
// is returned. The parent ctx scopes only the dial phase; once Connect
// returns, lifetime is owned by the caller via [PooledSession.Close].
//
// spec.DisplayName is suffixed with "-<idx>" per child so each member
// joins the Telemost room under a distinct identity (the SFU rejects
// duplicate display names in some configurations).
func Connect(ctx context.Context, transport sfu.Transport, spec sfu.ConnectSpec, size int, lg *log.Logger) (*PooledSession, error) {
	if size < 1 {
		return nil, fmt.Errorf("sfupool: invalid size %d (need ≥1)", size)
	}
	if transport == nil {
		return nil, errors.New("sfupool: transport is nil")
	}

	type result struct {
		idx  int
		sess sfu.Session
		err  error
	}
	results := make(chan result, size)
	baseName := spec.DisplayName

	for i := 0; i < size; i++ {
		go func(idx int) {
			childSpec := spec
			if baseName != "" {
				childSpec.DisplayName = fmt.Sprintf("%s-%d", baseName, idx)
			}
			if childSpec.Logger != nil {
				childSpec.Logger = log.New(childSpec.Logger.Writer(),
					fmt.Sprintf("%s[pool-%d] ", childSpec.Logger.Prefix(), idx),
					childSpec.Logger.Flags())
			}
			sess, err := transport.Connect(ctx, childSpec)
			results <- result{idx: idx, sess: sess, err: err}
		}(i)
	}

	children := make([]sfu.Session, 0, size)
	var firstErr error
	for i := 0; i < size; i++ {
		r := <-results
		if r.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("sfupool: child %d connect: %w", r.idx, r.err)
			}
			continue
		}
		children = append(children, r.sess)
	}
	if firstErr != nil {
		// Roll back any successful children.
		for _, c := range children {
			_ = c.Close()
		}
		return nil, firstErr
	}

	p := &PooledSession{
		children: children,
		logger:   lg,
		incoming: make(chan []byte, 1024),
		doneCh:   make(chan struct{}),
	}
	for i, c := range children {
		go p.fanInChild(i, c)
	}
	return p, nil
}

// Send round-robins the payload across child sessions. Each child
// publishes onto its own SFU track; the SFU then broadcasts each track
// to subscribers, giving the receiver pool N parallel streams.
func (p *PooledSession) Send(payload []byte) error {
	if p.closed.Load() {
		return sfu.ErrSessionClosed
	}
	idx := p.nextSend.Add(1) % uint64(len(p.children))
	return p.children[idx].Send(payload)
}

// Frames yields the multiplexed inbound payloads from all child sessions.
// Order is not preserved across children; the WireGuard layer above
// handles out-of-order delivery via its own replay window.
func (p *PooledSession) Frames() <-chan []byte { return p.incoming }

// Done closes when the first child session closes (any failure tears
// down the whole pool — see package doc).
func (p *PooledSession) Done() <-chan struct{} { return p.doneCh }

// Err returns the first non-nil child error observed, or nil for clean
// teardowns.
func (p *PooledSession) Err() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

// Close tears down all children. Idempotent.
func (p *PooledSession) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		for _, c := range p.children {
			_ = c.Close()
		}
		p.signalDone(nil)
	})
	return nil
}

// ICEHosts returns the union of ICE/TURN/STUN hosts reported by child
// sessions that implement [sfu.ICEHostsProvider]. Deduplicated.
func (p *PooledSession) ICEHosts() []string {
	set := make(map[string]struct{})
	for _, c := range p.children {
		hp, ok := c.(sfu.ICEHostsProvider)
		if !ok {
			continue
		}
		for _, h := range hp.ICEHosts() {
			set[h] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

// fanInChild pumps one child's Frames into the pool's incoming channel.
// When the child closes, the pool's Done is fired (conservative whole-
// pool teardown — see package doc).
func (p *PooledSession) fanInChild(idx int, child sfu.Session) {
	defer func() {
		if err := child.Err(); err != nil {
			p.errMu.Lock()
			if p.err == nil {
				p.err = fmt.Errorf("sfupool: child %d: %w", idx, err)
			}
			p.errMu.Unlock()
		}
		p.signalDone(child.Err())
	}()
	for {
		select {
		case <-p.doneCh:
			return
		case payload, ok := <-child.Frames():
			if !ok {
				return
			}
			select {
			case p.incoming <- payload:
			case <-p.doneCh:
				return
			}
		case <-child.Done():
			return
		}
	}
}

func (p *PooledSession) signalDone(err error) {
	p.doneOnce.Do(func() {
		if err != nil {
			p.errMu.Lock()
			if p.err == nil {
				p.err = err
			}
			p.errMu.Unlock()
		}
		close(p.doneCh)
	})
}
