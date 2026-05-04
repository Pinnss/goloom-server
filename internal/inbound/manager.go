package inbound

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/Sv9toslavPinigin/goloom-server/internal/wgrelay"
)

// Manager supervises a set of Runners, retrying failed ones with backoff
// and exposing CRUD operations the admin panel calls into.
type Manager struct {
	logger  *log.Logger
	history *History

	// rootCtx is the long-lived context every supervised goroutine
	// inherits from. Set by Start(); MUST NOT be the per-HTTP-request
	// context, otherwise inbounds get killed the instant the admin
	// panel returns its HTTP response.
	rootCtx context.Context

	mu      sync.Mutex
	entries map[string]*entry

	// onChange is fired whenever the spec set changes (add/remove/toggle)
	// so the caller can persist state.
	onChange func()
}

type entry struct {
	runner *Runner
	cancel context.CancelFunc
	done   chan struct{}
}

func NewManager(lg *log.Logger) *Manager {
	m := &Manager{
		logger:  lg,
		history: NewHistory(0),
		entries: make(map[string]*entry),
		rootCtx: context.Background(), // replaced by Start()
	}
	go m.recordHistoryLoop()
	return m
}

// Start binds the manager to a long-lived context. All inbound runners
// spawned afterwards inherit from this context. Call once at process
// startup, before adding any inbounds.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.rootCtx = ctx
	m.mu.Unlock()
}

// History exposes the throughput history store for the admin panel.
func (m *Manager) History() *History { return m.history }

func (m *Manager) recordHistoryLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		for _, s := range m.Statuses() {
			m.history.Record(s.ID, s.TxBytes, s.RxBytes)
		}
	}
}

// SetOnChange registers a callback fired after every Add/Remove/Toggle.
// Useful for persisting state to disk.
func (m *Manager) SetOnChange(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Add registers a new inbound and starts it (if Enabled). Returns an
// error if the ID is already in use.
//
// The ctx parameter is intentionally ignored for goroutine lifetime —
// supervisors inherit from m.rootCtx (set by Start()) so an inbound
// created via the admin panel doesn't die when the HTTP response is
// flushed. ctx is reserved for future synchronous work that should be
// caller-cancellable.
func (m *Manager) Add(ctx context.Context, spec Spec) error {
	m.mu.Lock()
	if _, exists := m.entries[spec.ID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("inbound %s already exists", spec.ID)
	}
	r := NewRunner(spec, m.logger)
	e := &entry{runner: r}
	m.entries[spec.ID] = e
	rootCtx := m.rootCtx
	m.mu.Unlock()

	if spec.Enabled {
		m.startEntry(rootCtx, e)
	}
	m.fireChange()
	return nil
}

// Remove stops and unregisters the inbound. Idempotent.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	e, ok := m.entries[id]
	if !ok {
		m.mu.Unlock()
		return errors.New("inbound not found")
	}
	delete(m.entries, id)
	m.mu.Unlock()

	m.stopEntry(e)
	m.history.Drop(id)
	m.fireChange()
	return nil
}

// SetEnabled toggles the inbound's running state. If disabling a running
// inbound, stops it; if enabling a stopped one, starts it.
func (m *Manager) SetEnabled(ctx context.Context, id string, enabled bool) error {
	m.mu.Lock()
	e, ok := m.entries[id]
	if !ok {
		m.mu.Unlock()
		return errors.New("inbound not found")
	}
	if e.runner.Spec.Enabled == enabled {
		m.mu.Unlock()
		return nil
	}
	e.runner.Spec.Enabled = enabled
	rootCtx := m.rootCtx
	m.mu.Unlock()

	if enabled {
		m.startEntry(rootCtx, e)
	} else {
		m.stopEntry(e)
	}
	m.fireChange()
	return nil
}

// Get returns the runner spec for inspection. Panel routes use this to
// render config/QR/etc.
func (m *Manager) Get(id string) (Spec, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok {
		return Spec{}, false
	}
	return e.runner.Spec, true
}

// List returns specs sorted by tag for stable rendering.
func (m *Manager) List() []Spec {
	m.mu.Lock()
	out := make([]Spec, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.runner.Spec)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// Statuses returns live statuses sorted by tag.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	out := make([]Status, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.runner.Status())
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// StopAll cancels every running inbound and waits for them to exit.
// Called at server shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	all := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		all = append(all, e)
	}
	m.mu.Unlock()

	for _, e := range all {
		m.stopEntry(e)
	}
}

func (m *Manager) startEntry(parent context.Context, e *entry) {
	m.mu.Lock()
	if e.cancel != nil {
		// already running
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	e.done = make(chan struct{})
	m.mu.Unlock()

	go m.supervise(ctx, e)
}

func (m *Manager) supervise(ctx context.Context, e *entry) {
	defer close(e.done)

	backoff := 5 * time.Second
	for {
		err := e.runner.Run(ctx)

		if ctx.Err() != nil {
			return
		}

		// Re-handshake (peer restarted) gets immediate retry — the
		// remote side is already up and waiting; backing off would just
		// stretch the user-visible outage. Reset backoff so a successful
		// reconnect followed by a real failure later starts fresh.
		retryAfter := backoff
		if errors.Is(err, wgrelay.ErrPeerRehandshake) {
			// 1s pause lets the SFU process WS-bye + DTLS close from
			// the old session before we rejoin. Skipping it leaves a
			// zombie participant for the ~30s ICE timeout.
			m.logger.Printf("inbound %s: peer rehandshake — reconnecting in 1s", e.runner.Spec.Tag)
			retryAfter = 1 * time.Second
			backoff = 5 * time.Second
		} else if err != nil && isLikelyEmptyRoom(err) {
			// Empty-room handshake timeouts are normal until a client
			// connects — quiet log, faster retry, no backoff growth.
			retryAfter = 5 * time.Second
			backoff = 5 * time.Second
		} else if err != nil {
			m.logger.Printf("inbound %s exited: %v — retrying in %s", e.runner.Spec.Tag, err, backoff)
		} else {
			m.logger.Printf("inbound %s exited cleanly — restarting in %s", e.runner.Spec.Tag, backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryAfter):
		}
		if !errors.Is(err, wgrelay.ErrPeerRehandshake) && backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

func (m *Manager) stopEntry(e *entry) {
	m.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.cancel = nil
	e.done = nil
	m.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			m.logger.Printf("inbound stop timed out")
		}
	}
}

func (m *Manager) fireChange() {
	m.mu.Lock()
	cb := m.onChange
	m.mu.Unlock()
	if cb != nil {
		cb()
	}
}
