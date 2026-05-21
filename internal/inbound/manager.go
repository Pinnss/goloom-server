package inbound

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/Pinnss/goloom-server/pkg/vkauth"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
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

	// captchaBroker is wired by the surrounding cmd binary
	// (cmd/goloom-wg-server) when admin-webview captcha solving is
	// available. nil means VK Calls inbounds with
	// captcha_mode=admin-webview will fail at Connect time. Set via
	// [SetCaptchaBroker]; goroutine-safe because it's only mutated at
	// startup before any Runner reads it.
	captchaBroker vkauth.AdminCaptchaBroker

	// vkProfileStore — пул browser-FP для VK auto-replay solver
	// (S1c). nil → replay выключен, captcha решается interactive.
	// Set via [SetVKProfileStore]; mutated only at startup.
	vkProfileStore *vkauth.ProfileStore

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

// SetCaptchaBroker installs the broker used by VK Calls inbounds
// running in captcha_mode=admin-webview. Pass nil to disable
// admin-webview solving (auto/none modes still work).
//
// Безопасно вызывать после mgr.Add — broker пропагируется во все
// уже существующие runners. Раньше этот сеттер только писал в поле
// Manager'а, и runners созданные до его вызова навсегда оставались с
// nil broker'ом — приходилось тоглить инбаунды через админку чтобы
// «подхватить».
func (m *Manager) SetCaptchaBroker(b vkauth.AdminCaptchaBroker) {
	m.mu.Lock()
	m.captchaBroker = b
	for _, e := range m.entries {
		e.runner.SetCaptchaBroker(b)
	}
	m.mu.Unlock()
}

// SetVKProfileStore installs the browser-FP pool used by VK Calls
// inbounds for auto-replay (S1c). Когда задан — captcha решается
// автоматически из пула, при провале — фоллбэк на interactive solver.
// Pass nil to disable auto-replay. Пропагируется в существующие
// runners (см. [SetCaptchaBroker] про rationale).
func (m *Manager) SetVKProfileStore(s *vkauth.ProfileStore) {
	m.mu.Lock()
	m.vkProfileStore = s
	for _, e := range m.entries {
		e.runner.SetVKProfileStore(s)
	}
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
	r.SetCaptchaBroker(m.captchaBroker)
	r.SetVKProfileStore(m.vkProfileStore)
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
		// Каждая попытка получает свой derived ctx — так watchdog может
		// прибить конкретно этот Run без того, чтобы убить весь supervise.
		runCtx, runCancel := context.WithCancel(ctx)

		// Watchdog следит за свежестью rx-трафика: если в фазе relaying
		// за 2 минуты не пришло ни одного нового пакета — Telemost-сессия
		// явно сдохла (ICE failed, peer disconnected, etc.) даже если
		// внутренний runner этого ещё не заметил. Cancel'ом forсим выход
		// из creator.Run и попадаем во второй виток retry-цикла.
		go m.watchdog(runCtx, runCancel, e.runner)

		err := e.runner.Run(runCtx)
		runCancel()

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

// watchdog следит за свежестью rx-трафика на активном inbound. Запускается
// внутри [supervise] и завершается либо вместе с runCtx, либо принудительно
// — когда замечает stall и сам же дёргает cancel.
//
// Алгоритм: раз в 30 сек смотрим rx-байты. Пока inbound не вышел в фазу
// `relaying`, baseline сбрасывается (handshake-таймауты и empty-room
// retry'и обрабатывает сам supervise). После того как пошёл реальный
// трафик — если за rxStallTimeout (2 мин) счётчик не сдвинулся, считаем
// сессию мёртвой и cancel'ит local ctx.
//
// 2 минуты выбраны так: WG persistent-keepalive раз в 25 сек, плюс
// несколько потерянных пакетов = ~75 сек. С запасом 120 сек гарантирует,
// что мы не дёрнем здоровое-но-тихое соединение, но всё-таки реагируем
// быстрее, чем за 15 часов простоя как было до фикса.
//
// Не применим к relay-family inbound'ам: у них нет wgrelay.Bridge, и
// RxBytes всегда нулевой — watchdog ложно сработает каждые 2 минуты и
// будет рвать клиенту DTLS-сессию (заставляя его заново проходить VK
// captcha). Свежесть relay-listener'а мы можем проверять отдельно через
// Status.RelayActive когда-нибудь, но сам listener не "застревает" —
// он просто принимает или не принимает входящие коннекшены, без
// внутреннего состояния которое может сгнить.
func (m *Manager) watchdog(ctx context.Context, cancel context.CancelFunc, r *Runner) {
	if isRelayTransport(r.Spec.Transport) {
		<-ctx.Done()
		return
	}
	const (
		tick           = 30 * time.Second
		rxStallTimeout = 2 * time.Minute
	)
	t := time.NewTicker(tick)
	defer t.Stop()

	var (
		lastRx     uint64
		lastChange = time.Now()
		wasActive  bool
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st := r.Status()
			if st.Phase != "relaying" {
				// Ещё не дошли до boilerplate-стадии или уже вышли —
				// сбрасываем baseline, чтобы не сорваться при следующем
				// переходе.
				lastRx = 0
				lastChange = time.Now()
				wasActive = false
				continue
			}
			if !wasActive {
				wasActive = true
				lastRx = st.RxBytes
				lastChange = time.Now()
				continue
			}
			if st.RxBytes != lastRx {
				lastRx = st.RxBytes
				lastChange = time.Now()
				continue
			}
			if time.Since(lastChange) > rxStallTimeout {
				m.logger.Printf("inbound %s: no rx for %s while phase=relaying — forcing reconnect",
					r.Spec.Tag, rxStallTimeout)
				cancel()
				return
			}
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
