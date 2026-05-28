// Пул browser-fingerprint'ов, захваченных во время ручных
// captcha-solve'ов. Идея: каждый раз когда оператор (или клиент в
// будущем) проходит captcha в реальном браузере через наш
// reverse-proxy, мы перехватываем тело `captchaNotRobot.componentDone`
// и `captchaNotRobot.check`, парсим оттуда поля `device`, `browser_fp`
// + берём `User-Agent` из заголовков, и сохраняем тройку как
// CapturedProfile. На следующих попытках авто-solver сможет
// подставить эти значения и пройти captcha без участия человека
// (см. `vk-turn-proxy` PR #162 client/captcha_v2.go::solveCheckboxCaptcha,
// поле savedProfile.{BrowserFp, DeviceJSON}).
//
// В этой слайсе (S1b) реализован только CAPTURE side — пул копится,
// но реплей ещё не задействован: для replay'я нужен полный port
// captcha_v2.go (fhttp + tls-client + PoW + slider) который
// делается отдельно (S1c).
//
// Хранилище — JSON файл рядом с admin.json
// (`<dir-of-yaml>/vkcalls/profiles.json`). Атомарная запись через
// tmp+rename. Concurrent access защищён мьютексом.

package vkauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// CapturedProfile — один захваченный fingerprint из браузера.
type CapturedProfile struct {
	ID         string    `json:"id"`           // 16-hex-чисел; для индексации
	UserAgent  string    `json:"user_agent"`   // как в `User-Agent` HTTP-заголовке
	DeviceJSON string    `json:"device_json"`  // raw JSON из form-поля `device`
	BrowserFP  string    `json:"browser_fp"`   // hex-строка из form-поля `browser_fp`
	CapturedAt time.Time `json:"captured_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	Successes  int       `json:"successes"`
	Failures   int       `json:"failures"`
	// ConsecutiveFails — фейлы подряд с момента последнего успеха
	// (сбрасывается в 0 на MarkSuccess). Это и есть «подряд» для
	// DropAfterFailures: профиль с большой историей успехов, который VK
	// внезапно забанил, должен вылетать через N фейлов подряд, а не
	// ждать пока Failures догонит Successes.
	ConsecutiveFails int `json:"consecutive_fails,omitempty"`
}

// ProfileStore — пул CapturedProfile с persistence.
//
// Параметры пула (из решения по открытым вопросам в poc/docs/vk-calls-redesign.md):
//   - Capacity: cap пула (10–20). При переполнении вытесняется худший
//     профиль (max Failures, затем oldest LastUsedAt).
//   - Cooldown: минимальное время между двумя реюзами одного профиля.
//     Если все профили в cooldown'е — Pick возвращает freshest anyway,
//     лучше попытаться чем фолбэкнуть на ручной solve.
//   - DropAfterFailures: 2 fail подряд → выбрасываем.
type ProfileStore struct {
	path              string
	capacity          int
	cooldown          time.Duration
	dropAfterFailures int

	mu       sync.Mutex
	profiles []*CapturedProfile
}

// ProfileStoreOptions — конфиг при создании.
type ProfileStoreOptions struct {
	Path              string        // путь к persistence-файлу. Обязателен.
	Capacity          int           // 0 → дефолт 16
	Cooldown          time.Duration // 0 → дефолт 90s
	DropAfterFailures int           // 0 → дефолт 2
}

// NewProfileStore создаёт стор и загружает существующие записи с диска.
// Если файла нет — стартует с пустым пулом. Если файл битый —
// возвращает ошибку (бить файл программно мы не должны, выгоднее
// дать оператору починить вручную).
func NewProfileStore(opts ProfileStoreOptions) (*ProfileStore, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("vkcalls: ProfileStore.Path is required")
	}
	if opts.Capacity == 0 {
		opts.Capacity = 16
	}
	if opts.Cooldown == 0 {
		opts.Cooldown = 90 * time.Second
	}
	if opts.DropAfterFailures == 0 {
		opts.DropAfterFailures = 2
	}
	s := &ProfileStore{
		path:              opts.Path,
		capacity:          opts.Capacity,
		cooldown:          opts.Cooldown,
		dropAfterFailures: opts.DropAfterFailures,
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	return s, nil
}

// Capture сохраняет fingerprint в пул.
//
// Если профиль с такими же device_json + browser_fp уже есть —
// апдейтится CapturedAt (актуализация freshness), счётчики не сбрасываем.
// Иначе вставляется новая запись; если пул переполнен — вытесняется
// худший.
//
// Пустые поля (UA / DeviceJSON / BrowserFP) → silently no-op,
// не загрязняем пул мусором.
func (s *ProfileStore) Capture(p CapturedProfile) {
	if p.UserAgent == "" || p.DeviceJSON == "" || p.BrowserFP == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.profiles {
		if existing.DeviceJSON == p.DeviceJSON && existing.BrowserFP == p.BrowserFP {
			existing.CapturedAt = time.Now()
			if existing.UserAgent == "" {
				existing.UserAgent = p.UserAgent
			}
			s.persistLocked()
			return
		}
	}

	p.ID = newProfileID()
	p.CapturedAt = time.Now()
	s.profiles = append(s.profiles, &p)

	if len(s.profiles) > s.capacity {
		s.evictWorstLocked()
	}
	s.persistLocked()
}

// Pick возвращает наиболее подходящий профиль для следующей попытки
// auto-solve или nil если пул пуст. Стратегия:
//
//  1. Профили в cooldown'е (LastUsedAt < now-cooldown) — приоритет.
//  2. Среди cooldown-passed — берём с минимумом fail/success ratio,
//     ties break'аем oldest LastUsedAt (LRU — даём отдохнуть свежим).
//  3. Если все в cooldown'е — берём наиболее «отдохнувший» (oldest
//     LastUsedAt) — лучше попытаться чем фолбэкнуть.
//
// Не помечает использование — это делает MarkSuccess/MarkFail в
// зависимости от исхода.
func (s *ProfileStore) Pick() *CapturedProfile {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.profiles) == 0 {
		return nil
	}

	now := time.Now()
	var fresh, stale []*CapturedProfile
	for _, p := range s.profiles {
		if now.Sub(p.LastUsedAt) >= s.cooldown {
			fresh = append(fresh, p)
		} else {
			stale = append(stale, p)
		}
	}

	candidates := fresh
	if len(candidates) == 0 {
		candidates = stale
	}

	sort.Slice(candidates, func(i, j int) bool {
		// Сначала по фейлам подряд: профиль, только что фейлнувший
		// live-captcha (ConsecutiveFails>0), должен уступать свежему
		// захваченному (0), даже если у него отличная история успехов.
		if candidates[i].ConsecutiveFails != candidates[j].ConsecutiveFails {
			return candidates[i].ConsecutiveFails < candidates[j].ConsecutiveFails
		}
		ai := candidates[i].Failures - candidates[i].Successes
		aj := candidates[j].Failures - candidates[j].Successes
		if ai != aj {
			return ai < aj
		}
		return candidates[i].LastUsedAt.Before(candidates[j].LastUsedAt)
	})

	picked := *candidates[0] // copy для возврата — caller не должен мутить пул напрямую
	return &picked
}

// MarkSuccess отмечает профиль как успешно прошедший captcha.
// LastUsedAt обновляется, Successes++.
func (s *ProfileStore) MarkSuccess(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.findLocked(id); p != nil {
		p.LastUsedAt = time.Now()
		p.Successes++
		p.ConsecutiveFails = 0
		s.persistLocked()
	}
}

// MarkFail отмечает captcha-fail. После dropAfterFailures фейлов
// ПОДРЯД (без успеха между ними) — удаляем профиль из пула: VK его уже
// flag'нул, дальнейшие попытки только жгут session_token'ы и упираются
// в интерактивный fallback. Считаем именно подряд (ConsecutiveFails),
// чтобы профиль с богатой историей успехов, который VK внезапно
// забанил, вылетал быстро, а не ждал пока Failures догонит Successes.
func (s *ProfileStore) MarkFail(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.findLocked(id)
	if p == nil {
		return
	}
	p.LastUsedAt = time.Now()
	p.Failures++
	p.ConsecutiveFails++
	if p.ConsecutiveFails >= s.dropAfterFailures {
		s.removeLocked(id)
	}
	s.persistLocked()
}

// Snapshot возвращает копию текущего пула — для admin UI / тестов.
func (s *ProfileStore) Snapshot() []CapturedProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CapturedProfile, len(s.profiles))
	for i, p := range s.profiles {
		out[i] = *p
	}
	return out
}

// ─── internals ─────────────────────────────────────────────────────

func (s *ProfileStore) findLocked(id string) *CapturedProfile {
	for _, p := range s.profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (s *ProfileStore) removeLocked(id string) {
	out := s.profiles[:0]
	for _, p := range s.profiles {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.profiles = out
}

// evictWorstLocked удаляет одну запись чтобы влезть в Capacity.
// Худший = max ConsecutiveFails, затем max Failures, при ties —
// oldest LastUsedAt.
func (s *ProfileStore) evictWorstLocked() {
	if len(s.profiles) == 0 {
		return
	}
	worstIdx := 0
	for i := 1; i < len(s.profiles); i++ {
		a, b := s.profiles[i], s.profiles[worstIdx]
		if a.ConsecutiveFails != b.ConsecutiveFails {
			if a.ConsecutiveFails > b.ConsecutiveFails {
				worstIdx = i
			}
			continue
		}
		if a.Failures != b.Failures {
			if a.Failures > b.Failures {
				worstIdx = i
			}
			continue
		}
		if a.LastUsedAt.Before(b.LastUsedAt) {
			worstIdx = i
		}
	}
	s.profiles = append(s.profiles[:worstIdx], s.profiles[worstIdx+1:]...)
}

func (s *ProfileStore) loadFromDisk() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil // пустой стор — старт с нуля
	}
	if err != nil {
		return fmt.Errorf("vkcalls: read profile store %s: %w", s.path, err)
	}
	var loaded []*CapturedProfile
	if err := json.Unmarshal(data, &loaded); err != nil {
		return fmt.Errorf("vkcalls: parse profile store %s: %w", s.path, err)
	}
	s.profiles = loaded
	return nil
}

// persistLocked атомарно записывает пул на диск. Должен вызываться
// из методов где mu уже взят. Ошибки записи — лог-only,
// in-memory pool остаётся валидным; VK-сервер не должен падать
// из-за ENOSPC на /var.
func (s *ProfileStore) persistLocked() {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(s.profiles, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}

func newProfileID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
