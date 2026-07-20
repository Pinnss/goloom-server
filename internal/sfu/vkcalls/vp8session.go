// VP8Session — альтернативный [sfu.Session] для VK Calls на стеке
// VP8 + [internal/tunnel] + [internal/wgrelay]. Параллельная имплементация
// вместо videocode'овой H.264 I_PCM grid; выбирается через
// VKCallsConnect.Codec="vp8".
//
// Структура слизана с telemost.Session — обёртка вокруг wgrelay.DataTunnel.

package vkcalls

import (
	"context"
	"net/url"
	"sync"
	"time"

	"log"

	"github.com/Pinnss/goloom-server/internal/sfu"
	"github.com/Pinnss/goloom-server/internal/tunnel"
	"github.com/Pinnss/goloom-server/internal/wgrelay"
)

// VP8Session — sfu.Session реализация для vp8 codec'a.
type VP8Session struct {
	logger       *log.Logger
	auth         *AuthResult
	peer         *peer
	cameraSender *tunnel.Sender
	dt           *wgrelay.DataTunnel

	ctx    context.Context
	cancel context.CancelFunc

	incoming chan []byte

	doneOnce sync.Once
	done     chan struct{}
	errMu    sync.Mutex
	errSlot  error

	closed sync.Once
}

func newVP8Session(parentCtx context.Context, lg *log.Logger, auth *AuthResult, p *peer, sender *tunnel.Sender, dt *wgrelay.DataTunnel) *VP8Session {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &VP8Session{
		logger:       lg,
		auth:         auth,
		peer:         p,
		cameraSender: sender,
		dt:           dt,
		ctx:          ctx,
		cancel:       cancel,
		incoming:     make(chan []byte, 512),
		done:         make(chan struct{}),
	}
	dt.SetOnData(s.onData)
	dt.SetOnClose(s.onTunnelClose)

	// Запуск dt.Run в goroutine — он читает frames из merged-канала
	// и диспатчит через onData.
	go s.runTunnel(ctx)

	// Watch underlying peer — если WS умер, сессия тоже мертва.
	go func() {
		select {
		case <-p.Done():
			s.signalDone(p.Err())
		case <-ctx.Done():
		}
	}()

	return s
}

func (s *VP8Session) Send(payload []byte) error {
	select {
	case <-s.done:
		return sfu.ErrSessionClosed
	default:
	}
	if err := s.dt.Send(payload); err != nil {
		return sfu.ErrSessionClosed
	}
	return nil
}

func (s *VP8Session) Frames() <-chan []byte { return s.incoming }
func (s *VP8Session) Done() <-chan struct{} { return s.done }

func (s *VP8Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.errSlot
}

func (s *VP8Session) Close() error {
	s.closed.Do(func() {
		s.cancel()
		_ = s.dt.Close()
		s.cameraSender.Close()
		if s.peer != nil {
			s.peer.Close()
		}
		s.signalDone(nil)
	})
	return nil
}

// ICEHosts — повторяет h264 Session.ICEHosts.
func (s *VP8Session) ICEHosts() []string {
	if s.auth == nil {
		return nil
	}
	hosts := make(map[string]struct{})
	add := func(raw string) {
		if h := vp8ExtractURLHost(raw); h != "" {
			hosts[h] = struct{}{}
		}
	}
	for _, u := range s.auth.TurnURLs {
		add(u)
	}
	for _, u := range s.auth.StunURLs {
		add(u)
	}
	add(s.auth.WSEndpoint)
	// Оба домена: VK мигрирует vk.com -> vk.ru поэтапно (см. ResolveSFUIPs).
	for _, h := range []string{
		"vk.ru",
		"vk.com",
		"id.vk.ru",
		"id.vk.com",
		"static.vk.ru",
		"ad.mail.ru",
		"login.vk.ru",
		"api.vk.ru",
		"api.vk.com",
		"calls.okcdn.ru",
		"videowebrtc.okcdn.ru",
	} {
		hosts[h] = struct{}{}
	}
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out
}

func (s *VP8Session) onData(payload []byte) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case s.incoming <- cp:
	case <-s.done:
	}
}

func (s *VP8Session) onTunnelClose() {
	var err error
	if s.dt.NeedsRehandshake() {
		err = sfu.ErrPeerRehandshake
	}
	s.signalDone(err)
}

func (s *VP8Session) runTunnel(ctx context.Context) {
	s.dt.Run(ctx)
}

func (s *VP8Session) signalDone(err error) {
	s.doneOnce.Do(func() {
		s.errMu.Lock()
		if s.errSlot == nil && err != nil {
			s.errSlot = err
		}
		s.errMu.Unlock()
		close(s.done)
		go func() {
			time.Sleep(50 * time.Millisecond)
			defer func() { _ = recover() }()
			close(s.incoming)
		}()
	})
}

// vp8ExtractURLHost — копия [extractURLHost] из session.go под другим
// именем чтобы не конфликтовать в пакете. (Дешевле один helper-копию
// держать чем выносить общий пакет.)
func vp8ExtractURLHost(raw string) string {
	for _, prefix := range []string{"stun:", "turn:", "turns:"} {
		if len(raw) > len(prefix) && raw[:len(prefix)] == prefix {
			rest := raw[len(prefix):]
			for i := 0; i < len(rest); i++ {
				if rest[i] == '?' || rest[i] == '#' {
					rest = rest[:i]
					break
				}
			}
			for i := 0; i < len(rest); i++ {
				if rest[i] == ':' {
					return rest[:i]
				}
			}
			return rest
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Compile-time assertions.
var _ sfu.Session = (*VP8Session)(nil)
var _ sfu.ICEHostsProvider = (*VP8Session)(nil)
