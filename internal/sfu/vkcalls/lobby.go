// LobbyPeer — minimal peer-join в VK звонке БЕЗ pion PeerConnection.
// Сервер использует для постоянного listening'а на in-band DIAL
// сообщения; клиент — для краткого визита в lobby чтобы выгрузить
// DIAL и забрать DIAL_OK перед уходом в target meeting.
//
// Стек:
//
//	DoAuth(meeting)            ← полный VK auth ladder (S1a-c)
//	dialPeer(auth, "lobby")    ← WS к videowebrtc.okcdn.ru/ws2
//	p.run()                    ← read loop, dispatch
//	  └─ handleTransmittedData ← фильтрует goloom_ctrl envelope'ы
//	     └─ controlListener    ← наш callback
//
// НЕ создаёт pion PC, НЕ публикует медиа, НЕ обрабатывает SDP/ICE.
// Только signaling для control сообщений.

package vkcalls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/Pinnss/goloom-server/internal/identity"
	"github.com/Pinnss/goloom-server/internal/sfu"
)

// LobbyPeer — обёртка над минимальной peer-сессией для control plane.
type LobbyPeer struct {
	auth *AuthResult
	peer *peer
	lg   *log.Logger

	mu      sync.Mutex
	closed  bool
	cancel  context.CancelFunc
	incoming chan IncomingCtrl
}

// LobbyOptions — конфиг при открытии lobby peer'а.
type LobbyOptions struct {
	MeetingURL    string                  // ссылка на VK звонок (lobby)
	DisplayName   string                  // optional, генерится если пусто
	CaptchaSolver sfu.VKCaptchaSolver     // обязателен (как и в обычном Connect)
}

// OpenLobbyPeer полностью аутентифицируется и заходит в указанный VK
// звонок как anonymous peer без публикации медиа. Возвращает LobbyPeer
// который можно слушать через Incoming() и в который можно слать
// через SendCtrl().
//
// Ctx живёт пока caller не вызовет Close(). Если ctx отменили извне —
// peer тоже останавливается.
func OpenLobbyPeer(parent context.Context, lg *log.Logger, opts LobbyOptions) (*LobbyPeer, error) {
	if opts.MeetingURL == "" {
		return nil, errors.New("vkcalls/lobby: MeetingURL required")
	}
	if opts.CaptchaSolver == nil {
		return nil, errors.New("vkcalls/lobby: CaptchaSolver required (lobby auth обычный VK)")
	}

	shortID := extractShortID(opts.MeetingURL)
	if shortID == "" {
		return nil, fmt.Errorf("vkcalls/lobby: cannot extract short id from %q", opts.MeetingURL)
	}

	ctx, cancel := context.WithCancel(parent)

	authSpec := AuthSpec{
		ShortID:  shortID,
		Name:     identity.NameOrGenerate(opts.DisplayName),
		DeviceID: uuid.NewString(),
		Solver:   opts.CaptchaSolver,
	}
	auth, err := DoAuth(ctx, lg, authSpec)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("vkcalls/lobby: auth: %w", err)
	}
	lg.Printf("vkcalls/lobby: auth ✓ peerId=%s userId=%s", auth.PeerID, auth.UserID)

	// Lobby peer всегда role="lobby" — для adoptParticipants/participant-joined
	// это значит "не sendOffer, не sendAnswer". Только signaling.
	p, err := dialPeer(ctx, lg, auth, "lobby", "h264")
	if err != nil {
		cancel()
		return nil, err
	}

	lp := &LobbyPeer{
		auth:     auth,
		peer:     p,
		lg:       lg,
		cancel:   cancel,
		incoming: make(chan IncomingCtrl, 32),
	}
	p.controlListener = func(from int64, ctrl GoloomCtrl) {
		select {
		case lp.incoming <- IncomingCtrl{From: from, Msg: ctrl}:
		default:
			lg.Printf("vkcalls/lobby: ctrl chan full, dropping %s from %d", ctrl.Type, from)
		}
	}

	go p.run(ctx)
	lg.Printf("vkcalls/lobby: ws connected, listening for goloom_ctrl")

	return lp, nil
}

// Incoming возвращает канал control сообщений от других peer'ов в lobby.
func (lp *LobbyPeer) Incoming() <-chan IncomingCtrl {
	return lp.incoming
}

// SendCtrl шлёт goloom_ctrl envelope конкретному peer'у через SFU
// transmit-data. participantID можно взять из IncomingCtrl.From,
// или RemotePeerID() для случая 2-peer lobby.
func (lp *LobbyPeer) SendCtrl(participantID int64, ctrl GoloomCtrl) error {
	lp.mu.Lock()
	if lp.closed {
		lp.mu.Unlock()
		return errors.New("lobby peer closed")
	}
	lp.mu.Unlock()
	if participantID == 0 {
		return errors.New("participantID required")
	}
	// Сериализуем GoloomCtrl как JSON object внутри data.
	raw, err := json.Marshal(ctrl)
	if err != nil {
		return fmt.Errorf("marshal ctrl: %w", err)
	}
	var dataObj map[string]any
	if err := json.Unmarshal(raw, &dataObj); err != nil {
		return fmt.Errorf("unmarshal ctrl: %w", err)
	}
	return lp.peer.sendCommand(map[string]any{
		"command":         "transmit-data",
		"participantId":   participantID,
		"participantType": "USER",
		"data":            dataObj,
	})
}

// RemotePeerID возвращает первый ненулевой не-self peer ID в lobby
// roster'е (после connection notification). 0 если ещё никого нет.
//
// Удобно для клиента в 2-peer lobby (server + client): после
// peer-join'а сервер уже там, его ID становится remoteID.
func (lp *LobbyPeer) RemotePeerID() int64 {
	return lp.peer.remoteID
}

// AuthResult возвращает auth state — caller может реюзить TURN
// creds или другие данные.
func (lp *LobbyPeer) Auth() *AuthResult { return lp.auth }

// Close корректно отрывает lobby peer.
func (lp *LobbyPeer) Close() {
	lp.mu.Lock()
	if lp.closed {
		lp.mu.Unlock()
		return
	}
	lp.closed = true
	lp.mu.Unlock()
	lp.cancel()
	if lp.peer != nil {
		lp.peer.Close()
	}
	close(lp.incoming)
}

// Done возвращает канал, который закрывается когда внутренняя WS
// сессия peer'а завершилась (server-side disconnect, network error,
// ctx cancel). Вызывающий должен реагировать teardown'ом.
func (lp *LobbyPeer) Done() <-chan struct{} {
	return lp.peer.Done()
}
