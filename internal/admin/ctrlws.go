// Ctrl-WS — клиентский control channel к VK-инбаундам, работающим в
// режиме AcceptClientMeeting (S2+S3). Клиент → сервер: при коннекте
// открывает WebSocket на /ctrl/inbound/<id>?token=<bearer>, шлёт
// HELLO + DIAL{meetingURL}, и сервер запускает Transport.Connect для
// VK с этим meeting'ом.
//
// Protocol (JSON-encoded text frames):
//
//	client → server:
//	  { "type": "HELLO",  "client_id": "<uuid>" }
//	  { "type": "DIAL",   "meeting_url": "https://vk.com/call/join/<id>" }
//	  { "type": "BYE" }
//
//	server → client:
//	  { "type": "WELCOME", "inbound_tag": "vk", "codec": "vp8" }
//	  { "type": "DIAL_OK", "session_id": "<uuid>" }
//	  { "type": "DIAL_FAIL", "reason": "<msg>" }
//	  { "type": "STATUS", "phase": "auth|peer-connect|relaying", "detail": "..." }
//
// Lifetime: WS живёт всю VK-сессию. На client BYE или close
// сервер отрывает session. На server-side ошибку (например, fail
// captcha) — шлёт DIAL_FAIL и закрывает.
//
// Auth: per-inbound bearer token (Spec.CtrlBearer). Клиент шлёт
// `?token=<bearer>` в query. Mismatched/empty → 401.
//
// Concurrency (MVP): 1 inbound = 1 active session. Если клиент уже
// держит ctrl-ws сессию, второй получает 409.

package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// CtrlMessage — общая обёртка. type определяет какие поля заполнены.
type CtrlMessage struct {
	Type       string `json:"type"`
	ClientID   string `json:"client_id,omitempty"`
	InboundTag string `json:"inbound_tag,omitempty"`
	Codec      string `json:"codec,omitempty"`
	MeetingURL string `json:"meeting_url,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// CtrlBackend — что Server'у нужно от Manager'а чтобы драйвить VK
// клиент-meeting сессии. Реализуется [internal/inbound].Manager.
type CtrlBackend interface {
	// VKDial находит VK-инбаунд по id, проверяет bearer-token,
	// триггерит Transport.Connect с указанным meeting URL.
	// Возвращает sessionID если успешно, или ошибку.
	// onClose вызывается когда сессия завершилась (например, peer
	// closed) — handler должен послать клиенту close frame.
	VKDial(inboundID, bearerToken, meetingURL string, onClose func()) (sessionID string, err error)

	// VKHangup корректно закрывает текущую сессию инбаунда.
	// Идемпотентен.
	VKHangup(inboundID, sessionID string)

	// VKInboundInfo возвращает tag + codec + наличие active-сессии
	// для приветствия клиента.
	VKInboundInfo(inboundID string) (tag, codec string, busy bool, ok bool)
}

// ctrlServer хранит backend + WS upgrader. Smonтирован под /ctrl/
// в admin.Server.
type ctrlServer struct {
	backend  CtrlBackend
	upgrader websocket.Upgrader
	logger   *log.Logger

	// активные сессии — для блокировки concurrent DIAL'ов на
	// один инбаунд. Защита от двойного коннекта.
	activeMu sync.Mutex
	active   map[string]string // inboundID → sessionID
}

func newCtrlServer(backend CtrlBackend, lg *log.Logger) *ctrlServer {
	return &ctrlServer{
		backend: backend,
		logger:  lg,
		active:  map[string]string{},
		upgrader: websocket.Upgrader{
			// Клиенты у нас собственные (goloom-wg-client / GUI / Android),
			// CORS на admin TLS не имеет значения.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// AttachToMux mounts /ctrl/inbound/{id} as a single dispatcher.
func (cs *ctrlServer) AttachToMux(mux *http.ServeMux) {
	mux.HandleFunc("/ctrl/inbound/", cs.handle)
}

func (cs *ctrlServer) handle(w http.ResponseWriter, r *http.Request) {
	// /ctrl/inbound/<id>
	idPart := strings.TrimPrefix(r.URL.Path, "/ctrl/inbound/")
	inboundID, _, _ := strings.Cut(idPart, "/")
	if inboundID == "" {
		http.Error(w, "inbound id required", http.StatusBadRequest)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token query param required", http.StatusUnauthorized)
		return
	}

	tag, codec, busy, ok := cs.backend.VKInboundInfo(inboundID)
	if !ok {
		http.Error(w, "inbound not found or not in client-meeting mode", http.StatusNotFound)
		return
	}
	if busy {
		http.Error(w, "inbound already has an active session", http.StatusConflict)
		return
	}

	conn, err := cs.upgrader.Upgrade(w, r, nil)
	if err != nil {
		cs.logf("ws upgrade %s: %v", inboundID, err)
		return
	}
	defer conn.Close()

	cs.runSession(conn, inboundID, token, tag, codec)
}

func (cs *ctrlServer) runSession(conn *websocket.Conn, inboundID, token, tag, codec string) {
	send := func(msg CtrlMessage) error {
		buf, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return conn.WriteMessage(websocket.TextMessage, buf)
	}
	sendFail := func(reason string) {
		_ = send(CtrlMessage{Type: "DIAL_FAIL", Reason: reason})
	}

	// Welcome.
	if err := send(CtrlMessage{Type: "WELCOME", InboundTag: tag, Codec: codec}); err != nil {
		cs.logf("ws send WELCOME %s: %v", inboundID, err)
		return
	}

	// Read HELLO + DIAL.
	var hello, dial CtrlMessage
	if err := readMsg(conn, &hello); err != nil {
		cs.logf("read HELLO %s: %v", inboundID, err)
		return
	}
	if hello.Type != "HELLO" {
		sendFail("expected HELLO first")
		return
	}
	if err := readMsg(conn, &dial); err != nil {
		cs.logf("read DIAL %s: %v", inboundID, err)
		return
	}
	if dial.Type != "DIAL" {
		sendFail("expected DIAL after HELLO")
		return
	}
	if dial.MeetingURL == "" {
		sendFail("DIAL.meeting_url required")
		return
	}

	// Lock the inbound for this session.
	cs.activeMu.Lock()
	if _, alreadyActive := cs.active[inboundID]; alreadyActive {
		cs.activeMu.Unlock()
		sendFail("inbound already busy (race)")
		return
	}
	cs.active[inboundID] = "pending"
	cs.activeMu.Unlock()
	defer func() {
		cs.activeMu.Lock()
		delete(cs.active, inboundID)
		cs.activeMu.Unlock()
	}()

	closedCh := make(chan struct{}, 1)
	onClose := func() {
		select {
		case closedCh <- struct{}{}:
		default:
		}
	}

	cs.logf("DIAL %s clientID=%s meeting=%s", inboundID, hello.ClientID, redactMeeting(dial.MeetingURL))
	sessionID, err := cs.backend.VKDial(inboundID, token, dial.MeetingURL, onClose)
	if err != nil {
		sendFail(err.Error())
		return
	}
	cs.activeMu.Lock()
	cs.active[inboundID] = sessionID
	cs.activeMu.Unlock()

	defer cs.backend.VKHangup(inboundID, sessionID)

	if err := send(CtrlMessage{Type: "DIAL_OK", SessionID: sessionID}); err != nil {
		cs.logf("ws send DIAL_OK %s: %v", inboundID, err)
		return
	}

	// Read loop — следим за BYE / disconnect и keepalive ping/pong.
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		for {
			var m CtrlMessage
			if err := readMsg(conn, &m); err != nil {
				return
			}
			if m.Type == "BYE" {
				return
			}
			// Прочие сообщения от клиента игнорируем (forward-compat).
		}
	}()

	select {
	case <-clientGone:
		cs.logf("ctrl-ws %s: client disconnected", inboundID)
	case <-closedCh:
		cs.logf("ctrl-ws %s: server-side session ended", inboundID)
		_ = send(CtrlMessage{Type: "STATUS", Phase: "closed", Detail: "session ended"})
	}
}

func readMsg(conn *websocket.Conn, out *CtrlMessage) error {
	mt, raw, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if mt != websocket.TextMessage {
		return errors.New("expected text frame")
	}
	return json.Unmarshal(raw, out)
}

func redactMeeting(url string) string {
	// VK call link выглядит как https://vk.com/call/join/<id-of-30-chars>.
	// Логируем только префикс id'шника — для дебага достаточно, для
	// audit'а полный URL сохраним в audit-log отдельно (TODO).
	if i := strings.LastIndex(url, "/"); i > 0 && i < len(url)-12 {
		return url[:i+13] + "***"
	}
	return "***"
}

func (cs *ctrlServer) logf(format string, args ...any) {
	if cs.logger == nil {
		return
	}
	cs.logger.Printf("ctrl-ws: "+format, args...)
}
