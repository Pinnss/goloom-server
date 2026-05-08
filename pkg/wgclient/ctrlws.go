// Ctrl-WS клиент для VK client-meeting mode (S2/S3). Открывает WS
// до admin :9443, шлёт HELLO + DIAL{meeting}, ждёт DIAL_OK с
// session ID. Держит WS открытым на всю длительность SFU-сессии,
// шлёт BYE на close — server тогда корректно завершает свою
// VK-session со стороны inbound runner'а.
//
// Лайфтайм:
//
//	conn := openCtrlWS(...)
//	conn.Dial(meeting)            ← Connect-time, blocks until DIAL_OK
//	defer conn.Close()
//	... используем SFU как обычно ...
//
// При ошибке connect'а WS уже закрыт. При сбое в середине сессии
// Closed() канал firms — caller должен tear down session.

package wgclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type ctrlMessage struct {
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

// ctrlConn — открытый ctrl-ws к admin'у. Один на сессию.
type ctrlConn struct {
	conn      *websocket.Conn
	sessionID string
	logger    *log.Logger

	closed chan struct{}
}

// openCtrlWS открывает WS на admin'е и проводит HELLO+DIAL handshake.
// publicURL должен быть https://<host>:<port>; превращается в wss:// схему.
func openCtrlWS(ctx context.Context, lg *log.Logger, publicURL, inboundID, bearer, meeting, clientID string) (*ctrlConn, error) {
	if publicURL == "" || inboundID == "" || bearer == "" {
		return nil, errors.New("ctrl-ws: PublicURL/InboundID/Bearer required")
	}
	if meeting == "" {
		return nil, errors.New("ctrl-ws: meeting URL required")
	}

	wsURL, err := buildCtrlWSURL(publicURL, inboundID, bearer)
	if err != nil {
		return nil, fmt.Errorf("ctrl-ws: build url: %w", err)
	}

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		// admin сервер ходит со self-signed CA — пропускаем проверку.
		// В будущем можно прикрутить pinned CA через connstr, но MVP
		// работает с auto_self_signed.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	lg.Printf("ctrl-ws: dialing %s", redactWS(wsURL))
	conn, resp, err := dialer.DialContext(dctx, wsURL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ctrl-ws: dial: %w (status=%d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("ctrl-ws: dial: %w", err)
	}

	cc := &ctrlConn{conn: conn, logger: lg, closed: make(chan struct{})}

	// Server first frame: WELCOME.
	var welcome ctrlMessage
	if err := cc.read(&welcome); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: read WELCOME: %w", err)
	}
	if welcome.Type != "WELCOME" {
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: expected WELCOME, got %q (reason=%s)", welcome.Type, welcome.Reason)
	}
	lg.Printf("ctrl-ws: welcome inbound=%s codec=%s", welcome.InboundTag, welcome.Codec)

	// Send HELLO + DIAL.
	if err := cc.write(ctrlMessage{Type: "HELLO", ClientID: clientID}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: write HELLO: %w", err)
	}
	if err := cc.write(ctrlMessage{Type: "DIAL", MeetingURL: meeting}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: write DIAL: %w", err)
	}

	// Read DIAL_OK / DIAL_FAIL.
	var dialResp ctrlMessage
	if err := cc.read(&dialResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: read DIAL response: %w", err)
	}
	switch dialResp.Type {
	case "DIAL_OK":
		cc.sessionID = dialResp.SessionID
		lg.Printf("ctrl-ws: DIAL_OK session=%s", dialResp.SessionID)
	case "DIAL_FAIL":
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: DIAL_FAIL: %s", dialResp.Reason)
	default:
		conn.Close()
		return nil, fmt.Errorf("ctrl-ws: unexpected response type %q", dialResp.Type)
	}

	// Запускаем reader goroutine — следит за server-side close /
	// STATUS frames.
	go cc.readLoop()

	return cc, nil
}

// Closed возвращает канал, который закрывается когда ctrl-ws теряет
// связь (server закрыл / network error / etc). Caller должен на это
// реагировать teardown'ом своей SFU-сессии.
func (c *ctrlConn) Closed() <-chan struct{} {
	return c.closed
}

// SessionID — идентификатор session'а который сервер выделил.
func (c *ctrlConn) SessionID() string {
	return c.sessionID
}

// Close шлёт BYE и закрывает WS. Idempotent.
func (c *ctrlConn) Close() {
	if c.conn == nil {
		return
	}
	_ = c.write(ctrlMessage{Type: "BYE"})
	_ = c.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second),
	)
	_ = c.conn.Close()
}

// ─── internals ──────────────────────────────────────────────────────

func (c *ctrlConn) read(out *ctrlMessage) error {
	mt, raw, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}
	if mt != websocket.TextMessage {
		return fmt.Errorf("expected text frame, got %d", mt)
	}
	return json.Unmarshal(raw, out)
}

func (c *ctrlConn) write(msg ctrlMessage) error {
	buf, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.conn.WriteMessage(websocket.TextMessage, buf)
}

func (c *ctrlConn) readLoop() {
	defer close(c.closed)
	for {
		var m ctrlMessage
		if err := c.read(&m); err != nil {
			c.logger.Printf("ctrl-ws: read closed: %v", err)
			return
		}
		switch m.Type {
		case "STATUS":
			c.logger.Printf("ctrl-ws: status phase=%s detail=%s", m.Phase, m.Detail)
		case "DIAL_FAIL":
			c.logger.Printf("ctrl-ws: server-side fail: %s", m.Reason)
			return
		default:
			c.logger.Printf("ctrl-ws: unknown msg %s", m.Type)
		}
	}
}

func buildCtrlWSURL(publicURL, inboundID, bearer string) (string, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
		// already fine
	default:
		return "", fmt.Errorf("unsupported scheme %q (use https/http/wss/ws)", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/ctrl/inbound/" + inboundID
	q := u.Query()
	q.Set("token", bearer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func redactWS(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Get("token") != "" {
		q.Set("token", "***")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// suppress unused imports if extracted differently
var _ = http.StatusOK
