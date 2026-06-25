package goloom

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// IncomingHandler receives a parsed Envelope plus the raw bytes of the
// inner-typed payload (the JSON value of the type key, e.g. the bytes of the
// PublisherSdpAnswer object). Type tells which key was set on the envelope.
type IncomingHandler func(typeName string, env *RecvEnvelope, payload json.RawMessage)

// RecvEnvelope is the parse-side counterpart of Envelope. We only extract the
// uid and let the caller decode the typed payload as needed.
type RecvEnvelope struct {
	UID     string
	Type    string          // e.g. "serverHello", "publisherSdpAnswer"
	Payload json.RawMessage // raw JSON value of the type field
	Raw     []byte          // entire frame
}

// Client manages one goloom WebSocket session. Lifecycle:
//
//	c := NewClient(ws, log)
//	c.OnIncoming(handler)   // optional dispatch
//	c.Start(ctx)            // launches read+write loops
//	c.Send(env)             // typed send (Send queues, returns immediately)
//	c.SendAck(uid)          // shorthand
//	c.Close()
//
// Ping and telemetry are driven by ConfigurePeriodicTasks once the server
// supplies pingPongConfiguration / telemetryConfiguration.
type Client struct {
	ws  *websocket.Conn
	log *log.Logger

	sendQ chan []byte

	mu          sync.Mutex
	closed      bool
	handler     IncomingHandler
	pendingAcks map[string]time.Time // uid -> sent_at, drained on incoming ack
	lastRecv    time.Time            // last successful WS read; liveness heartbeat

	pingTicker      *time.Ticker
	telemetryTicker *time.Ticker
	tickersDone     chan struct{}
	ackTimeout      time.Duration
}

// NewClient wraps an already-open WebSocket. UA/Origin headers must be set on
// the dialer by the caller.
func NewClient(ws *websocket.Conn, lg *log.Logger) *Client {
	return &Client{
		ws:          ws,
		log:         lg,
		sendQ:       make(chan []byte, 64),
		pendingAcks: make(map[string]time.Time),
		ackTimeout:  9 * time.Second,
	}
}

// pingDeadAfter is how long an idle session may go without ANY inbound WS
// message before the liveness watchdog declares it dead and forces a
// reconnect. A healthy session receives a ping-ack every few seconds, so this
// is ~6 missed pings — long enough to tolerate jitter, short enough that a
// dead idle inbound recovers before a user notices. This is what lets the
// server WaitForPeer wait indefinitely (no fixed reconnect timer) without
// churning the Telemost room.
const pingDeadAfter = 30 * time.Second

// OnIncoming registers a single dispatcher. The handler is invoked
// synchronously from the read loop, so it must not block on Send (use the
// fact that Send is non-blocking up to channel buffer).
func (c *Client) OnIncoming(h IncomingHandler) { c.handler = h }

// Start launches the read and write goroutines. Returns immediately. The
// goroutines exit when ctx is cancelled or the WS errors.
func (c *Client) Start(ctx context.Context) {
	go c.writeLoop(ctx)
	go c.readLoop(ctx)
}

// ConfigurePeriodicTasks starts the ping and telemetry timers using values
// from serverHello. If either interval is zero we use sane defaults.
func (c *Client) ConfigurePeriodicTasks(ctx context.Context, ping PingPongConfiguration, telem TelemetryConfiguration) {
	pingMs := ping.PingInterval
	if pingMs <= 0 {
		pingMs = 5000
	}
	if ping.AckTimeout > 0 {
		c.ackTimeout = time.Duration(ping.AckTimeout) * time.Millisecond
	}
	telemMs := telem.SendingInterval
	if telemMs <= 0 {
		telemMs = 20000
	}
	c.pingTicker = time.NewTicker(time.Duration(pingMs) * time.Millisecond)
	c.telemetryTicker = time.NewTicker(time.Duration(telemMs) * time.Millisecond)
	c.tickersDone = make(chan struct{})
	c.noteRecv() // seed the liveness heartbeat so the watchdog has a baseline
	go c.periodicLoop(ctx)
}

func (c *Client) periodicLoop(ctx context.Context) {
	defer func() {
		if c.pingTicker != nil {
			c.pingTicker.Stop()
		}
		if c.telemetryTicker != nil {
			c.telemetryTicker.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tickersDone:
			return
		case <-c.pingTicker.C:
			// Liveness watchdog: a healthy session receives a ping-ack every
			// few seconds. If nothing has arrived for pingDeadAfter the WS is
			// dead (often a silently-dropped TCP conn with no close frame) —
			// force-close so the supervisor reconnects instead of idling on a
			// corpse. Without this, waiting indefinitely for a peer would risk
			// hanging forever on a half-dead session.
			if since := c.sinceLastRecv(); since > pingDeadAfter {
				c.log.Printf("session dead: no WS message for %s (> %s) — closing for reconnect", since.Truncate(time.Second), pingDeadAfter)
				_ = c.Close()
				return
			}
			if err := c.Send(Envelope{Ping: &Ping{}}); err != nil {
				c.log.Printf("ping send err: %v", err)
				return
			}
		case <-c.telemetryTicker.C:
			if err := c.Send(Envelope{Telemetry: &Telemetry{PublisherRawStatsReport: []string{"{}"}}}); err != nil {
				c.log.Printf("telemetry send err: %v", err)
				return
			}
		}
	}
}

// Send queues an envelope for transmission. UID is auto-assigned if blank.
// Non-blocking up to the send buffer; returns error only if the conn is
// already closed or the queue is full (buffer overflow indicates a bug).
func (c *Client) Send(env Envelope) error {
	if env.UID == "" {
		env.UID = uuid.NewString()
	}
	buf, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	c.recordPending(env)
	select {
	case c.sendQ <- buf:
		c.logSend(env, buf)
		return nil
	default:
		return fmt.Errorf("send queue full")
	}
}

// SendAck builds and sends an ack frame using the supplied uid (NOT a fresh
// one) and an OK status.
func (c *Client) SendAck(replyUID string) error {
	env := Envelope{UID: replyUID, Ack: &Ack{Status: AckStatus{Code: "OK"}}}
	buf, err := json.Marshal(env)
	if err != nil {
		return err
	}
	select {
	case c.sendQ <- buf:
		c.log.Printf("← ack(%s)", shortUID(replyUID))
		return nil
	default:
		return fmt.Errorf("send queue full")
	}
}

// recordPending tracks every non-ack send so we can warn on missing acks.
func (c *Client) recordPending(env Envelope) {
	if env.Ack != nil {
		return
	}
	c.mu.Lock()
	c.pendingAcks[env.UID] = time.Now()
	c.mu.Unlock()
}

// matchAck removes an entry from pendingAcks when its server-side ack arrives.
func (c *Client) matchAck(uid string) {
	c.mu.Lock()
	delete(c.pendingAcks, uid)
	c.mu.Unlock()
}

func (c *Client) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.sendQ:
			if err := c.ws.Write(ctx, websocket.MessageText, msg); err != nil {
				c.log.Printf("ws write err: %v", err)
				return
			}
		}
	}
}

func (c *Client) readLoop(ctx context.Context) {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			c.log.Printf("ws read err: %v", err)
			c.markClosed()
			return
		}
		c.noteRecv()
		c.dispatch(data)
	}
}

func (c *Client) dispatch(data []byte) {
	// Parse just the keys to find uid + type.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		c.log.Printf("recv unmarshal err: %v body=%s", err, truncate(string(data), 200))
		return
	}
	var uid string
	if rawUID, ok := probe["uid"]; ok {
		_ = json.Unmarshal(rawUID, &uid)
	}
	var typeName string
	var payload json.RawMessage
	for k, v := range probe {
		if k == "uid" {
			continue
		}
		typeName = k
		payload = v
		break
	}
	c.logRecv(uid, typeName, data)

	env := &RecvEnvelope{UID: uid, Type: typeName, Payload: payload, Raw: data}

	// Server-side ack frames are not themselves ack-able; just clear pending.
	if typeName == "ack" {
		c.matchAck(uid)
		if c.handler != nil {
			c.handler(typeName, env, payload)
		}
		return
	}

	// Everything else gets an immediate ack. Spec'd handler may also act on it.
	if err := c.SendAck(uid); err != nil {
		c.log.Printf("auto-ack err: %v", err)
	}
	if c.handler != nil {
		c.handler(typeName, env, payload)
	}
}

func (c *Client) markClosed() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// IsClosed reports whether the WS has been closed — cleanly via Close() or
// after a read error / liveness-watchdog teardown. WaitForPeer polls this so
// it can wait indefinitely for a peer yet bail out promptly when the session
// dies, instead of relying on a fixed reconnect timer (which churns the room).
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// noteRecv records that a WS message just arrived (liveness heartbeat).
func (c *Client) noteRecv() {
	c.mu.Lock()
	c.lastRecv = time.Now()
	c.mu.Unlock()
}

// sinceLastRecv returns how long since the last WS message arrived.
func (c *Client) sinceLastRecv() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastRecv)
}

// Close shuts down the WS conn. Safe to call multiple times.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.tickersDone != nil {
		close(c.tickersDone)
	}
	return c.ws.Close(websocket.StatusNormalClosure, "bye")
}

func (c *Client) logSend(env Envelope, raw []byte) {
	t := envelopeType(env)
	c.log.Printf("→ %s (uid=%s, %d bytes)", t, shortUID(env.UID), len(raw))
}

func (c *Client) logRecv(uid, typeName string, raw []byte) {
	c.log.Printf("← %s (uid=%s, %d bytes)", typeName, shortUID(uid), len(raw))
}

func envelopeType(env Envelope) string {
	switch {
	case env.Hello != nil:
		return "hello"
	case env.Ack != nil:
		return "ack"
	case env.PublisherSdpOffer != nil:
		return "publisherSdpOffer"
	case env.SubscriberSdpAnswer != nil:
		return "subscriberSdpAnswer"
	case env.WebrtcIceCandidate != nil:
		return "webrtcIceCandidate"
	case env.SetSlots != nil:
		return "setSlots"
	case env.Telemetry != nil:
		return "telemetry"
	case env.Ping != nil:
		return "ping"
	case env.UpdatePublisherTrackDescription != nil:
		return "updatePublisherTrackDescription"
	case env.UpdateMe != nil:
		return "updateMe"
	case env.SdkCodecsInfo != nil:
		return "sdkCodecsInfo"
	default:
		return "?"
	}
}

func shortUID(u string) string {
	if len(u) >= 8 {
		return u[:8]
	}
	return u
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// DialOptions lets the caller specify the headers required by the goloom
// endpoint (UA + Origin must mirror the web client).
type DialOptions struct {
	UserAgent string
	Origin    string
}

// Dial opens the WS to the goloom signalling endpoint with the right headers.
// Telemost requires the Origin header; the UA is set as a courtesy / future
// platform-routing safety net.
func Dial(ctx context.Context, urlStr string, opts DialOptions) (*websocket.Conn, error) {
	hdr := http.Header{}
	hdr.Set("User-Agent", opts.UserAgent)
	hdr.Set("Origin", opts.Origin)
	conn, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	conn.SetReadLimit(8 * 1024 * 1024) // SDP frames + slotsConfig can be large
	return conn, nil
}
