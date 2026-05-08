package videocode

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
)

// Tunnel provides a bidirectional data channel over video streams.
// It fragments writes into MaxPayloadPerFrame-sized chunks, sends them
// via the Sender, and reassembles received chunks from the Receiver.
type Tunnel struct {
	sender   *Sender
	receiver *Receiver

	readCh  chan []byte
	readBuf []byte
	mu      sync.Mutex

	// Payloads dropped because readCh was full (reverse path congestion).
	readDropped atomic.Uint64
}

// readCh buffers decoded tunnel payloads toward the app; large enough to avoid drops when TUN/user is slow.
const tunnelReadChCap = 1024

func NewTunnel(sender *Sender, receiver *Receiver) *Tunnel {
	return &Tunnel{
		sender:   sender,
		receiver: receiver,
		readCh:   make(chan []byte, tunnelReadChCap),
	}
}

// Run starts the tunnel's receive pump. Blocks until ctx is cancelled.
func (t *Tunnel) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-t.receiver.RecvCh():
			// Blocking: backpressure instead of dropping when the consumer is slow.
			t.readCh <- frame.Payload
		}
	}
}

// Write sends data through the video tunnel. Fragments into MaxPayloadPerFrame chunks.
func (t *Tunnel) Write(p []byte) (n int, err error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayloadPerFrame {
			chunk = p[:MaxPayloadPerFrame]
		}
		cp := make([]byte, len(chunk))
		copy(cp, chunk)
		if err := t.sender.Send(context.Background(), cp); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read reads data received from the video tunnel.
func (t *Tunnel) Read(p []byte) (n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for len(t.readBuf) == 0 {
		t.mu.Unlock()
		data, ok := <-t.readCh
		t.mu.Lock()
		if !ok {
			return 0, io.EOF
		}
		t.readBuf = append(t.readBuf, data...)
	}

	n = copy(p, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

// ReadCh returns the raw receive channel for select-based reading.
func (t *Tunnel) ReadCh() <-chan []byte {
	return t.readCh
}

// ReadDroppedTotal returns how many decoded payloads were dropped due to a full readCh.
func (t *Tunnel) ReadDroppedTotal() uint64 {
	return t.readDropped.Load()
}
