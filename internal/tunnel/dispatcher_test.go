package tunnel

import (
	"context"
	"log"
	"os"
	"testing"
	"time"
)

func TestDispatcherRoutesKCP(t *testing.T) {
	_, pc := newTestSenderAndConn(t)
	defer pc.Close()

	hsCh := make(chan ReceivedFrame, 8)
	legacyCh := make(chan ReceivedFrame, 8)
	d := &Dispatcher{
		KCPConn:   pc,
		Handshake: hsCh,
		Legacy:    legacyCh,
	}

	in := make(chan ReceivedFrame, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, in, log.New(os.Stderr, "[test] ", 0))

	in <- ReceivedFrame{MsgID: 1, Flags: FlagKCP, Payload: []byte("kcp-data")}
	in <- ReceivedFrame{MsgID: 2, Flags: FlagHandshake | FlagTest, Payload: []byte("hello")}
	in <- ReceivedFrame{MsgID: 3, Flags: FlagPing | FlagTest, Payload: []byte("ping")}

	// KCP frame should arrive in PacketConn
	buf := make([]byte, 64)
	pc.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "kcp-data" {
		t.Fatalf("got %q want %q", buf[:n], "kcp-data")
	}

	// Handshake frame
	select {
	case f := <-hsCh:
		if !f.Flags.Has(FlagHandshake) {
			t.Fatalf("expected handshake flag, got %d", f.Flags)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake frame not received")
	}

	// Legacy frame
	select {
	case f := <-legacyCh:
		if !f.Flags.Has(FlagPing) {
			t.Fatalf("expected ping flag, got %d", f.Flags)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy frame not received")
	}
}
