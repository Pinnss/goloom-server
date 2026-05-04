package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func newTestSenderAndConn(t *testing.T) (*Sender, *TunnelPacketConn) {
	t.Helper()
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"test-video", "test-stream",
	)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSender(track)
	pc := NewPacketConn(s, 64)
	return s, pc
}

func TestPacketConnDeliverAndRead(t *testing.T) {
	_, pc := newTestSenderAndConn(t)
	defer pc.Close()

	data := []byte("hello kcp")
	if !pc.Deliver(data) {
		t.Fatal("Deliver returned false on open conn")
	}

	buf := make([]byte, 1024)
	pc.SetReadDeadline(time.Now().Add(time.Second))
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("got %q want %q", buf[:n], data)
	}
	if addr == nil {
		t.Fatal("addr should not be nil")
	}
}

func TestPacketConnReadTimeout(t *testing.T) {
	_, pc := newTestSenderAndConn(t)
	defer pc.Close()

	pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	_, _, err := pc.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("expected net.Error with Timeout(), got %T: %v", err, err)
	}
}

func TestPacketConnCloseUnblocksRead(t *testing.T) {
	_, pc := newTestSenderAndConn(t)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := pc.ReadFrom(buf)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	pc.Close()

	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}
}

func TestPacketConnDeliverAfterClose(t *testing.T) {
	_, pc := newTestSenderAndConn(t)
	pc.Close()

	if pc.Deliver([]byte("late")) {
		t.Fatal("Deliver should return false after Close")
	}
}

func TestPacketConnWriteAfterClose(t *testing.T) {
	_, pc := newTestSenderAndConn(t)
	pc.Close()

	_, err := pc.WriteTo([]byte("late"), nil)
	if err != net.ErrClosed {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}
