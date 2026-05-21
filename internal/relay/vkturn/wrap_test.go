package vkturn

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// TestWrap_RoundTrip exercises the WRAP layer end-to-end on loopback:
// bind a server-side wrapPacketListener, dial a plain UDP socket from
// the "client" side, hand-craft a wrapped packet with the same key,
// send it, and confirm the server's wrapped PacketConn surfaces the
// plaintext.
//
// Catches any regression in wrap_packet wire format / ChaCha20 nonce
// handling that would otherwise only surface as "DTLS handshake
// timeout" in production — same symptom we hit with anton48 client
// vs our v3.1.2 pion-dtls listener.
func TestWrap_RoundTrip(t *testing.T) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("gen key: %v", err)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	srvLn, err := listenWrapped(addr, key)
	if err != nil {
		t.Fatalf("listenWrapped: %v", err)
	}
	defer srvLn.Close()
	srvAddr := srvLn.Addr().(*net.UDPAddr)

	plaintext := []byte("hello wrap, this is plain DTLS bytes\x16\x01\x02\x03")

	// Server side: accept a virtual "connection" from the first source
	// address, read one packet, verify plaintext, and signal done.
	type readResult struct {
		got []byte
		err error
	}
	srvDone := make(chan readResult, 1)
	go func() {
		pc, _, err := srvLn.Accept()
		if err != nil {
			srvDone <- readResult{err: err}
			return
		}
		defer pc.Close()
		buf := make([]byte, 4096)
		if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			srvDone <- readResult{err: err}
			return
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			srvDone <- readResult{err: err}
			return
		}
		srvDone <- readResult{got: append([]byte(nil), buf[:n]...)}
	}()

	// Client side: hand-build wrapped wire bytes using the same helper
	// the server-side WriteTo uses, but here we just call the symmetric
	// primitive via a bare *wrapPacketConn — no need to wire up a full
	// listener on the client side for a one-shot send.
	clientConn, err := net.DialUDP("udp", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Reuse the server's WriteTo path by wrapping a plain UDP conn
	// behind wrapPacketConn. The "inner" PacketConn is the UDP one
	// dialled above (cast to net.PacketConn).
	innerPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client bind: %v", err)
	}
	defer innerPC.Close()
	wpc := &wrapPacketConn{inner: innerPC, key: key}
	if _, err := wpc.WriteTo(plaintext, srvAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	res := <-srvDone
	if res.err != nil {
		t.Fatalf("server read: %v", res.err)
	}
	if string(res.got) != string(plaintext) {
		t.Fatalf("plaintext mismatch:\n  sent:  %q\n  got:   %q", plaintext, res.got)
	}
}

// TestWrap_WrongKeyRejectsAsGarbage exercises the failure mode that
// anton48 hits when the client and server WRAP keys disagree: server
// "decrypts" with the wrong key, the output is noise, and any DTLS
// state machine on top would fail to parse it.
//
// We assert here that wrong-key output is *not* equal to the original
// plaintext (catching a hypothetical accidental-no-op like an early
// return before XOR'ing).
func TestWrap_WrongKeyRejectsAsGarbage(t *testing.T) {
	keyA := make([]byte, wrapKeyLen)
	keyB := make([]byte, wrapKeyLen)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatalf("gen keyA: %v", err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatalf("gen keyB: %v", err)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	srvLn, err := listenWrapped(addr, keyA)
	if err != nil {
		t.Fatalf("listenWrapped: %v", err)
	}
	defer srvLn.Close()
	srvAddr := srvLn.Addr().(*net.UDPAddr)

	plaintext := []byte("hello DTLS\x16\x01\x02")

	type readResult struct {
		got []byte
		err error
	}
	srvDone := make(chan readResult, 1)
	go func() {
		pc, _, err := srvLn.Accept()
		if err != nil {
			srvDone <- readResult{err: err}
			return
		}
		defer pc.Close()
		buf := make([]byte, 4096)
		if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			srvDone <- readResult{err: err}
			return
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			srvDone <- readResult{err: err}
			return
		}
		srvDone <- readResult{got: append([]byte(nil), buf[:n]...)}
	}()

	innerPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client bind: %v", err)
	}
	defer innerPC.Close()
	wpc := &wrapPacketConn{inner: innerPC, key: keyB} // wrong key
	if _, err := wpc.WriteTo(plaintext, srvAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	res := <-srvDone
	if res.err != nil {
		t.Fatalf("server read: %v", res.err)
	}
	if string(res.got) == string(plaintext) {
		t.Fatalf("wrong-key decrypt should be garbage but matched plaintext exactly: %q", res.got)
	}
}
