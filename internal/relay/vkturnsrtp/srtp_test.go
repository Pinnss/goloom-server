package vkturnsrtp

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSRTP_RoundTrip exercises the full client↔server SRTP path on
// loopback: spin up our Server, dial it from our Client, send some
// payload bytes in both directions, and verify they arrive intact
// after DTLS-SRTP handshake + RTP/SRTP encode/decode round-trip.
//
// Catches any regression in either Client or Server keystream /
// RTP packing — same bug surface that would otherwise only show up
// as opaque "DTLS handshake timeout" in production.
func TestSRTP_RoundTrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	srv, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	// Server side: accept one session, echo each Read back via Write.
	srvDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := srv.Accept(ctx)
		if err != nil {
			srvDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			srvDone <- err
			return
		}
		// Echo it back, verbatim.
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(buf[:n]); err != nil {
			srvDone <- err
			return
		}
		srvDone <- nil
	}()

	// Client side: bind a local UDP, point it at the server, run DTLS
	// + SRTP handshake, write payload, expect the echo back.
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client bind: %v", err)
	}
	defer clientUDP.Close()

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	cConn, err := Client(hsCtx, clientUDP, srv.Addr())
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	defer cConn.Close()

	payload := []byte("hello SRTP client→server→client round-trip")

	if err := cConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client write deadline: %v", err)
	}
	if _, err := cConn.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	echoed := make([]byte, 4096)
	if err := cConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	n, err := cConn.Read(echoed)
	if err != nil {
		t.Fatalf("client read echo: %v", err)
	}
	if string(echoed[:n]) != string(payload) {
		t.Fatalf("echo mismatch:\n  sent:  %q\n  got:   %q", payload, echoed[:n])
	}

	if err := <-srvDone; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
