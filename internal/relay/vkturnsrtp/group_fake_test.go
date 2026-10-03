package vkturnsrtp

import (
	"net"
	"sync"
	"time"
)

// fakeSRTPConn is a net.Conn that records what was written to it.
type fakeSRTPConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func newFakeSRTPConn() *fakeSRTPConn { return &fakeSRTPConn{} }

func (f *fakeSRTPConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (f *fakeSRTPConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	f.writes = append(f.writes, cp)
	return len(b), nil
}

func (f *fakeSRTPConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeSRTPConn) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeSRTPConn) LocalAddr() net.Addr                { return fakeSRTPAddr{} }
func (f *fakeSRTPConn) RemoteAddr() net.Addr               { return fakeSRTPAddr{} }
func (f *fakeSRTPConn) SetDeadline(time.Time) error        { return nil }
func (f *fakeSRTPConn) SetReadDeadline(time.Time) error    { return nil }
func (f *fakeSRTPConn) SetWriteDeadline(_ time.Time) error { return nil }

type fakeSRTPAddr struct{}

func (fakeSRTPAddr) Network() string { return "srtp" }
func (fakeSRTPAddr) String() string  { return "srtp" }
