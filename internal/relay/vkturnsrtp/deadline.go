package vkturnsrtp

import (
	"sync"
	"time"
)

// deadline is the read-deadline machinery shared by the two net.Conn-ish types
// in this package (packetConnAdapter and wrappedConn). Both used to carry their
// own copy, and both allocated a fresh time.AfterFunc plus a fresh channel on
// EVERY SetReadDeadline call.
//
// That is ruinous here, because the relay re-arms the deadline once per packet
// (see listener.go) with a 30-minute value: each uplink packet left a pending
// 30-minute timer whose closure pinned a channel, so a client pushing ~1000
// packets/s accumulated on the order of a million live timers per conn before
// the first one expired. Upstream diagnosed the same shape as a GC
// death-spiral. Here one timer per conn is re-armed with Reset instead.
//
// A superseded timer may still fire (Stop cannot cancel a callback already
// running), so expiry is decided by comparing against the CURRENT deadline
// rather than by trusting the wakeup: a stale fire finds exp in the future and
// does nothing.
type deadline struct {
	mu    sync.Mutex
	exp   time.Time
	ch    chan struct{}
	timer *time.Timer
}

// wait returns a channel that is closed when the current deadline expires.
// Callers must re-fetch it after every set.
func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ch == nil {
		d.ch = make(chan struct{})
	}
	return d.ch
}

// expired reports whether the current deadline has already passed.
func (d *deadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.exp.IsZero() && !time.Now().Before(d.exp)
}

// set installs a new deadline. The zero time clears it. Setting a new deadline
// releases anyone waiting on the previous channel, which is what the callers
// expect: they re-read wait() on the next iteration.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	closeCh(d.ch)
	d.ch = make(chan struct{})
	d.exp = t

	if t.IsZero() {
		if d.timer != nil {
			d.timer.Stop()
		}
		return
	}
	dur := time.Until(t)
	if dur <= 0 {
		close(d.ch)
		return
	}
	if d.timer == nil {
		d.timer = time.AfterFunc(dur, d.fire)
		return
	}
	d.timer.Stop()
	d.timer.Reset(dur)
}

// fire is the single timer callback, shared across every deadline this conn
// ever has. It closes the channel only if the deadline it was armed for has
// actually arrived.
func (d *deadline) fire() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.exp.IsZero() || time.Now().Before(d.exp) {
		return // superseded by a later deadline; not ours to expire
	}
	closeCh(d.ch)
}

// stop releases the timer. Call it when the conn is closed.
func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func closeCh(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}
