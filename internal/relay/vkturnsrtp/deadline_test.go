package vkturnsrtp

import (
	"runtime"
	"testing"
	"time"
)

// A deadline that is pushed forward over and over — which is what the relay
// does for every packet it forwards — must not accumulate one timer per call.
// The old code allocated a fresh time.AfterFunc plus a channel each time, and
// each of those lived until its 30-minute deadline, so a busy conn piled up
// timers until the GC buckled.
func TestDeadlineReusesOneTimer(t *testing.T) {
	var d deadline
	d.set(time.Now().Add(30 * time.Minute))
	first := d.timer
	if first == nil {
		t.Fatal("no timer armed")
	}
	for i := 0; i < 10_000; i++ {
		d.set(time.Now().Add(30 * time.Minute))
	}
	if d.timer != first {
		t.Error("timer was replaced; each set must re-arm the existing one")
	}
	d.stop()
	if d.timer != nil {
		t.Error("stop must release the timer")
	}
}

// Pushing the deadline forward must also keep it from firing: a stale wakeup
// from the previous, shorter deadline must not expire the new one.
func TestDeadlineExtensionSuppressesStaleFire(t *testing.T) {
	var d deadline
	defer d.stop()
	d.set(time.Now().Add(20 * time.Millisecond))
	ch := d.wait()
	d.set(time.Now().Add(10 * time.Second))

	select {
	case <-ch:
		// The channel from before the extension is released on purpose —
		// callers re-read wait() — so this is fine. What must NOT happen is
		// the NEW deadline reading as expired.
	case <-time.After(60 * time.Millisecond):
	}
	if d.expired() {
		t.Fatal("extended deadline reported as expired after the old timer fired")
	}
	if got := d.wait(); isClosed(got) {
		t.Fatal("current deadline channel closed by a stale fire")
	}
}

func TestDeadlineFiresWhenItActuallyPasses(t *testing.T) {
	var d deadline
	defer d.stop()
	d.set(time.Now().Add(15 * time.Millisecond))
	select {
	case <-d.wait():
	case <-time.After(2 * time.Second):
		t.Fatal("deadline never fired")
	}
	if !d.expired() {
		t.Error("expired() disagrees with the closed channel")
	}
}

// A deadline already in the past must expire immediately — net.Conn semantics
// the relay uses to unblock a reader on teardown.
func TestDeadlineInThePastExpiresAtOnce(t *testing.T) {
	var d deadline
	defer d.stop()
	d.set(time.Now().Add(-time.Second))
	if !isClosed(d.wait()) {
		t.Error("past deadline did not expire")
	}
	if !d.expired() {
		t.Error("expired() false for a past deadline")
	}
}

func TestDeadlineZeroClears(t *testing.T) {
	var d deadline
	defer d.stop()
	d.set(time.Now().Add(10 * time.Millisecond))
	d.set(time.Time{})
	time.Sleep(40 * time.Millisecond)
	if d.expired() {
		t.Error("cleared deadline still reports expired")
	}
}

// Concurrent set/wait/expired must not race or panic on a double close; the
// old per-call timers had exactly that bug (close of closed channel).
func TestDeadlineConcurrentUse(t *testing.T) {
	var d deadline
	defer d.stop()
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for j := 0; j < 2_000; j++ {
				d.set(time.Now().Add(time.Duration(j%3) * time.Millisecond))
				_ = d.expired()
				_ = d.wait()
				runtime.Gosched()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("timed out")
		}
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
