package wgrelay

import (
	"context"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Pinnss/goloom-server/internal/tunnel"
)

// TestWatchdog_NoTriggerBeforeHandshake — пока gotFirstRx==false (никаких
// WG-payload не приходило), watchdog не должен срабатывать даже если
// rx-counter не движется. Иначе reconnect-loop сразу после старта.
func TestWatchdog_NoTriggerBeforeHandshake(t *testing.T) {
	dt := &DataTunnel{}
	ctx, cancel := context.WithCancel(context.Background())
	var fired atomic.Bool

	wrappedCancel := func() { fired.Store(true); cancel() }
	go RunRxStallWatchdog(ctx, wrappedCancel, dt, log.New(os.Stderr, "[t] ", 0),
		20*time.Millisecond, 100*time.Millisecond)

	time.Sleep(300 * time.Millisecond)

	if fired.Load() {
		t.Fatal("watchdog fired without ever seeing a WG payload")
	}
	cancel()
}

// TestWatchdog_TriggersAfterStall — после первого WG-payload (gotFirstRx==true)
// и истечения rxStallTimeout без новых rx — watchdog должен:
//   1. вызвать cancel()
//   2. установить WasRxStalled() в true
func TestWatchdog_TriggersAfterStall(t *testing.T) {
	dt := &DataTunnel{}
	// эмулируем что один WG-payload пришёл — счётчики становятся "ready"
	dt.rxBytes.Store(148)
	dt.gotFirstRx.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	var fired atomic.Bool
	wrappedCancel := func() { fired.Store(true); cancel() }

	done := make(chan struct{})
	go func() {
		RunRxStallWatchdog(ctx, wrappedCancel, dt, log.New(os.Stderr, "[t] ", 0),
			20*time.Millisecond, 100*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("watchdog did not exit within 2s; should have detected stall")
	}

	if !fired.Load() {
		t.Error("watchdog did not call cancel()")
	}
	if !dt.WasRxStalled() {
		t.Error("watchdog did not mark DataTunnel as stalled")
	}
}

// TestWatchdog_ResetsBaselineOnRxMovement — пока rx-counter растёт, watchdog
// должен оставаться в "здоровом" режиме и не срабатывать.
func TestWatchdog_ResetsBaselineOnRxMovement(t *testing.T) {
	dt := &DataTunnel{}
	dt.rxBytes.Store(100)
	dt.gotFirstRx.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var fired atomic.Bool
	wrappedCancel := func() { fired.Store(true); cancel() }

	go RunRxStallWatchdog(ctx, wrappedCancel, dt, log.New(os.Stderr, "[t] ", 0),
		20*time.Millisecond, 100*time.Millisecond)

	// Каждые 30мс инкрементируем rx — watchdog должен видеть "движение".
	for i := 0; i < 20; i++ {
		time.Sleep(30 * time.Millisecond)
		dt.rxBytes.Add(50)
	}

	if fired.Load() {
		t.Fatal("watchdog falsely fired despite continuous rx movement")
	}
}

// TestDataTunnel_StatsCountersFromRun — Run() должен инкрементировать
// rxBytes и устанавливать gotFirstRx при получении FlagWGData кадра.
func TestDataTunnel_StatsCountersFromRun(t *testing.T) {
	frames := make(chan tunnel.ReceivedFrame, 4)
	dt := New(nil, frames, log.New(os.Stderr, "[t] ", 0))

	rx, _, ready := dt.Stats()
	if rx != 0 || ready {
		t.Fatalf("fresh DataTunnel: rx=%d ready=%v, want rx=0 ready=false", rx, ready)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Один FlagWGData кадр, один не-WG.
		frames <- tunnel.ReceivedFrame{
			Flags:   FlagWGData,
			Payload: []byte("0123456789"), // 10 bytes
		}
		frames <- tunnel.ReceivedFrame{
			Flags:   tunnel.Flags(0), // не FlagWGData — не должен учитываться
			Payload: []byte("xxxxx"),
		}
	}()

	go dt.Run(ctx)

	// Ждём пока Run обработает.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rx, _, ready = dt.Stats()
		if rx == 10 && ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("after WG frame: rx=%d ready=%v, want rx=10 ready=true", rx, ready)
}
