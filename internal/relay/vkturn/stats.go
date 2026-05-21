// throughputStats — per-session byte counters used when Options.Debug
// is on. Mirrors Moroka8 server/main.go::throughputStats verbatim,
// minus the global debugf() in favour of an injected *log.Logger.

package vkturn

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

type throughputStats struct {
	tx atomic.Uint64
	rx atomic.Uint64
}

func (s *throughputStats) addTx(n int) {
	if n > 0 {
		s.tx.Add(uint64(n))
	}
}

func (s *throughputStats) addRx(n int) {
	if n > 0 {
		s.rx.Add(uint64(n))
	}
}

// logEvery emits a delta + total line every 5s into lg until ctx
// fires. Skips emission for idle intervals (no rx/tx delta) to keep
// logs scannable.
func (s *throughputStats) logEvery(ctx context.Context, lg *log.Logger, label, txName, rxName string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var prevTx, prevRx uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tx := s.tx.Load()
			rx := s.rx.Load()
			deltaTx := tx - prevTx
			deltaRx := rx - prevRx
			prevTx = tx
			prevRx = rx

			if deltaTx == 0 && deltaRx == 0 {
				continue
			}

			lg.Printf(
				"%s throughput: %s=%s %s=%s total_%s=%s total_%s=%s",
				label,
				txName,
				formatBitsPerSecond(deltaTx, 5*time.Second),
				rxName,
				formatBitsPerSecond(deltaRx, 5*time.Second),
				txName,
				formatByteCount(tx),
				rxName,
				formatByteCount(rx),
			)
		}
	}
}

func formatBitsPerSecond(bytes uint64, interval time.Duration) string {
	if interval <= 0 {
		interval = time.Second
	}
	bps := float64(bytes*8) / interval.Seconds()
	if bps >= 1_000_000 {
		return fmt.Sprintf("%.2f Mbit/s", bps/1_000_000)
	}
	if bps >= 1_000 {
		return fmt.Sprintf("%.1f kbit/s", bps/1_000)
	}
	return fmt.Sprintf("%.0f bit/s", bps)
}

func formatByteCount(bytes uint64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MiB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}
