package inbound

import (
	"sync"
	"time"
)

// HistorySample is one bucket in the per-inbound throughput history. The
// admin panel renders these as sparklines, so we keep a small fixed-size
// ring (~5 minutes at 1s resolution) — enough to spot bursts without
// needing a real time-series store.
type HistorySample struct {
	At      int64  `json:"t"`  // unix seconds
	TxBytes uint64 `json:"tx"` // total since boot
	RxBytes uint64 `json:"rx"`
}

// History stores per-inbound counter samples in a fixed ring buffer.
// One global instance lives on the Manager; on every stat tick each
// runner contributes its current TX/RX byte totals.
type History struct {
	mu      sync.Mutex
	rings   map[string][]HistorySample
	cap     int
}

func NewHistory(capPerInbound int) *History {
	if capPerInbound <= 0 {
		capPerInbound = 300 // 5 min at 1s resolution
	}
	return &History{
		rings: make(map[string][]HistorySample),
		cap:   capPerInbound,
	}
}

// Record appends one sample for the given inbound. If the ring is at
// capacity the oldest entry is evicted.
func (h *History) Record(id string, tx, rx uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rings[id]
	r = append(r, HistorySample{
		At:      time.Now().Unix(),
		TxBytes: tx,
		RxBytes: rx,
	})
	if len(r) > h.cap {
		r = r[len(r)-h.cap:]
	}
	h.rings[id] = r
}

// Snapshot returns a copy of the ring for the given inbound, or nil if
// nothing has been recorded yet.
func (h *History) Snapshot(id string) []HistorySample {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rings[id]
	if len(r) == 0 {
		return nil
	}
	out := make([]HistorySample, len(r))
	copy(out, r)
	return out
}

// Drop forgets a removed inbound's history.
func (h *History) Drop(id string) {
	h.mu.Lock()
	delete(h.rings, id)
	h.mu.Unlock()
}
