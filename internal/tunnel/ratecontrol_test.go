package tunnel

import "testing"

// TestRateControllerBacksOffOnLoss: sustained heavy loss must drive the target
// down toward the floor.
func TestRateControllerBacksOffOnLoss(t *testing.T) {
	rc := NewRateController(10_000_000)
	start := rc.Target()
	for i := 0; i < 50; i++ {
		rc.Observe(80, 20) // 20% loss
	}
	if rc.Target() >= start {
		t.Fatalf("target did not drop under 20%% loss: start=%.0f now=%.0f", start, rc.Target())
	}
	if rc.Target() < rc.MinBps || rc.Target() > rc.MaxBps {
		t.Fatalf("target out of bounds: %.0f", rc.Target())
	}
}

// TestRateControllerRampsUpWhenClean: zero loss must let the target grow.
func TestRateControllerRampsUpWhenClean(t *testing.T) {
	rc := NewRateController(1_000_000)
	start := rc.Target()
	for i := 0; i < 50; i++ {
		rc.Observe(500, 0) // no loss
	}
	if rc.Target() <= start {
		t.Fatalf("target did not grow under zero loss: start=%.0f now=%.0f", start, rc.Target())
	}
}

// TestRateControllerClamps: target never escapes [MinBps, MaxBps].
func TestRateControllerClamps(t *testing.T) {
	rc := NewRateController(1_000_000)
	for i := 0; i < 10000; i++ {
		rc.Observe(1000, 0) // relentless increase
	}
	if rc.Target() > rc.MaxBps {
		t.Fatalf("target exceeded MaxBps: %.0f > %.0f", rc.Target(), rc.MaxBps)
	}
	for i := 0; i < 10000; i++ {
		rc.Observe(0, 1000) // relentless loss
	}
	if rc.Target() < rc.MinBps {
		t.Fatalf("target below MinBps: %.0f < %.0f", rc.Target(), rc.MinBps)
	}
}

// TestRateControllerEmptyWindow: a feedback window with no packets must not
// move the estimate or divide by zero.
func TestRateControllerEmptyWindow(t *testing.T) {
	rc := NewRateController(2_000_000)
	before := rc.Target()
	if got := rc.Observe(0, 0); got != before {
		t.Fatalf("empty window moved target: %.0f -> %.0f", before, got)
	}
}

// TestRateGap: the sender's rate gap scales with sample size and inversely with
// the limit, and is zero when unlimited.
func TestRateGap(t *testing.T) {
	s := NewSender(nil)
	if g := s.rateGap(1000); g != 0 {
		t.Fatalf("unlimited rateGap should be 0, got %v", g)
	}
	s.SetRateLimit(1_000_000) // 1 Mbps
	// 1250 bytes = 10000 bits; at 1 Mbps that is 10 ms.
	if g := s.rateGap(1250); g < 9*1e6 || g > 11*1e6 { // nanoseconds
		t.Fatalf("rateGap(1250)@1Mbps = %v, want ~10ms", g)
	}
	// Double the limit → half the gap.
	s.SetRateLimit(2_000_000)
	if g := s.rateGap(1250); g < 4*1e6 || g > 6*1e6 {
		t.Fatalf("rateGap(1250)@2Mbps = %v, want ~5ms", g)
	}
}
