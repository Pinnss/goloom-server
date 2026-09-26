package tunnel

import "sync"

// RateController turns the SFU's TWCC transport-feedback into a target send
// bitrate for the [Sender]. It exists because Telemost's SFU demotes a
// publisher whose stream it can't receive cleanly: our open-loop sender
// overshoots the path, self-induces packet loss, the SFU NACKs relentlessly,
// we have no RTX to answer with, and after ~10-120 s (faster the higher the
// overshoot) it unbinds our video slot (mid= emptied) and forwarding stops.
//
// The fix is closed-loop pacing: keep the send rate just under where loss
// appears, so the SFU sees a clean, gap-free stream and never NACKs. Excess
// tunnel data then drops LOCALLY in the Sender's queue (before it is assigned
// an RTP sequence number), which — unlike a sent-then-lost packet — creates NO
// wire-level sequence gap and therefore NO NACK. The inner TCP-over-WireGuard
// observes the backpressure and backs off on its own.
//
// The control law is a simple loss-based AIMD, the delay-based half of
// Google's GCC deliberately omitted (we cannot install pion's gcc pacer without
// putting a LeakyBucketPacer in the RTP path, which re-clocks the HELLO frames
// and breaks pairing — see the throughput memo). Feedback arrives only a few
// times per second, so loss is smoothed with an EMA before acting.
type RateController struct {
	mu      sync.Mutex
	target  float64 // current target bitrate, bits/sec
	lossEMA float64 // smoothed loss fraction [0,1]
	seeded  bool

	// Tunables (exported for tests / call-site override).
	MinBps      float64
	MaxBps      float64
	LowLoss     float64 // below this smoothed loss we ramp up
	HighLoss    float64 // above this we back off
	IncreaseMul float64 // multiplicative increase per feedback when clean
	EMAWeight   float64 // weight of the newest sample in the loss EMA
}

// NewRateController returns a controller seeded at initialBps.
func NewRateController(initialBps float64) *RateController {
	return &RateController{
		target:      clampf(initialBps, 250_000, 40_000_000),
		MinBps:      250_000,
		MaxBps:      40_000_000,
		LowLoss:     0.005, // 0.5%
		HighLoss:    0.01,  // 1% — keep NACKs near zero, we cannot retransmit
		IncreaseMul: 1.03,
		EMAWeight:   0.20,
	}
}

// Observe folds one TWCC feedback window (packets delivered vs lost) into the
// estimate and returns the updated target bitrate in bits/sec. delivered and
// lost come straight from [github.com/pion/rtcp.TransportLayerCC]: delivered =
// packets with a recv-delta, lost = status_count − delivered.
func (rc *RateController) Observe(delivered, lost int) float64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	total := delivered + lost
	if total <= 0 {
		return rc.target
	}
	sampleLoss := float64(lost) / float64(total)
	if !rc.seeded {
		rc.lossEMA = sampleLoss
		rc.seeded = true
	} else {
		rc.lossEMA = (1-rc.EMAWeight)*rc.lossEMA + rc.EMAWeight*sampleLoss
	}

	switch {
	case rc.lossEMA < rc.LowLoss:
		rc.target *= rc.IncreaseMul
	case rc.lossEMA > rc.HighLoss:
		// Multiplicative decrease scaled by how bad the loss is, à la GCC's
		// loss controller: target *= 1 − 0.5·loss, bounded so a single bad
		// window can't collapse us to the floor.
		dec := 0.5 * rc.lossEMA
		if dec > 0.5 {
			dec = 0.5
		}
		rc.target *= (1 - dec)
	}
	rc.target = clampf(rc.target, rc.MinBps, rc.MaxBps)
	return rc.target
}

// Target returns the current target bitrate in bits/sec.
func (rc *RateController) Target() float64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.target
}

// LossEMA returns the current smoothed loss fraction (for diagnostics).
func (rc *RateController) LossEMA() float64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.lossEMA
}

func clampf(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
