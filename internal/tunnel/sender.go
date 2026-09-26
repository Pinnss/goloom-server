package tunnel

import (
	"log"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// Sender turns Send([]byte) calls into VP8-shaped media samples.
//
// Three throughput optimizations over a naive one-Send-per-WriteSample:
//
//   1. Batching: concatenate up to BatchSize bytes (or up to BatchInterval
//      time) of frames into a single VP8 sample. Cuts per-RTP-packet
//      overhead and gets us under the SFU's per-packet rate cap.
//
//   2. Pacing: enforce a minimum gap (PacingInterval) between two
//      WriteSample calls so REMB/TWCC doesn't throttle us.
//
//   3. Keepalive: when the batch is empty for KeepaliveInterval, send a
//      real VP8 interframe to keep the SFU's track-active timers happy
//      (without it the SFU eventually stops forwarding the slot).
//
// Tuning is informed by a sibling project: pacing 500µs +
// batching 6KB/2ms got their tunnel from 6 Mbit/s to ~50 Mbit/s
// sustained, which appears to be Telemost's per-track bandwidth cap.
type Sender struct {
	track     *webrtc.TrackLocalStaticSample
	nextMsgID atomic.Uint32

	FrameDuration time.Duration

	// lastSampleAt tracks the wall-clock time of the previous WriteSample
	// so [Sender.computeSampleDuration] can advance the RTP timestamp at
	// the real 90 kHz rate. Accessed only from the sendLoop goroutine
	// (and synchronously from shipLocked when Start() wasn't called), so
	// no mutex is needed.
	lastSampleAt time.Time

	VP8Prefix []byte
	VP8Wrap   bool

	BatchSize         int
	BatchInterval     time.Duration
	PacingInterval    time.Duration
	KeepaliveInterval time.Duration

	// IdleKeepaliveInterval is the keepalive cadence used when no real
	// tunnel data has been sent for IdleAfter. Defaults to ~1fps —
	// enough to keep the SFU's track-active heuristics happy while
	// dropping our battery footprint by ~25× compared to the active
	// 25fps cadence. Set to 0 to disable idle-mode entirely.
	IdleKeepaliveInterval time.Duration
	IdleAfter             time.Duration

	// BatchSizeJitter randomizes per-batch flush threshold to
	// BatchSize × (1 ± BatchSizeJitter). 0.0 means constant BatchSize
	// (legacy behaviour); 0.4 means each batch flushes at a size drawn
	// uniformly from [0.6·BatchSize, 1.4·BatchSize]. Mimics the size
	// distribution of real VP8 interframes which varies with motion —
	// uniform 6KB samples every flush is a giveaway to classifiers.
	// See [Sender.pickBatchTarget].
	BatchSizeJitter float64

	// PacingJitter is the maximum ±delay applied on top of PacingInterval
	// per ship. 0 = constant pacing (legacy). Non-zero breaks the
	// periodic-write fingerprint that REMB/TWCC heuristics latch onto.
	PacingJitter time.Duration

	// KeyframeEvery, when >0 and combined with KeyframeBatchSize, makes
	// ~1-in-N batches use KeyframeBatchSize as the flush threshold instead
	// of BatchSize±jitter. Imitates the size spike of a real VP8 keyframe
	// (5-10× larger than interframes). 0 disables the peak entirely.
	KeyframeEvery     int
	KeyframeBatchSize int

	// SideFlag is OR'd into every outgoing frame's Flags byte. Used by the
	// SFU pool architecture to stamp each side's frames so the receiver
	// can drop same-side cross-talk (e.g. server bot J seeing server bot
	// K's frames via SFU broadcast). 0 = legacy single-instance behaviour.
	// See [tunnel.FlagFromServer].
	SideFlag Flags

	// InterframePrefix is the bytes prepended to outbound samples that
	// are NOT periodic keyframes — i.e. ~98% of frames in a realistic
	// VP9 stream. When non-empty and VP8Wrap is true, the sendLoop
	// alternates between [Sender.VP8Prefix] (keyframe header) for every
	// KeyframePeriod-th frame and InterframePrefix for all the others.
	//
	// pion's VP9 packetizer reads the uncompressed header inside the
	// prefix to decide keyframe vs interframe — keyframes emit an 11-byte
	// RTP descriptor (with Scalability Structure), interframes emit a
	// 3-byte descriptor. Real video sources alternate the same way, so
	// matching this ratio is critical for any DPI classifier looking at
	// keyframe-rate fingerprints.
	//
	// Empty (default) preserves the legacy single-prefix behaviour
	// (every frame uses VP8Prefix and is therefore tagged as keyframe).
	// 2026-05-28 — added to fix the "100% keyframes" DPI fingerprint.
	InterframePrefix []byte

	// KeyframePeriod controls how often the data path emits a real
	// keyframe (using VP8Prefix). Every KeyframePeriod-th frame counter
	// uses keyframe prefix; all others use InterframePrefix. 0 disables
	// alternation — every frame is a keyframe (legacy behaviour). Realistic
	// values: 60-90 (matches real WebRTC video sources at ~25-30 fps).
	KeyframePeriod int

	started atomic.Bool
	stopCh  chan struct{}

	queue chan []byte

	batchMu            sync.Mutex
	batchBuf           []byte
	batchTimer         *time.Timer
	batchTimerSet      bool
	currentBatchTarget int // sticky flush threshold for in-progress batch; reset on flush. Held under batchMu.

	TxSamples atomic.Uint64
	TxBytes   atomic.Uint64
	TxBatches atomic.Uint64
	TxDrops   atomic.Uint64 // batches dropped on full queue (backpressure) — diagnostic

	// rateLimitBps caps the average wire output to this many bits/sec (0 =
	// unlimited). Driven by [RateController] off the SFU's TWCC feedback so we
	// pace just under where loss appears. When incoming tunnel data exceeds the
	// limit the excess drops LOCALLY at [Sender.shipLocked] (queue full) — with
	// no RTP sequence assigned, so no wire gap and no SFU NACK. Accessed
	// atomically; read once per sample in [Sender.sendLoop].
	rateLimitBps atomic.Uint64

	// WriteMu, when non-nil, serializes track.WriteSample across ALL goroutines
	// that write the same video track (this Sender's data path plus the keyframe
	// refresh / PLI-keyframe helpers). pion's TrackLocalStaticSample assigns
	// seq/ts/pictureID under its own lock but RELEASES it before the per-packet
	// WriteRTP loop, so concurrent writers interleave packets ON THE WIRE — a
	// big data frame's packets get split by an injected keyframe packet, the SFU
	// sheds the out-of-order tail (gappy forward while TWCC stays 0% loss), and
	// with no RTX the gaps are never repaired → slot unbind. Holding one shared
	// mutex around the whole WriteSample makes each frame flush completely before
	// the next starts. Mutates zero wire bytes — only ordering. 2026-07-22.
	WriteMu *sync.Mutex

	// Logger, when non-nil, receives throttled backpressure-drop diagnostics.
	// Optional / nil-safe. Set by the server telemost path (2026-06-25) to
	// tell local queue-overflow stalls apart from network loss.
	Logger *log.Logger
}

const (
	// 2026-05-28 — frame cadence reworked to mimic real video. Was
	// BatchSize=6144 / BatchInterval=2ms which, under speedtest
	// saturation, shipped ~600-2000 samples/sec. A DPI classifier
	// counting RTP marker-bit "frames per second" saw 600-2000 fps —
	// impossible for video (real is 24-60 fps). Now BatchSize=64KB +
	// BatchInterval=20ms caps the cadence near ~50 fps while letting
	// frame *size* scale with bitrate, exactly like a constant-fps
	// variable-bitrate video encoder. Combined with computeSampleDuration
	// (timestamps track wall-clock) the flow's temporal fingerprint now
	// matches a genuine 50 fps source.
	DefaultBatchSize             = 64 * 1024
	DefaultBatchInterval         = 20 * time.Millisecond   // ~50 fps cadence ceiling
	DefaultPacingInterval        = 500 * time.Microsecond
	DefaultKeepaliveInterval     = 40 * time.Millisecond   // ~25fps when active
	DefaultIdleKeepaliveInterval = 1000 * time.Millisecond // 1fps when idle
	DefaultIdleAfter             = 10 * time.Second        // switch to idle after this much silence

	// Mask randomization defaults — applied on top of the legacy batch
	// pacing constants above. Average bitrate is preserved (jitters are
	// symmetric); only the size/timing *distribution* changes, which is
	// what classifiers fingerprint on. Added 2026-05-27 in response to
	// Yandex Telemost shaping plain DTLS+WG to ~10 kbit/s per track —
	// see [internal/wgrelay/datatunnel.go] for the long story.
	DefaultBatchSizeJitter   = 0.4               // batch threshold in [38KB, 90KB] for BatchSize=64KB
	DefaultPacingJitter      = 200 * time.Microsecond
	DefaultKeyframeEvery     = 50                // ~1 in 50 batches is keyframe-sized (~3% of ships)
	DefaultKeyframeBatchSize = 128 * 1024        // 128 KB — realistic 4K VP9 I-frame spike

	// DefaultKeyframePeriod paints ~1.6% of frames as keyframes which
	// matches real VP9 video streams at ~25 fps with a 2-3s keyframe
	// interval (Chrome / Telemost / Yandex SDK typical config).
	DefaultKeyframePeriod = 60
)

// vp8Interframe / vp8MinimalKeyframe were legacy VP8 keepalive frames.
// After the 2026-05-27 migration to VP9 they no longer parse via pion's
// VP9 packetizer (frame_marker bits don't match) so pion silently
// dropped them — keepalive was effectively broken for the new codec.
// The new sendLoop uses [Sender.VP8Prefix] / [Sender.InterframePrefix]
// directly as keepalive payloads (1-9 bytes of valid VP9 header), so
// these constants are deliberately gone.

func NewSender(track *webrtc.TrackLocalStaticSample) *Sender {
	s := &Sender{
		track:                 track,
		FrameDuration:         33 * time.Millisecond,
		BatchSize:             DefaultBatchSize,
		BatchInterval:         DefaultBatchInterval,
		PacingInterval:        DefaultPacingInterval,
		KeepaliveInterval:     DefaultKeepaliveInterval,
		IdleKeepaliveInterval: DefaultIdleKeepaliveInterval,
		IdleAfter:             DefaultIdleAfter,
		BatchSizeJitter:       DefaultBatchSizeJitter,
		PacingJitter:          DefaultPacingJitter,
		KeyframeEvery:         DefaultKeyframeEvery,
		KeyframeBatchSize:     DefaultKeyframeBatchSize,
		KeyframePeriod:        DefaultKeyframePeriod,
		stopCh:                make(chan struct{}),
		queue:                 make(chan []byte, 1024),
	}
	s.batchTimer = time.NewTimer(time.Hour)
	if !s.batchTimer.Stop() {
		<-s.batchTimer.C
	}
	return s
}

// Start launches the background send and batch-flush goroutines.
// Idempotent. Send() works without Start() but data won't actually
// be transmitted until Start is called.
func (s *Sender) Start() {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	go s.sendLoop()
	go s.batchFlushLoop()
}

// Close stops the background goroutines, flushing whatever is buffered.
// Idempotent.
func (s *Sender) Close() {
	if !s.started.CompareAndSwap(true, false) {
		return
	}
	s.batchMu.Lock()
	s.flushLocked()
	s.batchMu.Unlock()
	close(s.stopCh)
}

// Send queues a logical message for batched transmission. Returns the
// assigned msgID. Returns immediately — actual WriteSample happens on
// the background goroutine after batching/pacing.
//
// SideFlag is OR'd into the supplied flags; for pool-deployed senders
// this marks the originator side so receivers can drop same-side
// cross-talk via [Receiver.DropFlag].
func (s *Sender) Send(flags Flags, payload []byte) (uint32, error) {
	id := s.nextMsgID.Add(1)
	frame := EncodeFrame(id, flags|s.SideFlag, payload)
	s.enqueue(frame)
	return id, nil
}

func (s *Sender) enqueue(frame []byte) {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	if s.BatchSize <= 0 || len(frame) >= s.BatchSize {
		s.flushLocked()
		s.shipLocked(append([]byte(nil), frame...))
		return
	}

	if len(s.batchBuf) == 0 {
		s.currentBatchTarget = s.pickBatchTarget()
	}
	target := s.currentBatchTarget

	if len(s.batchBuf)+len(frame) > target {
		s.flushLocked()
		s.currentBatchTarget = s.pickBatchTarget()
		target = s.currentBatchTarget
	}

	s.batchBuf = append(s.batchBuf, frame...)

	if !s.batchTimerSet && s.BatchInterval > 0 {
		s.batchTimer.Reset(s.BatchInterval)
		s.batchTimerSet = true
	}

	if len(s.batchBuf) >= target {
		s.flushLocked()
	}
}

// pickBatchTarget returns the size at which the current batch should
// flush. Called from [Sender.enqueue] under batchMu when starting a
// fresh batch (batchBuf empty after a flush). The result is held in
// currentBatchTarget until the next flush.
//
// Distribution (in order of priority):
//   - 1/KeyframeEvery probability → KeyframeBatchSize (the "I-frame spike").
//   - Otherwise BatchSize ± (BatchSizeJitter × BatchSize) uniform.
//   - If all jitter knobs are zero, returns BatchSize verbatim (legacy).
//
// Uses math/rand/v2 package-level functions, which are safe under any
// number of concurrent callers — no per-Sender rng plumbing needed.
func (s *Sender) pickBatchTarget() int {
	if s.KeyframeEvery > 0 && s.KeyframeBatchSize > 0 && rand.IntN(s.KeyframeEvery) == 0 {
		return s.KeyframeBatchSize
	}
	if s.BatchSizeJitter > 0 && s.BatchSize > 0 {
		delta := int(float64(s.BatchSize) * s.BatchSizeJitter)
		if delta > 0 {
			return s.BatchSize + rand.IntN(2*delta+1) - delta
		}
	}
	return s.BatchSize
}

func (s *Sender) flushLocked() {
	if len(s.batchBuf) == 0 {
		return
	}
	out := make([]byte, len(s.batchBuf))
	copy(out, s.batchBuf)
	s.batchBuf = s.batchBuf[:0]
	s.currentBatchTarget = 0 // next enqueue picks a fresh randomized target

	if s.batchTimerSet {
		if !s.batchTimer.Stop() {
			select {
			case <-s.batchTimer.C:
			default:
			}
		}
		s.batchTimerSet = false
	}
	s.shipLocked(out)
}

func (s *Sender) shipLocked(out []byte) {
	if !s.started.Load() {
		// Synchronous fallback if Start() wasn't called — preserves the
		// pre-batching behavior for tests and edge cases.
		_ = s.writeSample(out)
		return
	}
	select {
	case s.queue <- out:
		s.TxBatches.Add(1)
	default:
		// Queue full — drop this batch rather than block the caller. WG runs
		// end-to-end above this tunnel and handles its own reliability, so a
		// dropped batch surfaces as a WG-layer retransmit, not corruption.
		// (The old comment claimed KCP retransmits — that stack is dead code.)
		// Counted + throttled-logged so a 0-Mbps stall caused by LOCAL queue
		// overflow is distinguishable from network loss.
		d := s.TxDrops.Add(1)
		if s.Logger != nil && (d == 1 || d%256 == 0) {
			s.Logger.Printf("tunnel-sender: backpressure drop #%d (queue %d/%d full)", d, len(s.queue), cap(s.queue))
		}
	}
}

func (s *Sender) batchFlushLoop() {
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.batchTimer.C:
			s.batchMu.Lock()
			s.batchTimerSet = false
			s.flushLocked()
			s.batchMu.Unlock()
		}
	}
}

func (s *Sender) sendLoop() {
	keepalive := time.NewTicker(s.KeepaliveInterval)
	defer keepalive.Stop()

	basePacing := s.PacingInterval
	lastSend := time.Now().Add(-basePacing)
	lastDataSend := time.Now() // last time real tunnel data went out
	frameCount := uint64(0)
	currentInterval := s.KeepaliveInterval

	// switchKeepalive resets the ticker if we're crossing the active⇄idle
	// boundary, so we don't keep waking up at 25fps when the tunnel has
	// been silent for minutes (battery on mobile, mostly).
	switchKeepalive := func(active bool) {
		want := s.KeepaliveInterval
		if !active && s.IdleKeepaliveInterval > 0 {
			want = s.IdleKeepaliveInterval
		}
		if want != currentInterval {
			currentInterval = want
			keepalive.Reset(want)
		}
	}

	// jitteredPacing returns PacingInterval ± a random offset in
	// [-PacingJitter, +PacingJitter]. Negative results are clamped to 0
	// (no extra wait). Drawn fresh on every ship — sustained writes don't
	// settle into a periodic pattern that REMB/TWCC fingerprint on.
	jitteredPacing := func() time.Duration {
		if basePacing <= 0 {
			return 0
		}
		if s.PacingJitter <= 0 {
			return basePacing
		}
		j := int64(s.PacingJitter)
		delta := rand.Int64N(2*j+1) - j
		out := basePacing + time.Duration(delta)
		if out < 0 {
			return 0
		}
		return out
	}

	for {
		select {
		case <-s.stopCh:
			return

		case data := <-s.queue:
			frameCount++
			isKeyframe := s.KeyframePeriod > 0 && frameCount%uint64(s.KeyframePeriod) == 0
			payload := s.wrapPayload(data, isKeyframe)
			// Space this sample by the larger of the anti-fingerprint pacing
			// jitter and the congestion-control rate gap (sized from this
			// sample's bytes and the current TWCC-driven limit). Holding the
			// average under the limit keeps the SFU from seeing loss; the
			// excess it can't fit has already dropped locally at shipLocked.
			gap := jitteredPacing()
			if rg := s.rateGap(len(payload)); rg > gap {
				gap = rg
			}
			if gap > 0 {
				if elapsed := time.Since(lastSend); elapsed < gap {
					time.Sleep(gap - elapsed)
				}
			}
			_ = s.writeSample(payload)
			lastSend = time.Now()
			lastDataSend = lastSend
			switchKeepalive(true)
			keepalive.Reset(currentInterval)

		case <-keepalive.C:
			active := s.IdleAfter <= 0 || time.Since(lastDataSend) < s.IdleAfter
			switchKeepalive(active)

			frameCount++
			isKeyframe := s.KeyframePeriod > 0 && frameCount%uint64(s.KeyframePeriod) == 0
			// Keepalive payload = just the codec header (1 byte interframe
			// or 9 byte keyframe). pion's VP9 packetizer parses it and emits
			// an RTP packet — enough to keep the SFU's track-active timers
			// alive without burning bandwidth.
			if frame := s.keepalivePayload(isKeyframe); len(frame) > 0 {
				_ = s.writeSampleRaw(frame)
			}
			lastSend = time.Now()
		}
	}
}

// keepalivePayload returns the codec header to use as a minimal keepalive
// "frame". With VP9, this is either [media.VP9BlackKeyframe] (9 bytes,
// keyframe) or [media.VP9InterframeHeader] (1 byte, interframe) depending
// on the keyframe schedule. Callers wrap zero data because the header
// alone is a structurally valid frame and pion's packetizer is happy.
func (s *Sender) keepalivePayload(isKeyframe bool) []byte {
	if !s.VP8Wrap {
		return nil
	}
	if isKeyframe {
		return s.VP8Prefix
	}
	if len(s.InterframePrefix) > 0 {
		return s.InterframePrefix
	}
	return s.VP8Prefix
}

// wrapPayload prepends the appropriate codec header (keyframe or
// interframe) to the data batch. The naming retains "VP8" elsewhere
// only for legacy field-name reasons — the actual prefix bytes are now
// VP9 headers ([media.VP9BlackKeyframe] / [media.VP9InterframeHeader]).
//
// When isKeyframe is true (every KeyframePeriod-th sample) the keyframe
// prefix [Sender.VP8Prefix] is used — pion's VP9 packetizer sees
// NonKeyFrame=false and emits an 11-byte RTP descriptor with the
// Scalability Structure. For every other sample the much shorter
// InterframePrefix is used and pion emits a 3-byte descriptor. The
// alternation matters because a DPI classifier counting keyframes-per-
// second sees a realistic ~1.6% keyframe ratio instead of 100%, which
// was the single biggest "I'm not real video" fingerprint we shipped.
//
// If InterframePrefix is empty (legacy callers) every sample falls back
// to VP8Prefix → behaves like the pre-2026-05-28 single-prefix path.
func (s *Sender) wrapPayload(data []byte, isKeyframe bool) []byte {
	if !s.VP8Wrap {
		return data
	}
	prefix := s.VP8Prefix
	if !isKeyframe && len(s.InterframePrefix) > 0 {
		prefix = s.InterframePrefix
	}
	if len(prefix) == 0 {
		return data
	}
	return superframeHide(prefix, data)
}

// superframeHide packs a real, decodable VP9 frame followed by opaque tunnel
// data into a single VP9 SUPERFRAME whose trailing index declares EXACTLY ONE
// frame of size len(realFrame). A VP9 decoder reads the index from the end,
// decodes only the real frame at the front, and never touches the bytes between
// it and the index — so `data` (WireGuard datagrams) rides completely hidden
// while framesDecoded still increments on every sample. This is what removes
// the SFU's "undecodable stream" cutoff: without the index, the trailing data
// corrupts the frame and libvpx rejects it ("Corrupt frame detected").
//
// Layout: realFrame ++ data ++ [marker, size(LE, `mag` bytes), marker].
// The superframe marker (VP9 bitstream superframe index) is
// 0b110·(mag-1)·(frames-1); frames=1 so the low 3 bits are 0. `mag` is the byte
// width of the declared size — 1 for our 36/19-byte frames (always <256).
// Verified against libvpx-vp9 (the browser decoder): 1 frame decoded, 0 errors,
// hidden data ignored, across single frames and multi-GOP sequences.
func superframeHide(realFrame, data []byte) []byte {
	n := len(realFrame)
	mag := 1
	for n>>(8*mag) > 0 {
		mag++
	}
	out := make([]byte, 0, len(realFrame)+len(data)+2+mag)
	out = append(out, realFrame...)
	out = append(out, data...)
	marker := byte(0xC0 | ((mag - 1) << 3)) // frames-1 == 0
	out = append(out, marker)
	for i := 0; i < mag; i++ {
		out = append(out, byte(n>>(8*i)))
	}
	out = append(out, marker)
	return out
}

// computeSampleDuration returns the wall-clock time elapsed since the
// previous WriteSample, clamped to [1ms, 1s]. Passing this as
// media.Sample.Duration makes pion advance the RTP timestamp at the real
// 90 kHz rate — i.e. timestamps track wall-clock exactly, like a genuine
// capture device. The legacy fixed 33ms Duration combined with our
// ~600-2000 ships/sec made the RTP timestamp clock run dozens of times
// faster than wall-clock, a glaring "not a real camera" signal for any
// DPI that compares timestamp rate against packet arrival rate.
//
// Called only from the sendLoop goroutine (and synchronously via
// shipLocked when Start() wasn't called), so the lastSampleAt field
// needs no mutex.
func (s *Sender) computeSampleDuration() time.Duration {
	now := time.Now()
	if s.lastSampleAt.IsZero() {
		s.lastSampleAt = now
		if s.FrameDuration > 0 {
			return s.FrameDuration
		}
		return 20 * time.Millisecond
	}
	dur := now.Sub(s.lastSampleAt)
	s.lastSampleAt = now
	if dur < time.Millisecond {
		dur = time.Millisecond
	}
	if dur > time.Second {
		dur = time.Second
	}
	return dur
}

func (s *Sender) writeSample(payload []byte) error {
	dur := s.computeSampleDuration()
	if s.WriteMu != nil {
		s.WriteMu.Lock()
	}
	err := s.track.WriteSample(media.Sample{Data: payload, Duration: dur})
	if s.WriteMu != nil {
		s.WriteMu.Unlock()
	}
	if err != nil {
		return err
	}
	s.TxSamples.Add(1)
	s.TxBytes.Add(uint64(len(payload)))
	return nil
}

func (s *Sender) writeSampleRaw(payload []byte) error {
	dur := s.computeSampleDuration()
	if s.WriteMu != nil {
		s.WriteMu.Lock()
	}
	err := s.track.WriteSample(media.Sample{Data: payload, Duration: dur})
	if s.WriteMu != nil {
		s.WriteMu.Unlock()
	}
	if err != nil {
		return err
	}
	s.TxSamples.Add(1)
	return nil
}

func (s *Sender) PeekNextID() uint32 { return s.nextMsgID.Load() + 1 }

// SetRateLimit sets the average wire output cap in bits/sec (0 = unlimited).
// Called by the congestion controller as its TWCC estimate moves. Safe for
// concurrent use.
func (s *Sender) SetRateLimit(bps uint64) { s.rateLimitBps.Store(bps) }

// RateLimit returns the current cap in bits/sec (0 = unlimited).
func (s *Sender) RateLimit() uint64 { return s.rateLimitBps.Load() }

// rateGap returns how long a sample of sampleBytes must be spaced from the
// previous one to hold the average output at the current rate limit. Zero when
// unlimited. Called only from the sendLoop goroutine.
func (s *Sender) rateGap(sampleBytes int) time.Duration {
	lim := s.rateLimitBps.Load()
	if lim == 0 || sampleBytes <= 0 {
		return 0
	}
	// seconds = bits / bitsPerSec = (bytes*8) / lim
	return time.Duration(float64(sampleBytes) * 8 / float64(lim) * float64(time.Second))
}
