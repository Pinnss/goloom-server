package tunnel

import (
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
// Tuning is informed by the call-gate measurements: pacing 500µs +
// batching 6KB/2ms got their tunnel from 6 Mbit/s to ~50 Mbit/s
// sustained, which appears to be Telemost's per-track bandwidth cap.
type Sender struct {
	track     *webrtc.TrackLocalStaticSample
	nextMsgID atomic.Uint32

	FrameDuration time.Duration

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

	started atomic.Bool
	stopCh  chan struct{}

	queue chan []byte

	batchMu       sync.Mutex
	batchBuf      []byte
	batchTimer    *time.Timer
	batchTimerSet bool

	TxSamples atomic.Uint64
	TxBytes   atomic.Uint64
	TxBatches atomic.Uint64
}

const (
	DefaultBatchSize             = 6144
	DefaultBatchInterval         = 2 * time.Millisecond
	DefaultPacingInterval        = 500 * time.Microsecond
	DefaultKeepaliveInterval     = 40 * time.Millisecond   // ~25fps when active
	DefaultIdleKeepaliveInterval = 1000 * time.Millisecond // 1fps when idle
	DefaultIdleAfter             = 10 * time.Second        // switch to idle after this much silence
)

// vp8Interframe / vp8Keyframe are minimal real VP8 frames used as
// keepalives when no tunnel data is in flight. Reused from call-gate
// (originally kulikov0/whitelist-bypass) — they decode cleanly in any
// VP8 decoder so the SFU happily forwards them without dropping the slot.
var vp8Interframe = []byte{
	177, 1, 0, 8, 17, 24, 0, 24, 0, 24, 88, 47, 244, 0, 8, 0, 0,
}

var vp8MinimalKeyframe = []byte{
	16, 2, 0, 157, 1, 42, 2, 0, 2, 0, 2, 7, 8, 133, 133, 136,
	153, 132, 136, 11, 2, 0, 12, 13, 96, 0, 254, 252, 173, 16,
}

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
func (s *Sender) Send(flags Flags, payload []byte) (uint32, error) {
	id := s.nextMsgID.Add(1)
	frame := EncodeFrame(id, flags, payload)
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

	if len(s.batchBuf)+len(frame) > s.BatchSize {
		s.flushLocked()
	}

	s.batchBuf = append(s.batchBuf, frame...)

	if !s.batchTimerSet && s.BatchInterval > 0 {
		s.batchTimer.Reset(s.BatchInterval)
		s.batchTimerSet = true
	}

	if len(s.batchBuf) >= s.BatchSize {
		s.flushLocked()
	}
}

func (s *Sender) flushLocked() {
	if len(s.batchBuf) == 0 {
		return
	}
	out := make([]byte, len(s.batchBuf))
	copy(out, s.batchBuf)
	s.batchBuf = s.batchBuf[:0]

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
		// Drop on backpressure — the receive side will detect via gaps
		// in msgIDs (KCP retransmits). Better than blocking the caller.
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

	pacing := s.PacingInterval
	lastSend := time.Now().Add(-pacing)
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

	for {
		select {
		case <-s.stopCh:
			return

		case data := <-s.queue:
			if pacing > 0 {
				if elapsed := time.Since(lastSend); elapsed < pacing {
					time.Sleep(pacing - elapsed)
				}
			}
			payload := s.wrapVP8(data)
			_ = s.writeSample(payload)
			lastSend = time.Now()
			lastDataSend = lastSend
			frameCount++
			// Periodic real keyframe so the SFU's decoder never desyncs.
			if frameCount%60 == 0 {
				if pacing > 0 {
					time.Sleep(pacing)
				}
				_ = s.writeSampleRaw(vp8MinimalKeyframe)
				lastSend = time.Now()
			}
			switchKeepalive(true)
			keepalive.Reset(currentInterval)

		case <-keepalive.C:
			active := s.IdleAfter <= 0 || time.Since(lastDataSend) < s.IdleAfter
			switchKeepalive(active)

			frame := vp8Interframe
			if frameCount%60 == 0 {
				frame = vp8MinimalKeyframe
			}
			_ = s.writeSampleRaw(frame)
			lastSend = time.Now()
			frameCount++
		}
	}
}

func (s *Sender) wrapVP8(data []byte) []byte {
	if !s.VP8Wrap || len(s.VP8Prefix) == 0 {
		return data
	}
	out := make([]byte, len(s.VP8Prefix)+len(data))
	copy(out, s.VP8Prefix)
	copy(out[len(s.VP8Prefix):], data)
	return out
}

func (s *Sender) writeSample(payload []byte) error {
	if err := s.track.WriteSample(media.Sample{
		Data:     payload,
		Duration: s.FrameDuration,
	}); err != nil {
		return err
	}
	s.TxSamples.Add(1)
	s.TxBytes.Add(uint64(len(payload)))
	return nil
}

func (s *Sender) writeSampleRaw(payload []byte) error {
	if err := s.track.WriteSample(media.Sample{
		Data:     payload,
		Duration: s.FrameDuration,
	}); err != nil {
		return err
	}
	s.TxSamples.Add(1)
	return nil
}

func (s *Sender) PeekNextID() uint32 { return s.nextMsgID.Load() + 1 }
