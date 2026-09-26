package tunnel

import (
	"sort"
	"time"
)

// Reassembler rebuilds tunnel samples from RTP packets that may arrive out of
// order, duplicated, late, or not at all.
//
// Every sample the Sender writes gets its own RTP timestamp (pion advances it
// by the sample Duration, which is always ≥1 ms), so packets are grouped by
// timestamp. A frame is complete once its first packet, its marker packet and
// every sequence number in between have arrived. It is released at once, even
// while an older frame is still incomplete, so one hole never delays the
// frames behind it. The first packet is recognised by the VP9 begin-of-frame
// bit, or by following the marker packet of another frame.
//
// An incomplete frame waits MaxWait for NACK retransmissions and is then
// released as its contiguous runs (Segments), so the caller can salvage the
// tunnel frames that did arrive instead of losing the whole ~64 KB sample.
// Packets for a frame that was already released are dropped as Late.
//
// 2026-09-26 — replaces the timestamp+marker FrameAssembler, which discarded
// the in-progress frame whenever a packet of another frame arrived before the
// marker. That turned every reordered or retransmitted packet into a lost
// frame (and was why NACK retransmission used to "poison" the handshake).
//
// Not safe for concurrent use; call from the single per-track read loop.
type Reassembler struct {
	// MaxWait is how long a frame waits after its LAST received packet before
	// it is released incomplete. It must be measured from the last packet, not
	// from the first: a 64 KB sample spread over a ~1.5 Mbit/s mobile leg takes
	// ~350 ms to arrive in full, so an age-based deadline would cut healthy,
	// loss-free frames in half.
	MaxWait time.Duration

	// MaxAge bounds how long a frame may be held in total, so a source that
	// keeps dribbling packets into one timestamp cannot pin memory forever.
	MaxAge time.Duration
	// MaxPending caps the frames held at once; the oldest is released early.
	MaxPending int

	now func() time.Time

	frames map[uint32]*pendingFrame

	// released remembers recently released timestamps so their late packets
	// are dropped instead of opening a new frame.
	released    map[uint32]struct{}
	releasedLog [reassemblerMemory]uint32
	releasedIdx int

	// markers remembers the sequence numbers of recent marker packets: the
	// packet after a marker is the first packet of the next frame.
	markers    map[uint16]struct{}
	markersLog [reassemblerMemory]uint16
	markersIdx int

	Complete uint64 // frames released with every packet
	Partial  uint64 // frames released with holes (timeout or eviction)
	Late     uint64 // packets for frames already released
	Dups     uint64 // duplicate packets within a pending frame
}

const (
	reassemblerMemory     = 512
	maxPacketsPerFrame    = 4096
	defaultReassemblyWait = 300 * time.Millisecond
	defaultMaxFrameAge    = 2 * time.Second
	defaultMaxPending     = 64
)

// ReleasedFrame is one sample handed back by the Reassembler.
type ReleasedFrame struct {
	// Segments holds the contiguous runs of the frame in sequence order. A
	// complete frame has exactly one segment.
	Segments [][]byte
	Complete bool
	// AtBegin reports that Segments[0] starts at the frame's first packet,
	// i.e. on the codec prefix rather than somewhere mid-frame.
	AtBegin bool
}

type pendingFrame struct {
	parts     map[uint16][]byte
	refSeq    uint16 // first sequence number seen, origin for ordering
	beginSeq  uint16
	haveBegin bool
	endSeq    uint16
	haveEnd   bool
	firstSeen time.Time
	lastSeen  time.Time
}

// NewReassembler returns a Reassembler with the default wait and limits.
func NewReassembler() *Reassembler {
	return &Reassembler{
		MaxWait:    defaultReassemblyWait,
		MaxAge:     defaultMaxFrameAge,
		MaxPending: defaultMaxPending,
		now:        time.Now,
		frames:     make(map[uint32]*pendingFrame),
		released:   make(map[uint32]struct{}, reassemblerMemory),
		markers:    make(map[uint16]struct{}, reassemblerMemory),
	}
}

// Add ingests one RTP packet's descriptor-stripped payload and appends every
// frame that became ready (complete, timed out or evicted) to out. begin is
// the VP9 B bit, marker the RTP marker bit. payload is copied.
func (r *Reassembler) Add(out []ReleasedFrame, seq uint16, ts uint32, begin, marker bool, payload []byte) []ReleasedFrame {
	now := r.now()

	if _, done := r.released[ts]; done {
		r.Late++
		return r.expire(out, now)
	}

	f := r.frames[ts]
	if f == nil {
		f = &pendingFrame{parts: make(map[uint16][]byte), refSeq: seq, firstSeen: now, lastSeen: now}
		r.frames[ts] = f
	}
	if _, dup := f.parts[seq]; dup {
		r.Dups++
		return r.expire(out, now)
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	f.parts[seq] = cp
	f.lastSeen = now

	if _, ok := r.markers[seq-1]; ok {
		begin = true
	}
	if begin {
		f.beginSeq, f.haveBegin = seq, true
	}
	if marker {
		f.endSeq, f.haveEnd = seq, true
		r.rememberMarker(seq)
		// The frame starting right after this marker may already be pending.
		for _, g := range r.frames {
			if _, ok := g.parts[seq+1]; ok && !g.haveBegin {
				g.beginSeq, g.haveBegin = seq+1, true
				break
			}
		}
	}

	out = r.releaseComplete(out)
	if g := r.frames[ts]; g != nil && len(g.parts) > maxPacketsPerFrame {
		out = r.release(out, ts, g)
	}
	return r.expire(out, now)
}

// releaseComplete releases every pending frame that has all its packets.
// Several can become complete from one packet: a marker also fixes the begin
// of the following frame.
func (r *Reassembler) releaseComplete(out []ReleasedFrame) []ReleasedFrame {
	for ts, f := range r.frames {
		if !f.complete() {
			continue
		}
		n := int(f.endSeq-f.beginSeq) + 1
		total := 0
		for i := 0; i < n; i++ {
			total += len(f.parts[f.beginSeq+uint16(i)])
		}
		buf := make([]byte, 0, total)
		for i := 0; i < n; i++ {
			buf = append(buf, f.parts[f.beginSeq+uint16(i)]...)
		}
		r.Complete++
		r.forget(ts)
		out = append(out, ReleasedFrame{Segments: [][]byte{buf}, Complete: true, AtBegin: true})
	}
	return out
}

func (f *pendingFrame) complete() bool {
	if !f.haveBegin || !f.haveEnd {
		return false
	}
	n := int(f.endSeq-f.beginSeq) + 1
	if n <= 0 || n > maxPacketsPerFrame || len(f.parts) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if _, ok := f.parts[f.beginSeq+uint16(i)]; !ok {
			return false
		}
	}
	return true
}

// expire releases frames idle for longer than MaxWait or held for longer than
// MaxAge, then the oldest frames while more than MaxPending are held.
func (r *Reassembler) expire(out []ReleasedFrame, now time.Time) []ReleasedFrame {
	for ts, f := range r.frames {
		if now.Sub(f.lastSeen) >= r.MaxWait || (r.MaxAge > 0 && now.Sub(f.firstSeen) >= r.MaxAge) {
			out = r.release(out, ts, f)
		}
	}
	for len(r.frames) > r.MaxPending {
		var oldestTS uint32
		var oldest *pendingFrame
		for ts, f := range r.frames {
			if oldest == nil || f.firstSeen.Before(oldest.firstSeen) {
				oldestTS, oldest = ts, f
			}
		}
		out = r.release(out, oldestTS, oldest)
	}
	return out
}

// release hands back an incomplete frame as its contiguous runs.
func (r *Reassembler) release(out []ReleasedFrame, ts uint32, f *pendingFrame) []ReleasedFrame {
	offsets := make([]int, 0, len(f.parts))
	for seq := range f.parts {
		offsets = append(offsets, int(int16(seq-f.refSeq)))
	}
	sort.Ints(offsets)

	beginOff := int(int16(f.beginSeq - f.refSeq))
	var segs [][]byte
	var cur []byte
	prev := 0
	for _, off := range offsets {
		if f.haveBegin && off < beginOff {
			continue // cannot precede the frame's first packet; ignore
		}
		if cur != nil && off != prev+1 {
			segs = append(segs, cur)
			cur = nil
		}
		cur = append(cur, f.parts[f.refSeq+uint16(off)]...)
		prev = off
	}
	if cur != nil {
		segs = append(segs, cur)
	}

	atBegin := false
	if f.haveBegin {
		for _, off := range offsets {
			if off >= beginOff {
				atBegin = off == beginOff
				break
			}
		}
	}

	r.Partial++
	r.forget(ts)
	if len(segs) == 0 {
		return out
	}
	return append(out, ReleasedFrame{Segments: segs, AtBegin: atBegin})
}

// forget drops a pending frame and remembers its timestamp as released.
func (r *Reassembler) forget(ts uint32) {
	delete(r.frames, ts)
	if len(r.released) >= reassemblerMemory {
		delete(r.released, r.releasedLog[r.releasedIdx])
	}
	r.releasedLog[r.releasedIdx] = ts
	r.releasedIdx = (r.releasedIdx + 1) % reassemblerMemory
	r.released[ts] = struct{}{}
}

func (r *Reassembler) rememberMarker(seq uint16) {
	if len(r.markers) >= reassemblerMemory {
		delete(r.markers, r.markersLog[r.markersIdx])
	}
	r.markersLog[r.markersIdx] = seq
	r.markersIdx = (r.markersIdx + 1) % reassemblerMemory
	r.markers[seq] = struct{}{}
}

// Pending returns the number of frames currently held.
func (r *Reassembler) Pending() int { return len(r.frames) }
