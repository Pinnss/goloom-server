package tunnel

import (
	"testing"
	"time"
)

// testReassembler returns a Reassembler driven by a manual clock.
func testReassembler() (*Reassembler, *time.Time) {
	r := NewReassembler()
	clock := time.Unix(1_000_000, 0)
	r.now = func() time.Time { return clock }
	return r, &clock
}

type rtpIn struct {
	seq    uint16
	ts     uint32
	begin  bool
	marker bool
	data   string
}

func feed(r *Reassembler, pkts ...rtpIn) []ReleasedFrame {
	var out []ReleasedFrame
	for _, p := range pkts {
		out = r.Add(out, p.seq, p.ts, p.begin, p.marker, []byte(p.data))
	}
	return out
}

func wantComplete(t *testing.T, got []ReleasedFrame, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("released %d frames, want %d: %+v", len(got), len(want), got)
	}
	for i, f := range got {
		if !f.Complete || len(f.Segments) != 1 || !f.AtBegin {
			t.Fatalf("frame %d = %+v, want one complete segment", i, f)
		}
		if string(f.Segments[0]) != want[i] {
			t.Fatalf("frame %d = %q, want %q", i, f.Segments[0], want[i])
		}
	}
}

func TestReassemblerSinglePacket(t *testing.T) {
	r, _ := testReassembler()
	wantComplete(t, feed(r, rtpIn{10, 1000, true, true, "hello"}), "hello")
	if r.Pending() != 0 {
		t.Fatalf("pending = %d, want 0", r.Pending())
	}
}

func TestReassemblerInOrder(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{10, 2000, true, false, "AAAA"},
		rtpIn{11, 2000, false, false, "BBBB"},
		rtpIn{12, 2000, false, true, "CCCC"},
	)
	wantComplete(t, got, "AAAABBBBCCCC")
}

// Reordering inside a frame must not lose it (the old assembler appended in
// arrival order and corrupted the sample).
func TestReassemblerReorderWithinFrame(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{12, 2000, false, true, "CC"},
		rtpIn{10, 2000, true, false, "AA"},
		rtpIn{11, 2000, false, false, "BB"},
	)
	wantComplete(t, got, "AABBCC")
}

// A packet of the next frame arriving mid-frame must not discard the frame in
// progress — that was the old assembler's "new timestamp = drop" rule.
func TestReassemblerInterleavedFrames(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{10, 1000, true, false, "a1"},
		rtpIn{12, 2000, true, false, "b1"},
		rtpIn{11, 1000, false, true, "a2"},
		rtpIn{13, 2000, false, true, "b2"},
	)
	wantComplete(t, got, "a1a2", "b1b2")
}

// A hole in an older frame must not delay a newer complete frame.
func TestReassemblerNoHeadOfLineBlocking(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{10, 1000, true, false, "a1"},
		// seq 11 (a2) is missing
		rtpIn{12, 1000, false, true, "a3"},
		rtpIn{13, 2000, true, true, "b"},
	)
	wantComplete(t, got, "b")
	if r.Pending() != 1 {
		t.Fatalf("pending = %d, want the holed frame still waiting", r.Pending())
	}
}

// A retransmission that arrives within MaxWait completes the frame.
func TestReassemblerRepairWithinWait(t *testing.T) {
	r, clock := testReassembler()
	if got := feed(r, rtpIn{10, 1000, true, false, "a1"}, rtpIn{12, 1000, false, true, "a3"}); len(got) != 0 {
		t.Fatalf("released %+v before the hole was filled", got)
	}
	*clock = clock.Add(100 * time.Millisecond)
	wantComplete(t, feed(r, rtpIn{11, 1000, false, false, "a2"}), "a1a2a3")
}

// After MaxWait an incomplete frame is released as its contiguous runs.
func TestReassemblerPartialAfterWait(t *testing.T) {
	r, clock := testReassembler()
	feed(r,
		rtpIn{10, 1000, true, false, "a1"},
		rtpIn{11, 1000, false, false, "a2"},
		rtpIn{13, 1000, false, false, "a4"},
		rtpIn{14, 1000, false, true, "a5"},
	)
	*clock = clock.Add(r.MaxWait)
	got := feed(r, rtpIn{20, 5000, true, true, "next"})
	if len(got) != 2 {
		t.Fatalf("released %d frames, want the partial one and the new one: %+v", len(got), got)
	}
	var partial ReleasedFrame
	for _, f := range got {
		if !f.Complete {
			partial = f
		}
	}
	if !partial.AtBegin || len(partial.Segments) != 2 {
		t.Fatalf("partial = %+v, want 2 segments starting at the frame begin", partial)
	}
	if string(partial.Segments[0]) != "a1a2" || string(partial.Segments[1]) != "a4a5" {
		t.Fatalf("segments = %q / %q", partial.Segments[0], partial.Segments[1])
	}
	if r.Partial != 1 {
		t.Fatalf("Partial = %d, want 1", r.Partial)
	}
}

// A big sample trickling in over a slow leg must NOT be cut: 64 KB at the
// ~1.5 Mbit/s the sender is capped to takes ~350 ms to arrive, i.e. longer
// than MaxWait. Timing out on frame AGE (rather than on inactivity) released
// such frames in half and dropped their tail as Late.
func TestReassemblerSlowFrameNotCut(t *testing.T) {
	r, clock := testReassembler()
	const n = 55 // ~64 KB at ~1200 B per packet
	var out []ReleasedFrame
	for i := 0; i < n; i++ {
		*clock = clock.Add(7 * time.Millisecond) // ~1.4 Mbit/s
		out = r.Add(out, uint16(100+i), 9000, i == 0, i == n-1, []byte("x"))
	}
	if len(out) != 1 || !out[0].Complete {
		t.Fatalf("released %+v, want one complete frame after %v", out, time.Duration(n)*7*time.Millisecond)
	}
	if len(out[0].Segments[0]) != n {
		t.Fatalf("frame has %d bytes, want %d — the tail was cut", len(out[0].Segments[0]), n)
	}
	if r.Late != 0 || r.Partial != 0 {
		t.Fatalf("Late=%d Partial=%d, want 0 and 0", r.Late, r.Partial)
	}
}

// MaxAge bounds a frame that keeps receiving packets but never completes, so a
// stuck timestamp cannot pin memory forever.
func TestReassemblerMaxAgeCap(t *testing.T) {
	r, clock := testReassembler()
	var out []ReleasedFrame
	for i := 0; i < 40; i++ { // never sets the marker
		*clock = clock.Add(100 * time.Millisecond)
		out = r.Add(out, uint16(200+i), 9100, i == 0, false, []byte("y"))
	}
	if r.Partial == 0 {
		t.Fatalf("frame held for %v without hitting MaxAge=%v", 4*time.Second, r.MaxAge)
	}
}

// Losing the first packet leaves every segment mid-frame.
func TestReassemblerPartialWithoutBegin(t *testing.T) {
	r, clock := testReassembler()
	feed(r, rtpIn{11, 1000, false, false, "a2"}, rtpIn{12, 1000, false, true, "a3"})
	*clock = clock.Add(r.MaxWait)
	got := feed(r, rtpIn{20, 5000, true, true, "x"})
	for _, f := range got {
		if f.Complete {
			continue
		}
		if f.AtBegin {
			t.Fatalf("partial %+v claims AtBegin without its first packet", f)
		}
		if len(f.Segments) != 1 || string(f.Segments[0]) != "a2a3" {
			t.Fatalf("segments = %q", f.Segments)
		}
		return
	}
	t.Fatal("partial frame was not released")
}

// Packets for a released frame are late and must not open a new frame.
func TestReassemblerLatePacketDropped(t *testing.T) {
	r, clock := testReassembler()
	feed(r, rtpIn{10, 1000, true, false, "a1"}, rtpIn{12, 1000, false, true, "a3"})
	*clock = clock.Add(r.MaxWait)
	feed(r, rtpIn{20, 5000, true, true, "x"})
	if got := feed(r, rtpIn{11, 1000, false, false, "a2"}); len(got) != 0 {
		t.Fatalf("late packet produced %+v", got)
	}
	if r.Late != 1 || r.Pending() != 0 {
		t.Fatalf("Late=%d pending=%d, want 1 and 0", r.Late, r.Pending())
	}
}

// Without the VP9 B bit the frame start is inferred from the previous marker.
func TestReassemblerBeginFromPreviousMarker(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{10, 1000, true, true, "a"},
		rtpIn{11, 2000, false, false, "b1"},
		rtpIn{12, 2000, false, true, "b2"},
	)
	wantComplete(t, got, "a", "b1b2")
}

// The marker can arrive after the next frame's first packet.
func TestReassemblerBeginInferredLate(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{11, 2000, false, false, "b1"},
		rtpIn{12, 2000, false, true, "b2"},
		rtpIn{10, 1000, true, true, "a"},
	)
	if len(got) != 2 {
		t.Fatalf("released %d frames, want 2: %+v", len(got), got)
	}
}

func TestReassemblerDuplicates(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{10, 1000, true, false, "a1"},
		rtpIn{10, 1000, true, false, "a1"},
		rtpIn{11, 1000, false, true, "a2"},
	)
	wantComplete(t, got, "a1a2")
	if r.Dups != 1 {
		t.Fatalf("Dups = %d, want 1", r.Dups)
	}
}

// pion reuses the RTP payload buffer between ReadRTP calls; the reassembler
// must copy.
func TestReassemblerCopiesInput(t *testing.T) {
	r, _ := testReassembler()
	scratch := []byte("WXYZ")
	out := r.Add(nil, 10, 7000, true, false, scratch)
	copy(scratch, "0000")
	out = r.Add(out, 11, 7000, false, true, []byte("END"))
	wantComplete(t, out, "WXYZEND")
}

func TestReassemblerSeqWrap(t *testing.T) {
	r, _ := testReassembler()
	got := feed(r,
		rtpIn{65535, 1000, true, false, "a"},
		rtpIn{0, 1000, false, false, "b"},
		rtpIn{1, 1000, false, true, "c"},
	)
	wantComplete(t, got, "abc")
}

func TestReassemblerMaxPendingEvictsOldest(t *testing.T) {
	r, clock := testReassembler()
	r.MaxPending = 2
	feed(r, rtpIn{10, 1000, true, false, "old"})
	*clock = clock.Add(time.Millisecond)
	feed(r, rtpIn{20, 2000, true, false, "mid"})
	*clock = clock.Add(time.Millisecond)
	got := feed(r, rtpIn{30, 3000, true, false, "new"})
	if len(got) != 1 || got[0].Complete || string(got[0].Segments[0]) != "old" {
		t.Fatalf("evicted %+v, want the oldest partial frame", got)
	}
	if r.Pending() != 2 {
		t.Fatalf("pending = %d, want 2", r.Pending())
	}
}

func TestResyncFramesSkipsGarbageAndHandshake(t *testing.T) {
	rcv := NewReceiver(8)
	data1 := EncodeFrame(1, 0, []byte("wg-1"))
	hello := EncodeFrame(2, FlagHandshake, []byte("peer"))
	data2 := EncodeFrame(3, 0, []byte("wg-2"))
	// The fragment starts mid-frame: a truncated tail of an earlier frame.
	frag := append([]byte{0x13, 0x37, 'G', 'T'}, data1...)
	frag = append(frag, hello...)
	frag = append(frag, data2...)
	frag = append(frag, data1[:7]...) // truncated trailing frame

	rcv.resyncFrames(t.Context(), frag)

	var got []string
	for len(rcv.out) > 0 {
		f := <-rcv.out
		got = append(got, string(f.Payload))
	}
	if len(got) != 2 || got[0] != "wg-1" || got[1] != "wg-2" {
		t.Fatalf("salvaged %q, want [wg-1 wg-2] without the handshake", got)
	}
	if rcv.ResyncFrames.Load() != 2 {
		t.Fatalf("ResyncFrames = %d, want 2", rcv.ResyncFrames.Load())
	}
}
