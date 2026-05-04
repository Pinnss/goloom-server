package tunnel

import (
	"bytes"
	"testing"
)

func TestAssemblerSinglePacket(t *testing.T) {
	var a FrameAssembler
	out, ok := a.Add(1000, []byte("hello"), true)
	if !ok {
		t.Fatal("expected complete frame on single marker packet")
	}
	if !bytes.Equal(out, []byte("hello")) {
		t.Fatalf("payload = %q", out)
	}
	if a.armed {
		t.Error("assembler should be disarmed after flush")
	}
}

func TestAssemblerMultiPacket(t *testing.T) {
	var a FrameAssembler
	if _, ok := a.Add(2000, []byte("AAAA"), false); ok {
		t.Fatal("first packet of multi-packet frame should not flush")
	}
	if _, ok := a.Add(2000, []byte("BBBB"), false); ok {
		t.Fatal("middle packet should not flush")
	}
	out, ok := a.Add(2000, []byte("CCCC"), true)
	if !ok {
		t.Fatal("marker packet should flush")
	}
	if !bytes.Equal(out, []byte("AAAABBBBCCCC")) {
		t.Fatalf("got %q want AAAABBBBCCCC", out)
	}
}

// New timestamp arriving before marker indicates the previous frame was lost
// (the SFU dropped its tail packets, or our network did). The assembler must
// abandon the partial buffer and start over on the new TS.
func TestAssemblerNewTimestampMidFrame(t *testing.T) {
	var a FrameAssembler
	a.Add(3000, []byte("ZZZ"), false)
	a.Add(3000, []byte("YYY"), false)
	out, ok := a.Add(4000, []byte("hello"), true)
	if !ok {
		t.Fatal("expected flush on marker for new TS")
	}
	if !bytes.Equal(out, []byte("hello")) {
		t.Fatalf("payload = %q, want only the new-TS data", out)
	}
	if a.PartialDrops != 1 {
		t.Errorf("PartialDrops = %d, want 1", a.PartialDrops)
	}
}

func TestAssemblerInputBufferReuse(t *testing.T) {
	// Pion reuses the underlying RTP payload buffer between ReadRTP calls.
	// Make sure assembler copies its input so the returned frame survives.
	scratch := make([]byte, 4)
	copy(scratch, []byte("WXYZ"))

	var a FrameAssembler
	a.Add(7000, scratch, false)

	// Mutate the caller's slice, simulating the next ReadRTP.
	copy(scratch, []byte("0000"))

	out, ok := a.Add(7000, []byte("END"), true)
	if !ok {
		t.Fatal("expected flush")
	}
	if !bytes.Equal(out, []byte("WXYZEND")) {
		t.Fatalf("buffer reused: got %q want WXYZEND", out)
	}
}

func TestAssemblerEmptyPacket(t *testing.T) {
	var a FrameAssembler
	a.Add(8000, []byte("aa"), false)
	a.Add(8000, []byte{}, false)
	out, ok := a.Add(8000, []byte("bb"), true)
	if !ok {
		t.Fatal("expected flush")
	}
	if !bytes.Equal(out, []byte("aabb")) {
		t.Fatalf("got %q want aabb", out)
	}
}

func TestAssemblerReset(t *testing.T) {
	var a FrameAssembler
	a.Add(9000, []byte("partial"), false)
	a.Reset()
	if a.armed {
		t.Error("Reset should disarm")
	}
	out, ok := a.Add(9001, []byte("new"), true)
	if !ok {
		t.Fatal("expected flush after Reset")
	}
	if !bytes.Equal(out, []byte("new")) {
		t.Fatalf("payload after Reset: %q", out)
	}
}
