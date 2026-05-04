package tunnel

import (
	"bytes"
	"testing"
)

// TestStripVP8DescriptorMinimal: X=0, just one descriptor byte.
// Pion's VP8Payloader emits this shape by default.
func TestStripVP8DescriptorMinimal(t *testing.T) {
	in := []byte{0x10, 0xAA, 0xBB, 0xCC} // S bit set, no extension
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("payload = %x, want AABBCC", out)
	}
}

// TestStripVP8DescriptorXNoFlags: X=1, but I=L=T=K=0 → 2 descriptor bytes.
func TestStripVP8DescriptorXNoFlags(t *testing.T) {
	in := []byte{0x90, 0x00, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorPictureID8: X=1, I=1, M=0 → 3 descriptor bytes.
func TestStripVP8DescriptorPictureID8(t *testing.T) {
	in := []byte{0x90, 0x80, 0x42, 0xAA, 0xBB}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA, 0xBB}) {
		t.Fatalf("payload = %x, want AABB", out)
	}
}

// TestStripVP8DescriptorPictureID16: X=1, I=1, M=1 → 4 descriptor bytes
// (PictureID 2 bytes, MSB has M flag set).
func TestStripVP8DescriptorPictureID16(t *testing.T) {
	in := []byte{0x90, 0x80, 0x80, 0x01, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorL: X=1, L=1 (TL0PICIDX present) → 3 bytes.
func TestStripVP8DescriptorL(t *testing.T) {
	in := []byte{0x90, 0x40, 0x05, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorT: X=1, T=1 (TID present) → 3 bytes.
func TestStripVP8DescriptorT(t *testing.T) {
	in := []byte{0x90, 0x20, 0x80, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorK: X=1, K=1 → 3 bytes.
func TestStripVP8DescriptorK(t *testing.T) {
	in := []byte{0x90, 0x10, 0x00, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorAllFlags: X=1, I=1 (8-bit pic id) + L=1 + T=1
// → 5 bytes total (1 hdr + 1 ext + 1 pic + 1 tl0 + 1 tid).
func TestStripVP8DescriptorAllFlags(t *testing.T) {
	in := []byte{0x90, 0xE0, 0x42, 0x05, 0x80, 0xAA, 0xBB}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA, 0xBB}) {
		t.Fatalf("payload = %x, want AABB", out)
	}
}

// TestStripVP8DescriptorAllFlags16: X=1, I=1 (16-bit pic id) + L=1 + K=1
// → 6 bytes total.
func TestStripVP8DescriptorAllFlags16(t *testing.T) {
	in := []byte{0x90, 0xD0, 0x80, 0x10, 0x05, 0x00, 0xAA}
	out, ok := StripVP8Descriptor(in)
	if !ok {
		t.Fatal("not ok")
	}
	if !bytes.Equal(out, []byte{0xAA}) {
		t.Fatalf("payload = %x, want AA", out)
	}
}

// TestStripVP8DescriptorTruncated covers each early-return.
func TestStripVP8DescriptorTruncated(t *testing.T) {
	cases := [][]byte{
		nil,
		{},                             // empty input
		{0x90},                         // X=1 but no extension byte
		{0x90, 0x80},                   // I=1 but no PictureID byte
		{0x90, 0x80, 0x80},             // I=1, M=1 but only 1 PictureID byte
		{0x90, 0x40},                   // L=1 but no TL0PICIDX
		{0x90, 0x20},                   // T=1 but no TID byte
		{0x90, 0xE0, 0x42, 0x05},       // missing TID byte
		{0x90, 0xE0, 0x42, 0x05, 0x80}, // header consumes whole input — empty payload OK?
	}
	for i, c := range cases {
		out, ok := StripVP8Descriptor(c)
		// Cases 0..7 are too short for the implied descriptor — must be !ok.
		// Case 8 has exactly the right number of descriptor bytes and zero
		// payload bytes — that's still a valid (if useless) descriptor: ok=true
		// with an empty payload slice.
		if i < 8 {
			if ok {
				t.Errorf("case %d: expected !ok, got payload=%x", i, out)
			}
			continue
		}
		if !ok {
			t.Errorf("case %d: expected ok with empty payload, got !ok", i)
		}
		if len(out) != 0 {
			t.Errorf("case %d: expected empty payload, got %x", i, out)
		}
	}
}
