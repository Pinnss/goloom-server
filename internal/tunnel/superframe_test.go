package tunnel

import (
	"bytes"
	"context"
	"io"
	"log"
	"testing"

	mediastubs "github.com/Pinnss/goloom-server/internal/media"
)

// drain reads all frames currently buffered on the receiver's out channel
// without blocking. walkFrames pushes synchronously to a buffered channel, so
// after it returns everything it produced is already queued.
func drain(r *Receiver) []ReceivedFrame {
	var out []ReceivedFrame
	for {
		select {
		case f := <-r.out:
			out = append(out, f)
		default:
			return out
		}
	}
}

// TestSuperframeHideDeclaresOnlyRealFrame verifies the trailing VP9 superframe
// index encodes exactly one frame whose size is the real frame's length — the
// property that makes a decoder skip the hidden tunnel data.
func TestSuperframeHideDeclaresOnlyRealFrame(t *testing.T) {
	real := mediastubs.VP9BlackKeyframe // 36 bytes < 256 → mag=1
	data := bytes.Repeat([]byte{0xAB}, 500)
	got := superframeHide(real, data)

	// Layout: real ++ data ++ [marker, size, marker].
	if want := len(real) + len(data) + 3; len(got) != want {
		t.Fatalf("superframe len = %d, want %d", len(got), want)
	}
	if !bytes.Equal(got[:len(real)], real) {
		t.Fatalf("real frame not at front")
	}
	idx := got[len(got)-3:]
	// mag=1, frames=1 → marker 0xC0; size byte = len(real).
	if idx[0] != 0xC0 || idx[2] != 0xC0 {
		t.Fatalf("superframe marker = %#x/%#x, want 0xC0/0xC0", idx[0], idx[2])
	}
	if int(idx[1]) != len(real) {
		t.Fatalf("declared frame size = %d, want %d", idx[1], len(real))
	}
}

// TestSuperframeRoundTrip feeds sender-shaped samples (real frame + hidden GT
// frames + superframe index) through the receiver and checks every tunnel frame
// comes back intact, with no bad-magic / decode-error counts and the trailing
// index silently ignored.
func TestSuperframeRoundTrip(t *testing.T) {
	lg := log.New(io.Discard, "", 0)
	ctx := context.Background()

	frames := []struct {
		id      uint32
		flags   Flags
		payload []byte
	}{
		{1, FlagTest | FlagHandshake, []byte("HELLO-round-0-peerid")},
		{2, 0, bytes.Repeat([]byte{0x11}, 1400)},
		{3, FlagTest, []byte("x")},
	}

	build := func(realFrame []byte) []byte {
		var batch []byte
		for _, f := range frames {
			batch = append(batch, EncodeFrame(f.id, f.flags, f.payload)...)
		}
		return superframeHide(realFrame, batch)
	}

	for _, tc := range []struct {
		name string
		real []byte
	}{
		{"keyframe", mediastubs.VP9BlackKeyframe},
		{"interframe", mediastubs.VP9InterframeHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReceiver(16)
			r.walkFrames(ctx, build(tc.real), lg)
			got := drain(r)
			if len(got) != len(frames) {
				t.Fatalf("recovered %d frames, want %d", len(got), len(frames))
			}
			for i, f := range frames {
				if got[i].MsgID != f.id || got[i].Flags != f.flags || !bytes.Equal(got[i].Payload, f.payload) {
					t.Fatalf("frame %d mismatch: got id=%d flags=%#x len=%d",
						i, got[i].MsgID, got[i].Flags, len(got[i].Payload))
				}
			}
			if n := r.BadMagic.Load(); n != 0 {
				t.Fatalf("BadMagic = %d, want 0 (trailing superframe index leaked)", n)
			}
			if n := r.DecodeErrs.Load(); n != 0 {
				t.Fatalf("DecodeErrs = %d, want 0", n)
			}
		})
	}
}

// TestBareKeyframeYieldsNoFrames confirms a bare real keyframe (keyframe-refresh
// / PLI response — no tunnel data, no index) is stripped clean and produces no
// spurious frames or bad-magic counts.
func TestBareKeyframeYieldsNoFrames(t *testing.T) {
	r := NewReceiver(4)
	r.walkFrames(context.Background(), append([]byte(nil), mediastubs.VP9BlackKeyframe...), log.New(io.Discard, "", 0))
	if got := drain(r); len(got) != 0 {
		t.Fatalf("bare keyframe produced %d frames, want 0", len(got))
	}
	if n := r.BadMagic.Load(); n != 0 {
		t.Fatalf("BadMagic = %d, want 0", n)
	}
}
