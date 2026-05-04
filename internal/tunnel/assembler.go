package tunnel

// FrameAssembler reassembles one logical frame from the stream of
// per-RTP-packet payloads that share a single RTP timestamp. The last RTP
// packet of a frame has its marker bit set; that's our signal to flush.
//
// Behaviour summary:
//   - First call sets currentTS and arms.
//   - Subsequent calls with the same timestamp append.
//   - A different timestamp before marker means the previous frame was lost
//     mid-flight; we drop the partial buffer and start fresh on the new TS.
//   - A call with marker=true returns the concatenated payload and disarms.
//
// Not safe for concurrent use; expected to be called from a single
// per-track read loop.
type FrameAssembler struct {
	currentTS uint32
	parts     [][]byte
	armed     bool

	// PartialDrops counts how many times we threw away a partial frame
	// because a new timestamp arrived before the marker. Useful for telemetry.
	PartialDrops uint64
}

// Add ingests one RTP packet's stripped payload. Returns (frame, true) when
// a complete frame is ready, otherwise (nil, false).
//
// The caller must pass an already-VP8-descriptor-stripped payload slice. The
// slice is copied internally because Pion reuses the underlying buffer
// across ReadRTP calls.
func (a *FrameAssembler) Add(timestamp uint32, payload []byte, marker bool) ([]byte, bool) {
	if !a.armed {
		a.currentTS = timestamp
		a.armed = true
		a.parts = a.parts[:0]
	} else if a.currentTS != timestamp {
		a.PartialDrops++
		a.parts = a.parts[:0]
		a.currentTS = timestamp
	}

	if len(payload) > 0 {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		a.parts = append(a.parts, cp)
	}

	if !marker {
		return nil, false
	}

	total := 0
	for _, p := range a.parts {
		total += len(p)
	}
	full := make([]byte, 0, total)
	for _, p := range a.parts {
		full = append(full, p...)
	}
	a.parts = a.parts[:0]
	a.armed = false
	return full, true
}

// Reset clears any partial state. Call when the underlying RTP stream resets
// (e.g. SSRC change or after teardown).
func (a *FrameAssembler) Reset() {
	a.armed = false
	a.parts = a.parts[:0]
}
