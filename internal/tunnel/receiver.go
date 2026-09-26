package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/pion/webrtc/v4"

	mediastubs "github.com/Pinnss/goloom-server/internal/media"
)

type ReceivedFrame struct {
	MsgID   uint32
	Flags   Flags
	Payload []byte
}

type Receiver struct {
	out chan ReceivedFrame

	// DropFlag, when non-zero, causes [Receiver.walkFrames] to silently
	// discard any frame whose Flags has DropFlag set. Used by the SFU pool
	// architecture: server-side pool members set DropFlag=FlagFromServer
	// so they drop frames produced by other server-side pool members
	// (which the SFU broadcasts to everyone in the room). 0 = no filtering
	// (legacy single-instance behaviour).
	DropFlag Flags

	RTPPackets     atomic.Uint64
	StripErrs      atomic.Uint64
	BadMagic       atomic.Uint64
	DecodeErrs     atomic.Uint64
	FramesPushed   atomic.Uint64
	HeaderTooShort atomic.Uint64
	HeaderBadStart atomic.Uint64
	SideFiltered   atomic.Uint64 // count of frames dropped via DropFlag
	PartialFrames  atomic.Uint64 // samples released with holes after the reassembly wait
	ResyncFrames   atomic.Uint64 // tunnel frames salvaged from mid-sample fragments
	LatePackets    atomic.Uint64 // packets for samples already released
}

func NewReceiver(bufSize int) *Receiver {
	return &Receiver{out: make(chan ReceivedFrame, bufSize)}
}

func (r *Receiver) Frames() <-chan ReceivedFrame { return r.out }

func (r *Receiver) Run(ctx context.Context, track *webrtc.TrackRemote, lg *log.Logger) {
	defer close(r.out)
	asm := NewReassembler()
	var released []ReleasedFrame

	// Media RTP sequence-gap tracking (2026-07-22). The SFU NACKs our publisher
	// even when TWCC reports 0% transport loss — meaning it sees gaps in the
	// MEDIA sequence space while every transport packet arrives. This measures,
	// on the FORWARDED stream a subscriber actually receives, whether the media
	// sequence numbers are contiguous. seq is uint16 so wraps are handled by the
	// uint16 delta.
	var (
		haveSeq   bool
		expectSeq uint16
		seqGaps   uint64
		seqRewind uint64
		prevFlags byte // VP9 descriptor flag byte of the previous packet
		prevMark  bool // marker bit of the previous packet
	)
	// descBits renders the VP9 descriptor flag byte (RFC 8741 §4.2):
	// I|P|L|F|B|E|V|Z — B=start-of-frame, E=end-of-frame, V=SS present.
	descBits := func(f byte) string {
		b := func(mask byte) int {
			if f&mask != 0 {
				return 1
			}
			return 0
		}
		return fmt.Sprintf("I%dP%dL%dF%dB%dE%dV%dZ%d",
			b(0x80), b(0x40), b(0x20), b(0x10), b(0x08), b(0x04), b(0x02), b(0x01))
	}

	for {
		if ctx.Err() != nil {
			return
		}
		pkt, _, err := track.ReadRTP()
		if err != nil {
			lg.Printf("receiver track %s read end: %v (rtp_pkts=%d frames=%d bad_magic=%d strip_errs=%d decode_errs=%d samples_ok=%d samples_partial=%d resync=%d late=%d dups=%d hdr_short=%d hdr_bad=%d seq_gaps=%d seq_rewind=%d)",
				track.ID(), err, r.RTPPackets.Load(), r.FramesPushed.Load(),
				r.BadMagic.Load(), r.StripErrs.Load(), r.DecodeErrs.Load(), asm.Complete, asm.Partial,
				r.ResyncFrames.Load(), asm.Late, asm.Dups,
				r.HeaderTooShort.Load(), r.HeaderBadStart.Load(), seqGaps, seqRewind)
			return
		}
		r.RTPPackets.Add(1)

		// Contiguity check on the media sequence number. delta is uint16:
		// 0 = contiguous, [1,0x8000) = forward gap (missing packets),
		// [0x8000,0xffff] = backward (reorder/duplicate/late).
		var curFlags byte
		if len(pkt.Payload) > 0 {
			curFlags = pkt.Payload[0]
		}
		if haveSeq {
			delta := pkt.SequenceNumber - expectSeq
			switch {
			case delta == 0:
				// contiguous — expected
			case delta < 0x8000:
				seqGaps += uint64(delta)
				// Log the descriptor of the packet BEFORE the gap and the one
				// AFTER, to see whether the dropped packets cluster on a frame
				// boundary / layer pattern (SFU layer-shedding) vs random.
				lg.Printf("receiver %s SEQ GAP: expected=%d got=%d missing=%d total=%d | before[%s mark=%v] after[%s mark=%v]",
					track.ID(), expectSeq, pkt.SequenceNumber, delta, seqGaps,
					descBits(prevFlags), prevMark, descBits(curFlags), pkt.Marker)
			default:
				seqRewind++
			}
		}
		if !haveSeq || pkt.SequenceNumber-expectSeq < 0x8000 {
			expectSeq = pkt.SequenceNumber + 1
			haveSeq = true
		}
		prevFlags, prevMark = curFlags, pkt.Marker

		// VP9 migration 2026-05-27: tunnel now publishes as VP9 to dodge
		// Telemost shaping. Old VP8 path retained in vp8.go for fallback.
		stripped, ok := StripVP9Descriptor(pkt.Payload)
		if !ok {
			r.StripErrs.Add(1)
			continue
		}
		lateBefore := asm.Late
		released = asm.Add(released[:0], pkt.SequenceNumber, pkt.Timestamp, curFlags&vp9FlagB != 0, pkt.Marker, stripped)
		if asm.Late != lateBefore {
			r.LatePackets.Add(1)
		}
		for _, f := range released {
			if f.Complete {
				r.walkFrames(ctx, f.Segments[0], lg)
				continue
			}
			r.PartialFrames.Add(1)
			for i, seg := range f.Segments {
				if i == 0 && f.AtBegin {
					r.walkFrames(ctx, seg, lg)
				} else {
					r.resyncFrames(ctx, seg)
				}
			}
		}
	}
}

// vp9FlagB is the begin-of-frame bit of the VP9 payload descriptor
// (RFC 9628 §4.2: I|P|L|F|B|E|V|Z).
const vp9FlagB = 0x08

// resyncFrames salvages tunnel frames from a fragment that does not start on
// a tunnel-frame boundary — the bytes after a packet that never arrived. It
// scans for the next plausible header and walks from there. A false match
// inside WireGuard ciphertext is ~2^-40 per byte and WireGuard rejects it
// anyway; handshake frames are never accepted from a fragment, because a
// stray HELLO tears the relay down.
func (r *Receiver) resyncFrames(ctx context.Context, buf []byte) {
	for i := 0; i+HeaderSize <= len(buf); {
		if buf[i] != MagicByte0 || buf[i+1] != MagicByte1 || buf[i+2] != Version {
			i++
			continue
		}
		length := binary.BigEndian.Uint32(buf[i+8 : i+12])
		total := HeaderSize + int(length)
		if length > MaxPayloadSize || i+total > len(buf) {
			i++
			continue
		}
		decoded, err := DecodeFrame(buf[i : i+total])
		if err != nil || decoded.Flags&(FlagHandshake|FlagHandshakeAck) != 0 {
			i++
			continue
		}
		r.ResyncFrames.Add(1)
		if !r.deliver(ctx, decoded) {
			return
		}
		i += total
	}
}

// deliver applies the side filter and hands one decoded frame to the
// consumer. It reports false once ctx is done.
func (r *Receiver) deliver(ctx context.Context, decoded DecodedFrame) bool {
	// Side-filter: drop frames stamped with our own pool-side flag.
	// Used by SFU pool members to avoid bot-to-bot loops when the SFU
	// broadcasts each publisher's track to every other participant.
	// Zero DropFlag (legacy default) makes this a no-op.
	if r.DropFlag != 0 && decoded.Flags.Has(r.DropFlag) {
		r.SideFiltered.Add(1)
		return true
	}

	payload := make([]byte, len(decoded.Payload))
	copy(payload, decoded.Payload)

	r.FramesPushed.Add(1)
	select {
	case r.out <- ReceivedFrame{MsgID: decoded.MsgID, Flags: decoded.Flags, Payload: payload}:
		return true
	case <-ctx.Done():
		return false
	}
}

// walkFrames extracts ALL tunnel frames from a reassembled VP8/VP9 sample.
// A sample may contain a codec keyframe/interframe prefix followed by one
// or more concatenated tunnel frames (Sender batching).
func (r *Receiver) walkFrames(ctx context.Context, buf []byte, lg *log.Logger) {
	// Strip the real, decodable VP9 frame that leads every tunnel sample.
	// The keyframe is len(VP9BlackKeyframe)=36 bytes (0x82 0x49 0x83 0x42 …);
	// the inter-frame is len(VP9InterframeHeader)=19 bytes (0x86 0x00 0x40
	// 0x92 …). Lengths are read from the media vars so the receiver can never
	// drift from the sender's prefixes (both derive from the same source).
	// What follows is the concatenated tunnel frames, then a 3-byte VP9
	// superframe index (see tunnel.superframeHide); that index is shorter than
	// HeaderSize, so the walk loop below stops before it and leaves it
	// untouched. (2026-07-23: was 9/1-byte header stubs — see the media pkg
	// for why real frames were needed.)
	kfLen := len(mediastubs.VP9BlackKeyframe)
	ifLen := len(mediastubs.VP9InterframeHeader)
	if len(buf) >= kfLen && buf[0] == 0x82 && buf[1] == 0x49 && buf[2] == 0x83 && buf[3] == 0x42 {
		buf = buf[kfLen:]
	} else if len(buf) >= ifLen && buf[0] == 0x86 && buf[1] == 0x00 && buf[2] == 0x40 && buf[3] == 0x92 {
		buf = buf[ifLen:]
	}
	// Legacy VP8 fallback: strip VP8 keyframe prefix if present (frame_tag
	// + start code 9d 01 2a). Pre-VP9 captures may still arrive briefly
	// during a server↔client version skew.
	if len(buf) > 30 && buf[3] == 0x9d && buf[4] == 0x01 && buf[5] == 0x2a {
		buf = buf[30:]
	}

	frameIdx := 0
	for len(buf) >= HeaderSize {
		if buf[0] != MagicByte0 || buf[1] != MagicByte1 {
			r.BadMagic.Add(1)
			return
		}
		length := binary.BigEndian.Uint32(buf[8:12])
		if length > MaxPayloadSize {
			r.DecodeErrs.Add(1)
			return
		}
		total := HeaderSize + int(length)
		if total > len(buf) {
			r.DecodeErrs.Add(1)
			return
		}
		decoded, err := DecodeFrame(buf[:total])
		if err != nil {
			if errors.Is(err, ErrBadMagic) {
				r.BadMagic.Add(1)
			} else {
				r.DecodeErrs.Add(1)
			}
			return
		}

		if !r.deliver(ctx, decoded) {
			return
		}

		buf = buf[total:]
		frameIdx++
	}
}
