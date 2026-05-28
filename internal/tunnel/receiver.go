package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"sync/atomic"

	"github.com/pion/webrtc/v4"
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
}

func NewReceiver(bufSize int) *Receiver {
	return &Receiver{out: make(chan ReceivedFrame, bufSize)}
}

func (r *Receiver) Frames() <-chan ReceivedFrame { return r.out }

func (r *Receiver) Run(ctx context.Context, track *webrtc.TrackRemote, lg *log.Logger) {
	defer close(r.out)
	var asm FrameAssembler

	for {
		if ctx.Err() != nil {
			return
		}
		pkt, _, err := track.ReadRTP()
		if err != nil {
			lg.Printf("receiver track %s read end: %v (rtp_pkts=%d frames=%d bad_magic=%d strip_errs=%d decode_errs=%d partial_drops=%d hdr_short=%d hdr_bad=%d)",
				track.ID(), err, r.RTPPackets.Load(), r.FramesPushed.Load(),
				r.BadMagic.Load(), r.StripErrs.Load(), r.DecodeErrs.Load(), asm.PartialDrops,
				r.HeaderTooShort.Load(), r.HeaderBadStart.Load())
			return
		}
		r.RTPPackets.Add(1)

		// VP9 migration 2026-05-27: tunnel now publishes as VP9 to dodge
		// Telemost shaping. Old VP8 path retained in vp8.go for fallback.
		stripped, ok := StripVP9Descriptor(pkt.Payload)
		if !ok {
			r.StripErrs.Add(1)
			continue
		}
		complete, ok := asm.Add(pkt.Timestamp, stripped, pkt.Marker)
		if !ok {
			continue
		}

		r.walkFrames(ctx, complete, lg)
	}
}

// walkFrames extracts ALL tunnel frames from a reassembled VP8/VP9 sample.
// A sample may contain a codec keyframe/interframe prefix followed by one
// or more concatenated tunnel frames (Sender batching).
func (r *Receiver) walkFrames(ctx context.Context, buf []byte, lg *log.Logger) {
	// Strip VP9 keyframe prefix if present (uncompressed header starting
	// with 0x82 frame_marker byte followed by sync code 0x49 0x83 0x42).
	// 9 bytes matches [internal/media.VP9BlackKeyframe].
	if len(buf) > 9 && buf[0] == 0x82 && buf[1] == 0x49 && buf[2] == 0x83 && buf[3] == 0x42 {
		buf = buf[9:]
	} else if len(buf) > 1 && buf[0] == 0x86 {
		// Strip VP9 interframe prefix (single byte 0x86 — frame_marker=2,
		// profile=0, show_existing=0, NonKeyFrame=1, ShowFrame=1, error_
		// resilient=0). Matches [internal/media.VP9InterframeHeader]. Used
		// by sender.go::wrapPayload for ~98% of frames after 2026-05-28
		// keyframe-ratio fix.
		buf = buf[1:]
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

		// Side-filter: drop frames stamped with our own pool-side flag.
		// Used by SFU pool members to avoid bot-to-bot loops when the SFU
		// broadcasts each publisher's track to every other participant.
		// Zero DropFlag (legacy default) makes this a no-op.
		if r.DropFlag != 0 && decoded.Flags.Has(r.DropFlag) {
			r.SideFiltered.Add(1)
			buf = buf[total:]
			frameIdx++
			continue
		}

		payload := make([]byte, len(decoded.Payload))
		copy(payload, decoded.Payload)

		r.FramesPushed.Add(1)
		select {
		case r.out <- ReceivedFrame{MsgID: decoded.MsgID, Flags: decoded.Flags, Payload: payload}:
		case <-ctx.Done():
			return
		}

		buf = buf[total:]
		frameIdx++
	}
}
