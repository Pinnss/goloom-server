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

	RTPPackets     atomic.Uint64
	StripErrs      atomic.Uint64
	BadMagic       atomic.Uint64
	DecodeErrs     atomic.Uint64
	FramesPushed   atomic.Uint64
	HeaderTooShort atomic.Uint64
	HeaderBadStart atomic.Uint64
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

		stripped, ok := StripVP8Descriptor(pkt.Payload)
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

// walkFrames extracts ALL tunnel frames from a reassembled VP8 sample.
// A sample may contain a VP8 keyframe prefix followed by one or more
// concatenated tunnel frames (Sender batching).
func (r *Receiver) walkFrames(ctx context.Context, buf []byte, lg *log.Logger) {
	// Strip VP8 keyframe prefix if present (frame_tag + start code 9d 01 2a).
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
