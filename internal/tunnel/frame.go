// Package tunnel implements PoC #2A's framing layer: arbitrary []byte
// payloads ride inside what the SFU sees as VP8 video frames. One logical
// message == one media.Sample == one VP8 "frame" (1+ RTP packets sharing a
// timestamp, last packet has marker=1).
//
// On the wire (after Pion's VP8 payload descriptor):
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+--... ----+
//	|magic 'G' 'T'|ver |flg|     msgID         |  ...payload (length bytes)
//	|0x47   0x54  |0x01|   |  BE uint32        |     |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--... ----+
//	     0    1    2    3   4   5   6   7   8 ... 11+length
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// MagicByte0 / MagicByte1 spell "GT" — they distinguish our frames from
	// genuine VP8 video that other (browser) participants in the same room
	// may publish. Receivers drop anything without this prefix silently.
	MagicByte0 byte = 0x47 // 'G'
	MagicByte1 byte = 0x54 // 'T'

	// Version is bumped on any wire-incompatible change to the header.
	Version byte = 0x01

	// HeaderSize is the fixed-length header before payload bytes.
	HeaderSize = 12

	// MaxPayloadSize caps a single frame to 10 MiB. Realistically we send
	// up to ~100 KB during PoC #2A T3, but the cap stops a malformed length
	// field from triggering huge allocations on the receive side.
	MaxPayloadSize = 10 * 1024 * 1024
)

// Flags occupies one byte. Multiple flags can be combined.
type Flags uint8

const (
	FlagTest         Flags = 1 << 0 // test-phase traffic (vs WG in future)
	FlagHandshake    Flags = 1 << 1 // HELLO frame, payload = our participantId
	FlagHandshakeAck Flags = 1 << 2 // HELLO_ACK frame, payload = our participantId
	FlagPing         Flags = 1 << 3 // initiator → echoer; payload[:4]=ping msgID, then data
	FlagPong         Flags = 1 << 4 // echoer → initiator; payload echoed verbatim
	FlagKCP          Flags = 1 << 5 // KCP reliable transport datagram
)

// Has reports whether all the bits set in other are also set in f.
func (f Flags) Has(other Flags) bool { return f&other == other }

// ErrShortFrame, ErrBadMagic, ErrBadVersion, ErrLengthMismatch are all
// non-fatal: receivers should drop the offending frame and keep going.
var (
	ErrShortFrame     = errors.New("tunnel: frame shorter than header")
	ErrBadMagic       = errors.New("tunnel: magic bytes mismatch (likely real video)")
	ErrBadVersion     = errors.New("tunnel: unknown frame version")
	ErrLengthMismatch = errors.New("tunnel: declared length != actual payload size")
	ErrPayloadTooBig  = errors.New("tunnel: declared length exceeds MaxPayloadSize")
)

// EncodeFrame builds one wire-format frame from a payload. msgID is the
// sender-monotonic sequence number, flags carries protocol bits.
func EncodeFrame(msgID uint32, flags Flags, payload []byte) []byte {
	buf := make([]byte, HeaderSize+len(payload))
	buf[0] = MagicByte0
	buf[1] = MagicByte1
	buf[2] = Version
	buf[3] = byte(flags)
	binary.BigEndian.PutUint32(buf[4:8], msgID)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf
}

// DecodedFrame is what DecodeFrame returns on success.
type DecodedFrame struct {
	MsgID   uint32
	Flags   Flags
	Payload []byte // alias into the input buffer; copy if you need to outlive it
}

// DecodeFrame validates a complete frame and returns the parsed view. The
// returned Payload aliases the input slice — callers that buffer it must
// copy.
func DecodeFrame(buf []byte) (DecodedFrame, error) {
	if len(buf) < HeaderSize {
		return DecodedFrame{}, ErrShortFrame
	}
	if buf[0] != MagicByte0 || buf[1] != MagicByte1 {
		return DecodedFrame{}, ErrBadMagic
	}
	if buf[2] != Version {
		return DecodedFrame{}, fmt.Errorf("%w: %d", ErrBadVersion, buf[2])
	}
	length := binary.BigEndian.Uint32(buf[8:12])
	if length > MaxPayloadSize {
		return DecodedFrame{}, fmt.Errorf("%w: declared=%d max=%d", ErrPayloadTooBig, length, MaxPayloadSize)
	}
	if int(length) != len(buf)-HeaderSize {
		return DecodedFrame{}, fmt.Errorf("%w: declared=%d actual=%d", ErrLengthMismatch, length, len(buf)-HeaderSize)
	}
	return DecodedFrame{
		MsgID:   binary.BigEndian.Uint32(buf[4:8]),
		Flags:   Flags(buf[3]),
		Payload: buf[HeaderSize:],
	}, nil
}
