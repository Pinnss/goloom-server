package tunnel

// StripVP9Descriptor removes the VP9 RTP payload descriptor (RFC 8741 §4.2)
// from the front of an RTP packet payload and returns the remaining VP9
// payload bytes. ok=false means the input is malformed (truncated descriptor).
//
// Descriptor layout for pion's [github.com/pion/rtp/codecs.VP9Payloader] in
// non-flexible mode with PictureID and (for keyframes) Scalability Structure:
//
//	byte 0: |I|P|L|F|B|E|V|Z|     mandatory flags
//	I=1   : |M| PictureID(7)|     1-byte (M=0) or
//	         | EXT_PID(8)   |     2-byte (M=1) — pion always uses 2-byte
//	L=1   : |TID|U|SID|D|        1 byte
//	L=1,F=0: TL0PICIDX            1 byte (non-flexible only)
//	V=1   : SS structure          variable (set on keyframes)
//
// pion in non-flexible mode + keyframes emits 0x80|0x01 | 0x08(B) | 0x04(E) |
// 0x02(V) = 0x8F header byte, followed by 2-byte PictureID, then a fixed
// 8-byte SS (N_S=0, Y=1, G=1, 1 spatial layer 4-byte WxH, N_G=1, 1 PG entry).
// Total 11-byte descriptor.
//
// Non-keyframes have 0x80|0x40(P)|0x08(B)|0x04(E)|0x01(Z) = 0xCD = 3 bytes.
//
// We don't validate inner VP9 bitstream — the SFU forwards bytes verbatim
// and we use those bytes as a tunnel for WireGuard datagrams.
//
// 2026-05-27 — added during VP8 → VP9 migration to bypass Telemost VP8
// shaping. Mirrors [StripVP8Descriptor] semantics.
func StripVP9Descriptor(payload []byte) ([]byte, bool) {
	if len(payload) < 1 {
		return nil, false
	}
	flags := payload[0]
	pos := 1

	// I: PictureID present
	if flags&0x80 != 0 {
		if pos >= len(payload) {
			return nil, false
		}
		// M bit (high bit of first PID byte): 1=15-bit picture ID over 2 bytes, 0=7-bit over 1 byte
		if payload[pos]&0x80 != 0 {
			pos += 2
		} else {
			pos += 1
		}
	}

	// L: Layer indices present (1 byte: TID/U/SID/D)
	if flags&0x20 != 0 {
		pos += 1
		// L=1 and F=0 (non-flexible mode) also carries TL0PICIDX (1 byte)
		if flags&0x10 == 0 {
			pos += 1
		}
	}

	// F: flexible mode — P_DIFF list, each byte has N bit (LSB) marking continuation
	if flags&0x10 != 0 {
		for {
			if pos >= len(payload) {
				return nil, false
			}
			n := payload[pos] & 0x01
			pos += 1
			if n == 0 {
				break
			}
		}
	}

	// V: Scalability Structure present (set on keyframes)
	if flags&0x02 != 0 {
		if pos >= len(payload) {
			return nil, false
		}
		nsYG := payload[pos]
		pos += 1
		nS := int((nsYG>>5)&0x07) + 1
		y := (nsYG >> 4) & 0x01
		g := (nsYG >> 3) & 0x01

		if y != 0 {
			// One 4-byte WxH per spatial layer (16-bit BE width, 16-bit BE height)
			pos += nS * 4
		}
		if g != 0 {
			if pos >= len(payload) {
				return nil, false
			}
			nG := int(payload[pos])
			pos += 1
			for i := 0; i < nG; i++ {
				if pos >= len(payload) {
					return nil, false
				}
				tidUR := payload[pos]
				pos += 1
				// R is 2 bits at bit positions 3-2 — matches pion writer
				// emitting `1<<4 | 1<<2 = 0x14` for TID=0, U=1, R=1. Old
				// `r := tidUR & 0x0F` mis-read R as 4 bits which made us
				// over-skip and corrupted tunnel frame magic detection.
				r := int((tidUR >> 2) & 0x03)
				pos += r
			}
		}
	}

	if pos > len(payload) {
		return nil, false
	}
	return payload[pos:], true
}
