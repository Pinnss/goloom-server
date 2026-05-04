package tunnel

// StripVP8Descriptor removes the VP8 RTP payload descriptor (RFC 7741 §4.2)
// from the front of an RTP packet payload and returns the remaining VP8
// payload bytes. ok=false means the input is malformed (truncated descriptor).
//
// Descriptor layout:
//
//	byte 0: |X|R|N|S|R| PID(3) |          mandatory
//	byte 1: |I|L|T|K| RSV(4)   |          present iff X=1
//	byte 2..: PictureID         present iff I=1; 1 byte (M=0) or 2 bytes (M=1, MSB has M flag set)
//	+1:      TL0PICIDX          present iff L=1
//	+1:      TID/Y/KEYIDX       present iff T=1 OR K=1 (single byte combines both)
//
// We don't validate the inner VP8 payload (Pion's Sample Builder would, but
// we never feed our payload to a VP8 decoder — the SFU forwards bytes
// verbatim). All we care about is computing the correct prefix length to
// strip so the caller sees pure VP8 video bytes (which in our case are our
// tunnel frame bytes).
func StripVP8Descriptor(payload []byte) ([]byte, bool) {
	if len(payload) < 1 {
		return nil, false
	}
	pos := 1

	// X bit (extension byte present)
	if payload[0]&0x80 != 0 {
		if len(payload) < 2 {
			return nil, false
		}
		ext := payload[1]
		pos = 2

		// I bit — PictureID present
		if ext&0x80 != 0 {
			if len(payload) <= pos {
				return nil, false
			}
			// M bit on first PictureID byte: 0 = 1-byte, 1 = 2-byte
			if payload[pos]&0x80 != 0 {
				pos += 2
			} else {
				pos += 1
			}
		}
		// L bit — TL0PICIDX (1 byte)
		if ext&0x40 != 0 {
			pos += 1
		}
		// T or K bit — TID/Y/KEYIDX (1 byte; both flags share the same byte)
		if ext&0x30 != 0 {
			pos += 1
		}
	}

	if len(payload) < pos {
		return nil, false
	}
	return payload[pos:], true
}
