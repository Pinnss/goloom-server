package tunnel

// VP8KeyframeHeader is a 10-byte fake VP8 frame header prepended to every
// outbound tunnel frame so the SFU's keyframe-gated forwarder treats each
// Sample as a key frame and forwards it. Pion's VP8Payloader doesn't peek
// inside the payload, and goloom's SFU only inspects the first few bytes
// to classify frames.
//
// Layout (RFC 6386 §9.1):
//
//	byte 0:  0x10  — frame tag bits: key_frame=0 (LSB), version=0,
//	                 show_frame=1, first_part_size_low=0
//	byte 1:  0x02  — first_part_size_mid
//	byte 2:  0x00  — first_part_size_high
//	byte 3-5: 0x9d 0x01 0x2a — start code (mandatory for keyframes)
//	byte 6-7: 0x40 0x01     — width = 0x140 = 320
//	byte 8-9: 0xf0 0x00     — height = 0x0f0 = 240
//
// Receivers MUST skip these 10 bytes (after stripping Pion's RTP payload
// descriptor) before parsing the tunnel header.
var VP8KeyframeHeader = []byte{
	0x10, 0x02, 0x00,
	0x9d, 0x01, 0x2a,
	0x40, 0x01,
	0xf0, 0x00,
}

// VP8KeyframeHeaderLen is the fixed prefix length (10).
const VP8KeyframeHeaderLen = 10
