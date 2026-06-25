package media

// VP9BlackKeyframe is the minimum VP9 frame whose uncompressed header
// satisfies pion's [github.com/pion/rtp/codecs/vp9.Header.Unmarshal]
// success path so [github.com/pion/rtp/codecs.VP9Payloader] doesn't drop
// the sample. The 9 bytes encode:
//
//   - frame_marker = 0b10 (required value 2)
//   - profile = 0 (8-bit, no extra bits)
//   - show_existing_frame = 0
//   - frame_type = 0 (KEYFRAME)
//   - show_frame = 1
//   - error_resilient_mode = 0
//   - sync_code = 0x49 0x83 0x42 (required by VP9 spec)
//   - color_config: ColorSpace=1 (BT.601), ColorRange=0
//   - frame_size: 16x16 (width_minus_1=15, height_minus_1=15)
//
// The bytes after this header don't have to be valid VP9 bitstream —
// pion only parses the uncompressed header and forwards the rest as
// RTP payload data verbatim. SFUs that "keyframe-gate" forwarding also
// look only at the descriptor + uncompressed header to detect keyframes.
//
// 2026-05-27 — added when migrating the goloom tunnel from VP8 to VP9.
// Replaces [VP8BlackKeyframe] for transports where VP9 is negotiated.
// NOTE: resolution is kept 16x16 on purpose — declaring a larger size
// (e.g. 1280x720) in the VP9 SS descriptor while the frame is only ~9 bytes
// is inconsistent and Telemost's SFU drops such "720p in 9 bytes" keyframes,
// which breaks pairing. Raising the declared resolution requires also padding
// keyframes to a plausible size (see throughput-masking work).
var VP9BlackKeyframe = []byte{
	0x82,             // 10 00 0 0 1 0 = frame_marker=2, profile=0, show_exist=0, key, show=1, error_resilient=0
	0x49, 0x83, 0x42, // VP9 sync_code (mandatory)
	0x20,             // ColorSpace=1 (3 bits, MSB-first = 001), ColorRange=0, top 4 bits of width_minus_1=0
	0x00,             // next 8 bits of width_minus_1 = 0
	0xF0,             // last 4 bits of width_minus_1 = 1111 (so width_minus_1=15 → width=16), top 4 bits of height_minus_1=0
	0x00,             // next 8 bits of height_minus_1 = 0
	0xF0,             // last 4 bits of height_minus_1 = 1111 (height=16), trailing bits padded with 0
}
