package media

// VP9InterframeHeader is the minimum byte sequence whose VP9 uncompressed
// header satisfies pion's [github.com/pion/rtp/codecs/vp9.Header.Unmarshal]
// success path with NonKeyFrame=1 — i.e. the frame is parsed as an
// inter-frame (P-frame). pion's [github.com/pion/rtp/codecs.VP9Payloader]
// then produces a 3-byte RTP descriptor (no Scalability Structure)
// instead of the 11-byte descriptor used for keyframes. This is the
// statistically realistic frame type for ~98% of a real video stream.
//
// The single byte encodes:
//
//   - frame_marker = 0b10 (required value 2, bits 7-6)
//   - profile_low_bit = 0 (bit 5)
//   - profile_high_bit = 0 (bit 4) — profile = 0
//   - show_existing_frame = 0 (bit 3)
//   - NonKeyFrame = 1 (bit 2) — INTER-FRAME
//   - ShowFrame = 1 (bit 1)
//   - ErrorResilientMode = 0 (bit 0)
//
// Total binary: 0b10000110 = 0x86.
//
// pion's Unmarshal exits successfully right after reading these 8 bits
// when NonKeyFrame=1 (it skips sync_code / color_config / frame_size
// which are only encoded for keyframes). So this single byte is enough
// for the packetizer to recognise an inter-frame and pass everything
// after it through as RTP payload.
//
// 2026-05-28 — added to fix the "100% keyframes" DPI fingerprint.
// Real WebRTC video sources emit ~1 keyframe every 60-90 frames; we now
// match that ratio by using [VP9BlackKeyframe] (9 bytes) for periodic
// keyframes and this 1-byte interframe header for all other data frames.
var VP9InterframeHeader = []byte{0x86}
