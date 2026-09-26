package media

// VP9InterframeHeader is a REAL, fully decodable VP9 inter-frame (P-frame,
// 256x144 solid black) produced by libvpx-vp9 in the same encode as
// [VP9BlackKeyframe] (it references that keyframe's reconstructed buffers). It
// is NOT a 1-byte header stub — libvpx decodes it to a black frame, provided a
// keyframe was decoded first, which our stream guarantees (periodic
// [VP9BlackKeyframe] refreshes + SendInitialKeyframes at startup).
//
// Verified against libvpx-vp9 (the browser decoder): a stream of 1 keyframe
// followed by 59 of these interframes — each carrying different hidden tunnel
// data via a superframe index — decodes 60/60 frames with 0 errors, and 3
// back-to-back GOPs decode 180/180 with no drift.
//
// It is used as [tunnel.Sender.InterframePrefix]: ~98% of data samples lead
// with this frame (only every KeyframePeriod-th sample uses the keyframe), so
// the published stream keeps a realistic ~1.6% keyframe ratio while every frame
// remains decodable. As with the keyframe, the tunnel data is hidden after this
// frame inside a VP9 superframe whose index declares only these 19 bytes (see
// tunnel.superframeHide); the decoder decodes the black P-frame and ignores the
// WireGuard bytes.
//
// The receiver strips exactly len(VP9InterframeHeader) bytes off the front of
// an interframe sample, so the length is load-bearing on both ends.
//
// 2026-05-28 introduced (as the 1-byte 0x86 header) for the keyframe-ratio fix.
// 2026-07-23 replaced with this real decodable inter-frame to defeat the SFU's
// undecodable-stream cutoff (the header stub decoded to nothing).
var VP9InterframeHeader = []byte{
	0x86, 0x00, 0x40, 0x92, 0x9c, 0x00, 0x49, 0x40,
	0x00, 0x03, 0x20, 0x00, 0x00, 0x5a, 0x33, 0xb7,
	0x57, 0x0a, 0x40,
}
