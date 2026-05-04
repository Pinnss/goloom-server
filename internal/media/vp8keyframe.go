package media

// VP8BlackKeyframe is a minimal valid VP8 I-frame for a 16×16 black image,
// pre-encoded by libvpx with default settings. We push it down our publisher
// video track during warmup so the SFU sees a "real" keyframe and starts
// forwarding subsequent packets to other subscribers. Without this, our
// tunnel frames (which look like inter-frames to a VP8 parser because
// payload byte 0 happens to have key_frame=1 set in RFC 6386's inverted
// convention) are dropped by goloom's keyframe-gated forwarder.
//
// Source: equivalent to `ffmpeg -f lavfi -i color=black:s=16x16:r=1 -t 1 -c:v vp8 out.ivf`
// then extracting the first frame's payload (byte range after the 32-byte
// IVF file header + 12-byte IVF frame header).
var VP8BlackKeyframe = []byte{
	0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00, 0x10, 0x00,
	0x00, 0x47, 0x08, 0x85, 0x85, 0x88, 0x85, 0x84, 0x88, 0x02,
	0x02, 0x00, 0x0c, 0x0d, 0x60, 0x00, 0xfe, 0xfc, 0x5c, 0xd0,
}
