package media

// VP9BlackKeyframe is a REAL, fully decodable VP9 keyframe (256x144 solid
// black), produced by libvpx-vp9 (`ffmpeg -f lavfi -i color=black:s=256x144
// -c:v libvpx-vp9`). It is NOT a hand-crafted header stub — libvpx decodes it
// to an actual black frame, so `framesDecoded` increments for any subscriber
// (browser / SFU) that decodes our published track.
//
// WHY THIS MATTERS (2026-07-23): the previous value was a 9-byte uncompressed-
// header stub with no compressed coefficient data. pion's VP9 packetizer parsed
// it, so packets flowed — but any real decoder rejects it ("Corrupt frame
// detected"), so framesDecoded stayed 0 forever. Telemost's SFU forwards our
// undecodable publisher on faith for a ~60 s grace period, then stops
// forwarding it (the "SFU detects our frames are garbage" cutoff). Emitting a
// genuinely decodable keyframe removes that signal. Verified against the exact
// decoder browsers use (libvpx-vp9): a bare keyframe decodes 1 frame / 0 errors.
//
// This value is written two ways:
//   - BARE, as a periodic keyframe-refresh / PLI response / handshake priming
//     sample (session.RunKeyframeRefresh, SendInitialKeyframes,
//     MakeKeyframePusher). A bare real keyframe decodes standalone.
//   - As the leading frame of a VP9 SUPERFRAME that also carries hidden tunnel
//     data (tunnel.Sender.wrapPayload). The superframe index declares ONLY this
//     36-byte frame, so the decoder decodes the black keyframe and ignores the
//     WireGuard bytes packed after it. See tunnel.superframeHide.
//
// The receiver (tunnel.Receiver.walkFrames) strips exactly len(VP9BlackKeyframe)
// bytes off the front of a keyframe sample before reading tunnel frames, so the
// length here is load-bearing on BOTH ends — keep sender and receiver builds in
// lockstep when changing it.
//
// 2026-05-27 introduced (as a 9-byte stub) during the VP8→VP9 migration.
// 2026-07-23 replaced with this real decodable frame to defeat the SFU's
// undecodable-stream cutoff.
var VP9BlackKeyframe = []byte{
	0x82, 0x49, 0x83, 0x42, 0x00, 0x0f, 0xf0, 0x08,
	0xf6, 0x00, 0x38, 0x24, 0x1c, 0x18, 0x42, 0x00,
	0x00, 0x50, 0x61, 0xf6, 0x30, 0x00, 0x00, 0x67,
	0x1b, 0x14, 0xcd, 0x27, 0x77, 0x16, 0x8b, 0x16,
	0xd8, 0x69, 0x65, 0x00,
}
