package media

// VP8Stub is a placeholder payload sent in the video track at low frame rate
// solely to keep the publisher transceiver "active" from the SFU's liveness
// perspective. It is NOT a valid VP8 keyframe — downstream decoders will
// drop it. PoC #1 only needs the SFU to keep the connection open; once we
// move to PoC #2 (real media tunneling) this gets replaced by a proper
// encoder pipeline.
var VP8Stub = make([]byte, 64)
