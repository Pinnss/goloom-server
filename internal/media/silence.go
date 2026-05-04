// Package media holds tiny hardcoded payloads used as send-side filler so the
// SFU sees periodic RTP and doesn't tear down our publisher PC for inactivity.
//
// These are NOT meant to decode to anything sensible. The SFU forwards bytes
// verbatim and other peers' decoders may complain — that's fine for PoC #1,
// where the only success criterion is that goloom keeps the connection alive.
package media

// OpusSilence is a single 20 ms Opus packet with the SILK NB mode TOC byte
// (0xf8 = config 31, mono, code 0) followed by a one-byte filler payload.
// Decoders interpret this as a frame of silence.
var OpusSilence = []byte{0xf8, 0xff, 0xfe}
