package tunnel

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		msgID   uint32
		flags   Flags
		payload []byte
	}{
		{"empty", 0, 0, []byte{}},
		{"one byte", 1, 0, []byte{0x42}},
		{"flag set", 7, FlagTest, []byte("hello")},
		{"large payload",
			0xDEADBEEF,
			FlagTest,
			bytes.Repeat([]byte{0xAB}, 100*1024),
		},
		{"max msgID", 0xFFFFFFFF, 0, []byte("end")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := EncodeFrame(c.msgID, c.flags, c.payload)
			if len(buf) != HeaderSize+len(c.payload) {
				t.Fatalf("encoded len = %d, want %d", len(buf), HeaderSize+len(c.payload))
			}
			f, err := DecodeFrame(buf)
			if err != nil {
				t.Fatalf("decode err: %v", err)
			}
			if f.MsgID != c.msgID {
				t.Errorf("msgID = %d, want %d", f.MsgID, c.msgID)
			}
			if f.Flags != c.flags {
				t.Errorf("flags = %d, want %d", f.Flags, c.flags)
			}
			if !bytes.Equal(f.Payload, c.payload) {
				t.Errorf("payload mismatch: got len=%d want len=%d", len(f.Payload), len(c.payload))
			}
		})
	}
}

func TestDecodeFrameErrors(t *testing.T) {
	// Header too short.
	if _, err := DecodeFrame([]byte{0x47, 0x54, 0x01}); !errors.Is(err, ErrShortFrame) {
		t.Errorf("short frame: got %v, want ErrShortFrame", err)
	}

	// Bad magic.
	bad := EncodeFrame(1, 0, []byte("abc"))
	bad[0] = 0x00
	if _, err := DecodeFrame(bad); !errors.Is(err, ErrBadMagic) {
		t.Errorf("bad magic: got %v, want ErrBadMagic", err)
	}

	// Bad version.
	badV := EncodeFrame(1, 0, []byte("abc"))
	badV[2] = 0xFF
	if _, err := DecodeFrame(badV); !errors.Is(err, ErrBadVersion) {
		t.Errorf("bad version: got %v, want ErrBadVersion", err)
	}

	// Length mismatch (truncated payload).
	good := EncodeFrame(1, 0, []byte("hello"))
	if _, err := DecodeFrame(good[:len(good)-1]); !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("truncated: got %v, want ErrLengthMismatch", err)
	}

	// Length too big.
	tooBig := EncodeFrame(1, 0, []byte{})
	tooBig[8] = 0xFF
	tooBig[9] = 0xFF
	tooBig[10] = 0xFF
	tooBig[11] = 0xFF
	if _, err := DecodeFrame(tooBig); !errors.Is(err, ErrPayloadTooBig) {
		t.Errorf("oversize: got %v, want ErrPayloadTooBig", err)
	}
}
