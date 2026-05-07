package wgclient

import (
	"bytes"
	"sync"
)

// lineWriter is an [io.Writer] that splits its input on '\n' and
// invokes onLine for each completed line (with the trailing newline
// stripped). Partial writes are buffered until the next newline lands.
//
// Used to bridge the standard log.Logger API (which writes one
// formatted record per call, ending in '\n') into our event-stream
// world without parsing log levels out of the binary writer interface.
type lineWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	onLine func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Write(p)

	for {
		data := w.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			break
		}
		// Take the line *without* the newline.
		line := string(data[:idx])
		// Trim a trailing CR (Windows-style line endings sneaking through).
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		// Advance the buffer past "<line>\n".
		w.buf.Next(idx + 1)

		if w.onLine != nil && line != "" {
			w.onLine(line)
		}
	}
	return len(p), nil
}
