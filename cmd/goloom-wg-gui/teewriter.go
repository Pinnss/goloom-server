package main

import "io"

// teeWriter writes to two io.Writers, ignoring secondary errors. Used
// to keep the wgclient capture pipeline (primary) AND a stderr mirror
// going during development/debug.
type teeWriter struct {
	primary   io.Writer
	secondary io.Writer
}

func (t *teeWriter) Write(p []byte) (int, error) {
	if t.secondary != nil {
		_, _ = t.secondary.Write(p)
	}
	return t.primary.Write(p)
}
