package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type RelayStats struct {
	BytesUp   atomic.Int64
	BytesDown atomic.Int64
}

// Relay copies data bidirectionally between a and b until one side
// closes or errors. Returns when both directions are done.
func Relay(a, b net.Conn, stats *RelayStats) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn, counter *atomic.Int64) {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		counter.Add(n)
		dst.SetWriteDeadline(time.Now())
		src.SetReadDeadline(time.Now())
	}

	go cp(a, b, &stats.BytesDown)
	go cp(b, a, &stats.BytesUp)
	wg.Wait()
}
