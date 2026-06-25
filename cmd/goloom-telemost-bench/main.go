// Command goloom-telemost-bench is a two-instance throughput test stand for
// the goloom-over-Telemost tunnel.
//
// It joins ONE fresh Telemost room with two telemost sessions (a "server" and
// a "client" side), completes the real in-band HELLO/HELLO_ACK handshake (the
// startup canary), then pushes a paced synthetic datagram flow through the
// tunnel and measures delivered goodput plus the loss/backpressure
// diagnostics. It exercises exactly the Sender -> fake-VP9 -> SFU -> Receiver
// pipeline the throughput work touches — with NO WireGuard / TUN / root /
// route changes, so it is safe to run anywhere with plain internet access.
//
// Both sessions run in this one process and pair with each other over the
// real Yandex SFU (traffic hairpins through Telemost), so the measured loss
// and TWCC feedback are real SFU-path numbers.
//
// Usage:
//
//	goloom-telemost-bench -meeting https://telemost.yandex.ru/j/XXXXXXX \
//	    -offered-mbps 20 -dur 30s [-dir both|s2c|c2s] [-logdir ./bench-logs]
//
// Sweep -offered-mbps (e.g. 5,10,20,30,40) to find where offered load starts
// outrunning the path (delivered goodput plateaus / TWCC lost climbs /
// backpressure drops appear) — that overshoot point is the saw-tooth the
// congestion-control work needs to tame. The handshake canary must pass on
// every run or the throughput numbers are discarded.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
	_ "github.com/Pinnss/goloom-server/internal/sfu/telemost" // registers KindTelemost
)

// tick holds the per-direction delivered goodput (Mbps) measured in one sample window.
type tick struct{ s2c, c2s float64 }

func main() {
	meeting := flag.String("meeting", "", "fresh Telemost meeting URL (https://telemost.yandex.ru/j/...) — REQUIRED")
	offeredMbps := flag.Float64("offered-mbps", 20, "offered load per active direction, Mbit/s")
	payload := flag.Int("payload", 1200, "synthetic datagram size, bytes (≈ a WG packet)")
	dur := flag.Duration("dur", 30*time.Second, "measurement duration after pairing")
	hsTimeout := flag.Duration("handshake-timeout", 90*time.Second, "max time for both sides to pair — startup canary")
	dir := flag.String("dir", "both", "load direction: both | s2c | c2s")
	logdir := flag.String("logdir", "bench-logs", "directory for per-session log files (TWCC / backpressure / caps land here)")
	flag.Parse()

	if *meeting == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -meeting is required (a FRESH Telemost room; degraded rooms won't pair)")
		flag.Usage()
		os.Exit(2)
	}
	if *dir != "both" && *dir != "s2c" && *dir != "c2s" {
		fmt.Fprintln(os.Stderr, "ERROR: -dir must be both|s2c|c2s")
		os.Exit(2)
	}

	if err := os.MkdirAll(*logdir, 0o755); err != nil {
		log.Fatalf("mkdir logdir: %v", err)
	}
	srvLog, srvClose := fileLogger(*logdir, "server")
	defer srvClose()
	cliLog, cliClose := fileLogger(*logdir, "client")
	defer cliClose()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	tr, err := sfu.Get(sfu.KindTelemost)
	if err != nil {
		log.Fatalf("sfu.Get(telemost): %v", err)
	}

	// ── Startup canary: connect both sides concurrently; they pair via HELLO.
	fmt.Printf("→ joining %s with two sessions (server + client)…\n", *meeting)
	type res struct {
		side string
		sess sfu.Session
		err  error
	}
	hctx, hcancel := context.WithTimeout(ctx, *hsTimeout)
	defer hcancel()
	out := make(chan res, 2)
	for _, s := range []struct {
		side string
		lg   *log.Logger
	}{{"server", srvLog}, {"client", cliLog}} {
		go func(side string, lg *log.Logger) {
			sess, err := tr.Connect(hctx, sfu.ConnectSpec{
				Kind:        sfu.KindTelemost,
				Side:        side,
				DisplayName: "bench-" + side,
				Logger:      lg,
				Telemost:    &sfu.TelemostConnect{MeetingURL: *meeting},
			})
			out <- res{side, sess, err}
		}(s.side, s.lg)
	}

	t0 := time.Now()
	var srv, cli sfu.Session
	for i := 0; i < 2; i++ {
		r := <-out
		if r.err != nil {
			hcancel()
			log.Fatalf("✗ CANARY FAILED: %s side did not pair: %v (see %s/)", r.side, r.err, *logdir)
		}
		if r.side == "server" {
			srv = r.sess
		} else {
			cli = r.sess
		}
	}
	pairMS := time.Since(t0)
	fmt.Printf("✓ CANARY: both sides paired (HELLO/HELLO_ACK) in %s\n", pairMS.Truncate(time.Millisecond))
	defer srv.Close()
	defer cli.Close()

	// ── Throughput run.
	stop := make(chan struct{})
	var s2cRx, c2sRx atomic.Uint64 // delivered bytes per direction
	var wg sync.WaitGroup

	if *dir == "both" || *dir == "s2c" {
		startDirection(&wg, stop, srv, cli, &s2cRx, *offeredMbps, *payload)
	}
	if *dir == "both" || *dir == "c2s" {
		startDirection(&wg, stop, cli, srv, &c2sRx, *offeredMbps, *payload)
	}

	fmt.Printf("→ load: dir=%s offered=%.1f Mbps/dir payload=%dB dur=%s\n", *dir, *offeredMbps, *payload, *dur)

	// Sample delivered goodput every 250ms.
	const sample = 250 * time.Millisecond
	var ticks []tick
	ticker := time.NewTicker(sample)
	defer ticker.Stop()
	var prevS2C, prevC2S uint64
	deadline := time.After(*dur)
	stopped := false
	for !stopped {
		select {
		case <-ctx.Done():
			stopped = true
		case <-deadline:
			stopped = true
		case <-ticker.C:
			s2c, c2s := s2cRx.Load(), c2sRx.Load()
			mbps := func(d uint64) float64 { return float64(d) * 8 / sample.Seconds() / 1e6 }
			tk := tick{mbps(s2c - prevS2C), mbps(c2s - prevC2S)}
			prevS2C, prevC2S = s2c, c2s
			ticks = append(ticks, tk)
			fmt.Printf("  [%5.1fs] s2c=%6.2f  c2s=%6.2f Mbps\n", float64(len(ticks))*sample.Seconds(), tk.s2c, tk.c2s)
		}
	}
	close(stop)
	wg.Wait()

	// ── Summary.
	fmt.Println("\n──────── RESULT ────────")
	fmt.Printf("handshake canary: PASS (%s)\n", pairMS.Truncate(time.Millisecond))
	if *dir == "both" || *dir == "s2c" {
		reportDir("s2c (server→client)", ticks, func(t tick) float64 { return t.s2c }, *offeredMbps)
	}
	if *dir == "both" || *dir == "c2s" {
		reportDir("c2s (client→server)", ticks, func(t tick) float64 { return t.c2s }, *offeredMbps)
	}

	// Loss / backpressure from the captured session logs.
	srvClose()
	cliClose()
	fmt.Println("\n──────── DIAGNOSTICS (from session logs) ────────")
	for _, name := range []string{"server", "client"} {
		scanDiagnostics(filepath.Join(*logdir, name+".log"), name)
	}
	fmt.Printf("\nFull per-session logs: %s/{server,client}.log\n", *logdir)
}

// startDirection paces a synthetic flow from `from` at offeredMbps and counts
// delivered bytes draining `to`.Frames().
func startDirection(wg *sync.WaitGroup, stop <-chan struct{}, from, to sfu.Session, rx *atomic.Uint64, offeredMbps float64, payload int) {
	buf := make([]byte, payload)
	for i := range buf {
		buf[i] = byte(i)
	}
	// Batch-paced to beat coarse timer granularity (esp. Windows ~15ms).
	const paceTick = 5 * time.Millisecond
	pps := offeredMbps * 1e6 / 8 / float64(payload)
	perTick := int(pps * paceTick.Seconds())
	if perTick < 1 {
		perTick = 1
	}

	wg.Add(2)
	go func() { // sender
		defer wg.Done()
		t := time.NewTicker(paceTick)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				for i := 0; i < perTick; i++ {
					if err := from.Send(buf); err != nil {
						return // session closed
					}
				}
			}
		}
	}()
	go func() { // receiver / counter
		defer wg.Done()
		frames := to.Frames()
		for {
			select {
			case <-stop:
				return
			case d, ok := <-frames:
				if !ok {
					return
				}
				rx.Add(uint64(len(d)))
			}
		}
	}()
}

func reportDir(name string, ticks []tick, get func(tick) float64, offered float64) {
	vals := make([]float64, 0, len(ticks))
	zero := 0
	for _, t := range ticks {
		v := get(t)
		vals = append(vals, v)
		if v < 0.05 {
			zero++
		}
	}
	if len(vals) == 0 {
		fmt.Printf("%s: no samples\n", name)
		return
	}
	sort.Float64s(vals)
	p := func(q float64) float64 { return vals[int(q*float64(len(vals)-1)+0.5)] }
	med, p5, p95 := p(0.5), p(0.05), p(0.95)
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	fmt.Printf("%s: offered=%.1f  mean=%.2f  median=%.2f  p5=%.2f  p95=%.2f Mbps  | 0-Mbps windows=%d/%d  delivered/offered=%.0f%%\n",
		name, offered, mean, med, p5, p95, zero, len(vals), 100*mean/offered)
}

// scanDiagnostics greps a session log for the throughput probes.
func scanDiagnostics(path, name string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("%s: (no log: %v)\n", name, err)
		return
	}
	defer f.Close()
	var caps string
	var twccLines, twccLost, twccDelivered, backpressure int
	var lastTWCC string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "SFU answer caps"):
			if i := strings.Index(line, "SFU answer caps"); i >= 0 {
				caps = line[i:]
			}
		case strings.Contains(line, " TWCC "):
			twccLines++
			lastTWCC = line
			twccLost += fieldInt(line, "lost=")
			twccDelivered += fieldInt(line, "delivered=")
		case strings.Contains(line, "backpressure drop"):
			backpressure++
		}
	}
	fmt.Printf("[%s]\n", name)
	if caps != "" {
		fmt.Printf("  %s\n", caps)
	}
	if twccLines > 0 {
		lossPct := 0.0
		if tot := twccLost + twccDelivered; tot > 0 {
			lossPct = 100 * float64(twccLost) / float64(tot)
		}
		fmt.Printf("  TWCC: %d feedback pkts, delivered=%d lost=%d (%.2f%% loss)\n", twccLines, twccDelivered, twccLost, lossPct)
		fmt.Printf("        last: %s\n", trimPrefixTo(lastTWCC, "TWCC"))
	} else {
		fmt.Printf("  TWCC: none seen (SFU sent no transport-cc, or no post-handshake media)\n")
	}
	fmt.Printf("  backpressure drops logged: %d\n", backpressure)
}

func fieldInt(line, key string) int {
	i := strings.Index(line, key)
	if i < 0 {
		return 0
	}
	rest := line[i+len(key):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	n := 0
	for _, c := range rest[:j] {
		n = n*10 + int(c-'0')
	}
	return n
}

func trimPrefixTo(line, marker string) string {
	if i := strings.Index(line, marker); i >= 0 {
		return line[i:]
	}
	return line
}

// fileLogger returns a *log.Logger writing to <dir>/<name>.log (buffered) and
// a close func that flushes. Key lines are NOT teed to stdout to keep the
// console readable — the bench prints its own progress.
func fileLogger(dir, name string) (*log.Logger, func()) {
	f, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		log.Fatalf("create %s log: %v", name, err)
	}
	bw := bufio.NewWriter(f)
	lg := log.New(bw, "["+name+"] ", log.LstdFlags|log.Lmicroseconds)
	var once sync.Once
	return lg, func() {
		once.Do(func() {
			bw.Flush()
			f.Close()
		})
	}
}
