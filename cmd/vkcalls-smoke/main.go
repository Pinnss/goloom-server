// vkcalls-smoke — end-to-end smoke test for the internal/sfu/vkcalls
// transport. Mirrors the goloom-poc PoC's `-echo` mode but exercises
// the production sfu.Transport / sfu.Session API instead of poking
// videocode internals directly.
//
// Two terminals, same call link:
//
//	-role=receiver: joins first, reads Frames, verifies CRC + pattern
//	-role=caller:   joins second, calls Send with CRC-keyed packets
//
// Each packet:
//
//	[0:4]   uint32 seq (LE)
//	[4:8]   uint32 payload-len (LE)
//	[8:12]  uint32 CRC32 of payload (IEEE)
//	[12:N]  payload (deterministic pattern keyed by seq)
//
// Receiver tallies received / gaps / corrupt; caller tallies sent.
// 0 corrupt + small gaps == production scaffold is healthy and we can
// confidently move on to CLI integration.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Pinnss/goloom-server/internal/sfu"
	// The vkcalls import does double duty:
	//  - it triggers init() which registers the transport in sfu's
	//    registry (so sfu.Get(KindVKCalls) finds it)
	//  - it gives us access to AutoProxyCaptchaSolver for the spec
	"github.com/Pinnss/goloom-server/internal/sfu/vkcalls"
)

const (
	echoHeaderLen   = 12
	echoPayloadSize = 4096
)

func main() {
	var (
		link        = flag.String("link", "", "VK call link (full URL or just the short id)")
		role        = flag.String("role", "receiver", "receiver | caller")
		name        = flag.String("name", "vkcalls-smoke", "participant display name")
		timeout     = flag.Duration("captcha-timeout", 2*time.Minute, "how long to wait for the captcha solver")
		profilePath = flag.String("profile-store", "", "path к JSON-пулу captured browser-FP. Если задан: первая попытка solve через AutoProxy + capture в пул, последующие — auto-replay. Пусто = legacy behaviour.")
		codec       = flag.String("codec", "h264", "video codec stack: h264 (videocode RS I_PCM) или vp8 (tunnel + wgrelay, экспериментально)")
	)
	flag.Parse()

	if *link == "" {
		fmt.Fprintln(os.Stderr, "usage: vkcalls-smoke -link <call-link> [-role caller|receiver] [-name NAME]")
		os.Exit(2)
	}

	lg := log.New(os.Stdout, "[vkcalls-smoke] ", log.LstdFlags|log.Lmicroseconds)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Resolve the transport from the registry. If the blank import
	// above didn't take, this errors out.
	t, err := sfu.Get(sfu.KindVKCalls)
	if err != nil {
		lg.Fatalf("sfu.Get: %v", err)
	}

	// Build the captcha-solver chain.
	// - profilePath не задан → legacy AutoProxy без replay'я
	// - profilePath задан → ProfileStore + AutoProxy с capture'ом +
	//   WithReplaySolver — первая попытка solve вручную, далее auto.
	var solver sfu.VKCaptchaSolver
	if *profilePath != "" {
		store, err := vkcalls.NewProfileStore(vkcalls.ProfileStoreOptions{Path: *profilePath})
		if err != nil {
			lg.Fatalf("profile store init: %v", err)
		}
		lg.Printf("profile pool: %s (loaded %d profiles)", *profilePath, len(store.Snapshot()))
		base := vkcalls.AutoProxyCaptchaSolver(*timeout, lg, store)
		solver = vkcalls.WithReplaySolver(store, base, lg)
	} else {
		solver = vkcalls.AutoProxyCaptchaSolver(*timeout, lg, nil)
	}

	spec := sfu.ConnectSpec{
		Kind:        sfu.KindVKCalls,
		DisplayName: *name,
		Logger:      lg,
		VKCalls: &sfu.VKCallsConnect{
			MeetingURL:    *link,
			Role:          *role,
			CaptchaSolver: solver,
			Codec:         *codec,
		},
	}

	lg.Printf("connecting role=%s …", *role)
	sess, err := t.Connect(ctx, spec)
	if err != nil {
		lg.Fatalf("Connect: %v", err)
	}
	defer sess.Close()
	lg.Printf("session ready ✓")

	// ICE hosts — log them so a future VPN-routing integration can
	// be sanity-checked against this list.
	if hp, ok := sess.(sfu.ICEHostsProvider); ok {
		lg.Printf("ICE hosts (route-exclusion list): %v", hp.ICEHosts())
	}

	// Drive the echo loop — caller pushes, receiver verifies.
	switch *role {
	case "caller":
		go runSenderLoop(ctx, lg, sess)
	case "receiver":
		go runReceiverLoop(ctx, lg, sess)
	default:
		lg.Fatalf("invalid -role=%q", *role)
	}

	// Wait for ctx cancel or session death.
	select {
	case <-ctx.Done():
		lg.Printf("ctx cancelled, closing session")
	case <-sess.Done():
		if err := sess.Err(); err != nil {
			lg.Printf("session ended: %v", err)
		} else {
			lg.Printf("session ended cleanly")
		}
	}
}

func runSenderLoop(ctx context.Context, lg *log.Logger, sess sfu.Session) {
	lg.Printf("sender: starting (payload=%dB per packet)", echoPayloadSize)

	buf := make([]byte, echoHeaderLen+echoPayloadSize)
	var seq uint32
	var sent uint64
	var pkts uint64
	last := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Done():
			return
		case <-tick.C:
			b := atomic.SwapUint64(&sent, 0)
			p := atomic.SwapUint64(&pkts, 0)
			dt := time.Since(last).Seconds()
			if dt < 0.001 {
				dt = 0.001
			}
			lg.Printf("sender: %.2f Mbps (pkts=%d bytes=%d %.2fs)",
				float64(b)*8/1e6/dt, p, b, dt)
			last = time.Now()
		default:
		}

		seq++
		fillEchoPattern(buf, seq, echoPayloadSize)
		if err := sess.Send(buf); err != nil {
			lg.Printf("sender: Send: %v", err)
			return
		}
		atomic.AddUint64(&sent, uint64(len(buf)))
		atomic.AddUint64(&pkts, 1)
	}
}

func runReceiverLoop(ctx context.Context, lg *log.Logger, sess sfu.Session) {
	lg.Printf("receiver: started")

	var rcvBytes uint64
	var rcvPkts uint64
	var seqGaps uint64
	var corrupt uint64
	var lastSeq uint32
	last := time.Now()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				b := atomic.SwapUint64(&rcvBytes, 0)
				p := atomic.SwapUint64(&rcvPkts, 0)
				g := atomic.LoadUint64(&seqGaps)
				c := atomic.LoadUint64(&corrupt)
				dt := time.Since(last).Seconds()
				if dt < 0.001 {
					dt = 0.001
				}
				lg.Printf("receiver: %.2f Mbps (pkts=%d bytes=%d %.2fs gaps=%d corrupt=%d)",
					float64(b)*8/1e6/dt, p, b, dt, g, c)
				last = time.Now()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Done():
			return
		case payload, ok := <-sess.Frames():
			if !ok {
				return
			}
			atomic.AddUint64(&rcvBytes, uint64(len(payload)))
			atomic.AddUint64(&rcvPkts, 1)

			if len(payload) < echoHeaderLen {
				atomic.AddUint64(&corrupt, 1)
				continue
			}
			seq := binary.LittleEndian.Uint32(payload[0:4])
			plen := binary.LittleEndian.Uint32(payload[4:8])
			expectedCRC := binary.LittleEndian.Uint32(payload[8:12])
			body := payload[echoHeaderLen:]

			if uint32(len(body)) != plen {
				atomic.AddUint64(&corrupt, 1)
				lg.Printf("receiver: seq=%d length-mismatch want=%d got=%d", seq, plen, len(body))
				continue
			}
			if crc32.ChecksumIEEE(body) != expectedCRC {
				atomic.AddUint64(&corrupt, 1)
				lg.Printf("receiver: seq=%d CRC mismatch", seq)
				continue
			}
			if !verifyEchoPattern(body, seq) {
				atomic.AddUint64(&corrupt, 1)
				lg.Printf("receiver: seq=%d pattern mismatch (CRC clean — should not happen)", seq)
				continue
			}
			if lastSeq != 0 && seq > lastSeq+1 {
				atomic.AddUint64(&seqGaps, uint64(seq-lastSeq-1))
			}
			lastSeq = seq
		}
	}
}

// ─── echo packet shape (mirrors goloom-poc/pocs/vk-poc1/echo.go) ─────

func fillEchoPattern(buf []byte, seq uint32, payloadLen int) {
	body := buf[echoHeaderLen : echoHeaderLen+payloadLen]
	mix := byte(seq >> 8)
	mul := uint32(0x9e3779b1)
	base := seq * mul
	for i := 0; i < payloadLen; i++ {
		body[i] = byte((base+uint32(i))&0xFF) ^ mix
	}
	crc := crc32.ChecksumIEEE(body)
	binary.LittleEndian.PutUint32(buf[0:4], seq)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(payloadLen))
	binary.LittleEndian.PutUint32(buf[8:12], crc)
}

func verifyEchoPattern(body []byte, seq uint32) bool {
	mix := byte(seq >> 8)
	mul := uint32(0x9e3779b1)
	base := seq * mul
	for i := 0; i < len(body); i++ {
		want := byte((base+uint32(i))&0xFF) ^ mix
		if body[i] != want {
			return false
		}
	}
	return true
}
