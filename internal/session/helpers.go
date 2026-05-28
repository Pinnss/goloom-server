package session

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	mediastubs "github.com/Pinnss/goloom-server/internal/media"
	"github.com/Pinnss/goloom-server/internal/tunnel"
)

// InjectBandwidthAttribute scans an SDP string and inserts a bandwidth
// declaration line ("b=AS:<kbps>") immediately after every matching
// m-section header. Existing b=AS lines for that m-section are stripped.
//
// SFUs that respect SDP-declared bandwidth (most do, per RFC 4566 §5.8)
// allocate forwarding/encoding budgets up to this cap. Default behaviour
// without b=AS is the SFU's own per-publisher default (which Yandex
// Telemost appears to clamp to ~3 Mbps).
//
// kind is the m-line kind ("video", "audio", "application") — only that
// kind's m-sections are touched.
func InjectBandwidthAttribute(sdp string, kind string, kbps int) string {
	lines := strings.Split(sdp, "\r\n")
	out := make([]string, 0, len(lines)+4)
	mPrefix := "m=" + kind + " "
	inTarget := false
	for _, line := range lines {
		if strings.HasPrefix(line, "m=") {
			// Entering a new m-section.
			if strings.HasPrefix(line, mPrefix) {
				inTarget = true
				out = append(out, line)
				out = append(out, fmt.Sprintf("b=AS:%d", kbps))
				continue
			}
			inTarget = false
		}
		// Drop pre-existing b=AS inside the target m-section so we don't
		// double up. Other b= attributes (TIAS, CT) we leave alone.
		if inTarget && strings.HasPrefix(line, "b=AS:") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\r\n")
}

const HandshakeInterval = 500 * time.Millisecond
const HandshakeTimeout = 120 * time.Second

func Handshake(ctx context.Context, lg *log.Logger, sess *Session, sender *tunnel.Sender, in <-chan tunnel.ReceivedFrame, round byte) (string, error) {
	deadline := time.Now().Add(HandshakeTimeout)
	deadCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	myID := sess.Conn.PeerID
	myIDBytes := append([]byte{round}, []byte(myID)...)

	send := func(flags tunnel.Flags) {
		if _, err := sender.Send(flags|tunnel.FlagTest, myIDBytes); err != nil {
			lg.Printf("HSK send err: %v", err)
		}
	}

	tk := time.NewTicker(HandshakeInterval)
	defer tk.Stop()
	send(tunnel.FlagHandshake)

	var peerID string
	receivedHello := false
	receivedAck := false
	sentAck := false

	for {
		if peerID != "" && receivedAck && sentAck {
			return peerID, nil
		}
		select {
		case <-deadCtx.Done():
			return "", fmt.Errorf("handshake timeout round=%d (peerID=%q gotHello=%v gotAck=%v sentAck=%v)",
				round, peerID, receivedHello, receivedAck, sentAck)
		case <-tk.C:
			// Keep advertising until the handshake is FULLY established
			// (our peer has ACKed us → receivedAck). The old code stopped
			// re-sending HELLO as soon as we'd ACKed someone (sentAck),
			// which deadlocks when the room has stale/zombie participants
			// (common after rapid reconnects or in pool mode): we ACK a
			// dead peer's leftover HELLO, go silent, and the REAL peer that
			// joins later never sees our HELLO so never ACKs us → timeout
			// with gotAck=false. Re-broadcasting HELLO (and re-ACKing once
			// we've seen any HELLO) makes a late-joining real peer able to
			// complete its side. Both HELLO and ACK are broadcast to every
			// participant via the SFU, so one send reaches everyone.
			if !receivedAck {
				send(tunnel.FlagHandshake)
				if receivedHello {
					send(tunnel.FlagHandshakeAck)
				}
			}
		case f := <-in:
			if !f.Flags.Has(tunnel.FlagTest) {
				continue
			}
			if len(f.Payload) < 1 || f.Payload[0] != round {
				continue
			}
			id := string(f.Payload[1:])
			if f.Flags.Has(tunnel.FlagHandshake) {
				if peerID == "" {
					peerID = id
					lg.Printf("HSK[%d] ← HELLO from %s (msgID=%d)", round, id, f.MsgID)
				}
				receivedHello = true
				if !sentAck {
					send(tunnel.FlagHandshakeAck)
					sentAck = true
					lg.Printf("HSK[%d] → HELLO_ACK", round)
				}
			} else if f.Flags.Has(tunnel.FlagHandshakeAck) {
				if peerID == "" {
					peerID = id
					lg.Printf("HSK[%d] ← HELLO_ACK from %s before HELLO (msgID=%d)", round, id, f.MsgID)
				} else {
					lg.Printf("HSK[%d] ← HELLO_ACK from %s (msgID=%d)", round, id, f.MsgID)
				}
				receivedAck = true
			}
		}
	}
}

func InitiatorLabel(b bool) string {
	if b {
		return "INITIATOR"
	}
	return "ECHOER"
}

func SendInitialKeyframes(lg *log.Logger, track *webrtc.TrackLocalStaticSample, n int) error {
	for i := 0; i < n; i++ {
		if err := track.WriteSample(media.Sample{
			Data:     mediastubs.VP9BlackKeyframe,
			Duration: 33 * time.Millisecond,
		}); err != nil {
			return err
		}
		time.Sleep(33 * time.Millisecond)
	}
	return nil
}

func RunOpusSilenceLoop(ctx context.Context, lg *log.Logger, track *webrtc.TrackLocalStaticSample) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := track.WriteSample(media.Sample{
				Data:     mediastubs.OpusSilence,
				Duration: 20 * time.Millisecond,
			}); err != nil {
				lg.Printf("opus silence write err: %v (loop exit)", err)
				return
			}
		}
	}
}

func RunKeyframeRefreshFast(ctx context.Context, lg *log.Logger, track *webrtc.TrackLocalStaticSample, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := track.WriteSample(media.Sample{
				Data:     mediastubs.VP9BlackKeyframe,
				Duration: 33 * time.Millisecond,
			}); err != nil {
				lg.Printf("keyframe refresh fast err: %v (loop exit)", err)
				return
			}
		}
	}
}

func RunKeyframeRefresh(ctx context.Context, lg *log.Logger, track *webrtc.TrackLocalStaticSample) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := track.WriteSample(media.Sample{
				Data:     mediastubs.VP9BlackKeyframe,
				Duration: 33 * time.Millisecond,
			}); err != nil {
				lg.Printf("keyframe refresh err: %v (loop exit)", err)
				return
			}
		}
	}
}

func MakeKeyframePusher(track *webrtc.TrackLocalStaticSample, lg *log.Logger, cooldown time.Duration) func() {
	var lastSent atomic.Int64
	var sent atomic.Uint64
	return func() {
		now := time.Now().UnixNano()
		prev := lastSent.Load()
		if now-prev < int64(cooldown) {
			return
		}
		if !lastSent.CompareAndSwap(prev, now) {
			return
		}
		if err := track.WriteSample(media.Sample{
			Data:     mediastubs.VP9BlackKeyframe,
			Duration: 33 * time.Millisecond,
		}); err != nil {
			lg.Printf("keyframe-on-PLI err: %v", err)
			return
		}
		n := sent.Add(1)
		if n%10 == 1 {
			lg.Printf("KEYFRAME pushed in response to PLI/FIR (cumulative=%d)", n)
		}
	}
}
