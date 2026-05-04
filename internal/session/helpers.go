package session

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	mediastubs "github.com/Sv9toslavPinigin/goloom-server/internal/media"
	"github.com/Sv9toslavPinigin/goloom-server/internal/tunnel"
)

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
			if !sentAck {
				send(tunnel.FlagHandshake)
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
			Data:     mediastubs.VP8BlackKeyframe,
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
				Data:     mediastubs.VP8BlackKeyframe,
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
				Data:     mediastubs.VP8BlackKeyframe,
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
			Data:     mediastubs.VP8BlackKeyframe,
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
