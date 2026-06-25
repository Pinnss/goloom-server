package session

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// startRTCPLoop reads RTCP from every RTPSender on the supplied PC. SFU
// feedback like PLI / FIR / REMB lands here for our publisher track. Returns
// immediately; per-sender goroutines run until ctx is done.
//
// onPLI is called (in the read goroutine) whenever a PLI or FIR arrives on
// the video sender — caller should respond by pushing a fresh keyframe down
// the same track ASAP so the SFU stops dropping our frames.
func StartRTCPLoop(ctx context.Context, lg *log.Logger, tag string, pc *webrtc.PeerConnection, onPLI func()) {
	for _, sender := range pc.GetSenders() {
		s := sender
		track := s.Track()
		label := tag
		isVideo := false
		if track != nil {
			label = fmt.Sprintf("%s[%s]", tag, track.Kind())
			isVideo = track.Kind() == webrtc.RTPCodecTypeVideo
		}
		go runRTCPSenderLoop(ctx, lg, label, s, isVideo, onPLI)
	}
}

func runRTCPSenderLoop(ctx context.Context, lg *log.Logger, label string, s *webrtc.RTPSender, isVideo bool, onPLI func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		pkts, _, err := s.ReadRTCP()
		if err != nil {
			lg.Printf("%s read end: %v", label, err)
			return
		}
		logRTCPPackets(lg, label, pkts)
		if isVideo && onPLI != nil {
			for _, pkt := range pkts {
				switch pkt.(type) {
				case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
					onPLI()
				}
			}
		}
	}
}

// startRTPRecvRTCPLoop reads RTCP for one *webrtc.RTPReceiver (i.e., for one
// remote track on the subscriber PC). Pion exposes SR / RR / SDES from the
// SFU here.
func startRTPRecvRTCPLoop(ctx context.Context, lg *log.Logger, label string, r *webrtc.RTPReceiver) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			pkts, _, err := r.ReadRTCP()
			if err != nil {
				lg.Printf("%s read end: %v", label, err)
				return
			}
			logRTCPPackets(lg, label, pkts)
		}
	}()
}

// logRTCPPackets emits one log line per packet, focusing on the types we
// actually care about for diagnosing SFU behaviour.
func logRTCPPackets(lg *log.Logger, label string, pkts []rtcp.Packet) {
	for _, pkt := range pkts {
		switch p := pkt.(type) {
		case *rtcp.PictureLossIndication:
			lg.Printf("%s PLI ssrc_media=%d sender=%d", label, p.MediaSSRC, p.SenderSSRC)
		case *rtcp.FullIntraRequest:
			fmts := make([]string, 0, len(p.FIR))
			for _, e := range p.FIR {
				fmts = append(fmts, fmt.Sprintf("ssrc=%d seq=%d", e.SSRC, e.SequenceNumber))
			}
			lg.Printf("%s FIR %s", label, strings.Join(fmts, ", "))
		case *rtcp.ReceiverEstimatedMaximumBitrate:
			lg.Printf("%s REMB %.2f Mbps over %d ssrcs", label, p.Bitrate/1e6, len(p.SSRCs))
		case *rtcp.TransportLayerNack:
			lg.Printf("%s NACK media=%d sender=%d nacks=%d", label, p.MediaSSRC, p.SenderSSRC, len(p.Nacks))
		case *rtcp.SenderReport:
			lg.Printf("%s SR ssrc=%d packets=%d octets=%d", label, p.SSRC, p.PacketCount, p.OctetCount)
		case *rtcp.ReceiverReport:
			for _, rep := range p.Reports {
				lg.Printf("%s RR ssrc=%d lost_total=%d frac_lost=%d jitter=%d",
					label, rep.SSRC, rep.TotalLost, rep.FractionLost, rep.Jitter)
			}
		case *rtcp.TransportLayerCC:
			// TWCC feedback from the SFU — the missing closed-loop signal a
			// congestion controller would consume. delivered = packets with a
			// recv-delta; lost ≈ status_count − delivered. Diagnostic only
			// (2026-06-25): confirms the SFU echoes transport-cc and quantifies
			// real loss before any rate-control work (see throughput memo).
			delivered := len(p.RecvDeltas)
			lost := int(p.PacketStatusCount) - delivered
			lg.Printf("%s TWCC base_seq=%d status_count=%d delivered=%d lost=%d fb_pkt=%d",
				label, p.BaseSequenceNumber, p.PacketStatusCount, delivered, lost, p.FbPktCount)
		case *rtcp.SourceDescription:
			// noisy and uninteresting; ignore
		default:
			lg.Printf("%s %T", label, pkt)
		}
	}
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
