package videocode

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	// ~3 Mbit/s per video tunnel at 240×180: Annex B I_PCM frame ≈ 69.5 KiB → FPS ≈ 3e6/(8*69508) ≈ 5.4.
	EncodeFPS      = 10
	FrameInterval  = time.Second / EncodeFPS
	minH264AUBytes = 400
	senderQueueCap = 2048
	// recvCh holds decoded tunnel payloads; must be large enough that tryDecodeFrame rarely blocks the RTP loop.
	receiverDataChCap = 2048
)

// Sender encodes data into H.264 video frames and writes them to a WebRTC track.
type Sender struct {
	track  *webrtc.TrackLocalStaticSample
	sendCh chan []byte
	seqNum uint32
	tag    string

	framesSent     uint64
	dataFramesSent uint64
	bytesSent      uint64
	encodeFailures uint64
	// Payloads accepted into sendCh (each ≈ one video frame slot).
	sendEnqueued uint64
	// Send() entered when sendCh was already full (about to block → TUN backpressure).
	sendBlockedEntries uint64
}

func NewSender(track *webrtc.TrackLocalStaticSample) *Sender {
	return &Sender{
		track:  track,
		sendCh: make(chan []byte, senderQueueCap),
	}
}

func (s *Sender) SetTag(tag string) { s.tag = tag }

// TunnelPayloadBytes is cumulative raw payload bytes sent through the video tunnel (before H.264 framing).
func (s *Sender) TunnelPayloadBytes() uint64 {
	if s == nil {
		return 0
	}
	return atomic.LoadUint64(&s.bytesSent)
}

// DecodePipelineFormed is access units that entered the H.264 path: decode attempts plus AU discarded before decode.
func (r *Receiver) DecodePipelineFormed() uint64 {
	if r == nil {
		return 0
	}
	return atomic.LoadUint64(&r.auDiscardedNonMarkerFlush) +
		atomic.LoadUint64(&r.auDiscardedTooShort) +
		atomic.LoadUint64(&r.decodeAttempts)
}

// DecodePipelineLost is AU dropped before decode plus decode failures (any cause after RTP delivery).
func (r *Receiver) DecodePipelineLost() uint64 {
	if r == nil {
		return 0
	}
	return atomic.LoadUint64(&r.auDiscardedNonMarkerFlush) +
		atomic.LoadUint64(&r.auDiscardedTooShort) +
		atomic.LoadUint64(&r.frameDecodeFail)
}

// Send enqueues one frame payload; blocks until there is space or ctx is cancelled.
func (s *Sender) Send(ctx context.Context, data []byte) error {
	if len(s.sendCh) >= senderQueueCap {
		atomic.AddUint64(&s.sendBlockedEntries, 1)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.sendCh <- data:
		atomic.AddUint64(&s.sendEnqueued, 1)
		return nil
	}
}

func (s *Sender) SendCh() chan<- []byte {
	return s.sendCh
}

func (s *Sender) encodeWrite(payload []byte) error {
	seq := atomic.AddUint32(&s.seqNum, 1)
	frame, err := EncodeFrame(seq, payload)
	if err != nil {
		atomic.AddUint64(&s.encodeFailures, 1)
		return err
	}
	annexB := rgbaToAnnexB(frame)
	if err := s.track.WriteSample(media.Sample{
		Data:     annexB,
		Duration: FrameInterval,
	}); err != nil {
		atomic.AddUint64(&s.encodeFailures, 1)
		return err
	}
	atomic.AddUint64(&s.framesSent, 1)
	if len(payload) > 0 {
		atomic.AddUint64(&s.dataFramesSent, 1)
		atomic.AddUint64(&s.bytesSent, uint64(len(payload)))
	}
	return nil
}

func (s *Sender) flush(buffer *[][]byte, currentSize *int) {
	if len(*buffer) == 0 {
		if err := s.encodeWrite(nil); err != nil {
			slog.Warn("videocode encode/write failed", "err", err)
		}
		*currentSize = 0
		return
	}
	bundle := PackBundle(*buffer, MaxPayloadPerFrame)
	if err := s.encodeWrite(bundle); err != nil {
		slog.Warn("videocode encode/write failed", "err", err)
	}
	*buffer = nil
	*currentSize = 0
}

// ingestFrag appends one tunnel fragment and flushes when the bundle is full enough.
func (s *Sender) ingestFrag(pkt []byte, packetBuffer *[][]byte, currentSize *int) {
	if *currentSize+len(pkt)+2 > MaxPayloadPerFrame {
		s.flush(packetBuffer, currentSize)
	}
	*packetBuffer = append(*packetBuffer, pkt)
	*currentSize += len(pkt) + 2
	if *currentSize > (MaxPayloadPerFrame * 7 / 10) {
		s.flush(packetBuffer, currentSize)
	}
}

func (s *Sender) Run(ctx context.Context) {
	ticker := time.NewTicker(FrameInterval)
	defer ticker.Stop()
	var packetBuffer [][]byte
	var currentSize int

	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.sendCh:
			s.ingestFrag(pkt, &packetBuffer, &currentSize)
			// When sendCh and ticker are both ready, select picks randomly and the ticker
			// starves throughput. Drain the whole queue before the next select.
		drain:
			for {
				select {
				case pkt2 := <-s.sendCh:
					s.ingestFrag(pkt2, &packetBuffer, &currentSize)
				default:
					break drain
				}
			}
		case <-ticker.C:
			s.flush(&packetBuffer, &currentSize)
		}
	}
}

// Receiver depacketizes RTP H.264 and decodes video frames back to data.
type Receiver struct {
	recvCh chan DataFrame
	tag    string

	rtpPackets    uint64
	framesDecoded uint64
	dataFrames    uint64
	bytesRecv     uint64
	decodeErrors  uint64
	// tryDecodeFrame invocations (access units handed to our H.264→grid decoder).
	decodeAttempts uint64
	// Failures inside tryDecodeFrame after counting an attempt (h264 nil or DecodeFrame err).
	frameDecodeFail uint64
	// Access units dropped before decode (not counted in error_rate_pct).
	// Timestamp changed before RTP marker: incomplete previous AU (never decode — partial I_PCM would show as black bands).
	auDiscardedNonMarkerFlush uint64
	auDiscardedTooShort       uint64 // tryDecodeFrame: raw shorter than minH264AUBytes

	errorCounts   map[string]int
	errorCountsMu sync.Mutex

	// Last good SPS NAL (with 1-byte header); SFU often drops SPS on some AUs while IDR remains.
	spsMu     sync.Mutex
	cachedSPS []byte

	disablePeriodicStats bool
}

type DataFrame struct {
	SeqNum  uint32
	Payload []byte
}

func NewReceiver() *Receiver {
	return &Receiver{
		recvCh:      make(chan DataFrame, receiverDataChCap),
		errorCounts: make(map[string]int),
	}
}

func (r *Receiver) SetTag(tag string) { r.tag = tag }

// SetDisablePeriodicStats suppresses the noisy 5s "videocode … stats" INFO lines (e.g. multiplex TUI).
func (r *Receiver) SetDisablePeriodicStats(v bool) { r.disablePeriodicStats = v }

func (r *Receiver) RecvCh() <-chan DataFrame {
	return r.recvCh
}

func (r *Receiver) HandleTrack(ctx context.Context, track *webrtc.TrackRemote, recv *webrtc.RTPReceiver) {
	slog.Info("videocode receiver started on track", "id", track.ID(), "kind", track.Kind().String())

	if r.disablePeriodicStats {
		// Stats goroutine skipped — see SetDisablePeriodicStats.
	} else {
		statsTicker := time.NewTicker(5 * time.Second)
		defer statsTicker.Stop()
		go func() {
			var lastRTP, lastDecoded, lastData, lastBytes, lastErrors, lastAttempts, lastFrameFail uint64
			var lastNonMarkerFlush, lastTooShort uint64
			for {
				select {
				case <-ctx.Done():
					return
				case <-statsTicker.C:
					rtp := atomic.LoadUint64(&r.rtpPackets)
					dec := atomic.LoadUint64(&r.framesDecoded)
					df := atomic.LoadUint64(&r.dataFrames)
					b := atomic.LoadUint64(&r.bytesRecv)
					e := atomic.LoadUint64(&r.decodeErrors)
					att := atomic.LoadUint64(&r.decodeAttempts)
					ff := atomic.LoadUint64(&r.frameDecodeFail)
					tag := r.tag
					if tag == "" {
						tag = "receiver"
					}

					r.errorCountsMu.Lock()
					errSummary := ""
					for k, v := range r.errorCounts {
						if errSummary != "" {
							errSummary += ", "
						}
						errSummary += fmt.Sprintf("%s:%d", k, v)
					}
					r.errorCounts = make(map[string]int)
					r.errorCountsMu.Unlock()

					attDelta := att - lastAttempts
					sf := atomic.LoadUint64(&r.auDiscardedNonMarkerFlush)
					tshort := atomic.LoadUint64(&r.auDiscardedTooShort)
					discDelta := (sf - lastNonMarkerFlush) + (tshort - lastTooShort)
					entered := attDelta + discDelta

					errPct := "0.00%"
					if attDelta > 0 {
						failDelta := ff - lastFrameFail
						errPct = fmt.Sprintf("%.2f%%", 100.0*float64(failDelta)/float64(attDelta))
					}
					auDropPct := "0.00%"
					if entered > 0 {
						auDropPct = fmt.Sprintf("%.2f%%", 100.0*float64(discDelta)/float64(entered))
					}

					rq := len(r.recvCh)
					slog.Info("videocode "+tag+" stats",
						"rtp_pkts", rtp-lastRTP,
						"decode_attempts", attDelta,
						"au_discarded", discDelta,
						"frames_decoded", dec-lastDecoded,
						"data_frames", df-lastData,
						"bytes_recv", b-lastBytes,
						"recv_queue_len", rq,
						"recv_queue_cap", cap(r.recvCh),
						"dbg_est_recv_serial_ms", int64(float64(rq)*float64(FrameInterval)/float64(time.Millisecond)),
						"decode_errors", e-lastErrors,
						"error_rate_pct", errPct,
						"au_drop_pct", auDropPct,
						"errors", errSummary,
					)
					lastRTP = rtp
					lastDecoded = dec
					lastData = df
					lastBytes = b
					lastErrors = e
					lastAttempts = att
					lastFrameFail = ff
					lastNonMarkerFlush = sf
					lastTooShort = tshort
				}
			}
		}()
	}

	// Manual RTP→Annex B assembly. pion's SampleBuilder often yields zero Pop() results on
	// SFU paths: it drops access units when IsPartitionHead fails, and defers emission until
	// the *next* RTP packet after the tail is visible — which breaks high-rate / transcoded streams.
	// RFC 6184: one access unit shares one timestamp; marker ends the unit (when set).
	// We only decode on marker. Decoding a timestamp-boundary flush was wrong for ~120 KiB I_PCM AUs:
	// SFU often bumps timestamp before the last FU arrives, so len(raw) ≫ 12 KiB but the IDR NAL is
	// still truncated → decoder reads zeros for missing macroblocks (black horizontal bands).
	var annexBuf bytes.Buffer
	dep := &codecs.H264Packet{}
	var lastTS uint32
	var haveTS bool

	flush := func(fromMarker bool) {
		if annexBuf.Len() == 0 {
			return
		}
		raw := append([]byte(nil), annexBuf.Bytes()...)
		annexBuf.Reset()
		dep = &codecs.H264Packet{}
		if !fromMarker {
			if annexBLikelyCompleteAU(len(raw)) {
				r.tryDecodeFrame(raw)
				return
			}
			atomic.AddUint64(&r.auDiscardedNonMarkerFlush, 1)
			return
		}
		r.tryDecodeFrame(raw)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, _, err := track.ReadRTP()
		if err != nil {
			slog.Debug("videocode track read error", "err", err)
			return
		}
		atomic.AddUint64(&r.rtpPackets, 1)

		if len(pkt.Payload) == 0 {
			continue
		}

		if haveTS && pkt.Timestamp != lastTS {
			flush(false)
		}
		haveTS = true
		lastTS = pkt.Timestamp

		annexB, err := dep.Unmarshal(pkt.Payload)
		if err != nil {
			r.recordError("depacketize:" + err.Error())
			continue
		}
		if len(annexB) > 0 {
			annexBuf.Write(annexB)
		}

		if pkt.Marker {
			flush(true)
		}
	}
}

func (r *Receiver) recordError(category string) {
	atomic.AddUint64(&r.decodeErrors, 1)
	r.errorCountsMu.Lock()
	r.errorCounts[category]++
	r.errorCountsMu.Unlock()
}

func (r *Receiver) tryDecodeFrame(raw []byte) {
	if len(raw) < minH264AUBytes {
		atomic.AddUint64(&r.auDiscardedTooShort, 1)
		return
	}
	atomic.AddUint64(&r.decodeAttempts, 1)
	img := r.annexBToRGBA(raw)
	if img == nil {
		atomic.AddUint64(&r.frameDecodeFail, 1)
		r.recordError("h264-to-rgba-nil")
		return
	}
	seqNum, bundle, err := DecodeFrame(img)
	if err != nil {
		atomic.AddUint64(&r.frameDecodeFail, 1)
		r.recordError("decode-frame:" + err.Error())
		return
	}
	atomic.AddUint64(&r.framesDecoded, 1)
	if len(bundle) == 0 {
		return
	}

	packets := UnpackBundle(bundle)
	for _, pkt := range packets {
		if len(pkt) == 0 {
			continue
		}
		atomic.AddUint64(&r.dataFrames, 1)
		atomic.AddUint64(&r.bytesRecv, uint64(len(pkt)))
		// Blocking send: non-blocking + drop destroyed throughput under burst; large recvCh keeps RTP moving.
		r.recvCh <- DataFrame{SeqNum: seqNum, Payload: pkt}
	}
}

// rgbaToAnnexB encodes an RGBA image as a complete Annex B H.264 bitstream.
// SPS + PPS + IDR slice, each prefixed with 0x00000001 start codes.
// This goes to pion's H264Payloader which splits and packetizes into RTP.
func rgbaToAnnexB(img *image.RGBA) []byte {
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()

	yuv := rgbaToYUV420(img)

	sps := buildSPS(w, h)
	pps := buildPPS()
	idr := buildIDRSlice(w, h, yuv)

	startCode := []byte{0x00, 0x00, 0x00, 0x01}

	var buf bytes.Buffer
	buf.Grow(len(sps) + len(pps) + len(idr) + 12)
	buf.Write(startCode)
	buf.Write(sps)
	buf.Write(startCode)
	buf.Write(pps)
	buf.Write(startCode)
	buf.Write(idr)

	return buf.Bytes()
}

func extractSPSAndIDR(nalus [][]byte) (spsData, idrData []byte) {
	for _, nalu := range nalus {
		if len(nalu) == 0 {
			continue
		}
		nalType := nalu[0] & 0x1F
		switch nalType {
		case 7:
			spsData = nalu
		case 5:
			idrData = nalu
		}
	}
	return spsData, idrData
}

// annexBToRGBA decodes one access unit; reuses cached SPS when the SFU omits it on some frames.
func (r *Receiver) annexBToRGBA(raw []byte) *image.RGBA {
	nalus := splitNALUs(raw)
	if len(nalus) == 0 {
		return nil
	}
	spsInline, idrData := extractSPSAndIDR(nalus)
	if idrData == nil {
		return nil
	}

	var spsData []byte
	spsFromCache := false
	if spsInline != nil {
		spsData = spsInline
	} else {
		r.spsMu.Lock()
		if r.cachedSPS != nil {
			spsData = append([]byte(nil), r.cachedSPS...)
			spsFromCache = true
		}
		r.spsMu.Unlock()
	}
	if spsData == nil {
		return nil
	}

	w, h := parseSPSDimensions(spsData)
	if w == 0 || h == 0 {
		return nil
	}
	mbW := (w + 15) / 16
	mbH := (h + 15) / 16
	if len(idrData) < idrPCMByteLowerBound(mbW, mbH) {
		if spsFromCache {
			r.spsMu.Lock()
			r.cachedSPS = nil
			r.spsMu.Unlock()
		}
		return nil
	}

	if spsInline != nil {
		cp := append([]byte(nil), spsInline...)
		r.spsMu.Lock()
		r.cachedSPS = cp
		r.spsMu.Unlock()
	}

	return extractYUV420ToRGBA(w, h, idrData)
}

// simpleH264ToRGBA decodes Annex B NALUs back to RGBA (tests; no SPS cache).
func simpleH264ToRGBA(raw []byte) *image.RGBA {
	nalus := splitNALUs(raw)
	if len(nalus) == 0 {
		return nil
	}
	spsData, idrData := extractSPSAndIDR(nalus)
	if spsData == nil || idrData == nil {
		return nil
	}
	w, h := parseSPSDimensions(spsData)
	if w == 0 || h == 0 {
		return nil
	}
	return extractYUV420ToRGBA(w, h, idrData)
}

func splitNALUs(data []byte) [][]byte {
	var nalus [][]byte
	start := 0
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0 && data[i+1] == 0 {
			if data[i+2] == 1 {
				if start < i {
					nalus = append(nalus, data[start:i])
				}
				start = i + 3
			} else if i+3 < len(data) && data[i+2] == 0 && data[i+3] == 1 {
				if start < i {
					nalus = append(nalus, data[start:i])
				}
				start = i + 4
				i++
			}
		}
	}
	if start < len(data) {
		nalus = append(nalus, data[start:])
	}
	return nalus
}

func buildSPS(width, height int) []byte {
	mbW := (width + 15) / 16
	mbH := (height + 15) / 16

	buf := []byte{
		0x67,
		0x42, // Baseline profile
		0x00, // constraint flags (VK-stable with our I_PCM path)
		0x1e, // level 3.0 (same as working 40 fps trial)
	}

	var bits bitWriter
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeBit(0)
	bits.writeUE(uint32(mbW - 1))
	bits.writeUE(uint32(mbH - 1))
	bits.writeBit(1)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeTrailingBits()

	return append(buf, bits.bytes()...)
}

func buildPPS() []byte {
	buf := []byte{0x68}
	var bits bitWriter
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeUE(0)
	bits.writeBit(0)
	bits.writeBits(0, 2)
	bits.writeSE(0)
	bits.writeSE(0)
	bits.writeSE(0)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeTrailingBits()
	return append(buf, bits.bytes()...)
}

func buildIDRSlice(width, height int, yuv *yuvImage) []byte {
	mbW := (width + 15) / 16
	mbH := (height + 15) / 16

	var bits bitWriter

	bits.writeUE(0)
	bits.writeUE(7)
	bits.writeUE(0)
	bits.writeBits(0, 4)
	bits.writeUE(0)
	bits.writeBits(0, 4)
	bits.writeBit(0)
	bits.writeBit(0)
	bits.writeSE(0)

	for mbY := 0; mbY < mbH; mbY++ {
		for mbX := 0; mbX < mbW; mbX++ {
			bits.writeUE(25) // I_PCM
			bits.alignByte()

			for dy := 0; dy < 16; dy++ {
				for dx := 0; dx < 16; dx++ {
					bits.writeByte(yuv.sampleY(mbX*16+dx, mbY*16+dy))
				}
			}
			for dy := 0; dy < 8; dy++ {
				for dx := 0; dx < 8; dx++ {
					bits.writeByte(yuv.sampleCb(mbX*8+dx, mbY*8+dy))
				}
			}
			for dy := 0; dy < 8; dy++ {
				for dx := 0; dx < 8; dx++ {
					bits.writeByte(yuv.sampleCr(mbX*8+dx, mbY*8+dy))
				}
			}
		}
	}

	bits.writeTrailingBits()

	nalu := []byte{0x65}
	return append(nalu, bits.bytes()...)
}

func parseSPSDimensions(sps []byte) (int, int) {
	if len(sps) < 5 {
		return 0, 0
	}

	r := newBitReader(sps[4:])
	r.readUE()
	r.readUE()
	r.readUE()
	r.readUE()
	r.readUE()
	r.readBit()
	mbW := r.readUE() + 1
	mbH := r.readUE() + 1

	return int(mbW) * 16, int(mbH) * 16
}

// idrPCMByteLowerBound is a conservative minimum IDR NAL length (including the 1-byte NAL header)
// for our Baseline I_PCM bitstream. If len(idr) is smaller than this for (mbW,mbH), the NAL is
// truncated or the SPS dimensions are wrong (e.g. stale cached SPS from a previous resolution).
func idrPCMByteLowerBound(mbW, mbH int) int {
	if mbW <= 0 || mbH <= 0 {
		return 1 << 30
	}
	// Macroblock PCM payload ~384 B/MB; trailing NAL overhead is resolution-dependent (tuned for FrameWidth×FrameHeight).
	return mbW*mbH*384 + 300
}

// annexBLikelyCompleteAU is true when the assembled Annex B buffer is big enough to be a full
// SPS+PPS+IDR access unit for the current FrameWidth×FrameHeight. Used only when the SFU ends
// an AU by RTP timestamp without setting the marker bit; mid-AU timestamp bumps produce a buffer
// that passes a small heuristic but is still far short of a full I_PCM AU and decodes as black bands.
func annexBLikelyCompleteAU(n int) bool {
	mbW := (FrameWidth + 15) / 16
	mbH := (FrameHeight + 15) / 16
	return n >= idrPCMByteLowerBound(mbW, mbH)+75
}

func extractYUV420ToRGBA(width, height int, idrData []byte) *image.RGBA {
	if len(idrData) < 1 {
		return nil
	}

	r := newBitReader(idrData[1:])
	r.readUE()
	r.readUE()
	r.readUE()
	r.readBits(4)
	r.readUE()
	r.readBits(4)
	r.readBit()
	r.readBit()
	r.readSE()

	mbW := (width + 15) / 16
	mbH := (height + 15) / 16

	yuv := newYUVImage(width, height)

	for mbY := 0; mbY < mbH; mbY++ {
		for mbX := 0; mbX < mbW; mbX++ {
			r.readUE()
			r.alignByte()

			for dy := 0; dy < 16; dy++ {
				for dx := 0; dx < 16; dx++ {
					px := mbX*16 + dx
					py := mbY*16 + dy
					val := r.readByte()
					if px < width && py < height {
						yuv.Y[py*width+px] = val
					}
				}
			}
			cW := width / 2
			for dy := 0; dy < 8; dy++ {
				for dx := 0; dx < 8; dx++ {
					px := mbX*8 + dx
					py := mbY*8 + dy
					val := r.readByte()
					if px < cW && py < height/2 {
						yuv.Cb[py*cW+px] = val
					}
				}
			}
			for dy := 0; dy < 8; dy++ {
				for dx := 0; dx < 8; dx++ {
					px := mbX*8 + dx
					py := mbY*8 + dy
					val := r.readByte()
					if px < cW && py < height/2 {
						yuv.Cr[py*cW+px] = val
					}
				}
			}
		}
	}

	return yuvToRGBA(yuv)
}

type yuvImage struct {
	Y, Cb, Cr     []byte
	Width, Height int
}

func newYUVImage(w, h int) *yuvImage {
	return &yuvImage{
		Y: make([]byte, w*h), Cb: make([]byte, w/2*h/2), Cr: make([]byte, w/2*h/2),
		Width: w, Height: h,
	}
}

func (y *yuvImage) sampleY(px, py int) byte {
	px = clampInt(px, 0, y.Width-1)
	py = clampInt(py, 0, y.Height-1)
	return y.Y[py*y.Width+px]
}
func (y *yuvImage) sampleCb(px, py int) byte {
	cW, cH := y.Width/2, y.Height/2
	px = clampInt(px, 0, cW-1)
	py = clampInt(py, 0, cH-1)
	return y.Cb[py*cW+px]
}
func (y *yuvImage) sampleCr(px, py int) byte {
	cW, cH := y.Width/2, y.Height/2
	px = clampInt(px, 0, cW-1)
	py = clampInt(py, 0, cH-1)
	return y.Cr[py*cW+px]
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func rgbaToYUV420(img *image.RGBA) *yuvImage {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	yuv := newYUVImage(w, h)

	for py := 0; py < h; py++ {
		for px := 0; px < w; px++ {
			off := (py-bounds.Min.Y)*img.Stride + (px-bounds.Min.X)*4
			r, g, b := float64(img.Pix[off]), float64(img.Pix[off+1]), float64(img.Pix[off+2])
			yuv.Y[py*w+px] = clampByte(0.299*r + 0.587*g + 0.114*b)
		}
	}

	cW := w / 2
	for cy := 0; cy < h/2; cy++ {
		for cx := 0; cx < cW; cx++ {
			off := (cy*2-bounds.Min.Y)*img.Stride + (cx*2-bounds.Min.X)*4
			r, g, b := float64(img.Pix[off]), float64(img.Pix[off+1]), float64(img.Pix[off+2])
			yuv.Cb[cy*cW+cx] = clampByte(128.0 - 0.168736*r - 0.331264*g + 0.5*b)
			yuv.Cr[cy*cW+cx] = clampByte(128.0 + 0.5*r - 0.418688*g - 0.081312*b)
		}
	}
	return yuv
}

func yuvToRGBA(yuv *yuvImage) *image.RGBA {
	w, h := yuv.Width, yuv.Height
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	cW := w / 2
	for py := 0; py < h; py++ {
		for px := 0; px < w; px++ {
			yy := float64(yuv.Y[py*w+px])
			cx := clampInt(px/2, 0, cW-1)
			cy := clampInt(py/2, 0, h/2-1)
			cb := float64(yuv.Cb[cy*cW+cx]) - 128.0
			cr := float64(yuv.Cr[cy*cW+cx]) - 128.0
			off := py*img.Stride + px*4
			img.Pix[off] = clampByte(yy + 1.402*cr)
			img.Pix[off+1] = clampByte(yy - 0.344136*cb - 0.714136*cr)
			img.Pix[off+2] = clampByte(yy + 1.772*cb)
			img.Pix[off+3] = 255
		}
	}
	return img
}

func clampByte(v float64) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(v)
}

type bitWriter struct {
	data    []byte
	current byte
	pos     uint8
}

func (w *bitWriter) writeBit(b uint8) {
	w.current |= (b & 1) << (7 - w.pos)
	w.pos++
	if w.pos == 8 {
		w.data = append(w.data, w.current)
		w.current = 0
		w.pos = 0
	}
}
func (w *bitWriter) writeBits(val uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		w.writeBit(uint8((val >> uint(i)) & 1))
	}
}
func (w *bitWriter) writeByte(b byte) {
	w.alignByte()
	w.data = append(w.data, b)
}
func (w *bitWriter) writeUE(val uint32) {
	val++
	zeros := 0
	tmp := val
	for tmp > 1 {
		tmp >>= 1
		zeros++
	}
	for i := 0; i < zeros; i++ {
		w.writeBit(0)
	}
	w.writeBits(val, zeros+1)
}
func (w *bitWriter) writeSE(val int32) {
	var m uint32
	if val > 0 {
		m = uint32(2*val - 1)
	} else if val < 0 {
		m = uint32(-2 * val)
	}
	w.writeUE(m)
}
func (w *bitWriter) alignByte() {
	if w.pos > 0 {
		w.data = append(w.data, w.current)
		w.current = 0
		w.pos = 0
	}
}
func (w *bitWriter) writeTrailingBits() {
	w.writeBit(1)
	for w.pos != 0 {
		w.writeBit(0)
	}
}
func (w *bitWriter) bytes() []byte {
	if w.pos > 0 {
		return append(w.data, w.current)
	}
	return w.data
}

type bitReader struct {
	data []byte
	pos  int
	bit  uint8
}

func newBitReader(data []byte) *bitReader { return &bitReader{data: data} }
func (r *bitReader) readBit() uint8 {
	if r.pos >= len(r.data) {
		return 0
	}
	val := (r.data[r.pos] >> (7 - r.bit)) & 1
	r.bit++
	if r.bit == 8 {
		r.bit = 0
		r.pos++
	}
	return val
}
func (r *bitReader) readBits(n int) uint32 {
	var val uint32
	for i := 0; i < n; i++ {
		val = (val << 1) | uint32(r.readBit())
	}
	return val
}
func (r *bitReader) readByte() byte {
	r.alignByte()
	if r.pos >= len(r.data) {
		return 0
	}
	val := r.data[r.pos]
	r.pos++
	return val
}
func (r *bitReader) readUE() uint32 {
	zeros := 0
	for r.readBit() == 0 {
		zeros++
		if zeros > 31 {
			return 0
		}
	}
	return (1 << uint(zeros)) - 1 + r.readBits(zeros)
}
func (r *bitReader) readSE() int32 {
	ue := r.readUE()
	if ue%2 == 0 {
		return -int32(ue / 2)
	}
	return int32((ue + 1) / 2)
}
func (r *bitReader) alignByte() {
	if r.bit > 0 {
		r.bit = 0
		r.pos++
	}
}

func BlankFrame() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, FrameWidth, FrameHeight))
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return img
}

func BlankH264() [][]byte {
	img := image.NewRGBA(image.Rect(0, 0, FrameWidth, FrameHeight))
	for y := 0; y < FrameHeight; y++ {
		for x := 0; x < FrameWidth; x++ {
			img.SetRGBA(x, y, color.RGBA{A: 255})
		}
	}
	return [][]byte{rgbaToAnnexB(img)}
}
