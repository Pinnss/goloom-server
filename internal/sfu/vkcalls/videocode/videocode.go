// Videocode: row-major grid, H.264 I_PCM over WebRTC. BlockSize 2 → 1×1 sub-pixels, 4 symbols/byte.
// Header uses spatial XOR; RS payload uses temporal XOR (seqNum).
package videocode

import (
	"encoding/binary"
	"fmt"
	"image"

	"github.com/klauspost/reedsolomon"
)

const (
	FrameWidth  = 240
	FrameHeight = 180
	BlockSize   = 2

	GridCols       = 120
	GridRows       = 90
	BlocksPerFrame = 10800

	TotalShards = 250
	ShardSize   = 42

	HeaderSize       = 10
	HeaderReps       = 10
	TotalHeaderBytes = 100

	// Data: 210 shards, Parity: 40 shards (16% ECC)
	MaxDataShards      = 210
	MaxPayloadPerFrame = 8820 // 210 * 42
)

var greyLevels = [4]uint8{0, 85, 170, 255}

func getSpatialMask(idx int) byte {
	h := uint32(idx) * 0x85ebca6b
	return byte(h ^ (h >> 13) ^ (h >> 16))
}

func getTemporalMask(idx int, seq uint32) byte {
	h := uint32(idx) ^ (seq * 0x1e35a7bd)
	h ^= h >> 13
	h *= 0x85ebca6b
	return byte(h ^ (h >> 16))
}

func EncodeFrame(seqNum uint32, bundle []byte) (*image.RGBA, error) {
	if len(bundle) > MaxPayloadPerFrame {
		return nil, fmt.Errorf("too large")
	}
	dataShards := (len(bundle) + ShardSize - 1) / ShardSize
	if dataShards < 1 {
		dataShards = 1
	}
	if dataShards > MaxDataShards {
		dataShards = MaxDataShards
	}
	parityShards := TotalShards - dataShards
	if parityShards < 1 {
		return nil, fmt.Errorf("invalid shard split: data=%d parity=%d", dataShards, parityShards)
	}

	hdr := make([]byte, HeaderSize)
	hdr[0], hdr[1] = 0x13, 0x37
	binary.BigEndian.PutUint32(hdr[2:6], seqNum)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(bundle)))
	hdr[8] = byte(dataShards)
	var sum byte
	for i := 0; i < 9; i++ {
		sum += hdr[i]
	}
	hdr[9] = sum

	raw := make([]byte, BlocksPerFrame)
	for i := 0; i < HeaderReps; i++ {
		copy(raw[i*HeaderSize:], hdr)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("RS init: %w", err)
	}
	shards := make([][]byte, TotalShards)
	for i := 0; i < TotalShards; i++ {
		shards[i] = make([]byte, ShardSize)
		if i < dataShards {
			start, end := i*ShardSize, (i+1)*ShardSize
			if start < len(bundle) {
				if end > len(bundle) {
					end = len(bundle)
				}
				copy(shards[i], bundle[start:end])
			}
		}
	}
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("RS encode: %w", err)
	}
	for i, s := range shards {
		copy(raw[TotalHeaderBytes+i*ShardSize:], s)
	}

	img := image.NewRGBA(image.Rect(0, 0, FrameWidth, FrameHeight))
	for i := 0; i < BlocksPerFrame; i++ {
		var val byte
		if i < TotalHeaderBytes {
			val = raw[i] ^ getSpatialMask(i)
		} else {
			val = raw[i] ^ getTemporalMask(i, seqNum)
		}
		drawBlock(img, i, val)
	}
	return img, nil
}

func DecodeFrame(img *image.RGBA) (uint32, []byte, error) {
	bounds := img.Bounds()
	if bounds.Dx() < FrameWidth || bounds.Dy() < FrameHeight {
		return 0, nil, fmt.Errorf("image too small: %dx%d", bounds.Dx(), bounds.Dy())
	}

	rawPixels := make([]byte, BlocksPerFrame)
	for i := 0; i < BlocksPerFrame; i++ {
		rawPixels[i] = readBlock(img, i)
	}
	var bestHdr []byte
	found := false
	for i := 0; i < TotalHeaderBytes; i += HeaderSize {
		if (rawPixels[i] ^ getSpatialMask(i)) == 0x13 {
			candidate := make([]byte, HeaderSize)
			var sum byte
			for j := 0; j < 9; j++ {
				candidate[j] = rawPixels[i+j] ^ getSpatialMask(i+j)
				sum += candidate[j]
			}
			if sum == (rawPixels[i+9] ^ getSpatialMask(i+9)) {
				bestHdr, found = candidate, true
				break
			}
		}
	}
	if !found {
		return 0, nil, fmt.Errorf("no hdr")
	}
	seqNum := binary.BigEndian.Uint32(bestHdr[2:6])
	pLen, dShards := int(binary.BigEndian.Uint16(bestHdr[6:8])), int(bestHdr[8])
	if dShards > TotalShards || dShards < 1 || pLen > MaxPayloadPerFrame {
		return 0, nil, fmt.Errorf("corrupt header data")
	}

	shards := make([][]byte, TotalShards)
	for i := 0; i < TotalShards; i++ {
		shards[i] = make([]byte, ShardSize)
		for j := 0; j < ShardSize; j++ {
			idx := TotalHeaderBytes + i*ShardSize + j
			shards[i][j] = rawPixels[idx] ^ getTemporalMask(idx, seqNum)
		}
	}
	enc, err := reedsolomon.New(dShards, TotalShards-dShards)
	if err != nil {
		return 0, nil, fmt.Errorf("RS init: %w", err)
	}
	ok, err := enc.Verify(shards)
	if err != nil {
		return 0, nil, fmt.Errorf("RS verify: %w", err)
	}
	if !ok {
		if err := enc.Reconstruct(shards); err != nil {
			return 0, nil, fmt.Errorf("RS reconstruct: %w", err)
		}
	}
	res := make([]byte, pLen)
	for i := 0; i < dShards; i++ {
		start, l := i*ShardSize, ShardSize
		if start+l > pLen {
			l = pLen - start
		}
		if start < pLen {
			copy(res[start:], shards[i][:l])
		}
	}
	return seqNum, res, nil
}

func drawBlock(img *image.RGBA, idx int, val byte) {
	x0, y0 := (idx%GridCols)*2, (idx/GridCols)*2
	bits := [4]uint8{(val >> 6) & 3, (val >> 4) & 3, (val >> 2) & 3, val & 3}
	for sb := 0; sb < 4; sb++ {
		g := greyLevels[bits[sb]]
		off := (y0+(sb/2))*img.Stride + (x0+(sb%2))*4
		img.Pix[off], img.Pix[off+1], img.Pix[off+2], img.Pix[off+3] = g, g, g, 255
	}
}

func readBlock(img *image.RGBA, idx int) byte {
	x0, y0 := (idx%GridCols)*2, (idx/GridCols)*2
	var bits [4]uint8
	for sb := 0; sb < 4; sb++ {
		off := (y0+(sb/2))*img.Stride + (x0+(sb%2))*4
		avg := (int(img.Pix[off]) + int(img.Pix[off+1]) + int(img.Pix[off+2])) / 3
		if avg < 42 {
			bits[sb] = 0
		} else if avg < 127 {
			bits[sb] = 1
		} else if avg < 212 {
			bits[sb] = 2
		} else {
			bits[sb] = 3
		}
	}
	return (bits[0] << 6) | (bits[1] << 4) | (bits[2] << 2) | bits[3]
}
