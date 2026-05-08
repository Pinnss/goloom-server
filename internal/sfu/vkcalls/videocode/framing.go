package videocode

import (
	"encoding/binary"
	"sync"
)

// PackBundle concatenates multiple network packets, each prefixed with a 2-byte big-endian length.
func PackBundle(packets [][]byte, maxSize int) []byte {
	bundle := make([]byte, 0, maxSize)
	var lenBuf [2]byte
	for _, p := range packets {
		if len(bundle)+len(p)+2 > maxSize {
			break
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		bundle = append(bundle, lenBuf[:]...)
		bundle = append(bundle, p...)
	}
	return bundle
}

// UnpackBundle splits a bundle into packets (length, payload pairs).
func UnpackBundle(bundle []byte) [][]byte {
	var packets [][]byte
	for i := 0; i+2 <= len(bundle); {
		pLen := int(binary.BigEndian.Uint16(bundle[i : i+2]))
		i += 2
		if pLen == 0 || i+pLen > len(bundle) {
			break
		}
		pkt := make([]byte, pLen)
		copy(pkt, bundle[i:i+pLen])
		packets = append(packets, pkt)
		i += pLen
	}
	return packets
}

const (
	frameFlagFirst byte = 0x80
	frameFlagLast  byte = 0x40
	frameHeaderLen      = 5
	FragmentPayload     = MaxPayloadPerFrame - frameHeaderLen
)

type Fragmenter struct {
	mu    sync.Mutex
	pktID uint16
}

func NewFragmenter() *Fragmenter { return &Fragmenter{} }

func (f *Fragmenter) Fragment(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}

	f.mu.Lock()
	f.pktID++
	pid := f.pktID
	f.mu.Unlock()

	totalFrags := (len(data) + FragmentPayload - 1) / FragmentPayload
	fragments := make([][]byte, 0, totalFrags)

	for i := 0; i < totalFrags; i++ {
		start := i * FragmentPayload
		end := start + FragmentPayload
		if end > len(data) {
			end = len(data)
		}

		chunkSize := end - start
		var flags byte
		if i == 0 {
			flags |= frameFlagFirst
		}
		if i == totalFrags-1 {
			flags |= frameFlagLast
		}

		frag := make([]byte, frameHeaderLen+chunkSize)
		frag[0] = flags
		binary.BigEndian.PutUint16(frag[1:3], pid)
		frag[3] = byte(i)
		frag[4] = byte(totalFrags)
		copy(frag[frameHeaderLen:], data[start:end])

		fragments = append(fragments, frag)
	}
	return fragments
}

type Defragmenter struct {
	mu      sync.Mutex
	pending map[uint16]*packetAssembly
}

type packetAssembly struct {
	fragments  [][]byte
	totalFrags int
	count      int
	totalBytes int
}

func NewDefragmenter() *Defragmenter {
	return &Defragmenter{pending: make(map[uint16]*packetAssembly)}
}

func (d *Defragmenter) Feed(payload []byte) []byte {
	if len(payload) < frameHeaderLen {
		return nil
	}

	flags := payload[0]
	pid := binary.BigEndian.Uint16(payload[1:3])
	fragIdx := int(payload[3])
	totalFrags := int(payload[4])
	data := payload[frameHeaderLen:]

	if flags&frameFlagFirst != 0 && flags&frameFlagLast != 0 {
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	asm, ok := d.pending[pid]
	if !ok {
		asm = &packetAssembly{
			fragments:  make([][]byte, totalFrags),
			totalFrags: totalFrags,
		}
		d.pending[pid] = asm
	}

	if asm.totalFrags != totalFrags || fragIdx >= totalFrags {
		return nil
	}

	if asm.fragments[fragIdx] == nil {
		fragCopy := make([]byte, len(data))
		copy(fragCopy, data)
		asm.fragments[fragIdx] = fragCopy
		asm.count++
		asm.totalBytes += len(data)
	}

	if asm.count == asm.totalFrags {
		result := make([]byte, 0, asm.totalBytes)
		for _, f := range asm.fragments {
			result = append(result, f...)
		}
		delete(d.pending, pid)

		if len(d.pending) > 64 {
			for k := range d.pending {
				delete(d.pending, k)
				if len(d.pending) <= 32 {
					break
				}
			}
		}
		return result
	}
	return nil
}
