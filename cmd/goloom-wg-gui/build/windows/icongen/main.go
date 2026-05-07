// One-shot tool that renders the goloom eye logo into the Windows
// .ico used by both the wails-built .exe and the systray icon.
//
// Run with: `go run ./build/windows/icongen` from cmd/goloom-wg-gui.
// Writes ../icon.ico (16x16, 32x32, 48x48, 256x256 multi-resolution).
//
// We draw with image/draw + a simple geometry helper rather than
// pulling in a full SVG renderer — the logo is just an eye-shape
// outline, a pupil, and a highlight, all easily described by lines
// + circles.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

// goloom green — matches the admin panel and GUI accent.
var (
	bg      = color.RGBA{14, 16, 20, 0}      // transparent — we render onto an alpha background
	accent  = color.RGBA{76, 217, 100, 255}  // #4cd964
	eyeFill = color.RGBA{14, 16, 20, 255}    // dark fill
	hilight = color.RGBA{255, 255, 255, 217} // 85% white
)

// drawEye renders the eye shape into the given rectangle on dst.
// Coordinates are normalised to a unit square inside the rect.
func drawEye(dst *image.RGBA, size int) {
	cx, cy := float64(size)/2, float64(size)/2
	// Aspect: width is 2× height for the eye outline. Limited by size.
	w := float64(size) * 0.46    // half-width of eye
	h := float64(size) * 0.30    // half-height
	stroke := math.Max(1.5, float64(size)/22)

	// Helper to paint a pixel if inside rect.
	put := func(x, y int, c color.RGBA) {
		if x < 0 || y < 0 || x >= size || y >= size {
			return
		}
		dst.SetRGBA(x, y, c)
	}

	// Compositor that blends c over existing pixel using c.A.
	blend := func(x, y int, c color.RGBA) {
		if x < 0 || y < 0 || x >= size || y >= size {
			return
		}
		dst.SetRGBA(x, y, c)
	}
	_ = blend

	// 1) Eye outline: a "lens" / leaf shape — intersection of two
	//    circles whose centers are above and below the horizontal.
	//
	//    The classic leaf shape: combine two arcs at top and bottom.
	//    For each pixel, we mark the inside as eyeFill + edge as accent.
	//
	//    Using r = (w² + h²)/(2h) for a chord of length 2w with sagitta h.
	r := (w*w + h*h) / (2 * h)
	// Center of top arc (curve sweeping downward) is below the y-axis
	// at y = cy + (r - h); center of bottom arc is above at y = cy - (r-h).
	yTop := cy + (r - h)
	yBot := cy - (r - h)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			// Distance from each arc center.
			dt := math.Hypot(fx-cx, fy-yTop)
			db := math.Hypot(fx-cx, fy-yBot)
			// Inside the lens iff both distances < r.
			insideT := dt <= r
			insideB := db <= r
			inside := insideT && insideB
			// Edge band: distance to arc surface within stroke.
			edge := false
			if insideT && math.Abs(dt-r) <= stroke {
				edge = true
			}
			if insideB && math.Abs(db-r) <= stroke {
				edge = true
			}
			switch {
			case edge:
				put(x, y, accent)
			case inside:
				put(x, y, eyeFill)
			}
		}
	}

	// 2) Iris ring (accent stroke).
	rIris := float64(size) * 0.18
	rIrisInner := rIris - math.Max(1, stroke*0.85)
	// 3) Pupil (filled accent).
	rPupil := float64(size) * 0.085
	// 4) Highlight (white glint, top-left of pupil).
	rHi := math.Max(1, float64(size)*0.030)
	hx := cx - float64(size)*0.045
	hy := cy - float64(size)*0.045

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			d := math.Hypot(fx-cx, fy-cy)
			if d <= rPupil {
				put(x, y, accent)
				continue
			}
			if d <= rIris && d >= rIrisInner {
				put(x, y, accent)
				continue
			}
			if math.Hypot(fx-hx, fy-hy) <= rHi {
				put(x, y, hilight)
			}
		}
	}
}

func renderPNG(size int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	// Transparent background — bg.A = 0.
	for i := 0; i < size*size; i++ {
		img.Pix[i*4+3] = 0
	}
	drawEye(img, size)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// writeICO packs multiple PNGs into the ICO multi-resolution
// container format (Windows Vista+ accepts PNG payloads inline,
// avoiding the need for full DIB encoding).
func writeICO(out string, sizes []int) error {
	images := make([][]byte, len(sizes))
	for i, s := range sizes {
		images[i] = renderPNG(s)
	}
	var buf bytes.Buffer
	// ICONDIR: reserved=0, type=1 (icon), count=len(sizes).
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(len(sizes)))
	// Directory entries (16 bytes each). Offsets follow after the dir.
	headerSize := 6 + 16*len(sizes)
	off := headerSize
	for i, s := range sizes {
		// Width / Height: 0 = 256.
		w := byte(s % 256)
		h := byte(s % 256)
		binary.Write(&buf, binary.LittleEndian, w)
		binary.Write(&buf, binary.LittleEndian, h)
		binary.Write(&buf, binary.LittleEndian, byte(0)) // colour count (0 == >256)
		binary.Write(&buf, binary.LittleEndian, byte(0)) // reserved
		binary.Write(&buf, binary.LittleEndian, uint16(1))   // colour planes
		binary.Write(&buf, binary.LittleEndian, uint16(32))  // bits/pixel
		binary.Write(&buf, binary.LittleEndian, uint32(len(images[i])))
		binary.Write(&buf, binary.LittleEndian, uint32(off))
		off += len(images[i])
	}
	for _, b := range images {
		buf.Write(b)
	}
	return os.WriteFile(out, buf.Bytes(), 0o644)
}

func main() {
	out := "build/windows/icon.ico"
	sizes := []int{16, 32, 48, 64, 256}
	if err := writeICO(out, sizes); err != nil {
		fmt.Fprintln(os.Stderr, "icongen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s — %d sizes (%v)\n", out, len(sizes), sizes)
}
