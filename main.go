// samsung-secos-analyzer analyzes Samsung Tizen TV secure OS image partitions.
//
// After the MSD container (AES-128-CBC) is stripped, secos.bin and secos_drv.bin
// remain as opaque "data" blobs. This tool maps their internal structure:
// non-zero block regions, entropy profiles, alignment patterns, and potential
// header fields. It does NOT decrypt the secure-OS payload — that requires
// reversing the TVs secure boot chain (sboot / EL3 monitor).
//
// Usage:
//
//	samsung-secos-analyzer <secos.bin> [secos_drv.bin]
//	samsung-secos-analyzer -all /path/to/extracted/
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Samsung secure image page size (observed alignment in secos.bin)
	pageSize = 4096
)

func main() {
	all := flag.Bool("all", false, "Analyze all known partition files in a directory")
	jsonOut := flag.Bool("json", false, "Output as JSON (not yet implemented)")
	flag.Parse()

	if *jsonOut {
		fmt.Fprintf(os.Stderr, "JSON output not yet implemented\n")
		os.Exit(1)
	}

	if *all {
		if flag.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "usage: samsung-secos-analyzer -all <directory>\n")
			os.Exit(1)
		}
		analyzeAll(flag.Arg(0))
		return
	}

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: samsung-secos-analyzer <secos.bin> [secos_drv.bin]\n")
		fmt.Fprintf(os.Stderr, "       samsung-secos-analyzer -all /path/to/extracted/\n")
		os.Exit(1)
	}

	for _, path := range flag.Args() {
		analyzeFile(path)
	}
}

func analyzeAll(dir string) {
	partitions := []string{
		"secos.bin", "secos_drv.bin",
		"seret.bin", "ddr.init", "sign.bin",
		"uImage", "dtb.bin",
	}
	for _, name := range partitions {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			analyzeFile(path)
		}
	}
}

func analyzeFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", path, err)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		return
	}

	name := filepath.Base(path)
	fmt.Printf("═══ %s ═══\n", name)
	fmt.Printf("  Size:        %d bytes (0x%x)\n", len(data), len(data))
	fmt.Printf("  SHA-256:     %x\n", sha256.Sum256(data))

	// Magic / header detection
	first4 := data[:4]
	fmt.Printf("  First 4:     %s\n", hex.EncodeToString(first4))
	switch {
	case string(first4) == "\x27\x05\x19\x56":
		fmt.Printf("  Format:      u-boot uImage\n")
	case string(first4) == "\xd0\x0d\xfe\xed":
		fmt.Printf("  Format:      Device Tree Blob\n")
	case string(first4) == "Salt":
		fmt.Printf("  Format:      OpenSSL Salted__ (encrypted)\n")
	default:
		fmt.Printf("  Format:      unknown (no recognized magic)\n")
	}

	// Entropy
	ent := entropy(data)
	fmt.Printf("  Entropy:     %.4f bits/byte\n", ent)

	// Zero statistics
	zeroCount := 0
	for _, b := range data {
		if b == 0 {
			zeroCount++
		}
	}
	zeroPct := float64(zeroCount) / float64(len(data)) * 100
	fmt.Printf("  Zeros:       %d (%.1f%%)\n", zeroCount, zeroPct)

	// Non-zero block analysis
	blocks := findNonZeroBlocks(data)
	fmt.Printf("  NZ blocks:   %d total", len(blocks))
	bigBlocks := filterBlocks(blocks, 64)
	fmt.Printf(", %d > 64 bytes\n", len(bigBlocks))

	// Block size distribution
	if len(bigBlocks) > 0 {
		sizes := make([]int, len(bigBlocks))
		for i, b := range bigBlocks {
			sizes[i] = b.size
		}
		sort.Ints(sizes)
		fmt.Printf("  Block sizes: min=%d median=%d max=%d\n",
			sizes[0], sizes[len(sizes)/2], sizes[len(sizes)-1])
	}

	// Page alignment analysis
	aligned, total := countPageAligned(blocks)
	fmt.Printf("  Page-align:  %d/%d blocks start on 4K boundary\n", aligned, total)

	// Entropy profile (16KB windows)
	fmt.Printf("  Entropy profile (16KB windows, >6.0 shown):\n")
	printEntropyProfile(data, 16384)

	// Non-zero region map (visual)
	fmt.Printf("  Block map (. = zero, # = data, 4K per char):\n")
	printBlockMap(data)

	fmt.Println()
}

type block struct {
	offset int
	size   int
}

func findNonZeroBlocks(data []byte) []block {
	var blocks []block
	i := 0
	for i < len(data) {
		if data[i] != 0 {
			start := i
			for i < len(data) && data[i] != 0 {
				i++
			}
			blocks = append(blocks, block{start, i - start})
		} else {
			i++
		}
	}
	return blocks
}

func filterBlocks(blocks []block, minSize int) []block {
	var result []block
	for _, b := range blocks {
		if b.size >= minSize {
			result = append(result, b)
		}
	}
	return result
}

func countPageAligned(blocks []block) (aligned, total int) {
	for _, b := range blocks {
		total++
		if b.offset%pageSize == 0 {
			aligned++
		}
	}
	return
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func printEntropyProfile(data []byte, windowSize int) {
	for i := 0; i < len(data); i += windowSize {
		end := i + windowSize
		if end > len(data) {
			end = len(data)
		}
		e := entropy(data[i:end])
		if e > 6.0 {
			bar := strings.Repeat("█", int((e-6.0)*20))
			fmt.Printf("    0x%06x: %.2f %s\n", i, e, bar)
		}
	}
}

func printBlockMap(data []byte) {
	chunkSize := pageSize
	lineWidth := 64
	for i := 0; i < len(data); i += chunkSize * lineWidth {
		fmt.Printf("    0x%06x: ", i)
		for j := 0; j < lineWidth; j++ {
			offset := i + j*chunkSize
			if offset >= len(data) {
				break
			}
			end := offset + chunkSize
			if end > len(data) {
				end = len(data)
			}
			hasData := false
			for _, b := range data[offset:end] {
				if b != 0 {
					hasData = true
					break
				}
			}
			if hasData {
				fmt.Print("#")
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}

// readUint32LE reads a little-endian uint32 at the given offset.
func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}

// readUint32BE reads a big-endian uint32 at the given offset.
func readUint32BE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.BigEndian.Uint32(data[offset:])
}

// hexdump writes a hex dump of a region to w.
func hexdump(w *bufio.Writer, data []byte, baseAddr int) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		fmt.Fprintf(w, "  %06x: ", baseAddr+i)
		for j := 0; j < 16; j++ {
			if j < len(chunk) {
				fmt.Fprintf(w, "%02x ", chunk[j])
			} else {
				fmt.Fprintf(w, "   ")
			}
			if j == 7 {
				fmt.Fprintf(w, " ")
			}
		}
		fmt.Fprintf(w, " ")
		for _, b := range chunk {
			if b >= 32 && b < 127 {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprintf(w, ".")
			}
		}
		fmt.Fprintln(w)
	}
}
