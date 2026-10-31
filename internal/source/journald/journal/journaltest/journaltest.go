// Package journaltest builds small journal files in memory for tests and
// fuzz seeds: header, DATA, ENTRY and chained ENTRY_ARRAY objects, regular or
// compact, plain or ZSTD/LZ4/XZ compressed (no hash tables: the reader does
// not use them).
package journaltest

import (
	"bytes"
	"encoding/binary"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

// Entry is one entry: its realtime (µs) and its "NAME=value" fields.
type Entry struct {
	Realtime uint64
	Fields   []string
}

// Options shape the file.
type Options struct {
	Compact bool
	// Compress is "", "zstd", "lz4" or "xz": every DATA payload is
	// compressed with it.
	Compress string
	// PerArray is the number of entries per ENTRY_ARRAY object (0: one
	// array for all), so a file can have a chain of arrays.
	PerArray int
}

const (
	headerSize = 272
	typeData   = 1
	typeEntry  = 3
	typeArray  = 6
)

type builder struct {
	o    Options
	buf  []byte
	data map[string]uint64
}

func (b *builder) obj(typ, flags uint8, body []byte) uint64 {
	off := uint64(len(b.buf))
	h := make([]byte, 16)
	h[0], h[1] = typ, flags
	binary.LittleEndian.PutUint64(h[8:], uint64(16+len(body)))
	b.buf = append(append(b.buf, h...), body...)
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
	return off
}

func (b *builder) item(dst []byte, off uint64) []byte {
	if b.o.Compact {
		return binary.LittleEndian.AppendUint32(dst, uint32(off))
	}
	return binary.LittleEndian.AppendUint64(dst, off)
}

func compress(kind string, p []byte) ([]byte, uint8) {
	switch kind {
	case "zstd":
		enc, _ := zstd.NewWriter(nil)
		defer enc.Close()
		return enc.EncodeAll(p, nil), 4
	case "lz4":
		out := make([]byte, 8+lz4.CompressBlockBound(len(p)))
		binary.LittleEndian.PutUint64(out, uint64(len(p)))
		n, _ := lz4.CompressBlock(p, out[8:], nil)
		if n == 0 { // incompressible: store as literals
			n = lz4Literals(p, out[8:])
		}
		return out[:8+n], 2
	case "xz":
		var buf bytes.Buffer
		w, _ := xz.WriterConfig{DictCap: 1 << 20}.NewWriter(&buf) // journald's dictionary
		w.Write(p)
		w.Close()
		return buf.Bytes(), 1
	}
	return p, 0
}

// lz4Literals writes p as one literal-only LZ4 sequence.
func lz4Literals(p, dst []byte) int {
	i := 0
	n := len(p)
	if n < 15 {
		dst[i] = byte(n << 4)
		i++
	} else {
		dst[i] = 0xF0
		i++
		r := n - 15
		for r >= 255 {
			dst[i] = 255
			i++
			r -= 255
		}
		dst[i] = byte(r)
		i++
	}
	return i + copy(dst[i:], p)
}

func (b *builder) dataObj(payload string) uint64 {
	if off, ok := b.data[payload]; ok {
		return off
	}
	head := 48
	if b.o.Compact {
		head += 8
	}
	p, flags := compress(b.o.Compress, []byte(payload))
	off := b.obj(typeData, flags, append(make([]byte, head), p...))
	b.data[payload] = off
	return off
}

// Build returns the journal file bytes.
func Build(o Options, es []Entry) []byte {
	b := &builder{o: o, buf: make([]byte, headerSize), data: map[string]uint64{}}
	var entries []uint64
	for i, e := range es {
		var items []byte
		for _, f := range e.Fields {
			items = b.item(items, b.dataObj(f))
			if !o.Compact {
				items = binary.LittleEndian.AppendUint64(items, 0) // hash
			}
		}
		body := make([]byte, 48)
		binary.LittleEndian.PutUint64(body[0:], uint64(i+1))
		binary.LittleEndian.PutUint64(body[8:], e.Realtime)
		binary.LittleEndian.PutUint64(body[16:], uint64(1000+i))
		entries = append(entries, b.obj(typeEntry, 0, append(body, items...)))
	}
	per := o.PerArray
	if per <= 0 {
		per = len(entries) + 1
	}
	// Arrays are written first to last, each pointing at the next: write
	// them in reverse so each knows its successor.
	var next, first uint64
	var chunks [][]uint64
	for i := 0; i < len(entries); i += per {
		chunks = append(chunks, entries[i:min(i+per, len(entries))])
	}
	if len(chunks) == 0 {
		chunks = [][]uint64{nil}
	}
	offs := make([]uint64, len(chunks))
	// Reserve the arrays in order (offsets must grow along the chain).
	for ci, c := range chunks {
		body := make([]byte, 8)
		for _, off := range c {
			body = b.item(body, off)
		}
		offs[ci] = b.obj(typeArray, 0, body)
	}
	for ci := len(chunks) - 1; ci >= 0; ci-- {
		binary.LittleEndian.PutUint64(b.buf[offs[ci]+16:], next)
		next = offs[ci]
	}
	first = next
	h := b.buf[:headerSize]
	copy(h, "LPKSHHRH")
	var incompat uint32
	if o.Compact {
		incompat |= 1 << 4
	}
	switch o.Compress {
	case "zstd":
		incompat |= 1 << 3
	case "lz4":
		incompat |= 1 << 1
	case "xz":
		incompat |= 1
	}
	le := binary.LittleEndian
	le.PutUint32(h[12:], incompat)
	le.PutUint64(h[88:], headerSize)
	le.PutUint64(h[96:], uint64(len(b.buf)-headerSize))
	le.PutUint64(h[136:], offs[len(offs)-1])
	le.PutUint64(h[152:], uint64(len(es)))
	le.PutUint64(h[176:], first)
	if len(es) > 0 {
		le.PutUint64(h[184:], es[0].Realtime)
		le.PutUint64(h[192:], es[len(es)-1].Realtime)
	}
	return b.buf
}
