// Package journal reads systemd journal files (the format of systemd's
// JOURNAL_FILE_FORMAT.md): regular and compact layouts, XZ, LZ4 and ZSTD
// compressed data objects, keyed or Jenkins hashes.
//
// It reads through an io.ReaderAt and never writes. Every offset is checked
// against the size the file had when opened; every decompressed DATA payload
// is capped (MaxData) before it is allocated, and a field's name is read
// before its value is decompressed, so a field the caller does not keep is
// never decompressed whole. What it returns is raw journal content.
package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

const (
	signature = "LPKSHHRH"

	incompatXZ        = 1 << 0
	incompatLZ4       = 1 << 1
	incompatKeyedHash = 1 << 2
	incompatZSTD      = 1 << 3
	incompatCompact   = 1 << 4
	incompatKnown     = incompatXZ | incompatLZ4 | incompatKeyedHash | incompatZSTD | incompatCompact

	objCompressedXZ   = 1 << 0
	objCompressedLZ4  = 1 << 1
	objCompressedZSTD = 1 << 2
	objCompressedMask = objCompressedXZ | objCompressedLZ4 | objCompressedZSTD

	typeData       = 1
	typeEntry      = 3
	typeEntryArray = 6

	objectHeaderSize = 16
	// headerMin is the header through tail_entry_monotonic (systemd 187+
	// files are longer; the reader needs nothing past it).
	headerMin = 208

	entryHeaderSize = 64

	// MaxData is the largest decompressed DATA payload (name=value) the
	// reader returns; larger fields are reported as dropped.
	MaxData = 1 << 20
	// maxCompressed bounds the stored size of a compressed DATA object
	// the reader decompresses (a payload under MaxData never needs more).
	maxCompressed = MaxData + 64<<10
	// maxEntryItems bounds the number of fields of one entry.
	maxEntryItems = 1 << 14
	// MaxEntryData bounds the decompressed bytes kept for one entry: the
	// fields past it are reported as dropped.
	MaxEntryData = 2 * MaxData
	// maxEntryWork bounds the bytes decoded for one entry, kept or not:
	// an over-cap field costs MaxData, and past the bound the remaining
	// fields are dropped undecoded.
	maxEntryWork = 4 * MaxData
	// lz4PrefixSource bounds the compressed bytes read to decode a field
	// name from an LZ4 payload.
	lz4PrefixSource = 64 << 10
	// maxArrayObject bounds one ENTRY_ARRAY object (items × 8 bytes).
	maxArrayObject = 64 << 20
	// MaxNameBytes is the longest field name journald accepts.
	MaxNameBytes = 64

	cacheMax     = 4096
	cachePayload = 512
	// bigCacheBytes bounds the larger decoded values kept per file, so an
	// object many entries share is decoded once.
	bigCacheBytes = 8 << 20
	maxArrayChain = 1 << 24
)

// Errors. Their text never holds journal content.
var (
	ErrNotJournal  = errors.New("journal: not a journal file")
	ErrUnsupported = errors.New("journal: unsupported journal file features")
	ErrCorrupt     = errors.New("journal: corrupt journal file")
)

// Header is the part of the file header the reader uses.
type Header struct {
	Compatible, Incompatible uint32
	State                    uint8
	FileID, MachineID        [16]byte
	SeqnumID                 [16]byte
	HeaderSize               uint64
	NEntries                 uint64
	EntryArrayOffset         uint64
	HeadRealtime             uint64
	TailRealtime             uint64
	TailObjectOffset         uint64
}

// File is an open journal file. It is not safe for concurrent use.
type File struct {
	r       io.ReaderAt
	size    uint64
	h       Header
	compact bool

	zd    *zstd.Decoder // streaming, reset per use
	names map[uint64]string
	data  map[uint64][]byte
	big   map[uint64][]byte
	bigN  int
	buf   [entryHeaderSize]byte
}

// Open reads and validates the header; size is the file size at open.
func Open(r io.ReaderAt, size int64) (*File, error) {
	if size < headerMin {
		return nil, ErrNotJournal
	}
	var b [headerMin]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return nil, ErrNotJournal
	}
	if string(b[:8]) != signature {
		return nil, ErrNotJournal
	}
	le := binary.LittleEndian
	h := Header{
		Compatible:       le.Uint32(b[8:]),
		Incompatible:     le.Uint32(b[12:]),
		State:            b[16],
		HeaderSize:       le.Uint64(b[88:]),
		TailObjectOffset: le.Uint64(b[136:]),
		NEntries:         le.Uint64(b[152:]),
		EntryArrayOffset: le.Uint64(b[176:]),
		HeadRealtime:     le.Uint64(b[184:]),
		TailRealtime:     le.Uint64(b[192:]),
	}
	copy(h.FileID[:], b[24:40])
	copy(h.MachineID[:], b[40:56])
	copy(h.SeqnumID[:], b[72:88])
	if h.Incompatible&^incompatKnown != 0 {
		return nil, ErrUnsupported
	}
	if h.HeaderSize < headerMin || h.HeaderSize > uint64(size) {
		return nil, ErrNotJournal
	}
	zd, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(16<<20),
		zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecoderLowmem(true))
	if err != nil {
		return nil, err
	}
	return &File{r: r, size: uint64(size), h: h, compact: h.Incompatible&incompatCompact != 0, zd: zd,
		names: map[uint64]string{}, data: map[uint64][]byte{}, big: map[uint64][]byte{}}, nil
}

// Header returns the file header.
func (f *File) Header() Header { return f.h }

// Close releases the decoders (not the reader).
func (f *File) Close() { f.zd.Close() }

func corrupt(what string, off uint64) error {
	return fmt.Errorf("%w: %s at offset %d", ErrCorrupt, what, off)
}

// read reads n bytes at off, inside the file and past the header.
func (f *File) read(dst []byte, off uint64) error {
	n := uint64(len(dst))
	if off < f.h.HeaderSize || off+n < off || off+n > f.size {
		return corrupt("object out of bounds", off)
	}
	if _, err := f.r.ReadAt(dst, int64(off)); err != nil {
		return corrupt("short read", off)
	}
	return nil
}

// objectHeader reads an object header and checks type and size bounds.
func (f *File) objectHeader(off uint64, typ uint8, min, max uint64) (flags uint8, size uint64, err error) {
	if off%8 != 0 {
		return 0, 0, corrupt("unaligned object", off)
	}
	var hb [objectHeaderSize]byte
	if err := f.read(hb[:], off); err != nil {
		return 0, 0, err
	}
	size = binary.LittleEndian.Uint64(hb[8:])
	if hb[0] != typ {
		return 0, 0, corrupt("unexpected object type", off)
	}
	if size < min || size > max || off+size < off || off+size > f.size {
		return 0, 0, corrupt("object size", off)
	}
	return hb[1], size, nil
}

// EntryOffsets walks the entry-array chain from the header and calls fn with
// each entry's index and object offset, in file order (seqnum order), until
// fn returns false.
func (f *File) EntryOffsets(fn func(i uint64, off uint64) bool) error {
	off := f.h.EntryArrayOffset
	item := uint64(8)
	if f.compact {
		item = 4
	}
	var i, prev uint64
	for n := 0; off != 0; n++ {
		if n > maxArrayChain || off <= prev {
			return corrupt("entry array chain", off)
		}
		prev = off
		_, size, err := f.objectHeader(off, typeEntryArray, 24, maxArrayObject)
		if err != nil {
			return err
		}
		b := make([]byte, size)
		if err := f.read(b, off); err != nil {
			return err
		}
		next := binary.LittleEndian.Uint64(b[16:])
		items := b[24:]
		for j := uint64(0); j+item <= uint64(len(items)); j += item {
			var p uint64
			if f.compact {
				p = uint64(binary.LittleEndian.Uint32(items[j:]))
			} else {
				p = binary.LittleEndian.Uint64(items[j:])
			}
			if p == 0 {
				return nil // unused tail slots end the chain
			}
			if i >= f.h.NEntries && f.h.State == 0 {
				// An offline file has exactly NEntries entries.
				return corrupt("more entries than the header holds", off)
			}
			if !fn(i, p) {
				return nil
			}
			i++
		}
		off = next
	}
	return nil
}

// EntryHead is an entry's fixed part: no field is read.
type EntryHead struct {
	Seqnum    uint64
	Realtime  uint64 // µs since the epoch
	Monotonic uint64
	BootID    [16]byte
	XorHash   uint64
	Size      uint64 // object size
}

// Head reads the fixed part of the entry at off.
func (f *File) Head(off uint64) (EntryHead, error) {
	itemSize := uint64(16)
	if f.compact {
		itemSize = 4
	}
	_, size, err := f.objectHeader(off, typeEntry, entryHeaderSize, entryHeaderSize+maxEntryItems*itemSize)
	if err != nil {
		return EntryHead{}, err
	}
	b := f.buf[:]
	if err := f.read(b, off); err != nil {
		return EntryHead{}, err
	}
	le := binary.LittleEndian
	e := EntryHead{Seqnum: le.Uint64(b[16:]), Realtime: le.Uint64(b[24:]), Monotonic: le.Uint64(b[32:]),
		XorHash: le.Uint64(b[56:]), Size: size}
	copy(e.BootID[:], b[40:56])
	return e, nil
}

// Realtime reads only the realtime (µs) of the entry at off: one small read.
func (f *File) Realtime(off uint64) (uint64, error) {
	if off%8 != 0 {
		return 0, corrupt("unaligned object", off)
	}
	var b [32]byte
	if err := f.read(b[:], off); err != nil {
		return 0, err
	}
	if b[0] != typeEntry {
		return 0, corrupt("unexpected object type", off)
	}
	return binary.LittleEndian.Uint64(b[24:]), nil
}

// Entry is one entry with the fields its reader kept.
type Entry struct {
	EntryHead
	Offset uint64
	// Fields are the kept fields in the file's item order; a name may
	// repeat.
	Fields []Field
	// Dropped counts fields left out: kept fields over MaxData or past the
	// entry's budgets, and compressed fields left undecoded (their name
	// unread) once the decode budget is spent.
	Dropped int
	// Decoded is the decompression work the entry cost, in bytes (names
	// and values decoded, not served from the caches): the bytes a
	// source reports as processed besides the entry's own size.
	Decoded int64
}

// Field is one name=value pair. Value may be binary; callers must not
// modify it.
type Field struct {
	Name  string
	Value []byte
}

// Entry reads the entry at off. keep is called with each field's name
// (before its value is decompressed); only fields it accepts are read.
func (f *File) Entry(off uint64, keep func(name string) bool) (*Entry, error) {
	h, err := f.Head(off)
	if err != nil {
		return nil, err
	}
	n := h.Size - entryHeaderSize
	items := make([]byte, n)
	if err := f.read(items, off+entryHeaderSize); err != nil {
		return nil, err
	}
	e := &Entry{EntryHead: h, Offset: off}
	seen := map[uint64]bool{}
	budget, work := MaxEntryData, maxEntryWork
	step := uint64(16)
	if f.compact {
		step = 4
	}
	for i := uint64(0); i+step <= n; i += step {
		var p uint64
		if f.compact {
			p = uint64(binary.LittleEndian.Uint32(items[i:]))
		} else {
			p = binary.LittleEndian.Uint64(items[i:])
		}
		if p == 0 || seen[p] {
			continue // journald never lists one object twice: a hostile file
		}
		seen[p] = true
		name, cost, err := f.nameCost(p, work > 0)
		if errors.Is(err, errNoWork) {
			e.Dropped++
			continue
		}
		if err != nil {
			return nil, err
		}
		work -= cost
		e.Decoded += int64(cost)
		if !keep(name) {
			continue
		}
		if budget <= 0 || work <= 0 {
			e.Dropped++
			continue
		}
		v, decoded, err := f.valueCost(p, len(name))
		e.Decoded += int64(decoded)
		if errors.Is(err, errTooLarge) {
			work -= MaxData
			e.Dropped++
			continue
		}
		work -= len(v)
		if err != nil {
			return nil, err
		}
		if budget -= len(v); budget < 0 {
			e.Dropped++
			continue
		}
		e.Fields = append(e.Fields, Field{Name: name, Value: v})
	}
	return e, nil
}

var errTooLarge = errors.New("journal: data over the size cap")

func (f *File) payloadStart() uint64 {
	if f.compact {
		return 72
	}
	return 64
}

// name returns the field name of the DATA object at off, decoding at most
// MaxNameBytes+1 bytes of its payload.
func (f *File) name(off uint64) (string, error) {
	n, _, err := f.nameCost(off, true)
	return n, err
}

// errNoWork reports a compressed field name left undecoded: the entry's
// decode budget is spent.
var errNoWork = errors.New("journal: entry decode budget spent")

// nameCompressedCost is what decoding one compressed field name is charged:
// a ZSTD or XZ decoder may decode a whole block (up to 128 KiB) to yield
// the first bytes.
const nameCompressedCost = 128 << 10

// nameCost returns the field name of the DATA object at off and the decode
// work it cost. With compressed false, a compressed name not in the cache
// is not decoded (errNoWork).
func (f *File) nameCost(off uint64, compressed bool) (string, int, error) {
	if n, ok := f.names[off]; ok {
		return n, 0, nil
	}
	start := f.payloadStart()
	flags, size, err := f.objectHeader(off, typeData, start+2, 1<<62)
	if err != nil {
		return "", 0, err
	}
	if flags&objCompressedMask != 0 && !compressed {
		return "", 0, errNoWork
	}
	cost := 0
	stored := size - start
	var prefix []byte
	switch flags & objCompressedMask {
	case 0:
		prefix = make([]byte, min(stored, MaxNameBytes+1))
		if err := f.read(prefix, off+start); err != nil {
			return "", 0, err
		}
	case objCompressedZSTD, objCompressedXZ:
		cost = nameCompressedCost
		r, err := f.stream(flags, off+start, stored, true)
		if err != nil {
			return "", 0, corrupt("compressed data", off)
		}
		prefix = make([]byte, MaxNameBytes+1)
		k, err := io.ReadFull(r, prefix)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return "", 0, corrupt("compressed data", off)
		}
		prefix = prefix[:k]
	case objCompressedLZ4:
		// Only the first bytes of the block are decoded: an LZ4 match
		// only points backwards, so a prefix stands on its own.
		if stored < 8 {
			return "", 0, corrupt("lz4 data", off)
		}
		src := make([]byte, min(stored-8, lz4PrefixSource))
		cost = len(src)
		if err := f.read(src, off+start+8); err != nil {
			return "", 0, err
		}
		prefix = lz4Prefix(src, MaxNameBytes+1)
	default:
		return "", 0, corrupt("data compression flags", off)
	}
	eq := bytes.IndexByte(prefix, '=')
	if eq <= 0 || !validName(prefix[:eq]) {
		return "", 0, corrupt("data field name", off)
	}
	name := string(prefix[:eq])
	if len(f.names) >= cacheMax {
		clear(f.names)
	}
	f.names[off] = name
	return name, cost, nil
}

// validName accepts journald's field names: A-Z, 0-9 and '_', not starting
// with a digit, at most 64 bytes.
func validName(b []byte) bool {
	if len(b) == 0 || len(b) > MaxNameBytes || (b[0] >= '0' && b[0] <= '9') {
		return false
	}
	for _, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// value returns the value of the DATA object at off (whose name is nameLen
// bytes), or errTooLarge when its payload is over MaxData.
func (f *File) value(off uint64, nameLen int) ([]byte, error) {
	v, _, err := f.valueCost(off, nameLen)
	return v, err
}

// valueCost is value, with the bytes it decoded (0 from a cache; an
// over-cap compressed value counts as MaxData).
func (f *File) valueCost(off uint64, nameLen int) ([]byte, int, error) {
	if v, ok := f.data[off]; ok {
		return v[nameLen+1:], 0, nil
	}
	if v, ok := f.big[off]; ok {
		return v[nameLen+1:], 0, nil
	}
	v, err := f.value0(off, nameLen)
	if errors.Is(err, errTooLarge) {
		return nil, MaxData, err
	}
	if err != nil {
		return nil, 0, err
	}
	return v, nameLen + 1 + len(v), nil
}

func (f *File) value0(off uint64, nameLen int) ([]byte, error) {
	start := f.payloadStart()
	flags, size, err := f.objectHeader(off, typeData, start+2, 1<<62)
	if err != nil {
		return nil, err
	}
	stored := size - start
	var p []byte
	switch flags & objCompressedMask {
	case 0:
		if stored > MaxData {
			return nil, errTooLarge
		}
		p = make([]byte, stored)
		if err := f.read(p, off+start); err != nil {
			return nil, err
		}
	case objCompressedZSTD, objCompressedXZ:
		if stored > maxCompressed {
			return nil, errTooLarge
		}
		if flags&objCompressedZSTD != 0 {
			// The frame header declares the content size: check it
			// before decoding anything.
			var hb [zstd.HeaderMaxSize]byte
			k := min(uint64(len(hb)), stored)
			if err := f.read(hb[:k], off+start); err != nil {
				return nil, err
			}
			var fh zstd.Header
			if err := fh.Decode(hb[:k]); err != nil {
				return nil, corrupt("zstd frame header", off)
			}
			if fh.HasFCS && fh.FrameContentSize > MaxData {
				return nil, errTooLarge
			}
		}
		r, err := f.stream(flags, off+start, stored, false)
		if err != nil {
			return nil, err
		}
		p, err = io.ReadAll(io.LimitReader(r, MaxData+1))
		if errors.Is(err, errTooLarge) {
			return nil, err
		}
		if err != nil {
			return nil, corrupt("compressed data", off)
		}
		if len(p) > MaxData {
			return nil, errTooLarge
		}
	case objCompressedLZ4:
		p, err = f.lz4(off+start, stored)
		if err != nil {
			return nil, err
		}
	default:
		return nil, corrupt("data compression flags", off)
	}
	if len(p) <= nameLen || p[nameLen] != '=' {
		return nil, corrupt("data payload", off)
	}
	if len(p) <= cachePayload {
		if len(f.data) >= cacheMax {
			clear(f.data)
		}
		f.data[off] = p
	} else if len(p) <= bigCacheBytes/2 {
		if f.bigN+len(p) > bigCacheBytes {
			clear(f.big)
			f.bigN = 0
		}
		f.big[off] = p
		f.bigN += len(p)
	}
	return p[nameLen+1:], nil
}

// stream returns a decompressing reader over a ZSTD or XZ payload.
func (f *File) stream(flags uint8, off, n uint64, prefixOnly bool) (io.Reader, error) {
	if off < f.h.HeaderSize || off+n < off || off+n > f.size {
		return nil, corrupt("object out of bounds", off)
	}
	if prefixOnly {
		// A field name lies in the first block: read no further, so a
		// name hidden behind empty blocks or frames costs no more than
		// it is charged.
		n = min(n, nameCompressedCost+2048)
	}
	src := io.NewSectionReader(f.r, int64(off), int64(n))
	if flags&objCompressedZSTD != 0 {
		if err := f.zd.Reset(src); err != nil {
			return nil, corrupt("zstd data", off)
		}
		return f.zd, nil
	}
	r, err := xzReader(src, prefixOnly)
	if errors.Is(err, errTooLarge) {
		return nil, err
	}
	if err != nil {
		return nil, corrupt("xz data", off)
	}
	return r, nil
}

// lz4 decodes an LZ4 payload: a little-endian 64-bit size, then one block.
func (f *File) lz4(off, n uint64) ([]byte, error) {
	if n < 8 {
		return nil, corrupt("lz4 data", off)
	}
	var sb [8]byte
	if err := f.read(sb[:], off); err != nil {
		return nil, err
	}
	want := binary.LittleEndian.Uint64(sb[:])
	if want > MaxData {
		return nil, errTooLarge
	}
	if n-8 > maxCompressed {
		return nil, corrupt("lz4 data", off)
	}
	src := make([]byte, n-8)
	if err := f.read(src, off+8); err != nil {
		return nil, err
	}
	out := make([]byte, want)
	got, err := lz4.UncompressBlock(src, out)
	if err != nil || uint64(got) != want {
		return nil, corrupt("lz4 data", off)
	}
	return out, nil
}

// lz4Prefix decodes at most n bytes from the start of an LZ4 block. It
// stops early (returning what it has) on a truncated or invalid block.
func lz4Prefix(src []byte, n int) []byte {
	out := make([]byte, 0, n)
	i := 0
	for i < len(src) && len(out) < n {
		token := src[i]
		i++
		lit := int(token >> 4)
		if lit == 15 {
			for i < len(src) {
				b := src[i]
				i++
				lit += int(b)
				if lit > 1<<30 {
					return out
				}
				if b != 255 {
					break
				}
			}
		}
		take := min(lit, n-len(out), len(src)-i)
		out = append(out, src[i:i+take]...)
		if len(out) >= n || lit > len(src)-i {
			return out
		}
		i += lit
		if i+2 > len(src) {
			return out // the last sequence has literals only
		}
		offset := int(src[i]) | int(src[i+1])<<8
		i += 2
		ml := int(token&15) + 4
		if token&15 == 15 {
			for i < len(src) {
				b := src[i]
				i++
				ml += int(b)
				if ml > 1<<30 {
					return out
				}
				if b != 255 {
					break
				}
			}
		}
		if offset == 0 || offset > len(out) {
			return out
		}
		for k := 0; k < ml && len(out) < n; k++ {
			out = append(out, out[len(out)-offset])
		}
	}
	return out
}
