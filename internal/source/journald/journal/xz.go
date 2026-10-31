package journal

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// MaxXZDict is the largest LZMA2 dictionary an XZ payload may declare. The
// decoder allocates the declared dictionary, so a crafted header could
// otherwise make it allocate up to 4 GiB; payloads are at most MaxData, so
// a larger dictionary is never needed (journald's own is 1 MiB).
const MaxXZDict uint64 = MaxData + 64<<10

var errXZ = errors.New("journal: unsupported or corrupt xz data")

// xzReader returns a reader of the first block of an XZ stream: it parses
// the stream and block headers itself, refuses anything but a single LZMA2
// filter, and refuses a declared dictionary over MaxXZDict before the
// decoder allocates it. A value whose stream holds a second block is
// reported over the cap. With prefixOnly (reading a field name: the first
// bytes only, whose matches reach at most that far back) the smallest
// dictionary is used whatever the header declares, and an over-cap
// declared size is not refused. Later blocks are never read (journald writes one); the
// stream's checksums are not verified.
func xzReader(src io.Reader, prefixOnly bool) (io.Reader, error) {
	cr := &countReader{r: src}
	br := bufio.NewReaderSize(cr, 4096)
	var sh [12]byte
	if _, err := io.ReadFull(br, sh[:]); err != nil {
		return nil, errXZ
	}
	if !bytes.Equal(sh[:6], []byte{0xFD, '7', 'z', 'X', 'Z', 0}) || sh[6] != 0 {
		return nil, errXZ
	}
	checkSize, ok := map[byte]int{0: 0, 1: 4, 4: 8, 10: 32}[sh[7]]
	if !ok {
		return nil, errXZ
	}
	b0, err := br.ReadByte()
	if err != nil || b0 == 0 { // 0 is the index: a stream without blocks
		return nil, errXZ
	}
	hdr := make([]byte, (int(b0)+1)*4-1) // the rest of the block header, its CRC32 last
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, errXZ
	}
	flags := hdr[0]
	if flags&0x3C != 0 || flags&0x03 != 0 { // reserved bits; exactly one filter
		return nil, errXZ
	}
	p := hdr[1 : len(hdr)-4]
	if flags&0x40 != 0 { // compressed size
		if p, err = skipVarint(p); err != nil {
			return nil, err
		}
	}
	if flags&0x80 != 0 { // uncompressed size: refuse an over-cap one now
		var u uint64
		if u, p, err = varint(p); err != nil {
			return nil, err
		}
		if u > MaxData && !prefixOnly {
			return nil, errTooLarge
		}
	}
	id, p, err := varint(p)
	if err != nil || id != 0x21 { // LZMA2
		return nil, errXZ
	}
	n, p, err := varint(p)
	if err != nil || n != 1 || len(p) < 1 {
		return nil, errXZ
	}
	dict, ok := lzma2Dict(p[0])
	if !ok {
		return nil, errXZ
	}
	if dict > MaxXZDict && !prefixOnly {
		return nil, errTooLarge
	}
	capd := int(min(dict, MaxXZDict))
	if prefixOnly {
		// The first bytes only reach that far back: the smallest
		// dictionary does.
		capd = lzma.MinDictCap
	}
	lr, err := lzma.Reader2Config{DictCap: max(capd, lzma.MinDictCap)}.NewReader2(br)
	if err != nil {
		return nil, errXZ
	}
	if prefixOnly {
		return lr, nil
	}
	return &xzBlock{lr: lr, br: br, cr: cr, check: checkSize}, nil
}

// countReader counts the bytes read from r.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// xzBlock reads the first block's data and, at its end, checks that the
// stream's index follows: a second block (which journald never writes)
// makes the value over the cap rather than silently cut.
type xzBlock struct {
	lr    io.Reader
	br    *bufio.Reader
	cr    *countReader
	check int
	done  bool
}

func (x *xzBlock) Read(p []byte) (int, error) {
	if x.done {
		return 0, io.EOF
	}
	n, err := x.lr.Read(p)
	if err != io.EOF {
		return n, err
	}
	x.done = true
	consumed := x.cr.n - int64(x.br.Buffered()) // stream header, block header, data
	pad := (4 - (consumed-12)%4) % 4
	if _, err := x.br.Discard(int(pad) + x.check); err != nil {
		return n, errXZ
	}
	if b, err := x.br.ReadByte(); err != nil || b != 0 {
		return n, errTooLarge // more blocks follow
	}
	return n, io.EOF
}

// lzma2Dict decodes the LZMA2 dictionary-size property byte.
func lzma2Dict(b byte) (uint64, bool) {
	if b > 40 {
		return 0, false
	}
	if b == 40 {
		return 1<<32 - 1, true
	}
	return (2 | uint64(b&1)) << (b/2 + 11), true
}

func varint(p []byte) (uint64, []byte, error) {
	var v uint64
	for i := 0; i < len(p) && i < 9; i++ {
		v |= uint64(p[i]&0x7f) << (7 * i)
		if p[i]&0x80 == 0 {
			return v, p[i+1:], nil
		}
	}
	return 0, nil, errXZ
}

func skipVarint(p []byte) ([]byte, error) {
	_, rest, err := varint(p)
	return rest, err
}
