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
const MaxXZDict = MaxData + 64<<10

var errXZ = errors.New("journal: unsupported or corrupt xz data")

// xzReader returns a reader of the first block of an XZ stream: it parses
// the stream and block headers itself, refuses anything but a single LZMA2
// filter, and refuses a declared dictionary over MaxXZDict before the
// decoder allocates it. With prefixOnly (reading a field name: the first
// bytes only, whose matches reach at most that far back) the smallest
// dictionary is used whatever the header declares, and an over-cap
// declared size is not refused. Later blocks are never read (journald writes one); the
// stream's checksums are not verified.
func xzReader(src io.Reader, prefixOnly bool) (io.Reader, error) {
	br := bufio.NewReaderSize(src, 4096)
	var sh [12]byte
	if _, err := io.ReadFull(br, sh[:]); err != nil {
		return nil, errXZ
	}
	if !bytes.Equal(sh[:6], []byte{0xFD, '7', 'z', 'X', 'Z', 0}) || sh[6] != 0 {
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
	if prefixOnly {
		// The first bytes only reach that far back: the smallest
		// dictionary does.
		dict = lzma.MinDictCap
	}
	return lzma.Reader2Config{DictCap: max(dict, lzma.MinDictCap)}.NewReader2(br)
}

// lzma2Dict decodes the LZMA2 dictionary-size property byte.
func lzma2Dict(b byte) (int, bool) {
	if b > 40 {
		return 0, false
	}
	if b == 40 {
		return 1<<32 - 1, true
	}
	return (2 | int(b&1)) << (b/2 + 11), true
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
