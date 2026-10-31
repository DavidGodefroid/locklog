package journal

import (
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

// maxLZMA2Chunks bounds the LZMA2 chunks of a value: a real payload of at
// most MaxData needs about one per 64 KiB of output (journald's encoder
// writes up to 2 MiB per chunk). Each chunk can reset the decoder state,
// which costs far more than the bytes it holds, so a stream of thousands
// of tiny chunks is refused before decoding.
const maxLZMA2Chunks = 2*((MaxData+65535)/65536) + 2

var errXZ = errors.New("journal: unsupported or corrupt xz data")

// xzHeader is what locklog reads of an XZ stream before decoding: the
// stream and first block headers, parsed here so that only a single LZMA2
// filter is accepted and its dictionary is known before any allocation.
type xzHeader struct {
	dict      uint64
	usize     uint64 // declared uncompressed size, 0 when absent
	hasUsize  bool
	dataStart int // offset of the LZMA2 data
	check     int // size of the block check
}

func parseXZ(b []byte) (xzHeader, error) {
	var h xzHeader
	if len(b) < 13 || !bytes.Equal(b[:6], []byte{0xFD, '7', 'z', 'X', 'Z', 0}) || b[6] != 0 {
		return h, errXZ
	}
	check, ok := map[byte]int{0: 0, 1: 4, 4: 8, 10: 32}[b[7]]
	if !ok {
		return h, errXZ
	}
	h.check = check
	b0 := b[12]
	if b0 == 0 { // the index: a stream without blocks
		return h, errXZ
	}
	end := 12 + (int(b0)+1)*4
	if end > len(b) {
		return h, errXZ
	}
	hdr := b[13:end]
	flags := hdr[0]
	if flags&0x3C != 0 || flags&0x03 != 0 { // reserved bits; exactly one filter
		return h, errXZ
	}
	p := hdr[1 : len(hdr)-4] // without the header CRC32
	var err error
	if flags&0x40 != 0 { // compressed size
		if _, p, err = varint(p); err != nil {
			return h, err
		}
	}
	if flags&0x80 != 0 {
		if h.usize, p, err = varint(p); err != nil {
			return h, err
		}
		h.hasUsize = true
	}
	id, p, err := varint(p)
	if err != nil || id != 0x21 { // LZMA2
		return h, errXZ
	}
	n, p, err := varint(p)
	if err != nil || n != 1 || len(p) < 1 {
		return h, errXZ
	}
	if h.dict, ok = lzma2Dict(p[0]); !ok {
		return h, errXZ
	}
	h.dataStart = end
	return h, nil
}

// xzPrefix decodes at most n bytes from the start of an XZ payload b (a
// prefix of the stored bytes): the smallest dictionary does, whatever the
// header declares, since the first bytes only reach that far back.
func xzPrefix(b []byte, n int) ([]byte, error) {
	h, err := parseXZ(b)
	if err != nil {
		return nil, err
	}
	r, err := lzma.Reader2Config{DictCap: lzma.MinDictCap}.NewReader2(bytes.NewReader(b[h.dataStart:]))
	if err != nil {
		return nil, errXZ
	}
	out := make([]byte, n)
	k, err := io.ReadFull(r, out)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, errXZ
	}
	return out[:k], nil
}

// xzValue decodes a whole XZ payload b. Before decoding it refuses a
// declared dictionary or size over the caps, a stream of more than
// maxLZMA2Chunks chunks, and a second block (journald writes one); the
// stream's checksums are not verified.
func xzValue(b []byte) ([]byte, error) {
	h, err := parseXZ(b)
	if err != nil {
		return nil, err
	}
	if h.dict > MaxXZDict || h.hasUsize && h.usize > MaxData {
		return nil, errTooLarge
	}
	// Walk the LZMA2 chunk headers: they are plain, with their sizes.
	i, chunks := h.dataStart, 0
	for {
		if i >= len(b) {
			return nil, errXZ
		}
		c := b[i]
		if c == 0 {
			i++
			break
		}
		if chunks++; chunks > maxLZMA2Chunks {
			return nil, errXZ
		}
		switch {
		case c == 1 || c == 2: // stored chunk
			if i+3 > len(b) {
				return nil, errXZ
			}
			i += 3 + (int(b[i+1])<<8 | int(b[i+2])) + 1
		case c >= 0x80: // LZMA chunk
			if i+5 > len(b) {
				return nil, errXZ
			}
			hdr := 5
			if c >= 0xC0 {
				hdr = 6 // with a properties byte
			}
			i += hdr + (int(b[i+3])<<8 | int(b[i+4])) + 1
		default:
			return nil, errXZ
		}
	}
	lzmaEnd := i
	i += (4-(i-12)%4)%4 + h.check // block padding, then its check
	if i >= len(b) || b[i] != 0 {
		return nil, errTooLarge // a second block follows
	}
	r, err := lzma.Reader2Config{DictCap: max(int(h.dict), lzma.MinDictCap)}.NewReader2(bytes.NewReader(b[h.dataStart:lzmaEnd]))
	if err != nil {
		return nil, errXZ
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxData+1))
	if err != nil {
		return nil, errXZ
	}
	if len(out) > MaxData {
		return nil, errTooLarge
	}
	return out, nil
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
