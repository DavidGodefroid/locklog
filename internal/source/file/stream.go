package file

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	// PrefixBytes is the length of the prefix hashed into a file's
	// identity.
	PrefixBytes = 64 << 10
	// MaxRatio bounds decompressed bytes per compressed byte.
	MaxRatio = 100
	// ratioSlack lets tiny, highly compressible files through.
	ratioSlack = 1 << 20
	// zstdMaxWindow and zstdMaxMemory bound the zstd decoder.
	zstdMaxWindow = 8 << 20
	zstdMaxMemory = 64 << 20
)

// Compression of a file, detected from its magic bytes.
const (
	compNone = ""
	compGzip = "gzip"
	compZstd = "zstd"
)

// identity is what identifies an open file: (dev, inode), its size and
// mtime at open, the SHA-256 of its first PrefixBytes bytes (fewer for a
// smaller file), and its compression.
type identity struct {
	dev, ino    uint64
	size        int64
	mtime       time.Time
	prefixLen   int
	prefixHash  string
	compression string
}

// identify reads f's identity. It reads at most PrefixBytes bytes.
func identify(f *os.File) (identity, error) {
	fi, err := f.Stat()
	if err != nil {
		return identity{}, err
	}
	dev, ino, err := devIno(fi)
	if err != nil {
		return identity{}, err
	}
	id := identity{dev: dev, ino: ino, size: fi.Size(), mtime: fi.ModTime()}
	n := int(min(fi.Size(), PrefixBytes))
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return identity{}, err
	}
	buf = buf[:got]
	h := sha256.Sum256(buf)
	id.prefixLen, id.prefixHash = got, hex.EncodeToString(h[:])
	switch {
	case len(buf) >= 2 && buf[0] == 0x1f && buf[1] == 0x8b:
		id.compression = compGzip
	case len(buf) >= 4 && buf[0] == 0x28 && buf[1] == 0xb5 && buf[2] == 0x2f && buf[3] == 0xfd:
		id.compression = compZstd
	}
	return id, nil
}

// hashPrefix returns the SHA-256 of f's first n bytes, or false when f is
// shorter.
func hashPrefix(f *os.File, n int) (string, bool) {
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, 0)
	if got < n || err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:]), true
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

var errRatio = fmt.Errorf("compressed file expands more than %d:1", MaxRatio)

// ratioReader stops a decompressed stream that expands beyond MaxRatio.
type ratioReader struct {
	r   io.Reader
	in  *countingReader
	out int64
}

func (r *ratioReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	r.out += int64(n)
	if r.out > MaxRatio*r.in.n+ratioSlack {
		return n, errRatio
	}
	return n, err
}

// stream is a decompressed (or plain) byte stream of an open file, with the
// bytes it processed counted: read from the file, plus decompressed bytes.
type stream struct {
	io.Reader
	in    *countingReader
	ratio *ratioReader
	close func()
}

// openStream returns f's content from offset off of the decompressed
// stream. For a plain file it seeks; for a compressed one it decompresses
// from the start and discards up to off, checking ctx every discardStep
// bytes.
func openStream(ctx context.Context, f *os.File, comp string, off int64) (*stream, error) {
	if comp == compNone {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
		in := &countingReader{r: f}
		return &stream{Reader: in, in: in, close: func() {}}, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	in := &countingReader{r: bufio.NewReaderSize(f, 64<<10)}
	var dec io.Reader
	var closeFn func()
	switch comp {
	case compGzip:
		gz, err := gzip.NewReader(in)
		if err != nil {
			return nil, err
		}
		dec, closeFn = gz, func() { gz.Close() }
	case compZstd:
		zr, err := zstd.NewReader(in, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(zstdMaxMemory))
		if err != nil {
			return nil, err
		}
		dec, closeFn = zr, zr.Close
	default:
		return nil, fmt.Errorf("unknown compression %q", comp)
	}
	rr := &ratioReader{r: dec, in: in}
	s := &stream{Reader: rr, in: in, ratio: rr, close: closeFn}
	for left := off; left > 0; left -= discardStep {
		if err := ctx.Err(); err != nil {
			closeFn()
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, rr, min(left, discardStep)); err != nil {
			closeFn()
			if errors.Is(err, io.EOF) {
				return nil, errShort
			}
			return nil, err
		}
	}
	return s, nil
}

// discardStep is how many decompressed bytes are discarded between two
// cancellation checks.
const discardStep = 1 << 20

var errShort = errors.New("stream shorter than planned")

// processed returns the bytes the stream cost so far: file bytes read, plus
// decompressed bytes for a compressed file.
func (s *stream) processed() int64 {
	if s.ratio != nil {
		return s.in.n + s.ratio.out
	}
	return s.in.n
}
