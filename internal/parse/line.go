package parse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Line is one physical line of a stream.
type Line struct {
	// Text is the line without its terminator ("\n" or "\r\n"), cut at
	// MaxLineBytes on a UTF-8 boundary, invalid UTF-8 replaced by U+FFFD.
	Text string
	// Offset is the stream offset of the line's first byte.
	Offset int64
	// Length is the number of stream bytes the line consumed, terminator
	// and dropped tail included.
	Length int64
	// Truncated is set when the line was longer than MaxLineBytes.
	Truncated bool
}

// LineReader reads bounded lines. Its memory use is bounded by MaxLineBytes
// plus the bufio buffer, whatever the input.
type LineReader struct {
	r   *bufio.Reader
	off int64
	buf []byte
}

// NewLineReader reads lines from r; base is the stream offset of r's first
// byte (non-zero when a scan starts inside a file).
func NewLineReader(r io.Reader, base int64) *LineReader {
	return &LineReader{r: bufio.NewReaderSize(r, 64<<10), off: base}
}

// Offset returns the stream offset of the next byte to read.
func (lr *LineReader) Offset() int64 { return lr.off }

// Next returns the next line, or io.EOF when the stream is exhausted. A final
// line without a terminator is returned as a line.
func (lr *LineReader) Next() (Line, error) {
	start := lr.off
	lr.buf = lr.buf[:0]
	var n int64
	truncated := false
	for {
		frag, err := lr.r.ReadSlice('\n')
		n += int64(len(frag))
		if room := MaxLineBytes + 2 - len(lr.buf); room > 0 {
			// Keep two bytes beyond the cap so a "\r\n" right at the
			// cap is still recognised as a terminator.
			if len(frag) > room {
				lr.buf = append(lr.buf, frag[:room]...)
				truncated = true
			} else {
				lr.buf = append(lr.buf, frag...)
			}
		} else if len(frag) > 0 {
			truncated = true
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if n == 0 {
				return Line{}, io.EOF
			}
			break
		}
		lr.off += n
		return Line{}, err
	}
	lr.off += n
	b := lr.buf
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) > MaxLineBytes {
		b = cutUTF8(b, MaxLineBytes)
		truncated = true
	}
	return Line{Text: validText(b), Offset: start, Length: n, Truncated: truncated}, nil
}

// cutUTF8 returns the longest prefix of b of at most n bytes that does not end
// inside a UTF-8 sequence.
func cutUTF8(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	b = b[:n]
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			return b
		}
	}
	return b
}

// validText converts b to a string with invalid UTF-8 replaced by U+FFFD.
func validText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}
