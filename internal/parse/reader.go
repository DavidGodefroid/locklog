package parse

import (
	"io"
	"slices"
	"strings"
	"time"
)

// Reader assembles and decodes the events of one stream. Memory is bounded by
// MaxEventBytes plus one line. It is not safe for concurrent use.
//
// Every byte of the stream is accounted for: events are returned in stream
// order, never overlap, and the bytes between two events (blank lines) are
// only those the Reader skipped. Offset reports the stream position.
type Reader struct {
	p  *Parser
	lr *LineReader

	peeks   []logical // lines read ahead, in order
	pending *assembly
	err     error

	lastTime time.Time
	hasLast  bool
	// hold is the offset of the last returned event when it ended with an
	// unterminated line (-1 otherwise): Offset stays there, so a reader
	// following a growing stream reads that event again once complete.
	hold int64
	// splitNext marks the next event as a split part (pattern mode, after
	// a full event and a skipped blank line).
	splitNext bool
}

// holdBlank holds Offset on a skipped blank line that is unterminated: the
// writer may complete it into a line that matters.
func (r *Reader) holdBlank(ln logical) {
	if ln.Unterminated {
		r.hold = ln.Offset
	}
}

// logical is a logical line: one physical line, or the partial frames of a
// framed format joined.
type logical struct {
	Line
	frame *Frame // set for a framed format
}

// assembly is an event being assembled.
type assembly struct {
	lines        []string
	size         int // bytes of text, lines joined by "\n"
	offset       int64
	length       int64
	truncated    bool
	unterminated bool
	split        bool
	format       Format // structured format of the first line, nil for free text
	frame        *Frame // frame of the first line
}

// NewReader reads events from r; base is the stream offset of r's first
// byte. A scan that starts inside a file must start at a line boundary.
func (p *Parser) NewReader(r io.Reader, base int64) *Reader {
	return &Reader{p: p, lr: NewLineReader(r, base), hold: -1}
}

// Offset returns the stream offset up to which events have been returned or
// skipped: resuming a stream at Offset (with a new Reader) yields the events
// that follow, except that a Split continuation resumed alone is not flagged
// Split. When the last event returned ends with an unterminated line (the
// stream may still be written), Offset is that event's offset.
func (r *Reader) Offset() int64 {
	switch {
	case r.pending != nil:
		return r.pending.offset
	case len(r.peeks) > 0:
		return r.peeks[0].Offset
	case r.hold >= 0:
		return r.hold
	}
	return r.lr.Offset()
}

// Next returns the next event, or io.EOF.
func (r *Reader) Next() (Event, error) {
	for {
		ln, err := r.nextLogical()
		if err != nil {
			if r.pending != nil {
				return r.emit(), nil
			}
			return Event{}, err
		}
		if strings.TrimSpace(ln.Text) == "" {
			if r.pending != nil && r.p.opts.Multiline == MultilinePattern && r.pending.format == nil {
				// In pattern mode a blank line continues the event.
				if r.fits(ln) {
					r.appendLine(ln)
					continue
				}
				// The event is full: the blank line is skipped and
				// the next continuation line starts a split part.
				ev := r.emit()
				r.splitNext = true
				r.holdBlank(ln)
				return ev, nil
			}
			if r.pending != nil {
				// A skipped blank line ends the pending event: emit it
				// first so offsets stay ordered.
				ev := r.emit()
				r.holdBlank(ln)
				return ev, nil
			}
			r.holdBlank(ln)
			continue // blank line between events: skipped
		}
		if r.pending != nil && r.continues(ln) {
			if r.fits(ln) {
				r.appendLine(ln)
				continue
			}
			// The event is full: emit it; this line starts a split
			// continuation.
			ev := r.emit()
			r.start(ln, true)
			return ev, nil
		}
		if r.pending != nil {
			r.peeks = append([]logical{ln}, r.peeks...)
			return r.emit(), nil
		}
		r.start(ln, false)
		if r.pending.format != nil || r.p.opts.Multiline == MultilineNone {
			return r.emit(), nil
		}
	}
}

// nextLogical returns the peeked line or reads one, joining partial frames.
func (r *Reader) nextLogical() (logical, error) {
	if len(r.peeks) > 0 {
		ln := r.peeks[0]
		r.peeks = r.peeks[1:]
		return ln, nil
	}
	if r.err != nil {
		return logical{}, r.err
	}
	l, err := r.lr.Next()
	if err != nil {
		r.err = err
		return logical{}, err
	}
	if r.p.framer == nil {
		return logical{Line: l}, nil
	}
	fr, ok := r.p.framer.Unwrap(l.Text, &r.p.opts)
	if !ok {
		return logical{Line: l}, nil // not a frame: free text
	}
	// A Framer is a plug-in: its output is capped and validated again.
	var cut bool
	fr.Text, cut = capText([]byte(fr.Text), MaxLineBytes)
	out := logical{Line: l, frame: &fr}
	out.Truncated = out.Truncated || cut
	// The payload is joined in a buffer capped at MaxLineBytes (linear
	// in the number of frames).
	var buf []byte
	open := false // the run was still partial at the end of the stream
	for fr.Partial {
		l2, err := r.lr.Next()
		if err != nil {
			r.err = err
			open = true
			break
		}
		next, ok := r.p.framer.Unwrap(l2.Text, &r.p.opts)
		if !ok {
			// A non-frame line ends the partial run; it is read
			// again as the next logical line.
			r.peeks = append(r.peeks, logical{Line: l2})
			break
		}
		next.Text = validText([]byte(next.Text))
		out.Length += l2.Length
		out.Truncated = out.Truncated || l2.Truncated
		out.Unterminated = l2.Unterminated
		if buf == nil {
			buf = append(make([]byte, 0, len(fr.Text)+len(next.Text)), fr.Text...)
		}
		if room := MaxLineBytes - len(buf); room > 0 {
			if len(next.Text) > room {
				buf = append(buf, cutUTF8([]byte(next.Text), room)...)
				out.Truncated = true
			} else {
				buf = append(buf, next.Text...)
			}
		} else if next.Text != "" {
			out.Truncated = true
		}
		fr.Partial = next.Partial
	}
	if buf != nil {
		out.frame.Text = string(buf)
	}
	if open {
		// The rest of the run may still be written: hold the event.
		out.Unterminated = true
	}
	out.frame.Partial = false
	out.Text = out.frame.Text
	return out, nil
}

// continues reports whether ln joins the pending event.
func (r *Reader) continues(ln logical) bool {
	if r.pending.format != nil {
		return false
	}
	switch r.p.opts.Multiline {
	case MultilineNone:
		return false
	case MultilinePattern:
		return !r.p.start.MatchString(ln.Text)
	}
	t := ln.Text
	if t == "" {
		return false
	}
	if t[0] == ' ' || t[0] == '\t' {
		return true
	}
	return strings.HasPrefix(t, "Caused by:") || strings.HasPrefix(t, "Suppressed:")
}

func (r *Reader) fits(ln logical) bool {
	return len(r.pending.lines) < MaxEventLines && r.pending.size+1+len(ln.Text) <= MaxEventBytes
}

func (r *Reader) start(ln logical, split bool) {
	a := &assembly{
		lines:        []string{ln.Text},
		size:         len(ln.Text),
		offset:       ln.Offset,
		length:       ln.Length,
		truncated:    ln.Truncated,
		split:        split,
		unterminated: ln.Unterminated,
		frame:        ln.frame,
	}
	// A split continuation is free text; so is a line that would be a
	// continuation after any free-text line (indented in indent mode, not
	// matching the start pattern in pattern mode), so that a reader
	// resumed there agrees with one that read through.
	var continuation bool
	switch r.p.opts.Multiline {
	case MultilineIndent:
		continuation = ln.Text != "" && (ln.Text[0] == ' ' || ln.Text[0] == '\t')
	case MultilinePattern:
		continuation = !r.p.start.MatchString(ln.Text)
	}
	if r.splitNext && continuation {
		a.split = true
	}
	r.splitNext = false
	if !a.split && !continuation {
		a.format = r.p.structured(ln.Text)
	}
	r.pending = a
}

func (r *Reader) appendLine(ln logical) {
	a := r.pending
	a.lines = append(a.lines, ln.Text)
	a.size += 1 + len(ln.Text)
	a.length = ln.Offset + ln.Length - a.offset
	a.truncated = a.truncated || ln.Truncated
	a.unterminated = ln.Unterminated
}

func (r *Reader) emit() Event {
	a := r.pending
	r.pending = nil
	text := strings.Join(a.lines, "\n")
	ev := r.p.decode(text, a.format)
	ev.Raw = text
	ev.Offset = a.offset
	ev.Length = a.length
	ev.Lines = len(a.lines)
	ev.Truncated = a.truncated
	ev.Split = a.split
	ev.Unterminated = a.unterminated
	r.hold = -1
	if a.unterminated {
		r.hold = a.offset
	}
	if a.frame != nil {
		ev.Attrs = a.frame.Attrs
		if a.frame.HasTime {
			// The runtime's timestamp is authoritative for ordering;
			// a payload timestamp stays in the payload text/fields.
			if ev.timeMember != nil {
				ev.Fields = slices.Insert(slices.Clone(ev.Fields), min(ev.timePos, len(ev.Fields)), *ev.timeMember)
			}
			if ev.Format == "plain" && ev.HasTime {
				// Keep the payload's leading timestamp in the
				// message.
				ev.Message = text
			}
			ev.Time, ev.HasTime, ev.TimeKey, ev.timeMember = a.frame.Time, true, "", nil
		}
	}
	if ev.HasTime {
		r.lastTime, r.hasLast = ev.Time, true
	} else if r.hasLast {
		ev.Time, ev.Inherited = r.lastTime, true
	}
	return ev
}
