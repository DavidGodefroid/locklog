package parse

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Format decodes the text of one event.
type Format interface {
	// Name is the configuration name of the format.
	Name() string
	// Detect reports whether a line is in this format; "auto" tries the
	// registered detectable formats in priority order.
	Detect(line string) bool
	// Decode decodes an event's text. It fills Format, Time, Fields,
	// Message and the key names; the reader fills the position. It
	// returns false when the text is not in this format.
	Decode(text string, o *Options) (Event, bool)
}

// Framer is implemented by formats that wrap each application line in a
// container frame (CRI, docker json-file): the frame carries the runtime's
// timestamp, the stream, and whether the line was split by the runtime
// ("partial"). The reader joins partial frames into one logical line, then
// decodes the payload with "auto".
type Framer interface {
	Format
	Unwrap(line string, o *Options) (Frame, bool)
}

// Frame is the content of one framed line.
type Frame struct {
	Text    string
	Time    time.Time
	HasTime bool
	Partial bool
	// Attrs are the frame's own fields (stream, ...), trusted metadata of
	// the runtime, kept apart from the payload's fields.
	Attrs []Member
}

var (
	regMu    sync.RWMutex
	registry = map[string]Format{}
	// autoOrder lists the formats "auto" tries, by priority.
	autoOrder []autoEntry
)

type autoEntry struct {
	prio int
	f    Format
}

// Register adds a format. prio orders it for "auto" (lower first); a negative
// prio keeps it out of "auto". Registering a name twice panics.
func Register(f Format, prio int) {
	regMu.Lock()
	defer regMu.Unlock()
	name := f.Name()
	if _, dup := registry[name]; dup || name == "auto" || name == "" {
		panic("parse: format registered twice or reserved: " + name)
	}
	registry[name] = f
	if prio >= 0 {
		autoOrder = append(autoOrder, autoEntry{prio, f})
		sort.SliceStable(autoOrder, func(i, j int) bool { return autoOrder[i].prio < autoOrder[j].prio })
	}
}

// Formats returns the registered format names plus "auto", sorted.
func Formats() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := []string{"auto"}
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func init() {
	Register(jsonFormat{}, 10)
	Register(logfmtFormat{}, 20)
	Register(combinedFormat{}, 30)
	Register(syslogFormat{}, 40)
	Register(criFormat{}, -1)
	Register(dockerJSONFormat{}, -1)
	Register(plainFormat{}, -1)
}

// Multiline modes.
const (
	// MultilineIndent (default) joins a line that starts with a space or a
	// tab, or with "Caused by:" / "Suppressed:", to the free-text event
	// before it (stack traces). Structured events are never joined, and a
	// line that starts with a space or a tab is always free text (so that
	// a reader resumed on it agrees with one that read through).
	MultilineIndent = "indent"
	// MultilineNone makes every line an event.
	MultilineNone = "none"
	// MultilinePattern starts an event at each line matching Start; other
	// lines join the event before them.
	MultilinePattern = "pattern"
)

// MaxPatternBytes bounds a multiline start pattern (RE2).
const MaxPatternBytes = 256

// Options configure a Parser.
type Options struct {
	// Format is a registered format name or "auto" (default).
	Format string
	// Multiline is one of the Multiline* modes (default indent).
	Multiline string
	// Start is the RE2 pattern of MultilinePattern.
	Start string
	// Location reads zone-less timestamps; nil means UTC.
	Location *time.Location
}

func (o *Options) location() *time.Location {
	if o == nil || o.Location == nil {
		return time.UTC
	}
	return o.Location
}

// Parser is a validated, immutable parsing configuration, safe for concurrent
// use.
type Parser struct {
	opts   Options
	format Format // nil for auto
	framer Framer // set when format is a Framer
	start  *regexp.Regexp
}

// New validates opts.
func New(opts Options) (*Parser, error) {
	p := &Parser{opts: opts}
	if p.opts.Format == "" {
		p.opts.Format = "auto"
	}
	if p.opts.Format != "auto" {
		regMu.RLock()
		f, ok := registry[p.opts.Format]
		regMu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("parse: unknown format %q (known: %s)", p.opts.Format, strings.Join(Formats(), ", "))
		}
		p.format = f
		if fr, ok := f.(Framer); ok {
			p.framer = fr
		}
	}
	switch p.opts.Multiline {
	case "":
		p.opts.Multiline = MultilineIndent
	case MultilineIndent, MultilineNone:
	case MultilinePattern:
		if p.opts.Start == "" || len(p.opts.Start) > MaxPatternBytes {
			return nil, fmt.Errorf("parse: multiline pattern needs a start pattern of 1..%d bytes", MaxPatternBytes)
		}
		re, err := regexp.Compile(p.opts.Start)
		if err != nil {
			return nil, fmt.Errorf("parse: multiline start pattern: %w", err)
		}
		p.start = re
	default:
		return nil, fmt.Errorf("parse: unknown multiline mode %q", p.opts.Multiline)
	}
	if p.opts.Multiline != MultilinePattern && p.opts.Start != "" {
		return nil, fmt.Errorf("parse: a start pattern needs multiline = %q", MultilinePattern)
	}
	return p, nil
}

// Options returns the normalised options.
func (p *Parser) Options() Options { return p.opts }

// structured returns the structured format that decodes a line, or nil when
// the line is free text for this parser.
func (p *Parser) structured(line string) Format {
	if p.format != nil && p.framer == nil {
		if _, isPlain := p.format.(plainFormat); isPlain {
			return nil
		}
		// An explicit format decodes any line it accepts (a one-pair
		// logfmt line too), not only those "auto" would detect.
		if p.format.Detect(line) {
			return p.format
		}
		if _, ok := p.format.Decode(line, &p.opts); ok {
			return p.format
		}
		return nil
	}
	regMu.RLock()
	defer regMu.RUnlock()
	for _, e := range autoOrder {
		if _, isFramer := e.f.(Framer); isFramer {
			continue // frames are never nested
		}
		if e.f.Detect(line) {
			return e.f
		}
	}
	return nil
}

// decode decodes an event's text; f is the structured format chosen for its
// first line (nil for free text). It never fails: text that does not decode
// becomes a plain event, with Fallback set when a structured format was
// expected.
func (p *Parser) decode(text string, f Format) Event {
	if f != nil {
		if ev, ok := f.Decode(text, &p.opts); ok {
			return ev
		}
	}
	ev, _ := plainFormat{}.Decode(text, &p.opts)
	expected := p.format != nil && p.framer == nil
	if _, isPlain := p.format.(plainFormat); isPlain {
		expected = false
	}
	ev.Fallback = f != nil || expected
	return ev
}

// Line decodes one already-delimited record (a Loki entry, a journald
// MESSAGE): no line splitting, no multiline assembly; invalid UTF-8 is
// replaced, then the text is cut at MaxEventLines lines and MaxEventBytes
// bytes, like an assembled event.
func (p *Parser) Line(text string) Event {
	length := int64(len(text))
	text, truncated := capText([]byte(text), MaxEventBytes)
	if n := strings.Count(text, "\n"); n >= MaxEventLines {
		i, cut := 0, 0
		for k := 0; k < MaxEventLines; k++ {
			j := strings.IndexByte(text[i:], '\n')
			cut = i + j
			i = cut + 1
		}
		text, truncated = text[:cut], true
	}
	ev := p.decode(text, p.structured(text))
	ev.Raw = text
	ev.Length = length
	ev.Lines = strings.Count(text, "\n") + 1
	ev.Truncated = truncated
	return ev
}

// plainFormat is free text: an optional leading timestamp (bare or in
// brackets) and an optional level word after it, kept as the parser-known
// field "level". The message is the text after the timestamp.
type plainFormat struct{}

func (plainFormat) Name() string { return "plain" }

func (plainFormat) Detect(string) bool { return true }

func (plainFormat) Decode(text string, o *Options) (Event, bool) {
	ev := Event{Format: "plain", Message: text}
	if t, rest, ok := leadingTime(text, o.location()); ok {
		ev.Time, ev.HasTime = t, true
		ev.Message = rest
	}
	if lvl, ok := leadingLevel(ev.Message); ok {
		ev.Fields = []Member{{Key: "level", Value: Value{Kind: KindString, Str: lvl}}}
	}
	return ev, true
}

// levels maps level words to their canonical names.
var levels = map[string]string{
	"trace": "trace", "debug": "debug", "dbg": "debug",
	"info": "info", "inf": "info", "notice": "notice",
	"warn": "warn", "warning": "warn", "wrn": "warn",
	"error": "error", "err": "error", "eror": "error",
	"crit": "critical", "critical": "critical",
	"fatal": "fatal", "ftl": "fatal", "panic": "panic",
	"alert": "alert", "emerg": "emergency", "emergency": "emergency",
}

// leadingLevel recognises a level word at the start of s: bare, followed by
// ':' or in brackets ("ERROR", "[warn]", "error:").
func leadingLevel(s string) (string, bool) {
	tok := s
	if i := strings.IndexAny(tok, " \t"); i >= 0 {
		tok = tok[:i]
	}
	if len(tok) > 12 {
		return "", false
	}
	tok = strings.TrimSuffix(tok, ":")
	if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") && len(tok) >= 2 {
		tok = tok[1 : len(tok)-1]
	}
	lvl, ok := levels[strings.ToLower(tok)]
	return lvl, ok
}
