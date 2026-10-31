// Package journald is the journald log source: systemd journal files under
// the console's read-only journal roots, read by the pure-Go reader in
// ./journal, with a field allowlist applied before any value is read.
//
// Only MESSAGE (decoded by the source's parser, masked as text downstream)
// and the allowed fields (the trusted journald fields, the human's trusted
// fields and the reviewed allow list) ever leave this package. Core dumps,
// command lines, executables, audit and OBJECT_ fields and binary values are
// dropped whatever the lists say.
package journald

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal"
)

// Kind is the source kind.
const Kind = "journald"

const (
	// GranuleEntries is the size of a plan granule: fixed groups of
	// entries of one file, in file order, independent of any query.
	GranuleEntries = 256
	// MaxAround bounds before and after of Around.
	MaxAround = 50
	// catalogTTL is how long a file listing is reused.
	catalogTTL = 10 * time.Second
	// message is the field holding the text.
	message = "MESSAGE"
)

// Trusted are the journald fields locklog always serves (after the
// detectors), besides MESSAGE.
var Trusted = []string{"CODE_FILE", "CODE_FUNC", "CODE_LINE", "CONTAINER_NAME", "PRIORITY",
	"SYSLOG_IDENTIFIER", "_HOSTNAME", "_PID", "_SYSTEMD_UNIT", "_TRANSPORT"}

// NeverServed reports a field no list can make this source serve: core
// dumps, command lines, executables, audit records and OBJECT_ fields.
func NeverServed(name string) bool {
	for _, p := range []string{"COREDUMP", "_COREDUMP", "_AUDIT_", "AUDIT_", "OBJECT_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return strings.HasSuffix(name, "CMDLINE") || strings.HasSuffix(name, "_EXE") || name == "EXE"
}

// Options configure a journald source.
type Options struct {
	Name string
	// Roots are the journal roots mounted read-only (/var/log/journal,
	// /run/log/journal): each holds <machine-id>/ directories.
	Roots []string
	// Units are globs on _SYSTEMD_UNIT; empty serves every unit.
	Units []string
	// Trusted are the human's trusted fields beyond Trusted; Allow the
	// reviewed fields served (masked) besides MESSAGE and the trusted ones.
	Trusted []string
	Allow   []string
	// UserJournals also serves user-*.journal files.
	UserJournals bool
	// Parser decodes MESSAGE (format of the message).
	Parser *parse.Parser
	// Now is the clock (tests).
	Now func() time.Time
}

// Source is a journald source. It is safe for concurrent use.
type Source struct {
	opts    Options
	fields  map[string]bool // served besides MESSAGE
	trusted map[string]bool

	mu      sync.Mutex
	catalog []fileInfo
	catTime time.Time
}

type dirEntry struct {
	name     string
	dir, reg bool
}

// fileInfo is one journal file.
type fileInfo struct {
	root, dir, name string
	stream          string // "journal:" + file id
	size            int64
	head            journal.Header
}

// New validates opts.
func New(opts Options) (*Source, error) {
	if opts.Parser == nil {
		return nil, errors.New("journald source: no parser")
	}
	if len(opts.Roots) == 0 {
		return nil, errors.New("journald source: no journal root")
	}
	for _, r := range opts.Roots {
		if !path.IsAbs(r) || path.Clean(r) != r || r == "/" {
			return nil, fmt.Errorf("journald source: invalid root %q", r)
		}
	}
	for _, u := range opts.Units {
		if _, err := path.Match(u, ""); err != nil {
			return nil, fmt.Errorf("journald source: invalid unit glob %q", u)
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	fields, trusted := map[string]bool{}, map[string]bool{}
	for _, f := range append(slices.Clone(Trusted), opts.Trusted...) {
		if f != message && !NeverServed(f) {
			fields[f], trusted[f] = true, true
		}
	}
	for _, f := range opts.Allow {
		if f != message && !NeverServed(f) {
			fields[f] = true
		}
	}
	return &Source{opts: opts, fields: fields, trusted: trusted}, nil
}

// Name returns the source name.
func (s *Source) Name() string { return s.opts.Name }

// Kind returns "journald".
func (s *Source) Kind() string { return Kind }

func machineID(name string) bool {
	if len(name) != 32 {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil && strings.ToLower(name) == name
}

// journalFile reports whether name is a journal file the source serves.
func (s *Source) journalFile(name string) bool {
	base := strings.TrimSuffix(name, "~")
	if !strings.HasSuffix(base, ".journal") {
		return false
	}
	stem := strings.TrimSuffix(base, ".journal")
	switch {
	case stem == "system" || strings.HasPrefix(stem, "system@"):
		return true
	case strings.HasPrefix(stem, "user-"):
		return s.opts.UserJournals
	}
	return false
}

// files lists the journal files, newest first (by their newest entry).
func (s *Source) files(ctx context.Context) ([]fileInfo, error) {
	s.mu.Lock()
	if s.catalog != nil && s.opts.Now().Sub(s.catTime) < catalogTTL {
		c := s.catalog
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	var out []fileInfo
	seen := map[string]bool{}
	for _, root := range s.opts.Roots {
		dirs, err := listDir(root, "")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("journald source %s: cannot list a journal root", s.opts.Name)
		}
		for _, d := range dirs {
			if !d.dir || !machineID(d.name) {
				continue
			}
			ents, err := listDir(root, d.name)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !e.reg || !s.journalFile(e.name) {
					continue
				}
				fi, err := s.stat(root, d.name, e.name)
				if err != nil || seen[fi.stream] {
					continue // unreadable, not a journal, or a duplicate id
				}
				seen[fi.stream] = true
				out = append(out, fi)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].head.TailRealtime != out[j].head.TailRealtime {
			return out[i].head.TailRealtime > out[j].head.TailRealtime
		}
		return out[i].name < out[j].name
	})
	s.mu.Lock()
	s.catalog, s.catTime = out, s.opts.Now()
	s.mu.Unlock()
	return out, nil
}

func (s *Source) stat(root, dir, name string) (fileInfo, error) {
	f, jf, size, err := openJournal(root, dir, name)
	if err != nil {
		return fileInfo{}, err
	}
	defer f.Close()
	defer jf.Close()
	h := jf.Header()
	return fileInfo{root: root, dir: dir, name: name, size: size, head: h,
		stream: streamID(h)}, nil
}

func openJournal(root, dir, name string) (*os.File, *journal.File, int64, error) {
	f, err := openBeneath(root, dir, name)
	if err != nil {
		return nil, nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	jf, err := journal.Open(f, st.Size())
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	return f, jf, st.Size(), nil
}

// open opens the file of a stream, by its file id (a file keeps its id when
// journald renames it on rotation).
func (s *Source) open(ctx context.Context, stream string) (*os.File, *journal.File, error) {
	for attempt := 0; attempt < 2; attempt++ {
		files, err := s.files(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, fi := range files {
			if fi.stream != stream {
				continue
			}
			f, jf, _, err := openJournal(fi.root, fi.dir, fi.name)
			if err == nil && streamID(jf.Header()) == stream {
				return f, jf, nil
			}
			if err == nil {
				jf.Close()
				f.Close()
			}
		}
		s.mu.Lock()
		s.catalog = nil // renamed or vacuumed since the listing: list again
		s.mu.Unlock()
	}
	return nil, nil, source.ErrNotFound
}

// granule is one plan granule of a file: entries [first, last] by index,
// with their offsets.
type granule struct {
	index         int64
	first, last   uint64 // entry offsets
	n             int64
	headRealtime  uint64
	nextRealtime  uint64 // realtime of the next granule's first entry, 0 at the end
	monotonicTime bool
}

// granules lists the fixed granules of an open file. Reading them touches
// only entry-array objects and entry headers.
func granules(jf *journal.File) ([]granule, bool, error) {
	var out []granule
	var prevRT uint64
	ordered := true
	err := jf.EntryOffsets(func(i, off uint64) bool {
		g := int64(i / GranuleEntries)
		if i%GranuleEntries == 0 {
			h, err := jf.Head(off)
			if err != nil {
				return false
			}
			if h.Realtime < prevRT {
				ordered = false
			}
			prevRT = h.Realtime
			if n := len(out); n > 0 {
				out[n-1].nextRealtime = h.Realtime
			}
			out = append(out, granule{index: g, first: off, headRealtime: h.Realtime})
		}
		out[len(out)-1].last = off
		out[len(out)-1].n++
		return true
	})
	return out, ordered, err
}

// Plan returns, per file, one chunk of the consecutive granules that may
// hold entries of r. A file's time bounds come from its header and its
// granules' first entries; a file whose granule timestamps go backwards
// (clock changes) is never narrowed below the file.
func (s *Source) Plan(ctx context.Context, r source.Range, _ source.Selector) (source.Byteplan, error) {
	files, err := s.files(ctx)
	if err != nil {
		return source.Byteplan{}, err
	}
	var plan source.Byteplan
	for _, fi := range files {
		if err := ctx.Err(); err != nil {
			return source.Byteplan{}, err
		}
		f, jf, size, err := openJournal(fi.root, fi.dir, fi.name)
		if err != nil {
			continue
		}
		gs, ordered, err := granules(jf)
		h := jf.Header()
		jf.Close()
		f.Close()
		if err != nil || len(gs) == 0 {
			continue
		}
		if ordered && h.HeadRealtime != 0 && h.TailRealtime != 0 &&
			!r.Overlaps(usec(h.HeadRealtime), usec(h.TailRealtime)) {
			continue
		}
		var run []source.Granule
		var runStart uint64
		var runEnd uint64
		flush := func() {
			if len(run) == 0 {
				return
			}
			plan.Chunks = append(plan.Chunks, source.Chunk{Source: s.opts.Name, Stream: fi.stream,
				Version: fi.stream, Granules: run, Bytes: int64(runEnd - runStart)})
			run = nil
		}
		for i, g := range gs {
			if ordered && !granuleMayHold(g, r) {
				flush()
				continue
			}
			if len(run) == 0 {
				runStart = g.first
			}
			// A granule costs the bytes from its first entry to the next
			// granule's (entries and the data objects written with
			// them): a function of the file, not of any query.
			if i+1 < len(gs) {
				runEnd = gs[i+1].first
			} else {
				runEnd = uint64(size)
			}
			run = append(run, source.Granule{Start: g.index * GranuleEntries, End: g.index*GranuleEntries + g.n})
		}
		flush()
	}
	return plan, nil
}

// granuleMayHold: entries of granule g lie in [headRealtime, nextRealtime]
// when the file's granules are ordered (the last granule is open-ended).
func granuleMayHold(g granule, r source.Range) bool {
	if !usec(g.headRealtime).Before(r.To) {
		return false
	}
	if g.nextRealtime != 0 && usec(g.nextRealtime).Before(r.From) {
		return false
	}
	return true
}

func usec(us uint64) time.Time { return time.UnixMicro(int64(us)).UTC() }

// Scan reads the entries of a chunk: entry indexes [Start, End) of its
// granules, in file order.
func (s *Source) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	if len(c.Granules) == 0 {
		return nil, errors.New("journald source: empty chunk")
	}
	f, jf, err := s.open(ctx, c.Stream)
	if err != nil {
		return nil, err
	}
	var offs []uint64
	start, end := c.Start(), c.End()
	err = jf.EntryOffsets(func(i, off uint64) bool {
		if int64(i) >= end {
			return false
		}
		if int64(i) >= start {
			offs = append(offs, off)
		}
		return true
	})
	if err == nil && int64(len(offs)) != end-start {
		err = source.ErrStale
	}
	if err != nil {
		jf.Close()
		f.Close()
		if errors.Is(err, journal.ErrCorrupt) {
			return nil, source.ErrStale
		}
		return nil, err
	}
	return &iter{ctx: ctx, src: s, f: f, jf: jf, stream: c.Stream, offs: offs, base: start, start: start}, nil
}

type iter struct {
	ctx       context.Context
	src       *Source
	f         *os.File
	jf        *journal.File
	stream    string
	offs      []uint64
	base      int64 // entry index of offs[0]
	start     int64 // entry index of the chunk's first granule
	i         int
	processed int64
}

func (it *iter) Next() (source.RawRecord, error) {
	for it.i < len(it.offs) {
		if err := it.ctx.Err(); err != nil {
			return source.RawRecord{}, err
		}
		idx := it.base + int64(it.i)
		off := it.offs[it.i]
		it.i++
		rec, ok, n, err := it.src.read(it.jf, it.stream, off)
		it.processed += n
		if err != nil {
			continue // a corrupt entry is skipped, as journalctl does
		}
		if !ok {
			continue // a unit not served
		}
		rec.Granule = int((idx - it.start) / GranuleEntries)
		return rec, nil
	}
	return source.RawRecord{}, io.EOF
}

func (it *iter) Processed() int64 { return it.processed }

func (it *iter) Close() error {
	it.jf.Close()
	return it.f.Close()
}

// read reads one entry: the record, whether its unit is served, and the
// bytes processed (the entry's object size).
func (s *Source) read(jf *journal.File, stream string, off uint64) (source.RawRecord, bool, int64, error) {
	e, err := jf.Entry(off, s.keep)
	if err != nil {
		return source.RawRecord{}, false, 0, err
	}
	n := int64(e.Size)
	var msg string
	var hasMsg bool
	var members []parse.Member
	unit := ""
	for _, fl := range e.Fields {
		if fl.Name == message {
			if !hasMsg { // a repeated MESSAGE: the first one is the message
				msg, hasMsg = text(fl.Value), true
			}
			continue
		}
		v, ok := fieldValue(fl.Value)
		if !ok {
			continue // binary values are never served
		}
		if fl.Name == "_SYSTEMD_UNIT" && unit == "" {
			unit = v
		}
		members = append(members, parse.Member{Key: fl.Name, Value: parse.Value{Kind: parse.KindString, Str: v}})
	}
	if !s.unitServed(unit) {
		return source.RawRecord{}, false, n, nil
	}
	ev := s.opts.Parser.Line(msg)
	// Fields decoded from the message text come after the journal's. A
	// message key named like a served journal field (a JSON message with
	// "_SYSTEMD_UNIT") would pass for the trusted one: it is dropped.
	for _, m := range ev.Fields {
		if !s.fields[m.Key] && m.Key != message {
			members = append(members, m)
		}
	}
	ev.Fields = members
	ev.Time, ev.HasTime, ev.Inherited = usec(e.Realtime), true, false
	ev.TimeKey = "__REALTIME_TIMESTAMP"
	if ev.MessageKey == "" {
		ev.MessageKey = message
	}
	ev.Offset, ev.Length = int64(off), n
	if e.Dropped > 0 {
		ev.Truncated = true
	}
	return source.RawRecord{Ref: source.RawRef{Source: s.opts.Name, Stream: stream, Offset: int64(off), Length: n}, Event: ev}, true, n, nil
}

// keep is the allowlist, applied to each field's name before its value is
// read.
func (s *Source) keep(name string) bool {
	return name == message || s.fields[name]
}

func (s *Source) unitServed(unit string) bool {
	if len(s.opts.Units) == 0 {
		return true
	}
	for _, g := range s.opts.Units {
		if ok, _ := path.Match(g, unit); ok {
			return true
		}
	}
	return false
}

// text is MESSAGE as text: invalid UTF-8 and NUL become U+FFFD (other
// control characters are left to the masker and the renderers).
func text(b []byte) string {
	s := strings.ToValidUTF8(string(b), "�")
	return strings.ReplaceAll(s, "\x00", "�")
}

// fieldValue accepts a printable UTF-8 value (tab allowed); binary values
// are refused.
func fieldValue(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	for _, r := range string(b) {
		if r < ' ' && r != '\t' || r >= 0x7f && r <= 0x9f {
			return "", false
		}
	}
	return string(b), true
}

// Reread returns the entry at ref.Offset in ref's stream, or ErrStale when
// the file is gone or no longer holds that entry there.
func (s *Source) Reread(ctx context.Context, ref source.RawRef) (source.RawRecord, error) {
	f, jf, err := s.open(ctx, ref.Stream)
	if errors.Is(err, source.ErrNotFound) {
		return source.RawRecord{}, source.ErrStale
	}
	if err != nil {
		return source.RawRecord{}, err
	}
	defer f.Close()
	defer jf.Close()
	idx, ok := entryIndex(jf, uint64(ref.Offset))
	if !ok {
		return source.RawRecord{}, source.ErrStale
	}
	rec, served, n, err := s.read(jf, ref.Stream, uint64(ref.Offset))
	if err != nil || !served || n != ref.Length {
		return source.RawRecord{}, source.ErrStale
	}
	rec.Ref = ref
	rec.Granule = int(idx % GranuleEntries) // its granule in a chunk of one
	return rec, nil
}

// entryIndex finds the index of the entry at off in the file's entry order.
func entryIndex(jf *journal.File, off uint64) (int64, bool) {
	var idx int64 = -1
	jf.EntryOffsets(func(i, o uint64) bool {
		if o == off {
			idx = int64(i)
			return false
		}
		return o < off // entry offsets grow with the index
	})
	return idx, idx >= 0
}

// Around returns up to before served entries before ref, ref's entry and up
// to after served entries after it, from ref's file.
func (s *Source) Around(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, error) {
	before, after = max(0, min(before, MaxAround)), max(0, min(after, MaxAround))
	f, jf, err := s.open(ctx, ref.Stream)
	if errors.Is(err, source.ErrNotFound) {
		return nil, source.ErrStale
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer jf.Close()
	var offs []uint64
	at := -1
	if err := jf.EntryOffsets(func(_, o uint64) bool {
		offs = append(offs, o)
		if o == uint64(ref.Offset) {
			at = len(offs) - 1
		}
		// Units not served may sit between: keep up to 4× after
		// beyond ref.
		return at < 0 || len(offs)-at <= 4*after+1
	}); err != nil {
		return nil, source.ErrStale
	}
	if at < 0 {
		return nil, source.ErrStale
	}
	var back []source.RawRecord
	for i := at - 1; i >= 0 && len(back) < before; i-- {
		if rec, ok, _, err := s.read(jf, ref.Stream, offs[i]); err == nil && ok {
			back = append(back, rec)
		}
	}
	slices.Reverse(back)
	self, ok, _, err := s.read(jf, ref.Stream, offs[at])
	if err != nil || !ok {
		return nil, source.ErrStale
	}
	out := append(back, self)
	for i, n := at+1, 0; i < len(offs) && n < after; i++ {
		if rec, ok, _, err := s.read(jf, ref.Stream, offs[i]); err == nil && ok {
			out = append(out, rec)
			n++
		}
	}
	return out, nil
}

// Describe returns the source's fields, file count, size and time bounds.
// It reads headers only.
func (s *Source) Describe(ctx context.Context) (source.Schema, error) {
	files, err := s.files(ctx)
	if err != nil {
		return source.Schema{}, err
	}
	sch := source.Schema{Kind: Kind, Format: s.opts.Parser.Options().Format, Streams: len(files)}
	names := []string{message}
	for f := range s.fields {
		names = append(names, f)
	}
	sort.Strings(names[1:])
	for _, n := range names {
		sch.Fields = append(sch.Fields, source.FieldInfo{Name: n, Trusted: s.trusted[n]})
	}
	for _, fi := range files {
		sch.Bytes += fi.size
		if h := fi.head.HeadRealtime; h != 0 && (sch.Oldest.IsZero() || usec(h).Before(sch.Oldest)) {
			sch.Oldest = usec(h)
		}
		if t := fi.head.TailRealtime; t != 0 && usec(t).After(sch.Newest) {
			sch.Newest = usec(t)
		}
	}
	return sch, nil
}

// streamID names a file's stream by its file id, which journald keeps when
// it renames the file on rotation.
func streamID(h journal.Header) string { return "journal:" + hex.EncodeToString(h.FileID[:]) }
