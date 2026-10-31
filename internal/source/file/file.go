// Package file is the file log source: globs of plain, gzip and zstd files
// under the console's read-only mount roots, read beneath their root without
// following symbolic links, planned in fixed granules, and indexed locally.
package file

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Kind is the source kind.
const Kind = "file"

const (
	// mtimeSlack: a file last written more than this before a range
	// starts holds no record of the range.
	mtimeSlack = 5 * time.Minute
	// compressedEstimate estimates the decompressed size of a compressed
	// file not yet measured, per compressed byte.
	compressedEstimate = 8
	// maxLeadingUntimed bounds the records held back at a granule's start
	// to give them the time of the first timed record.
	maxLeadingUntimed = 64
	// catalogTTL is how long a file listing is reused by Scan/Reread.
	catalogTTL = 10 * time.Second
)

// Options configure a file source.
type Options struct {
	Name      string
	Paths     []string // absolute globs
	Recursive bool
	// Roots are the read-only mount roots; every path must be under one.
	Roots  []string
	Parser *parse.Parser
	// Trusted are the trusted low-cardinality fields the index counts.
	Trusted []string
	// Index is the local index store (nil: no index).
	Index *index.Store
	// Sensitive reports a trusted value a detector flags: it is indexed
	// as index.Redacted.
	Sensitive func(field, value string) bool
	// Now is the clock (tests).
	Now func() time.Time
}

// Source is a file source. It is safe for concurrent use.
type Source struct {
	opts Options

	mu      sync.Mutex
	gens    map[[2]uint64]gen // streams seen, by (dev, inode)
	failed  map[string]bool   // compressed streams whose indexing failed
	catalog []fileInfo
	catTime time.Time
}

type gen struct {
	id         string
	prefixLen  int
	prefixHash string
}

// fileInfo is one matched file.
type fileInfo struct {
	m  match
	id identity
	// stream is the stream id: dev-inode-generation.
	stream string
	gen    string
}

// New validates opts.
func New(opts Options) (*Source, error) {
	if opts.Parser == nil {
		return nil, errors.New("file source: no parser")
	}
	if len(opts.Paths) == 0 {
		return nil, errors.New("file source: no paths")
	}
	for _, p := range opts.Paths {
		if err := checkPattern(p, opts.Recursive); err != nil {
			return nil, err
		}
		if _, err := rootOf(opts.Roots, p); err != nil {
			return nil, err
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.Trusted = slices.Clone(opts.Trusted)
	sort.Strings(opts.Trusted)
	return &Source{opts: opts, gens: map[[2]uint64]gen{}, failed: map[string]bool{}}, nil
}

// Name returns the source name.
func (s *Source) Name() string { return s.opts.Name }

// Kind returns "file".
func (s *Source) Kind() string { return Kind }

// files lists the matched files, newest first (mtime, then path).
func (s *Source) files(ctx context.Context) ([]fileInfo, error) {
	var ms []match
	seen := map[string]bool{}
	for _, p := range s.opts.Paths {
		got, err := expand(s.opts.Roots, p, s.opts.Recursive)
		if err != nil {
			return nil, err
		}
		for _, m := range got {
			if !seen[m.path()] {
				seen[m.path()] = true
				ms = append(ms, m)
			}
		}
	}
	var out []fileInfo
	for _, m := range ms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := openBeneath(m.root, m.rel)
		if err != nil {
			continue // vanished or unreadable since the listing
		}
		fi, err := s.identifyOpen(f, m)
		f.Close()
		if err != nil {
			continue
		}
		out = append(out, fi)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].id.mtime.Equal(out[j].id.mtime) {
			return out[i].id.mtime.After(out[j].id.mtime)
		}
		return out[i].m.rel > out[j].m.rel
	})
	// One stream once: a hard link, or a file renamed during the listing,
	// is the same stream under two paths.
	seenStream := map[string]bool{}
	uniq := out[:0]
	for _, fi := range out {
		if !seenStream[fi.stream] {
			seenStream[fi.stream] = true
			uniq = append(uniq, fi)
		}
	}
	out = uniq
	s.mu.Lock()
	live := map[[2]uint64]bool{}
	for _, fi := range out {
		live[[2]uint64{fi.id.dev, fi.id.ino}] = true
	}
	for k := range s.gens {
		if !live[k] {
			delete(s.gens, k) // forgotten: a file seen again is a new stream
		}
	}
	s.catalog, s.catTime = out, s.opts.Now()
	s.mu.Unlock()
	return out, nil
}

// identifyOpen identifies an open file and resolves its stream generation:
// the same (dev, inode) whose earlier prefix still hashes the same is the
// same stream (it grew); otherwise it is a new stream and its old index is
// dropped.
func (s *Source) identifyOpen(f *os.File, m match) (fileInfo, error) {
	id, err := identify(f)
	if err != nil {
		return fileInfo{}, err
	}
	same := func(plen int, phash string) bool {
		if plen > id.prefixLen {
			return false
		}
		if plen == id.prefixLen {
			return phash == id.prefixHash
		}
		h, ok := hashPrefix(f, plen)
		return ok && h == phash
	}
	k := [2]uint64{id.dev, id.ino}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.gens[k]
	if ok && !same(g.prefixLen, g.prefixHash) {
		ok = false
	}
	if !ok && s.opts.Index != nil {
		stale := false
		s.opts.Index.With(s.opts.Name, id.dev, id.ino, func(st *index.Stream) *index.Stream {
			switch {
			case st == nil:
			case same(st.PrefixLen, st.PrefixHash):
				g, ok = gen{id: st.Gen, prefixLen: st.PrefixLen, prefixHash: st.PrefixHash}, true
			default:
				stale = true // the inode holds another stream now
			}
			return nil
		})
		if stale {
			s.opts.Index.Delete(s.opts.Name, id.dev, id.ino)
		}
	}
	if !ok {
		// A new stream: a random generation, so that a stream that
		// replaced another on the same inode (copytruncate, an inode
		// reused) never takes its id, its refs or its index.
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return fileInfo{}, err
		}
		g = gen{id: hex.EncodeToString(b[:])}
	}
	g.prefixLen, g.prefixHash = id.prefixLen, id.prefixHash
	s.gens[k] = g
	stream := strconv.FormatUint(id.dev, 16) + "-" + strconv.FormatUint(id.ino, 16) + "-" + g.id
	return fileInfo{m: m, id: id, stream: stream, gen: g.id}, nil
}

// openStreamFile finds and opens the file of a stream: from the cached
// listing first, then, when that file changed (rotation), from a new one.
func (s *Source) openStreamFile(ctx context.Context, stream string) (*os.File, fileInfo, error) {
	fi, err := s.lookup(ctx, stream)
	if err == nil {
		if f, now, err := s.open(fi); err == nil {
			return f, now, nil
		}
	}
	if _, err := s.files(ctx); err != nil {
		return nil, fileInfo{}, err
	}
	if fi, err = s.lookup(ctx, stream); err != nil {
		return nil, fileInfo{}, err
	}
	return s.open(fi)
}

// lookup finds the file of a stream, from the cached listing when fresh.
func (s *Source) lookup(ctx context.Context, stream string) (fileInfo, error) {
	s.mu.Lock()
	cat, fresh := s.catalog, s.opts.Now().Sub(s.catTime) < catalogTTL
	s.mu.Unlock()
	if fresh {
		for _, fi := range cat {
			if fi.stream == stream {
				return fi, nil
			}
		}
	}
	cat, err := s.files(ctx)
	if err != nil {
		return fileInfo{}, err
	}
	for _, fi := range cat {
		if fi.stream == stream {
			return fi, nil
		}
	}
	return fileInfo{}, source.ErrNotFound
}

// open opens fi's file again and checks it is still the same stream.
func (s *Source) open(fi fileInfo) (*os.File, fileInfo, error) {
	f, err := openBeneath(fi.m.root, fi.m.rel)
	if err != nil {
		return nil, fileInfo{}, source.ErrStale
	}
	now, err := s.identifyOpen(f, fi.m)
	if err != nil || now.stream != fi.stream {
		f.Close()
		return nil, fileInfo{}, source.ErrStale
	}
	return f, now, nil
}

// streamIndex returns a snapshot of the stream's index, or nil when the
// index is missing or was built for other fields.
func (s *Source) streamIndex(fi fileInfo) (fields []string, size int64, granules map[int64]*index.Granule) {
	size = -1
	if s.opts.Index == nil {
		return nil, size, nil
	}
	s.opts.Index.With(s.opts.Name, fi.id.dev, fi.id.ino, func(st *index.Stream) *index.Stream {
		if st == nil || st.Gen != fi.gen || !s.sameFields(st) {
			return nil
		}
		fields, size = slices.Clone(st.Fields), st.Size
		granules = make(map[int64]*index.Granule, len(st.Granules))
		for n, g := range st.Granules {
			granules[n] = g // stored granules are immutable
		}
		return nil
	})
	return fields, size, granules
}

// sameFields reports whether st indexes the source's trusted fields.
func (s *Source) sameFields(st *index.Stream) bool {
	all := append(slices.Clone(st.Fields), st.Dropped...)
	sort.Strings(all)
	return slices.Equal(all, s.opts.Trusted)
}

// streamSize returns the length of fi's stream: the file size for a plain
// file, the measured decompressed size for a compressed one (-1 unknown).
func streamSize(fi fileInfo, indexed int64) int64 {
	if fi.id.compression == compNone {
		return fi.id.size
	}
	return indexed
}

// usable reports whether an indexed granule describes the stream as it is
// now: a sealed granule, or the tail granule while the stream has not grown.
func usable(g *index.Granule, size int64) bool {
	return g != nil && (g.Sealed || g.End == size)
}

// granuleBounds returns granule n's offsets in a stream of size bytes.
func granuleBounds(n, size int64) (int64, int64) {
	return n * source.GranuleBytes, min((n+1)*source.GranuleBytes, size)
}

// Plan returns the chunks of the files that may hold records of r matching
// sel. Granules of the local index are filtered by their time span and,
// when every selector field is indexed, by their counts; other granules are
// all included.
func (s *Source) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	files, err := s.files(ctx)
	if err != nil {
		return source.Byteplan{}, err
	}
	var plan source.Byteplan
	for _, fi := range files {
		if fi.id.mtime.Before(r.From.Add(-mtimeSlack)) {
			continue
		}
		fields, isize, gs := s.streamIndex(fi)
		size := streamSize(fi, isize)
		ver := strconv.FormatInt(fi.id.size, 10)
		if size < 0 {
			// Compressed, never measured: one open-ended granule.
			plan.Chunks = append(plan.Chunks, source.Chunk{Source: s.opts.Name, Stream: fi.stream, Version: ver,
				Granules: []source.Granule{{Start: 0, End: math.MaxInt64}},
				Bytes:    fi.id.size*compressedEstimate + fi.id.size})
			continue
		}
		var run []source.Granule
		flush := func() {
			if len(run) == 0 {
				return
			}
			c := source.Chunk{Source: s.opts.Name, Stream: fi.stream, Version: ver, Granules: run}
			c.Bytes = c.End() - c.Start()
			if fi.id.compression != compNone {
				c.Bytes = c.End() + fi.id.size // decompress from the start
			}
			plan.Chunks = append(plan.Chunks, c)
			run = nil
		}
		n := (size + source.GranuleBytes - 1) / source.GranuleBytes
		for i := int64(0); i < n; i++ {
			start, end := granuleBounds(i, size)
			g := source.Granule{Start: start, End: end}
			if ig := gs[i]; usable(ig, size) {
				g.Indexed, g.Records = true, ig.Records
				g.From, g.To, _ = ig.Span()
				if !granuleMayMatch(ig, fields, r, sel) {
					flush()
					continue
				}
			}
			run = append(run, g)
		}
		flush()
	}
	return plan, nil
}

// granuleMayMatch reports whether an indexed granule may hold a record of r
// matching sel.
func granuleMayMatch(g *index.Granule, fields []string, r source.Range, sel source.Selector) bool {
	from, to, timed := g.Span()
	if !timed && len(g.Untimed) == 0 {
		return false // no record at all
	}
	if timed && !r.Overlaps(from, to) && len(g.Untimed) == 0 {
		return false
	}
	if !selectorIndexed(sel, fields) {
		return true
	}
	names := termFields(sel)
	match := func(cs []index.Count) bool {
		for _, c := range cs {
			// A redacted or overflowing value is unknown: it may
			// match.
			if unknown(fields, c.Vals, names) || sel.Match(tupleMap(fields, c.Vals)) {
				return true
			}
		}
		return false
	}
	for _, m := range g.Minutes {
		if r.Overlaps(time.Unix(m.M*60, 0), time.Unix(m.M*60+59, 999999999)) && match(m.Counts) {
			return true
		}
	}
	return match(g.Untimed)
}

func selectorIndexed(sel source.Selector, fields []string) bool {
	for _, t := range sel.Terms {
		if !slices.Contains(fields, t.Field) {
			return false
		}
	}
	return true
}

// termFields returns the fields a selector's terms name.
func termFields(sel source.Selector) []string {
	var out []string
	for _, t := range sel.Terms {
		out = append(out, t.Field)
	}
	return out
}

// unknown reports whether a tuple holds, for one of names, a value the index
// does not know (index.Redacted: a detector flagged it; index.Other: the
// minute had too many tuples). Such a tuple may match any term on that
// field, and cannot be counted by it.
func unknown(fields, vals, names []string) bool {
	for i, f := range fields {
		if (vals[i] == index.Redacted || vals[i] == index.Other) && slices.Contains(names, f) {
			return true
		}
	}
	return false
}

// tupleMap maps fields to a tuple's values, leaving absent fields out.
func tupleMap(fields, vals []string) map[string]string {
	m := make(map[string]string, len(fields))
	for i, f := range fields {
		if vals[i] != index.Absent {
			m[f] = vals[i]
		}
	}
	return m
}

// Scan returns the records of a chunk.
func (s *Source) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	if len(c.Granules) == 0 {
		return nil, errors.New("file source: empty chunk")
	}
	f, fi, err := s.openStreamFile(ctx, c.Stream)
	if err != nil {
		return nil, err
	}
	if fi.id.compression == compNone && fi.id.size < c.End() && c.End() != math.MaxInt64 {
		f.Close()
		return nil, source.ErrStale // truncated since the plan
	}
	it, err := s.newIter(ctx, f, fi, c.Start(), c.End())
	if err != nil {
		f.Close()
		return nil, err
	}
	return it, nil
}

// iter reads the records of the granules of [start, end) of a stream.
type iter struct {
	ctx   context.Context
	src   *Source
	f     *os.File
	fi    fileInfo
	st    *stream
	lr    *parse.LineReader
	end   int64 // exclusive end of the last granule (MaxInt64: to EOF)
	gran  int64 // current granule number
	r     *parse.Reader
	held  []parse.Event // leading untimed records of the granule
	queue []source.RawRecord
	eof   bool
}

// newIter positions a stream at start, a granule boundary: the line that
// straddles it belongs to the previous granule and is skipped.
func (s *Source) newIter(ctx context.Context, f *os.File, fi fileInfo, start, end int64) (*iter, error) {
	open := start
	if start > 0 {
		open = start - 1
	}
	st, err := openStream(f, fi.id.compression, open)
	if err != nil {
		if errors.Is(err, errShort) {
			return nil, source.ErrStale
		}
		return nil, fmt.Errorf("file source: %w", err)
	}
	lr := parse.NewLineReader(st, open)
	if start > 0 {
		// Skip through the first "\n" at or after start-1.
		if _, err := lr.Next(); err != nil && !errors.Is(err, io.EOF) {
			st.close()
			return nil, fmt.Errorf("file source: %w", err)
		}
	}
	it := &iter{ctx: ctx, src: s, f: f, fi: fi, st: st, end: end, lr: lr}
	it.gran = lr.Offset() / source.GranuleBytes
	it.nextSection()
	return it, nil
}

func (it *iter) nextSection() {
	_, gend := granuleBounds(it.gran, math.MaxInt64)
	gend = min(gend, it.end)
	it.r = it.src.opts.Parser.NewSectionReader(it.lr, gend)
}

// Next returns the next record.
func (it *iter) Next() (source.RawRecord, error) {
	for {
		if len(it.queue) > 0 {
			rec := it.queue[0]
			it.queue = it.queue[1:]
			return rec, nil
		}
		if it.eof {
			return source.RawRecord{}, io.EOF
		}
		if err := it.ctx.Err(); err != nil {
			return source.RawRecord{}, err
		}
		ev, err := it.r.Next()
		if errors.Is(err, io.EOF) {
			it.release(time.Time{}, false)
			if it.lr.Offset() >= it.end || it.atEOF() {
				it.eof = true
				continue
			}
			it.gran = it.lr.Offset() / source.GranuleBytes
			it.nextSection()
			continue
		}
		if err != nil {
			if errors.Is(err, errRatio) {
				return source.RawRecord{}, fmt.Errorf("file source: %w", err)
			}
			return source.RawRecord{}, fmt.Errorf("file source: read: %w", err)
		}
		if !ev.HasTime && !ev.Inherited && len(it.held) < maxLeadingUntimed {
			it.held = append(it.held, ev)
			continue
		}
		if ev.HasTime && !ev.Inherited {
			it.release(ev.Time, true)
		} else {
			it.release(time.Time{}, false)
		}
		it.queue = append(it.queue, it.record(ev))
	}
}

// atEOF reports whether the line reader is exhausted.
func (it *iter) atEOF() bool {
	l, err := it.lr.Next()
	if err != nil {
		return true
	}
	it.lr.Unread(l)
	return false
}

// release queues the held leading records, giving them t when ok.
func (it *iter) release(t time.Time, ok bool) {
	for _, ev := range it.held {
		if ok {
			ev.Time, ev.Inherited = t, true
		}
		it.queue = append(it.queue, it.record(ev))
	}
	it.held = it.held[:0]
}

func (it *iter) record(ev parse.Event) source.RawRecord {
	return source.RawRecord{
		Ref:     source.RawRef{Source: it.src.opts.Name, Stream: it.fi.stream, Offset: ev.Offset, Length: ev.Length},
		Event:   ev,
		Granule: int(ev.Offset / source.GranuleBytes),
	}
}

// Processed returns the bytes processed so far.
func (it *iter) Processed() int64 { return it.st.processed() }

// Close releases the file.
func (it *iter) Close() error {
	it.st.close()
	return it.f.Close()
}

// Reread returns the record at ref.
func (s *Source) Reread(ctx context.Context, ref source.RawRef) (source.RawRecord, error) {
	if ref.Source != s.opts.Name || ref.Offset < 0 || ref.Length <= 0 {
		return source.RawRecord{}, source.ErrStale
	}
	f, fi, err := s.openStreamFile(ctx, ref.Stream)
	if err != nil {
		return source.RawRecord{}, err
	}
	defer f.Close()
	st, err := openStream(f, fi.id.compression, ref.Offset)
	if err != nil {
		return source.RawRecord{}, source.ErrStale
	}
	defer st.close()
	lr := parse.NewLineReader(st, ref.Offset)
	ev, err := s.opts.Parser.NewSectionReader(lr, ref.Offset+ref.Length).Next()
	if err != nil || ev.Offset != ref.Offset || ev.Length != ref.Length {
		return source.RawRecord{}, source.ErrStale
	}
	return source.RawRecord{Ref: ref, Event: ev, Granule: int(ref.Offset / source.GranuleBytes)}, nil
}

// MaxAround bounds before and after of Around.
const MaxAround = 50

// Around returns up to before records before ref, ref's record and up to
// after records after it, reading back at most 16 granules.
func (s *Source) Around(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, error) {
	before, after = max(0, min(before, MaxAround)), max(0, min(after, MaxAround))
	n := ref.Offset / source.GranuleBytes
	for _, back := range []int64{1, 4, 16} {
		recs, enough, err := s.around(ctx, ref, max(0, n-back), before, after)
		if err != nil {
			return nil, err
		}
		if enough || n-back <= 0 || back == 16 {
			return recs, nil
		}
	}
	return nil, nil // unreachable
}

func (s *Source) around(ctx context.Context, ref source.RawRef, fromGranule int64, before, after int) ([]source.RawRecord, bool, error) {
	f, fi, err := s.openStreamFile(ctx, ref.Stream)
	if err != nil {
		return nil, false, err
	}
	it, err := s.newIter(ctx, f, fi, fromGranule*source.GranuleBytes, math.MaxInt64)
	if err != nil {
		f.Close()
		return nil, false, err
	}
	defer it.Close()
	var prev []source.RawRecord
	var out []source.RawRecord
	found := false
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if !found {
			if rec.Ref.Offset == ref.Offset {
				if rec.Ref.Length != ref.Length {
					return nil, false, source.ErrStale
				}
				found = true
				out = append(prev, rec)
				if after == 0 {
					break
				}
				continue
			}
			if rec.Ref.Offset > ref.Offset {
				return nil, false, source.ErrStale
			}
			prev = append(prev, rec)
			if len(prev) > before {
				prev = prev[1:]
			}
			continue
		}
		out = append(out, rec)
		if len(out)-len(prev)-1 >= after {
			break
		}
	}
	if !found {
		return nil, false, source.ErrStale
	}
	return out, len(prev) >= before || fromGranule == 0, nil
}

// Describe returns the source's schema: streams, sizes, the index coverage
// and the trusted fields with their indexed values.
func (s *Source) Describe(ctx context.Context) (source.Schema, error) {
	files, err := s.files(ctx)
	if err != nil {
		return source.Schema{}, err
	}
	sch := source.Schema{Kind: Kind, Format: s.opts.Parser.Options().Format, Streams: len(files)}
	values := map[string]map[string]bool{}
	dropped := map[string]bool{}
	cov := s.coverage(files)
	sch.IndexedFrom, sch.FullyIndexed = cov.indexedFrom, cov.full
	for _, fi := range files {
		fields, isize, gs := s.streamIndex(fi)
		if size := streamSize(fi, isize); size >= 0 {
			sch.Bytes += size
		} else {
			sch.Bytes += fi.id.size * compressedEstimate
		}
		for _, g := range gs {
			if from, to, ok := g.Span(); ok {
				if sch.Oldest.IsZero() || from.Before(sch.Oldest) {
					sch.Oldest = from
				}
				if to.After(sch.Newest) {
					sch.Newest = to
				}
			}
			for _, m := range g.Minutes {
				for _, c := range m.Counts {
					for i, f := range fields {
						if v := c.Vals[i]; v != index.Absent && v != index.Other && v != index.Redacted {
							if values[f] == nil {
								values[f] = map[string]bool{}
							}
							values[f][v] = true
						}
					}
				}
			}
		}
		for _, f := range s.opts.Trusted {
			if !slices.Contains(fields, f) && gs != nil {
				dropped[f] = true
			}
		}
	}
	for _, f := range s.opts.Trusted {
		info := source.FieldInfo{Name: f, Trusted: true}
		if !dropped[f] && len(values[f]) <= index.MaxDistinct {
			for v := range values[f] {
				info.Values = append(info.Values, v)
			}
			sort.Strings(info.Values)
		}
		sch.Fields = append(sch.Fields, info)
	}
	return sch, nil
}

type coverage struct {
	indexedFrom time.Time
	full        bool
}

// coverage walks the granules newest first (files by mtime, granules from
// the last) and returns the start of the indexed run that reaches the
// newest record.
func (s *Source) coverage(files []fileInfo) coverage {
	var c coverage
	c.full = true
	for _, fi := range files {
		_, isize, gs := s.streamIndex(fi)
		size := streamSize(fi, isize)
		if size < 0 {
			c.full = false
			return c
		}
		n := (size + source.GranuleBytes - 1) / source.GranuleBytes
		for i := n - 1; i >= 0; i-- {
			g := gs[i]
			if g == nil {
				c.full = false
				return c
			}
			if !usable(g, size) {
				// A grown tail (being indexed again) does not end the
				// run: counts send it to the residual scan.
				c.full = false
			}
			if from, _, ok := g.Span(); ok && (c.indexedFrom.IsZero() || from.Before(c.indexedFrom)) {
				c.indexedFrom = from
			}
		}
	}
	return c
}

// stringsKey joins values for map keys (length-prefixed).
func stringsKey(vals []string) string {
	var b strings.Builder
	for _, v := range vals {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}
