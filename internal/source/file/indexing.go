package file

import (
	"context"
	"errors"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// IndexStep indexes granules not yet in the local index, newest first:
// files by mtime, and within a plain file from its last granule backwards,
// so that "when did it start" over recent data is answered from the index
// as early as possible. A compressed file is indexed in one forward pass,
// which may exceed maxBytes (by up to the decompression ratio cap): the
// scheduler's token bucket then goes negative and waits it out.
// It processes about maxBytes (a compressed file may exceed it) and reports
// the bytes processed and whether nothing is left to index.
//
// With upkeep false, only backfill runs: streams and granules never indexed.
// Upkeep is re-indexing a grown tail granule; the scheduler pauses it while
// agents are busy.
func (s *Source) IndexStep(ctx context.Context, maxBytes int64, upkeep bool) (int64, bool, error) {
	if s.opts.Index == nil {
		return 0, true, nil
	}
	files, err := s.files(ctx)
	if err != nil {
		return 0, false, err
	}
	var done int64
	for _, fi := range files {
		_, isize, gs := s.streamIndex(fi)
		if fi.id.compression != compNone {
			s.mu.Lock()
			failed := s.failed[failKey(fi)]
			s.mu.Unlock()
			if failed || isize >= 0 && complete(gs, isize) || !upkeep && isize >= 0 {
				continue
			}
			if done >= maxBytes {
				return done, false, nil
			}
			n, err := s.indexCompressed(ctx, fi)
			done += n
			if err != nil {
				return done, false, err
			}
			continue
		}
		size := fi.id.size
		count := (size + source.GranuleBytes - 1) / source.GranuleBytes
		for i := count - 1; i >= 0; i-- {
			if usable(gs[i], size) || !upkeep && gs[i] != nil {
				continue // indexed (or, without upkeep, indexed once)
			}
			if done >= maxBytes {
				return done, false, nil
			}
			n, err := s.indexPlain(ctx, fi, i)
			done += n
			if err != nil {
				return done, false, err
			}
		}
	}
	return done, true, nil
}

func complete(gs map[int64]*index.Granule, size int64) bool {
	n := (size + source.GranuleBytes - 1) / source.GranuleBytes
	for i := int64(0); i < n; i++ {
		if !usable(gs[i], size) {
			return false
		}
	}
	return true
}

// store records granules of a stream, creating or replacing its index when
// missing, of another generation or built for other fields.
func (s *Source) store(fi fileInfo, size int64, gs []index.Granule) {
	s.opts.Index.With(s.opts.Name, fi.id.dev, fi.id.ino, func(st *index.Stream) *index.Stream {
		if st == nil || st.Gen != fi.gen || !s.sameFields(st) {
			st = index.NewStream(fi.id.dev, fi.id.ino, fi.gen, s.opts.Trusted)
			st.Compression = fi.id.compression
			st.Tag = s.opts.Tag
		}
		st.PrefixLen, st.PrefixHash = fi.id.prefixLen, fi.id.prefixHash
		if fi.id.compression != compNone {
			st.FileSize = fi.id.size
		}
		if size >= 0 {
			st.Size = size
		}
		for _, g := range gs {
			st.PutBuilt(g, s.opts.Trusted)
		}
		return st
	})
}

// indexPlain indexes granule n of a plain file.
func (s *Source) indexPlain(ctx context.Context, fi fileInfo, n int64) (int64, error) {
	f, fi, err := s.open(fi)
	if err != nil {
		return 0, nil // changed since the listing: the next step sees it
	}
	size := fi.id.size
	start, end := granuleBounds(n, size)
	it, err := s.newIter(ctx, f, fi, start, end)
	if err != nil {
		f.Close()
		return 0, err
	}
	defer it.Close()
	b := index.NewBuilder(s.fields(), s.opts.Sensitive)
	var lastEnd int64
	lastOpen := false
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return it.Processed(), err
		}
		b.Add(rec.Event)
		lastEnd, lastOpen = rec.Ref.Offset+rec.Ref.Length, rec.Event.Unterminated
	}
	// Sealed only when the granule is whole and its last record was
	// complete before the end of the file: a line still being written
	// across the boundary is indexed again once complete.
	// The reader must also have reached the boundary (a line starting at
	// or after it): a held blank or partial tail line starting before it is
	// not a record yet.
	sealed := end == (n+1)*source.GranuleBytes && !lastOpen && lastEnd <= size && it.r.Offset() >= end
	s.store(fi, -1, []index.Granule{b.Finish(n, start, end, sealed)})
	return it.Processed(), nil
}

// indexCompressed indexes a compressed file in one pass and records its
// decompressed size.
func (s *Source) indexCompressed(ctx context.Context, fi fileInfo) (int64, error) {
	f, fi, err := s.open(fi)
	if err != nil {
		return 0, nil
	}
	it, err := s.newIter(ctx, f, fi, 0, math.MaxInt64)
	if err != nil {
		f.Close()
		return 0, err
	}
	defer it.Close()
	// Records come in stream order: each granule is finished as soon as
	// the next starts (memory: one builder). Every granule is indexed,
	// empty ones included, so the whole stream is covered.
	var out []index.Granule
	cur := int64(0)
	b := index.NewBuilder(s.fields(), s.opts.Sensitive)
	finish := func(upTo int64) {
		for ; cur < upTo; cur++ {
			start, end := granuleBounds(cur, math.MaxInt64)
			out = append(out, b.Finish(cur, start, end, true))
			b = index.NewBuilder(s.fields(), s.opts.Sensitive)
		}
	}
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.mu.Lock()
			s.failed[failKey(fi)] = true // retried only once the file changes
			s.mu.Unlock()
			return it.Processed(), err
		}
		finish(rec.Ref.Offset / source.GranuleBytes)
		b.Add(rec.Event)
	}
	size := it.lr.Offset()
	finish((size + source.GranuleBytes - 1) / source.GranuleBytes)
	s.store(fi, size, out)
	return it.Processed(), nil
}

func (s *Source) fields() []string { return s.opts.Trusted }

// failKey identifies a compressed file's state: a failed indexing (a bomb, a
// file still being written) is retried once its size or mtime changes.
func failKey(fi fileInfo) string {
	return fi.stream + "/" + strconv.FormatInt(fi.id.size, 10) + "/" + strconv.FormatInt(fi.id.mtime.UnixNano(), 10)
}

// ErrNotIndexable, CountQuery, CountRow and CountResult: see package source.
var ErrNotIndexable = source.ErrNotIndexable

type (
	CountQuery  = source.CountQuery
	CountRow    = source.CountRow
	CountResult = source.CountResult
)

// IndexCounts answers a trusted-field count from the local index, at minute
// resolution: a minute counts when its start is in the range. Granules the
// index does not hold come back as a residual plan.
func (s *Source) IndexCounts(ctx context.Context, q CountQuery) (CountResult, error) {
	if q.Bucket < 0 || q.Bucket%time.Minute != 0 {
		return CountResult{}, errors.New("file source: count bucket must be a whole number of minutes")
	}
	// The index counts whole minutes: a range that is not whole minutes
	// would count differently depending on how granules are cut.
	if !q.Range.From.Equal(q.Range.From.Truncate(time.Minute)) || !q.Range.To.Equal(q.Range.To.Truncate(time.Minute)) {
		return CountResult{}, ErrNotIndexable
	}
	plan, err := s.Plan(ctx, q.Range, q.Selector)
	if err != nil {
		return CountResult{}, err
	}
	var res CountResult
	acc := map[string]*CountRow{}
	for _, c := range plan.Chunks {
		fi, err := s.lookup(ctx, c.Stream)
		if err != nil {
			return CountResult{}, stale(err) // vanished since the plan
		}
		fields, isize, gs := s.streamIndex(fi)
		size := streamSize(fi, isize)
		var rest []source.Granule
		flush := func() {
			if len(rest) > 0 {
				rc := c
				rc.Granules = rest
				rc.Bytes = rc.End() - rc.Start()
				if fi.id.compression != compNone {
					rc.Bytes = c.Bytes
				}
				res.Residual.Chunks = append(res.Residual.Chunks, rc)
				rest = nil
			}
		}
		for _, g := range c.Granules {
			ig := gs[g.Start/source.GranuleBytes]
			// Re-checked on this snapshot: a granule re-indexed since
			// the plan is used only if it still describes the stream.
			if !g.Indexed || ig == nil || !usable(ig, size) {
				rest = append(rest, g)
				continue
			}
			if !selectorIndexed(q.Selector, fields) || !selectorIndexed(source.Selector{Terms: byTerms(q.By)}, fields) {
				return CountResult{}, ErrNotIndexable
			}
			// A granule with a redacted or overflowing value of a
			// counted or selected field is scanned instead.
			if granuleUnknown(ig, fields, append(termFields(q.Selector), q.By...)) {
				rest = append(rest, g)
				continue
			}
			flush()
			pos := positions(fields, q.By)
			for _, m := range ig.Minutes {
				t := time.Unix(m.M*60, 0).UTC()
				if !q.Range.Contains(t) {
					continue
				}
				b := q.Range.From
				if q.Bucket > 0 {
					b = q.Range.From.Add(t.Sub(q.Range.From) / q.Bucket * q.Bucket)
				}
				for _, cnt := range m.Counts {
					if !q.Selector.Match(tupleMap(fields, cnt.Vals)) {
						continue
					}
					vals := project(cnt.Vals, pos)
					k := b.String() + "|" + stringsKey(vals)
					if acc[k] == nil {
						acc[k] = &CountRow{Bucket: b, Vals: vals}
					}
					acc[k].N += cnt.N
				}
			}
			for _, cnt := range ig.Untimed {
				if q.Selector.Match(tupleMap(fields, cnt.Vals)) {
					res.Untimed += cnt.N
				}
			}
		}
		flush()
	}
	for _, r := range acc {
		res.Rows = append(res.Rows, *r)
	}
	sort.Slice(res.Rows, func(i, j int) bool {
		if !res.Rows[i].Bucket.Equal(res.Rows[j].Bucket) {
			return res.Rows[i].Bucket.Before(res.Rows[j].Bucket)
		}
		return slices.Compare(res.Rows[i].Vals, res.Rows[j].Vals) < 0
	})
	files, err := s.files(ctx)
	if err != nil {
		return CountResult{}, err
	}
	cov := s.coverage(files)
	res.IndexedFrom, res.IndexedUntil = cov.indexedFrom, cov.indexedUntil
	return res, nil
}

func granuleUnknown(g *index.Granule, fields, names []string) bool {
	for _, m := range g.Minutes {
		for _, c := range m.Counts {
			if unknown(fields, c.Vals, names) {
				return true
			}
		}
	}
	for _, c := range g.Untimed {
		if unknown(fields, c.Vals, names) {
			return true
		}
	}
	return false
}

func byTerms(by []string) []source.Term {
	ts := make([]source.Term, len(by))
	for i, f := range by {
		ts[i] = source.Term{Field: f}
	}
	return ts
}

func positions(fields, by []string) []int {
	pos := make([]int, len(by))
	for i, f := range by {
		pos[i] = slices.Index(fields, f)
	}
	return pos
}

func project(vals []string, pos []int) []string {
	out := make([]string, len(pos))
	for i, p := range pos {
		out[i] = vals[p]
	}
	return out
}
