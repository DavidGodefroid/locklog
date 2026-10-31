package file

import (
	"context"
	"errors"
	"io"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// IndexStep indexes granules not yet in the local index, newest first:
// files by mtime, and within a plain file from its last granule backwards,
// so that "when did it start" over recent data is answered from the index
// as early as possible. A compressed file is indexed in one forward pass.
// It processes about maxBytes (a compressed file may exceed it) and reports
// the bytes processed and whether nothing is left to index.
func (s *Source) IndexStep(ctx context.Context, maxBytes int64) (int64, bool, error) {
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
			if isize >= 0 && complete(gs, isize) {
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
			if usable(gs[i], size) {
				continue
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
		}
		st.PrefixLen, st.PrefixHash = fi.id.prefixLen, fi.id.prefixHash
		if size >= 0 {
			st.Size = size
		}
		for _, g := range gs {
			st.Put(g)
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
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return it.Processed(), err
		}
		b.Add(rec.Event)
	}
	s.store(fi, -1, []index.Granule{b.Finish(n, start, end, end == (n+1)*source.GranuleBytes)})
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
	builders := map[int64]*index.Builder{}
	for {
		rec, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return it.Processed(), err
		}
		g := rec.Ref.Offset / source.GranuleBytes
		if builders[g] == nil {
			builders[g] = index.NewBuilder(s.fields(), s.opts.Sensitive)
		}
		builders[g].Add(rec.Event)
	}
	size := it.lr.Offset()
	// Every granule is indexed, empty ones included, so the whole stream
	// is covered.
	var out []index.Granule
	for n := int64(0); n*source.GranuleBytes < size; n++ {
		b := builders[n]
		if b == nil {
			b = index.NewBuilder(s.fields(), s.opts.Sensitive)
		}
		start, end := granuleBounds(n, size)
		out = append(out, b.Finish(n, start, end, true))
	}
	s.store(fi, size, out)
	return it.Processed(), nil
}

func (s *Source) fields() []string { return s.opts.Trusted }

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
	plan, err := s.Plan(ctx, q.Range, q.Selector)
	if err != nil {
		return CountResult{}, err
	}
	var res CountResult
	acc := map[string]*CountRow{}
	for _, c := range plan.Chunks {
		fi, err := s.lookup(ctx, c.Stream)
		if err != nil {
			return CountResult{}, err
		}
		fields, _, gs := s.streamIndex(fi)
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
			if !g.Indexed || ig == nil {
				rest = append(rest, g)
				continue
			}
			flush()
			if !selectorIndexed(q.Selector, fields) || !selectorIndexed(source.Selector{Terms: byTerms(q.By)}, fields) {
				return CountResult{}, ErrNotIndexable
			}
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
	res.IndexedFrom = s.coverage(files).indexedFrom
	return res, nil
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
