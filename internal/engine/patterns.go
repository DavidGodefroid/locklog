package engine

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Pattern limits.
const (
	DefaultTop = 20
	MaxTop     = 100
	// MaxTemplateTokens and MaxTemplateBytes bound a template: beyond, it
	// ends with TemplateCut.
	MaxTemplateTokens = 64
	MaxTemplateBytes  = 512
	// Variable replaces a variable part of a template.
	Variable = "<*>"
	// TemplateCut ends a template cut at its bounds.
	TemplateCut = "…"
)

// Template is the pattern of a masked text: a pseudonym keeps its kind and
// loses its id (⟦email:…⟧), other placeholders stay as they are, and every
// part of a word holding a digit (parts are split at = : , ; ( ) [ ] { } "
// ' / and @) becomes Variable. Words are joined by one space. It reads
// masked text only: a template carries less than the text it comes from.
// A bare placeholder equal to Other is written ⟦other:…⟧, so that a
// template is never the overflow key. It runs in time linear in its input
// and stops reading once the template is over MaxTemplateBytes.
func Template(masked string) string {
	var b strings.Builder
	words := 0
	for w := range strings.FieldsSeq(masked) {
		if words == MaxTemplateTokens {
			b.WriteString(" " + TemplateCut)
			break
		}
		if words > 0 {
			b.WriteByte(' ')
		}
		templateWord(&b, w)
		words++
		if b.Len() > MaxTemplateBytes {
			s := b.String()
			cut := MaxTemplateBytes
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			return s[:cut] + TemplateCut
		}
	}
	return b.String()
}

func templateWord(b *strings.Builder, w string) {
	// closed is false once w holds no ⟧ past the current point: every ⟦
	// left is then literal (without it, each lone ⟦ would search the rest
	// of w again: quadratic).
	closed := true
	for len(w) > 0 && b.Len() <= MaxTemplateBytes {
		if closed && strings.HasPrefix(w, mask.Open) {
			if end := strings.Index(w, mask.Close); end >= 0 {
				ph := w[:end+len(mask.Close)]
				switch i := strings.IndexByte(ph, ':'); {
				case i >= 0:
					b.WriteString(ph[:i+1] + "…" + mask.Close)
				case ph == Other:
					b.WriteString(mask.Open + "other:…" + mask.Close)
				default:
					b.WriteString(ph)
				}
				w = w[end+len(mask.Close):]
				continue
			}
			closed = false
		}
		i := 0
		for i < len(w) && !templateDelim(w[i]) && !strings.HasPrefix(w[i:], mask.Open) {
			i++
		}
		if i == 0 {
			// A delimiter, or a lone ⟦ without its ⟧.
			_, n := utf8.DecodeRuneInString(w)
			b.WriteString(w[:n])
			w = w[n:]
			continue
		}
		if strings.ContainsAny(w[:i], "0123456789") {
			b.WriteString(Variable)
		} else {
			b.WriteString(w[:i])
		}
		w = w[i:]
	}
}

func templateDelim(c byte) bool {
	return strings.IndexByte("=:,;()[]{}\"'/@", c) >= 0
}

// PatternsQuery asks for the top templates of the masked message text
// (locklog_patterns).
type PatternsQuery struct {
	Query
	// Top is the number of patterns returned (DefaultTop, at most MaxTop).
	Top int `json:"top,omitempty"`
	// Baseline, when set, is an offset ("24h"): the same window that much
	// earlier is counted too, for each pattern's baseline count and the
	// new and gone lists. It is at least the window's length (the windows
	// never overlap).
	Baseline string `json:"baseline,omitempty"`

	offset time.Duration
}

// PatternGroup is one pattern and its counts.
type PatternGroup struct {
	Pattern   string     `json:"pattern"`
	N         int64      `json:"n"`
	BaselineN *int64     `json:"baseline_n,omitempty"`
	First     *time.Time `json:"first,omitempty"`
	Last      *time.Time `json:"last,omitempty"`
}

// PatternsResult is the answer of a patterns query.
type PatternsResult struct {
	Epoch string `json:"epoch"`
	// Patterns are the top patterns of the window, most frequent first.
	Patterns []PatternGroup `json:"patterns"`
	// Distinct is the number of distinct patterns of the window, Records
	// the records counted (with a message), NoText the matching records
	// without one.
	Distinct int   `json:"distinct"`
	Records  int64 `json:"records"`
	NoText   int64 `json:"no_text,omitempty"`
	// Untimed counts the matching untimed records of the window's plan.
	Untimed int64 `json:"untimed,omitempty"`
	// Truncated is set when the window or the baseline had more distinct
	// patterns than MaxGroups (or MaxGroupBytes): the rest count under
	// Other, in their own group (counted in Distinct). New is then left
	// empty when the baseline is truncated, Gone when the window is.
	Truncated bool `json:"truncated,omitempty"`
	// With a baseline: New are the top patterns absent from it, Gone the
	// top patterns of the baseline absent from the window.
	BaselineFrom   *time.Time     `json:"baseline_from,omitempty"`
	BaselineTo     *time.Time     `json:"baseline_to,omitempty"`
	New            []PatternGroup `json:"new,omitempty"`
	Gone           []PatternGroup `json:"gone,omitempty"`
	Complete       bool           `json:"complete"`
	CoveredUntil   *time.Time     `json:"covered_until,omitempty"`
	Cursor         string         `json:"cursor,omitempty"`
	Scanned        Scanned        `json:"scanned"`
	MaskedFailures int            `json:"masked_failures,omitempty"`
}

// Bucket keys of a patterns aggregate: the window and the baseline.
var (
	windowBucket   = time.Unix(0, 0).UTC()
	baselineBucket = time.Unix(1, 0).UTC()
)

// Patterns runs a patterns query: it scans the plan of the window (and of
// the baseline), masking every record first, and groups the matching
// records' masked messages by Template. Admission, stopping points and
// cursors are those of a count: functions of the plan, never of matches.
func (e *Engine) Patterns(ctx context.Context, q PatternsQuery) (_ PatternsResult, retErr error) {
	q.Where = slices.Clone(q.Where)
	cursor := q.Cursor
	q.Cursor = ""
	if len(q.Sources) > MaxSources || len(q.Where) > MaxPredicates {
		return PatternsResult{}, refuse(EBadQuery, "", "at most %d sources and %d predicates", MaxSources, MaxPredicates)
	}
	if q.Top == 0 {
		q.Top = DefaultTop
	}
	if q.Top < 1 || q.Top > MaxTop {
		return PatternsResult{}, refuse(EBadQuery, "top", "want 1 to %d", MaxTop)
	}
	if len(q.Sources) == 0 {
		q.Sources = append([]string(nil), e.names...)
	}
	lim := e.limits(ctx)
	maxRange, remoteRange, hasRemote := lim.LocalRange, lim.RemoteRange, false
	for _, s := range q.Sources {
		if _, ok := e.o.Sources[s]; ok && e.remote(s) {
			maxRange, hasRemote = min(maxRange, remoteRange), true
		}
	}
	last := q.Last
	var st cursorState
	if cursor != "" {
		var err *Error
		if st, err = e.openCursor(cursor); err != nil {
			return PatternsResult{}, err
		}
		if err = restoreWindow(&q.Query, st); err != nil {
			return PatternsResult{}, err
		}
	}
	v := e.validator(maxRange)
	if err := v.validate(&q.Query); err != nil {
		return PatternsResult{}, err
	}
	var base Query
	if q.Baseline != "" {
		d, err := time.ParseDuration(q.Baseline)
		if err != nil || d < q.To.Sub(q.From) {
			return PatternsResult{}, refuse(EBadQuery, "baseline", "want an offset of at least the window's length (%s)", q.To.Sub(q.From))
		}
		if d > 400*24*time.Hour {
			return PatternsResult{}, refuse(EBadQuery, "baseline", "want an offset of at most 400d")
		}
		if 2*q.To.Sub(q.From) > remoteRange && hasRemote {
			return PatternsResult{}, &Error{Code: EOverBudget, Span: "baseline", Message: fmt.Sprintf("the window and its baseline are over the %s range budget of remote sources", remoteRange),
				Estimate: &Estimate{Range: 2 * q.To.Sub(q.From)}}
		}
		q.offset = d
		base = q.Query
		base.From, base.To = q.From.Add(-d), q.To.Add(-d)
	}
	digest := e.queryDigest("patterns", q)
	if cursor != "" {
		var err *Error
		if digest, err = e.scanDigest(ctx, "patterns", digest); err != nil {
			return PatternsResult{}, err
		}
	}
	res := PatternsResult{Epoch: e.o.Masker.Epoch(), Patterns: []PatternGroup{}}

	var f *frozen
	chunk, gran := 0, 0
	a := newAgg()
	a.base = newAgg()
	if cursor != "" {
		var err *Error
		if f, err = e.resume(st, digest); err != nil {
			return PatternsResult{}, err
		}
		chunk, gran = st.Chunk, st.Granule
		var ok bool
		if a, ok = e.aggs.get(st.Cache); !ok || a.base == nil {
			return PatternsResult{}, &Error{Code: EStale, Span: "cursor", Message: "the cursor expired: run the query again"}
		}
		defer func() {
			if retErr == nil {
				e.aggs.drop(st.Cache)
			}
		}()
	} else {
		pq := q.Query
		pq.Order = "asc"
		plan, err := e.planQuery(ctx, &pq, lim.RemoteBytes, lim.LocalBytes)
		if err != nil {
			return PatternsResult{}, err
		}
		if q.offset > 0 {
			bq := base
			bq.Order = "asc"
			bp, err := e.planQuery(ctx, &bq, lim.RemoteBytes, lim.LocalBytes)
			if err != nil {
				return PatternsResult{}, err
			}
			a.winChunks = len(plan.Chunks)
			plan = withBaseline(plan, bp, compressed)
			var local, remote int64
			for _, c := range plan.Chunks {
				if e.remote(c.Source) {
					remote += c.Bytes
				} else {
					local += c.Bytes
				}
			}
			if local > lim.LocalBytes || remote > lim.RemoteBytes {
				return PatternsResult{}, &Error{Code: EOverBudget, Message: "the plan of the window and its baseline exceeds this call's byte budget (narrow the range or the sources, or ask for locklog_scan)",
					Estimate: &Estimate{Bytes: plan.Bytes(), Granules: plan.Granules(), Range: 2 * q.To.Sub(q.From)}}
			}
		}
		if q.offset == 0 {
			a.winChunks = len(plan.Chunks)
		}
		var aerr error
		if f, digest, aerr = e.admitPlan(ctx, "patterns", digest, plan, false, func() []string { return scopeLines(q.Query) }); aerr != nil {
			return PatternsResult{}, aerr
		}
	}

	sc, failures := Scanned{}, 0
	var err *Error
	chunk, gran, sc, failures, err = e.run(ctx, &f, chunk, gran, nil, e.callBytes(ctx, q.Sources), q.evalFactor()+1, func(raw source.RawRecord, rec mask.Record, b *budget) {
		t, timed := rec.Time()
		var bucket time.Time
		switch {
		case !timed:
		case q.Query.rangeContains(t, false) && b.chunk < a.winChunks:
			// The window counts from its own plan only: the
			// baseline's, made by a second call, may hold a newer
			// part of a growing stream.
			bucket = windowBucket
		case q.offset > 0 && base.rangeContains(t, false):
			bucket = baselineBucket
		default:
			return
		}
		if !q.match(rec, b) {
			return
		}
		if !timed {
			// Untimed records count from the window's chunks only:
			// the baseline's would be counted on top of them.
			if b.chunk < a.winChunks {
				a.untimed++
			}
			return
		}
		m := rec.Message()
		if m == "" {
			if bucket == windowBucket {
				a.noText++
			}
			return
		}
		if b.charge(leafCost + int64(len(m))) {
			return
		}
		p := Template(m)
		if bucket == windowBucket {
			a.add(bucket, []*string{&p}, 1, t, true)
		} else {
			a.base.add(bucket, []*string{&p}, 1, t, true)
		}
	})
	if err != nil {
		return PatternsResult{}, err
	}
	res.Scanned, res.MaskedFailures, res.Untimed, res.NoText = sc, failures, a.untimed, a.noText
	res.Truncated = a.truncated || a.base.truncated
	win, bl := map[string]*Group{}, map[string]*Group{}
	for _, g := range a.groups {
		win[*g.Key[0]] = g
		res.Records += g.N
	}
	for _, g := range a.base.groups {
		bl[*g.Key[0]] = g
	}
	res.Distinct = len(win)
	group := func(k string, g *Group, withBase bool) PatternGroup {
		pg := PatternGroup{Pattern: k}
		if g != nil {
			pg.N, pg.First, pg.Last = g.N, g.First, g.Last
		}
		if withBase {
			var n int64
			if bg := bl[k]; bg != nil {
				n = bg.N
			}
			pg.BaselineN = &n
		}
		return pg
	}
	all := make([]PatternGroup, 0, len(win))
	for k, g := range win {
		all = append(all, group(k, g, q.offset > 0))
	}
	topOf := func(gs []PatternGroup, n func(PatternGroup) int64) []PatternGroup {
		sort.Slice(gs, func(i, j int) bool {
			if n(gs[i]) != n(gs[j]) {
				return n(gs[i]) > n(gs[j])
			}
			return gs[i].Pattern < gs[j].Pattern
		})
		return gs[:min(len(gs), q.Top)]
	}
	res.Patterns = topOf(all, func(g PatternGroup) int64 { return g.N })
	if q.offset > 0 {
		bf, bt := base.From, base.To
		res.BaselineFrom, res.BaselineTo = &bf, &bt
		res.New, res.Gone = []PatternGroup{}, []PatternGroup{}
		// A side past its cap holds some patterns under Other: the
		// other side's patterns cannot be said absent from it.
		for k, g := range win {
			if bl[k] == nil && k != Other && !a.base.truncated {
				res.New = append(res.New, group(k, g, true))
			}
		}
		res.New = topOf(res.New, func(g PatternGroup) int64 { return g.N })
		for k, bg := range bl {
			if win[k] == nil && k != Other && !a.truncated {
				z := bg.N
				res.Gone = append(res.Gone, PatternGroup{Pattern: k, BaselineN: &z, First: bg.First, Last: bg.Last})
			}
		}
		res.Gone = topOf(res.Gone, func(g PatternGroup) int64 { return *g.BaselineN })
	}
	res.Complete = chunk >= len(f.plan.Chunks)
	if !res.Complete {
		st := cursorState{Plan: f.id, Query: digest, Chunk: chunk, Granule: gran, Epoch: e.o.Masker.Epoch(), PolicyFP: e.o.PolicyFP(), Cache: e.aggs.put(a),
			From: q.From, To: q.To, Last: last, Scan: scanID(ctx)}
		res.Cursor = e.seal("Lc1", st)
		// The plan holds the window, then the baseline: until the window
		// is read, coverage is the window's.
		asc := q.Query
		asc.Order = "asc" // the plan is read in time order
		if chunk >= a.winChunks {
			to := q.To
			res.CoveredUntil = &to
		} else if cu, ok := coveredUntil(f.plan, chunk, gran, asc); ok {
			res.CoveredUntil = &cu
		}
	} else {
		to := q.To
		res.CoveredUntil = &to
	}
	return res, nil
}

// withBaseline appends to the window's plan the granules of the baseline's
// plan it does not hold: a granule both plans hold (an unindexed one is
// planned for any range) is read once, its records sorted into the window
// or the baseline by time. The plans are made by two calls: the last
// granule of a growing stream may differ between them ([k, size1) and
// [k, size2)), so a baseline granule is left out when it overlaps any
// window granule of its stream, not only when it equals one. A baseline
// chunk is split into runs of the granules left; a run of a compressed
// stream still costs its whole chunk (decompressing from where the chunk
// starts).
func withBaseline(win, base source.Byteplan, compressed func(source.Chunk) bool) source.Byteplan {
	inWin := windowSpans(win.Chunks)
	out := source.Byteplan{Chunks: slices.Clip(win.Chunks)}
	for _, c := range base.Chunks {
		var run []source.Granule
		flush := func() {
			if len(run) == 0 {
				return
			}
			n := source.Chunk{Source: c.Source, Stream: c.Stream, Version: c.Version, Granules: run}
			if compressed(c) || len(run) == len(c.Granules) {
				n.Bytes = c.Bytes
			} else {
				for _, g := range run {
					n.Bytes += g.Bytes
				}
			}
			out.Chunks = append(out.Chunks, n)
			run = nil
		}
		for _, g := range c.Granules {
			if inWin.overlaps(c.Source, c.Stream, g.Start, g.End) {
				flush()
				continue
			}
			run = append(run, g)
		}
		flush()
	}
	return out
}

// spans are the granule intervals of chunks, by source and stream.
type spans map[[2]string][][2]int64

func windowSpans(chunks []source.Chunk) spans {
	s := spans{}
	for _, c := range chunks {
		k := [2]string{c.Source, c.Stream}
		for _, g := range c.Granules {
			s[k] = append(s[k], [2]int64{g.Start, g.End})
		}
	}
	return s
}

// overlaps reports whether [start, end) overlaps a span of the stream.
func (s spans) overlaps(src, stream string, start, end int64) bool {
	for _, iv := range s[[2]string{src, stream}] {
		if start < iv[1] && iv[0] < end {
			return true
		}
	}
	return false
}

// String describes a pattern group (tests and status screens).
func (g PatternGroup) String() string { return fmt.Sprintf("%d %s", g.N, g.Pattern) }
