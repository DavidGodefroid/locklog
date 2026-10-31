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
	for len(w) > 0 {
		if strings.HasPrefix(w, mask.Open) {
			if end := strings.Index(w, mask.Close); end >= 0 {
				ph := w[:end+len(mask.Close)]
				if i := strings.IndexByte(ph, ':'); i >= 0 {
					b.WriteString(ph[:i+1] + "…" + mask.Close)
				} else {
					b.WriteString(ph)
				}
				w = w[end+len(mask.Close):]
				continue
			}
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
	Untimed  int64 `json:"untimed,omitempty"`
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
	maxRange := e.o.Limits.LocalRange
	for _, s := range q.Sources {
		if _, ok := e.o.Sources[s]; ok && e.remote(s) {
			maxRange = min(maxRange, e.o.Limits.RemoteRange)
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
		q.offset = d
		base = q.Query
		base.From, base.To = q.From.Add(-d), q.To.Add(-d)
	}
	digest := e.queryDigest("patterns", q)
	res := PatternsResult{Epoch: e.o.Masker.Epoch(), Patterns: []PatternGroup{}}

	var f *frozen
	chunk, gran := 0, 0
	a := newAgg()
	if cursor != "" {
		var err *Error
		if f, err = e.resume(st, digest); err != nil {
			return PatternsResult{}, err
		}
		chunk, gran = st.Chunk, st.Granule
		var ok bool
		if a, ok = e.aggs.get(st.Cache); !ok {
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
		plan, err := e.planQuery(ctx, &pq, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
		if err != nil {
			return PatternsResult{}, err
		}
		if q.offset > 0 {
			bq := base
			bq.Order = "asc"
			bp, err := e.planQuery(ctx, &bq, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
			if err != nil {
				return PatternsResult{}, err
			}
			plan = withBaseline(plan, bp, compressed)
			var local, remote int64
			for _, c := range plan.Chunks {
				if e.remote(c.Source) {
					remote += c.Bytes
				} else {
					local += c.Bytes
				}
			}
			if local > e.o.Limits.LocalBytes || remote > e.o.Limits.RemoteBytes {
				return PatternsResult{}, &Error{Code: EOverBudget, Message: "the plan of the window and its baseline exceeds this call's byte budget (narrow the range or the sources, or ask for locklog_scan)",
					Estimate: &Estimate{Bytes: plan.Bytes(), Granules: plan.Granules(), Range: 2 * q.To.Sub(q.From)}}
			}
		}
		f = e.freeze(digest, plan)
	}

	sc, failures := Scanned{}, 0
	var err *Error
	chunk, gran, sc, failures, err = e.run(ctx, f.plan, chunk, gran, nil, e.callBytes(q.Sources), q.evalFactor()+1, func(raw source.RawRecord, rec mask.Record, b *budget) {
		t, timed := rec.Time()
		var bucket time.Time
		switch {
		case !timed:
		case q.Query.rangeContains(t, false):
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
			a.untimed++
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
		a.add(bucket, []*string{&p}, 1, t, true)
	})
	if err != nil {
		return PatternsResult{}, err
	}
	res.Scanned, res.MaskedFailures, res.Untimed, res.NoText = sc, failures, a.untimed, a.noText
	win, bl := map[string]*Group{}, map[string]*Group{}
	for _, g := range a.groups {
		k := *g.Key[0]
		if g.Bucket.Equal(windowBucket) {
			win[k] = g
			res.Records += g.N
		} else {
			bl[k] = g
		}
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
		for k, g := range win {
			if bl[k] == nil {
				res.New = append(res.New, group(k, g, true))
			}
		}
		res.New = topOf(res.New, func(g PatternGroup) int64 { return g.N })
		for k, bg := range bl {
			if win[k] == nil {
				z := bg.N
				res.Gone = append(res.Gone, PatternGroup{Pattern: k, BaselineN: &z, First: bg.First, Last: bg.Last})
			}
		}
		res.Gone = topOf(res.Gone, func(g PatternGroup) int64 { return *g.BaselineN })
	}
	res.Complete = chunk >= len(f.plan.Chunks)
	if !res.Complete {
		st := cursorState{Plan: f.id, Query: digest, Chunk: chunk, Granule: gran, Epoch: e.o.Masker.Epoch(), PolicyFP: e.o.PolicyFP(), Cache: e.aggs.put(a),
			From: q.From, To: q.To, Last: last}
		res.Cursor = e.seal("Lc1", st)
		// The plan holds the window, then the baseline: until the window
		// is read, coverage is the window's.
		if cu, ok := coveredUntil(f.plan, chunk, gran, q.Query); ok {
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
// or the baseline by time. A baseline chunk is split into runs of the
// granules left; a run of a compressed stream still costs its whole chunk
// (decompressing from where the chunk starts).
func withBaseline(win, base source.Byteplan, compressed func(source.Chunk) bool) source.Byteplan {
	type gk struct {
		src, stream string
		start, end  int64
	}
	seen := map[gk]bool{}
	for _, c := range win.Chunks {
		for _, g := range c.Granules {
			seen[gk{c.Source, c.Stream, g.Start, g.End}] = true
		}
	}
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
			if seen[gk{c.Source, c.Stream, g.Start, g.End}] {
				flush()
				continue
			}
			run = append(run, g)
		}
		flush()
	}
	return out
}

// String describes a pattern group (tests and status screens).
func (g PatternGroup) String() string { return fmt.Sprintf("%d %s", g.N, g.Pattern) }
