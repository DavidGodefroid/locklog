package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Count limits.
const (
	MaxBy      = 2
	MaxBuckets = 1000
	// MaxGroups bounds distinct (bucket, by) groups; beyond, records
	// count under an "⟦other⟧" key. Distinct counts are exact up to it.
	MaxGroups = 100000
	// MaxGroupBytes bounds the memory of one count's groups (keys are
	// masked values of any length): beyond, records count under
	// "⟦other⟧" as beyond MaxGroups.
	MaxGroupBytes = 8 << 20
	// groupOverhead is the memory of a group besides its key bytes.
	groupOverhead = 160
	// maxAggBytes bounds the partial counts kept between continuations,
	// in total.
	maxAggBytes = 64 << 20
)

// Other is the key of groups beyond MaxGroups or MaxGroupBytes, or of
// index overflow.
const Other = mask.Open + "other" + mask.Close

// CountQuery is a count (locklog_count).
type CountQuery struct {
	Query
	// Bucket is a duration ("5m"); empty: one bucket for the range.
	Bucket string `json:"bucket,omitempty"`
	// By groups by up to two trusted or pseudonymised line fields, and
	// ByLabels by source labels (Loki stream labels, journald and docker
	// attributes); at most MaxBy in all. A group's key holds the By
	// values, then the ByLabels values.
	By       []string `json:"by,omitempty"`
	ByLabels []string `json:"by_labels,omitempty"`
	// FirstLast adds each group's first and last timestamp.
	FirstLast bool `json:"first_last,omitempty"`

	bucket time.Duration
}

// Group is one counted group.
type Group struct {
	Bucket time.Time  `json:"bucket"`
	Key    []*string  `json:"key,omitempty"` // masked values; null when absent
	N      int64      `json:"n"`
	First  *time.Time `json:"first,omitempty"`
	Last   *time.Time `json:"last,omitempty"`
}

// CountResult is the answer of a count.
type CountResult struct {
	Epoch        string     `json:"epoch"`
	Groups       []Group    `json:"groups"`
	Untimed      int64      `json:"untimed,omitempty"`
	Complete     bool       `json:"complete"`
	CoveredUntil *time.Time `json:"covered_until,omitempty"`
	Cursor       string     `json:"cursor,omitempty"`
	Scanned      Scanned    `json:"scanned"`
	// FromIndex is set when the local index answered (part of) the
	// count; IndexedFrom is where the index starts.
	FromIndex      bool       `json:"from_index,omitempty"`
	IndexedFrom    *time.Time `json:"indexed_from,omitempty"`
	IndexedUntil   *time.Time `json:"indexed_until,omitempty"`
	MaskedFailures int        `json:"masked_failures,omitempty"`
}

// agg accumulates a count across continuations.
type agg struct {
	groups  map[string]*Group
	untimed int64
	indexed bool
	from    time.Time
	until   time.Time
	noFrom  bool
	bytes   int64 // memory of the groups (keys twice, plus overhead)
}

func newAgg() *agg { return &agg{groups: map[string]*Group{}} }

func groupKey(b time.Time, key []*string) string {
	var sb strings.Builder
	sb.WriteString(b.UTC().Format(time.RFC3339Nano))
	for _, k := range key {
		if k == nil {
			sb.WriteString("|-")
		} else {
			fmt.Fprintf(&sb, "|%d:%s", len(*k), *k)
		}
	}
	return sb.String()
}

func (a *agg) add(b time.Time, key []*string, n int64, t time.Time, timed bool) {
	k := groupKey(b, key)
	g := a.groups[k]
	if g == nil {
		size := groupOverhead + 2*int64(len(k))
		if len(a.groups) >= MaxGroups || a.bytes+size > MaxGroupBytes {
			o := Other
			key = make([]*string, len(key))
			for i := range key {
				key[i] = &o
			}
			k = groupKey(b, key)
			g = a.groups[k]
		}
		if g == nil {
			g = &Group{Bucket: b, Key: key}
			a.groups[k] = g
			a.bytes += groupOverhead + 2*int64(len(k))
		}
	}
	g.N += n
	if timed {
		if g.First == nil || t.Before(*g.First) {
			tt := t
			g.First = &tt
		}
		if g.Last == nil || t.After(*g.Last) {
			tt := t
			g.Last = &tt
		}
	}
}

// aggCache keeps partial counts between continuations, at most maxAggs
// and maxAggBytes in total (the oldest are evicted first).
type aggCache struct {
	mu    sync.Mutex
	m     map[string]*agg
	o     []string
	bytes int64
}

const maxAggs = 64

func (c *aggCache) put(a *agg) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*agg{}
	}
	for len(c.o) > 0 && (len(c.o) >= maxAggs || c.bytes+a.bytes > maxAggBytes) {
		c.bytes -= c.m[c.o[0]].bytes
		delete(c.m, c.o[0])
		c.o = c.o[1:]
	}
	c.bytes += a.bytes
	var b [12]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	c.m[id] = a
	c.o = append(c.o, id)
	return id
}

// get returns a copy of the partial count of id, leaving it in place: a
// continuation drops it only once it succeeded, so a failed one (which may
// have added part of a group to its copy) can be retried.
func (c *aggCache) get(id string) (*agg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[id]
	if !ok {
		return nil, false
	}
	return a.clone(), true
}

// drop removes the partial count of id.
func (c *aggCache) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[id]
	if !ok {
		return
	}
	c.bytes -= a.bytes
	delete(c.m, id)
	c.o = slices.DeleteFunc(c.o, func(o string) bool { return o == id })
}

// clone is a deep copy of a.
func (a *agg) clone() *agg {
	b := *a
	b.groups = make(map[string]*Group, len(a.groups))
	for k, g := range a.groups {
		gg := *g
		b.groups[k] = &gg // Key and the times are never mutated in place
	}
	return &b
}

func (q *CountQuery) bucketOf(t time.Time) time.Time {
	if q.bucket == 0 {
		return q.From
	}
	return q.From.Add(t.Sub(q.From) / q.bucket * q.bucket)
}

// Count runs a count. A trusted-field-only count is answered from the local
// index where it holds the range, and from a plan-based scan of the rest
// (continued free); every other count scans its plan, masking every record
// first. A record masking fails on is reported in masked_failures; a
// trusted-only count still counts it by its trusted values, as the index
// does (countFailed), while any other count leaves it out, since its masked
// predicates cannot be evaluated on it.
func (e *Engine) Count(ctx context.Context, q CountQuery) (_ CountResult, retErr error) {
	// The caller's predicates are not shared: validation and evaluation
	// write into them.
	q.Where = slices.Clone(q.Where)
	cursor := q.Cursor
	q.Cursor = ""
	// The caps first: the trust loops below are sources × predicates.
	if len(q.Sources) > MaxSources || len(q.Where) > MaxPredicates || len(q.By)+len(q.ByLabels) > MaxBy {
		return CountResult{}, refuse(EBadQuery, "", "at most %d sources, %d predicates and %d fields and labels to count by", MaxSources, MaxPredicates, MaxBy)
	}
	trustedOnly := q.trustedOnly(e.o.Trusted)
	if len(q.Sources) == 0 {
		q.Sources = append([]string(nil), e.names...)
		trustedOnly = q.trustedOnly(e.o.Trusted)
	}
	for _, p := range q.groupBy() {
		for _, s := range q.Sources {
			if !e.o.Trusted(s, p.name(), p.label()) {
				trustedOnly = false
			}
		}
	}
	maxRange := e.o.Limits.CountRange
	if !trustedOnly {
		maxRange = e.o.Limits.LocalRange
	}
	for _, s := range q.Sources {
		// A remote source without its own counts is scanned: its range,
		// trusted-only or not.
		if src, ok := e.o.Sources[s]; ok && e.remote(s) {
			if _, counts := src.(source.Counter); !trustedOnly || !counts {
				maxRange = min(maxRange, e.o.Limits.RemoteRange)
			}
		}
	}
	last := q.Last
	var st cursorState
	if cursor != "" {
		var err *Error
		if st, err = e.openCursor(cursor); err != nil {
			return CountResult{}, err
		}
		if err = restoreWindow(&q.Query, st); err != nil {
			return CountResult{}, err
		}
	}
	v := e.validator(maxRange)
	if err := v.validate(&q.Query); err != nil {
		return CountResult{}, err
	}
	if len(q.By)+len(q.ByLabels) > MaxBy {
		return CountResult{}, refuse(EBadQuery, "by", "at most %d fields and labels", MaxBy)
	}
	for i, b := range q.By {
		if err := v.path(&q.Query, b, fmt.Sprintf("by[%d]", i)); err != nil {
			return CountResult{}, err
		}
	}
	for i, l := range q.ByLabels {
		if l == "" || len(l) > 512 || !utf8.ValidString(l) || strings.ContainsFunc(l, unicode.IsControl) {
			return CountResult{}, refuse(EBadQuery, fmt.Sprintf("by_labels[%d]", i), "invalid label name")
		}
	}
	if q.Bucket != "" {
		d, err := time.ParseDuration(q.Bucket)
		if err != nil || d < time.Second {
			return CountResult{}, refuse(EBadQuery, "bucket", "want a duration of at least 1s")
		}
		if q.To.Sub(q.From)/d > MaxBuckets {
			return CountResult{}, refuse(EBadQuery, "bucket", "at most %d buckets", MaxBuckets)
		}
		q.bucket = d
	}
	digest := e.queryDigest("count", q)
	res := CountResult{Epoch: e.o.Masker.Epoch(), Groups: []Group{}}

	var f *frozen
	chunk, gran := 0, 0
	a := newAgg()
	if cursor != "" {
		var err *Error
		if f, err = e.resume(st, digest); err != nil {
			return CountResult{}, err
		}
		chunk, gran = st.Chunk, st.Granule
		var ok bool
		if a, ok = e.aggs.get(st.Cache); !ok {
			return CountResult{}, &Error{Code: EStale, Span: "cursor", Message: "the cursor expired: run the query again"}
		}
		defer func() {
			if retErr == nil {
				e.aggs.drop(st.Cache)
			}
		}()
	} else {
		var plan source.Byteplan
		if trustedOnly && q.bucket%time.Minute == 0 && e.indexable(q.Sources) {
			p, err := e.indexCounts(ctx, &q, a)
			if err == nil {
				plan = p
			} else if !errors.Is(err, source.ErrNotIndexable) {
				return CountResult{}, sourceError(err)
			} else {
				a = newAgg()
			}
		}
		if !a.indexed {
			// Scanned, not answered by the sources' counts: a remote
			// source's range applies (its bytes are unknown before
			// the fetch, so admission cannot bound a longer range).
			for _, s := range q.Sources {
				if _, ok := e.o.Sources[s]; ok && e.remote(s) && q.To.Sub(q.From) > e.o.Limits.RemoteRange {
					return CountResult{}, &Error{Code: EOverBudget, Span: "to",
						Message:  fmt.Sprintf("this count is scanned, and a remote source's range is at most %s: narrow the range, or count by trusted labels only on whole-minute buckets", e.o.Limits.RemoteRange),
						Estimate: &Estimate{Range: q.To.Sub(q.From)}}
				}
			}
			p, err := e.planQuery(ctx, &q.Query, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
			if err != nil {
				return CountResult{}, err
			}
			plan = p
		} else if plan.Bytes() > e.o.Limits.LocalBytes {
			return CountResult{}, &Error{Code: EOverBudget, Message: "the part of the range the local index does not hold exceeds this call's byte budget; retry once more is indexed, or ask for locklog_scan",
				Estimate: &Estimate{Bytes: plan.Bytes(), Granules: plan.Granules(), Range: q.To.Sub(q.From)}}
		}
		f = e.freeze(digest, plan)
	}

	sc, failures := Scanned{}, 0
	var err *Error
	chunk, gran, sc, failures, err = e.run(ctx, f.plan, chunk, gran, nil, e.callBytes(q.Sources), q.evalFactor(), func(raw source.RawRecord, rec mask.Record, b *budget) {
		if rec.Failed() && trustedOnly {
			// The index counts every record by its trusted values;
			// a scan of a trusted-only count does the same for a
			// record masking failed on (still withheld from any
			// output and reported in masked_failures), so index and
			// scan answers agree.
			e.countFailed(&q, raw, rec, a)
			return
		}
		if !q.match(rec, b) {
			return
		}
		t, timed := rec.Time()
		if !timed {
			a.untimed++
			return
		}
		if !q.Query.rangeContains(t, a.indexed) {
			return
		}
		by := q.groupBy()
		key := make([]*string, len(by))
		for i := range by {
			// A label is read from the record's labels, a field
			// from its line fields: never one for the other.
			vs := lookup(rec, &by[i])
			if len(vs) > 0 && vs[0].kind != mask.Object && vs[0].kind != mask.Null {
				s := vs[0].text
				key[i] = &s
			}
		}
		a.add(q.bucketOf(t), key, 1, t, true)
	})
	if err != nil {
		return CountResult{}, err
	}
	res.Scanned, res.MaskedFailures = sc, failures
	res.FromIndex = a.indexed
	if !a.from.IsZero() && !a.noFrom {
		fr := a.from
		res.IndexedFrom = &fr
	}
	if !a.until.IsZero() {
		u := a.until
		res.IndexedUntil = &u
	}
	res.Untimed = a.untimed
	for _, g := range a.groups {
		gg := *g
		if !q.FirstLast {
			gg.First, gg.Last = nil, nil
		}
		res.Groups = append(res.Groups, gg)
	}
	sort.Slice(res.Groups, func(i, j int) bool {
		if !res.Groups[i].Bucket.Equal(res.Groups[j].Bucket) {
			return res.Groups[i].Bucket.Before(res.Groups[j].Bucket)
		}
		return groupKey(time.Time{}, res.Groups[i].Key) < groupKey(time.Time{}, res.Groups[j].Key)
	})
	res.Complete = chunk >= len(f.plan.Chunks)
	if !res.Complete {
		st := cursorState{Plan: f.id, Query: digest, Chunk: chunk, Granule: gran, Epoch: e.o.Masker.Epoch(), PolicyFP: e.o.PolicyFP(), Cache: e.aggs.put(a),
			From: q.From, To: q.To, Last: last}
		res.Cursor = e.seal("Lc1", st)
		if cu, ok := coveredUntil(f.plan, chunk, gran, q.Query); ok {
			res.CoveredUntil = &cu
		}
	} else {
		to := q.To
		res.CoveredUntil = &to
	}
	return res, nil
}

// rangeContains: the index counts at minute resolution (a minute counts when
// it starts in the range), so a count mixing index and scan does the same
// for scanned records.
func (q *Query) rangeContains(t time.Time, minuteResolution bool) bool {
	if minuteResolution {
		t = t.Truncate(time.Minute)
	}
	return !t.Before(q.From) && t.Before(q.To)
}

// countFailed counts a record masking failed on, in a trusted-only count, by
// the values the index holds for it: its raw trusted values (index.Lookup),
// shown through the masker's text path. A value the masker would change is
// unknown, as in the index (index.Redacted): the record then cannot be
// counted and is left out, which the index path does too (such a granule
// goes to the residual scan).
func (e *Engine) countFailed(q *CountQuery, raw source.RawRecord, rec mask.Record, a *agg) {
	known := func(name, v string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		return e.o.Masker.TrustedValue(raw.Ref.Source, name, v) == v
	}
	sel := q.selector(raw.Ref.Source, e.o.Trusted)
	fields, labels := map[string]string{}, map[string]string{}
	get := func(name string, label bool) (string, bool, bool) {
		m := fields
		if label {
			m = labels
		}
		v := index.Value(raw.Event, index.TermKey(name, label))
		switch {
		case v == index.Absent:
			return "", false, true
		case v == index.Redacted || !known(name, v):
			return "", false, false // unknown, as in the index
		}
		m[name] = v
		return v, true, true
	}
	for _, t := range sel.Terms {
		if _, _, ok := get(t.Field, t.Label); !ok {
			return
		}
	}
	if !sel.Match(fields, labels) {
		return
	}
	by := q.groupBy()
	key := make([]*string, len(by))
	for i, p := range by {
		v, present, ok := get(p.name(), p.Label != "")
		if !ok {
			return
		}
		if present {
			key[i] = &v
		}
	}
	t, timed := rec.Time()
	if !timed {
		a.untimed++
		return
	}
	if !q.Query.rangeContains(t, a.indexed) {
		return
	}
	a.add(q.bucketOf(t), key, 1, t, true)
}

// groupBy is the group key's parts: By fields, then ByLabels labels.
func (q *CountQuery) groupBy() []Pred {
	var out []Pred
	for _, b := range q.By {
		out = append(out, Pred{Field: b})
	}
	for _, l := range q.ByLabels {
		out = append(out, Pred{Label: l})
	}
	return out
}

func (e *Engine) indexable(srcs []string) bool {
	for _, s := range srcs {
		if _, ok := e.o.Sources[s].(source.Counter); !ok {
			return false
		}
	}
	return true
}

// indexCounts adds the index's answer to a and returns the residual plan.
func (e *Engine) indexCounts(ctx context.Context, q *CountQuery, a *agg) (source.Byteplan, error) {
	var plan source.Byteplan
	for _, name := range q.Sources {
		ic := e.o.Sources[name].(source.Counter)
		r, err := ic.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: q.From, To: q.To},
			Selector: q.selector(name, e.o.Trusted), By: q.By, ByLabels: q.ByLabels, Bucket: q.bucket})
		if err != nil {
			return source.Byteplan{}, err
		}
		by := q.groupBy()
		for _, row := range r.Rows {
			key := make([]*string, len(row.Vals))
			for i, v := range row.Vals {
				key[i] = e.indexValue(name, by[i].name(), v)
			}
			a.add(row.Bucket, key, row.N, time.Time{}, false)
		}
		a.untimed += r.Untimed
		// The weakest claim of all sources: nothing when one claims
		// nothing.
		if r.IndexedFrom.IsZero() {
			a.noFrom = true
		} else if a.from.IsZero() || r.IndexedFrom.After(a.from) {
			a.from = r.IndexedFrom
		}
		if !r.IndexedUntil.IsZero() && (a.until.IsZero() || r.IndexedUntil.Before(a.until)) {
			a.until = r.IndexedUntil
		}
		plan.Chunks = append(plan.Chunks, r.Residual.Chunks...)
	}
	a.indexed = true
	return plan, nil
}

// indexValue masks an indexed raw value of a trusted field or label for the
// agent; markers become placeholders. A value the masker would change as a
// trusted leaf (an index built before a rule, or by another Sensitive) is
// withheld, never shown clear: the scan shows it masked.
func (e *Engine) indexValue(src, name, v string) *string {
	var s string
	switch v {
	case index.Absent:
		return nil
	case index.Redacted:
		s = mask.Redacted
	case index.Other:
		s = Other
	default:
		s = v
		if e.o.Masker.TrustedValue(src, name, v) != v {
			s = mask.Redacted
		}
	}
	return &s
}
