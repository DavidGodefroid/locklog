package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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
)

// Other is the key of groups beyond MaxGroups or of index overflow.
const Other = mask.Open + "other" + mask.Close

// CountQuery is a count (locklog_count).
type CountQuery struct {
	Query
	// Bucket is a duration ("5m"); empty: one bucket for the range.
	Bucket string `json:"bucket,omitempty"`
	// By groups by up to two trusted or pseudonymised fields.
	By []string `json:"by,omitempty"`
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
		if len(a.groups) >= MaxGroups {
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

// aggCache keeps partial counts between continuations.
type aggCache struct {
	mu sync.Mutex
	m  map[string]*agg
	o  []string
}

const maxAggs = 64

func (c *aggCache) put(a *agg) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*agg{}
	}
	for len(c.o) >= maxAggs {
		delete(c.m, c.o[0])
		c.o = c.o[1:]
	}
	var b [12]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	c.m[id] = a
	c.o = append(c.o, id)
	return id
}

func (c *aggCache) take(id string) (*agg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[id]
	delete(c.m, id)
	return a, ok
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
// first.
func (e *Engine) Count(ctx context.Context, q CountQuery) (CountResult, error) {
	cursor := q.Cursor
	q.Cursor = ""
	trustedOnly := q.trustedOnly(func(s, f string) bool { return e.o.Trusted(s, f) })
	if len(q.Sources) == 0 {
		q.Sources = append([]string(nil), e.names...)
		trustedOnly = q.trustedOnly(func(s, f string) bool { return e.o.Trusted(s, f) })
	}
	for _, b := range q.By {
		for _, s := range q.Sources {
			if !e.o.Trusted(s, b) {
				trustedOnly = false
			}
		}
	}
	maxRange := e.o.Limits.CountRange
	if !trustedOnly {
		maxRange = e.o.Limits.LocalRange
		for _, s := range q.Sources {
			if _, ok := e.o.Sources[s]; ok && e.remote(s) {
				maxRange = min(maxRange, e.o.Limits.RemoteRange)
			}
		}
	}
	var st cursorState
	if cursor != "" {
		var err *Error
		if st, err = e.openCursor(cursor); err != nil {
			return CountResult{}, err
		}
		restoreWindow(&q.Query, st)
	}
	v := e.validator(maxRange)
	if err := v.validate(&q.Query); err != nil {
		return CountResult{}, err
	}
	if len(q.By) > MaxBy {
		return CountResult{}, refuse(EBadQuery, "by", "at most %d fields", MaxBy)
	}
	for i, b := range q.By {
		if err := v.path(&q.Query, b, fmt.Sprintf("by[%d]", i)); err != nil {
			return CountResult{}, err
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
		if a, ok = e.aggs.take(st.Cache); !ok {
			return CountResult{}, &Error{Code: EStale, Span: "cursor", Message: "the cursor expired: run the query again"}
		}
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
	chunk, gran, sc, failures, err = e.run(ctx, f.plan, chunk, gran, nil, e.callBytes(q.Sources), func(raw source.RawRecord, rec mask.Record) {
		if !q.match(rec) {
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
		key := make([]*string, len(q.By))
		for i, b := range q.By {
			vs := lookup(rec, &Pred{Field: b})
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
			From: q.From, To: q.To}
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
			Selector: q.selector(name, e.o.Trusted), By: q.By, Bucket: q.bucket})
		if err != nil {
			return source.Byteplan{}, err
		}
		for _, row := range r.Rows {
			key := make([]*string, len(row.Vals))
			for i, v := range row.Vals {
				key[i] = e.indexValue(v)
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

// indexValue masks an indexed raw value for the agent: trusted values pass
// the masker's text path; markers become placeholders.
func (e *Engine) indexValue(v string) *string {
	var s string
	switch v {
	case index.Absent:
		return nil
	case index.Redacted:
		s = mask.Redacted
	case index.Other:
		s = Other
	default:
		s = e.o.Masker.Text(v)
	}
	return &s
}
