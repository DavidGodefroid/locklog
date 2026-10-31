package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// MaxCountBy bounds the fields of a server-side count (nested terms).
const MaxCountBy = 2

type countResponse struct {
	Count  *int64 `json:"count"`
	Shards struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
}

// bucketJSON is one bucket of a date_histogram or terms aggregation, with
// its sub-aggregations (t0, t1, ...) kept raw.
type bucketJSON struct {
	Key      json.RawMessage `json:"key"`
	DocCount int64           `json:"doc_count"`
	Subs     map[string]json.RawMessage
}

func (b *bucketJSON) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	b.Key = m["key"]
	if err := json.Unmarshal(m["doc_count"], &b.DocCount); err != nil {
		return err
	}
	b.Subs = m
	return nil
}

type aggJSON struct {
	Buckets        []bucketJSON `json:"buckets"`
	SumOtherDocCnt int64        `json:"sum_other_doc_count"`
	// DocCountError is the bound of the error of the buckets' counts
	// (shards each answering their top terms): 0 when they are exact.
	DocCountError int64 `json:"doc_count_error_upper_bound"`
}

func termsName(i int) string { return "t" + strconv.Itoa(i) }

// termsChain nests one terms aggregation per field of by.
func termsChain(by []string, i int) map[string]Agg {
	if i >= len(by) {
		return nil
	}
	absent := index.Absent
	return map[string]Agg{termsName(i): {Terms: &TermsAgg{Field: by[i], Size: MaxTermsSize, Missing: &absent}, Aggs: termsChain(by, i+1)}}
}

// IndexCounts answers a trusted-field count on the server: a _count for a
// selector-only question, else a search of size 0 with a date_histogram
// (at most MaxHistogramBuckets buckets) and nested terms aggregations (at
// most MaxTermsSize values each; the rest counts under index.Other). No
// document leaves the backend. Counts on untrusted fields, by more than
// MaxCountBy fields, on bounds finer than a millisecond, or with too many
// buckets are not served (source.ErrNotIndexable).
func (s *Source) IndexCounts(ctx context.Context, q source.CountQuery) (source.CountResult, error) {
	// Counts are by labels (trusted document fields) only: a line field
	// (q.By) is inside the message.
	if len(q.By) > 0 || len(q.ByLabels) > MaxCountBy {
		return source.CountResult{}, source.ErrNotIndexable
	}
	s.mu.Lock()
	checked := s.checked
	s.mu.Unlock()
	if !checked {
		return source.CountResult{}, source.ErrNotIndexable // Check first
	}
	for _, b := range q.ByLabels {
		if !s.trusted(b) || !s.serverSide(b) {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	for _, t := range q.Selector.Terms {
		if !s.pushable(t) {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	r := q.Range
	if !r.From.Before(r.To) || r.From.Truncate(time.Millisecond) != r.From || r.To.Truncate(time.Millisecond) != r.To {
		return source.CountResult{}, source.ErrNotIndexable
	}
	bucket := q.Bucket
	if bucket != 0 {
		if bucket < time.Millisecond || bucket%time.Millisecond != 0 {
			return source.CountResult{}, source.ErrNotIndexable
		}
		if n := (r.To.Sub(r.From) + bucket - 1) / bucket; n > MaxHistogramBuckets {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	qry, err := s.filter(q.Selector).query(s.o.TimeField, r.From, r.To)
	if err != nil {
		return source.CountResult{}, fmt.Errorf("elasticsearch source: %w", err)
	}
	var res source.CountResult
	res.IndexedFrom = r.From
	if bucket == 0 && len(q.ByLabels) == 0 {
		body, err := countJSON(CountBody{Query: qry})
		if err != nil {
			return source.CountResult{}, err
		}
		resp, err := s.do(ctx, http.MethodPost, s.countPath(), readParams(), body)
		if err != nil {
			return source.CountResult{}, fmt.Errorf("elasticsearch source: %w", err)
		}
		var cr countResponse
		if json.Unmarshal(resp, &cr) != nil || cr.Count == nil {
			return source.CountResult{}, errResponse
		}
		if cr.Shards.Failed > 0 {
			return source.CountResult{}, fmt.Errorf("elasticsearch source: the count failed on some shards")
		}
		if *cr.Count > 0 {
			res.Rows = []source.CountRow{{Bucket: r.From, Vals: []string{}, N: *cr.Count}}
		}
		return res, nil
	}
	by := slices.Clone(q.ByLabels)
	aggs := termsChain(by, 0)
	if bucket != 0 {
		ms := bucket.Milliseconds()
		off := ((r.From.UnixMilli() % ms) + ms) % ms
		aggs = map[string]Agg{"h": {DateHistogram: &DateHistogram{Field: s.o.TimeField, FixedInterval: strconv.FormatInt(ms, 10) + "ms",
			Offset: "+" + strconv.FormatInt(off, 10) + "ms", MinDocCount: 1}, Aggs: aggs}}
	}
	body, err := searchJSON(SearchBody{Size: 0, Timeout: SearchTimeout, TrackTotalHits: true, Query: qry, Aggs: aggs})
	if err != nil {
		return source.CountResult{}, err
	}
	resp, err := s.do(ctx, http.MethodPost, s.searchPath(), readParams(), body)
	if err != nil {
		return source.CountResult{}, fmt.Errorf("elasticsearch source: %w", err)
	}
	var sr searchResponse
	if json.Unmarshal(resp, &sr) != nil {
		return source.CountResult{}, errResponse
	}
	if err := sr.complete(); err != nil {
		return source.CountResult{}, err
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(sr.Aggregations, &top) != nil {
		return source.CountResult{}, errResponse
	}
	emit := func(b time.Time, vals []string, n int64) {
		if n > 0 {
			res.Rows = append(res.Rows, source.CountRow{Bucket: b, Vals: slices.Clone(vals), N: n})
		}
	}
	if bucket != 0 {
		var h aggJSON
		if json.Unmarshal(top["h"], &h) != nil {
			return source.CountResult{}, errResponse
		}
		for _, hb := range h.Buckets {
			var ms int64
			if json.Unmarshal(hb.Key, &ms) != nil {
				return source.CountResult{}, errResponse
			}
			at := time.UnixMilli(ms).UTC()
			if at.Before(r.From) || !at.Before(r.To) {
				continue
			}
			if err := walkTerms(hb.Subs, by, 0, nil, hb.DocCount, func(v []string, n int64) { emit(at, v, n) }); err != nil {
				return source.CountResult{}, err
			}
		}
	} else {
		if sr.Hits == nil || sr.Hits.Total == nil || sr.Hits.Total.Relation != "eq" {
			return source.CountResult{}, errResponse
		}
		if err := walkTerms(top, by, 0, nil, sr.Hits.Total.Value, func(v []string, n int64) { emit(r.From, v, n) }); err != nil {
			return source.CountResult{}, err
		}
	}
	sort.Slice(res.Rows, func(i, j int) bool {
		if !res.Rows[i].Bucket.Equal(res.Rows[j].Bucket) {
			return res.Rows[i].Bucket.Before(res.Rows[j].Bucket)
		}
		return slices.Compare(res.Rows[i].Vals, res.Rows[j].Vals) < 0
	})
	return res, nil
}

// walkTerms emits the rows of the terms aggregation of level i of by under
// subs (parent counts the parent bucket's documents). The
// documents beyond the MaxTermsSize values count under index.Other at that
// level and the levels below. Values summing past their parent (a
// multi-valued field: one document in several buckets) are not served.
func walkTerms(subs map[string]json.RawMessage, by []string, i int, vals []string, parent int64, emit func([]string, int64)) error {
	if i >= len(by) {
		emit(vals, parent)
		return nil
	}
	var a aggJSON
	if json.Unmarshal(subs[termsName(i)], &a) != nil {
		return errResponse
	}
	// An approximate answer (a term's count missed on some shard) is
	// not served: the engine scans instead.
	if a.DocCountError != 0 {
		return source.ErrNotIndexable
	}
	sum := a.SumOtherDocCnt
	for _, b := range a.Buckets {
		sum += b.DocCount
	}
	if sum > parent {
		return source.ErrNotIndexable
	}
	for _, b := range a.Buckets {
		vs, ok := stringValues(json.RawMessage("[" + string(b.Key) + "]"))
		if !ok || len(vs) != 1 {
			return errResponse
		}
		if err := walkTerms(b.Subs, by, i+1, append(slices.Clone(vals), vs[0]), b.DocCount, emit); err != nil {
			return err
		}
	}
	if a.SumOtherDocCnt > 0 {
		other := slices.Clone(vals)
		for range by[i:] {
			other = append(other, index.Other)
		}
		emit(other, a.SumOtherDocCnt)
	}
	return nil
}
