//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/elastic"
)

// esDoc is one document of the fake Elasticsearch: its time and keyword
// fields (one value or several; absent when missing).
type esDoc struct {
	ts     int64
	id     string
	fields map[string][]string
}

// fakeElastic is a fake Elasticsearch client for the engine tests: it
// serves searches over docs (sorted by time, then id) with Elasticsearch's
// semantics for range, term, terms and must_not on multi-valued keyword
// fields, size and search_after. It counts the response bytes it served and
// the requests in flight.
type fakeElastic struct {
	docs []esDoc
	mu   sync.Mutex
	// served is the response bytes served, maxPage the largest response,
	// in and maxIn the requests in flight.
	served, maxPage int64
	in, maxIn       int
}

func (f *fakeElastic) Send(_ context.Context, method, path string, _ url.Values, body []byte) (egress.Response, error) {
	f.mu.Lock()
	f.in++
	f.maxIn = max(f.maxIn, f.in)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.in--
		f.mu.Unlock()
	}()
	if method != "POST" || !strings.HasSuffix(path, "/_search") {
		return egress.Response{Status: 404}, fmt.Errorf("fake: %s %s", method, path)
	}
	var sb elastic.SearchBody
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&sb); err != nil {
		return egress.Response{Status: 400}, err
	}
	var after int64 = -1 << 63
	if len(sb.SearchAfter) > 0 {
		n, _ := sb.SearchAfter[0].(json.Number)
		after, _ = strconv.ParseInt(n.String(), 10, 64)
	}
	var hits []map[string]any
	for _, d := range f.docs {
		if len(hits) >= sb.Size {
			break
		}
		if d.ts <= after || !esMatches(sb.Query, d) {
			continue
		}
		fields := map[string]any{}
		for _, k := range sb.Fields {
			if vs, ok := d.fields[k]; ok {
				fields[k] = vs
			}
		}
		hits = append(hits, map[string]any{"_index": "logs", "_id": d.id, "fields": fields, "sort": []int64{d.ts}})
	}
	out, _ := json.Marshal(map[string]any{"timed_out": false, "_shards": map[string]any{"failed": 0}, "hits": map[string]any{"hits": hits}})
	f.mu.Lock()
	f.served += int64(len(out))
	f.maxPage = max(f.maxPage, int64(len(out)))
	f.mu.Unlock()
	return egress.Response{Status: 200, Body: out}, nil
}

func esClause(c elastic.Clause, d esDoc) bool {
	for _, r := range c.Range {
		lo, _ := time.Parse(time.RFC3339Nano, r.GTE)
		hi, _ := time.Parse(time.RFC3339Nano, r.LT)
		return d.ts >= lo.UnixNano() && d.ts < hi.UnixNano()
	}
	for k, v := range c.Term {
		return slices.Contains(d.fields[k], v)
	}
	for k, want := range c.Terms {
		return slices.ContainsFunc(d.fields[k], func(v string) bool { return slices.Contains(want, v) })
	}
	return false
}

func esMatches(q elastic.Query, d esDoc) bool {
	for _, c := range q.Bool.Filter {
		if !esClause(c, d) {
			return false
		}
	}
	for _, c := range q.Bool.MustNot {
		if esClause(c, d) {
			return false
		}
	}
	return true
}

// bigElastic is an hour of documents every 5 s from t0, the first of each
// minute at level error (short), the others padded to pad bytes.
func bigElastic(pad int) *fakeElastic {
	f := &fakeElastic{}
	for ts := t0; ts.Before(t0.Add(time.Hour)); ts = ts.Add(5 * time.Second) {
		level, msg := "info", fmt.Sprintf("time=%s msg=\"entry %d\" pad=%s", ts.Format(time.RFC3339Nano), ts.UnixNano(), strings.Repeat("x", pad))
		if ts.Sub(t0)%time.Minute == 0 {
			level, msg = "error", fmt.Sprintf("time=%s msg=\"minute %d\"", ts.Format(time.RFC3339Nano), ts.UnixNano())
		}
		f.docs = append(f.docs, esDoc{ts: ts.UnixNano(), id: strconv.FormatInt(ts.UnixNano(), 10),
			fields: map[string][]string{"message": {msg}, "level": {level}}})
	}
	return f
}

func newElastic(t *testing.T, f *fakeElastic, inFlight int) *elastic.Source {
	t.Helper()
	p, _ := parse.New(parse.Options{})
	src, err := elastic.New(elastic.Options{Name: "es", Client: f, Parser: p, Indices: []string{"logs"},
		TrustedFields: []string{"level", "tag"}, InFlight: inFlight, Size: 4, Now: func() time.Time { return t0.Add(2 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// TestElasticPagedUnderBudget: an Elasticsearch range holding many times
// one call's byte budget is read in partial pages with a cursor that
// resumes where the last call stopped, ascending and descending, every
// record once; each call fetches at most its budget plus the pages in
// flight, never the range whole.
func TestElasticPagedUnderBudget(t *testing.T) {
	const budget = 256 << 10
	const inFlight = 2
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			fe := bigElastic(4 << 10)
			src := newElastic(t, fe, inFlight)
			f := newFixture(t, "x\n", func(o *Options) {
				o.Sources["es"] = src
				o.Limits.RemoteBytes = budget
				o.Trusted = func(s, name string, label bool) bool {
					return s == "es" && label && (name == "level" || name == "tag") || s != "es" && !label && (name == "level" || name == "status")
				}
			})
			qq := q(func(q *Query) {
				q.From, q.To = t0, t0.Add(time.Hour) // 60 slices of 1 min
				q.Sources = []string{"es"}
				q.Where = []Pred{{Label: "level", Op: OpNe, Value: raw("debug")}}
				q.Limit = 200
				q.Order = order
			})
			var recs []json.RawMessage
			calls := 0
			for {
				fe.mu.Lock()
				fe.served = 0
				fe.mu.Unlock()
				res, err := f.eng.Search(ctx, qq)
				if err != nil {
					t.Fatalf("call %d: %v", calls, err)
				}
				calls++
				fe.mu.Lock()
				served, page := fe.served, fe.maxPage
				fe.mu.Unlock()
				if bound := int64(budget) + int64(inFlight+1)*page; served > bound {
					t.Fatalf("call %d fetched %d bytes, bound %d", calls, served, bound)
				}
				recs = append(recs, res.Records...)
				if res.Complete {
					break
				}
				if res.Cursor == "" || calls > 400 {
					t.Fatalf("call %d: incomplete without a cursor", calls)
				}
				qq.Cursor = res.Cursor
			}
			if calls < 4 {
				t.Fatalf("%d calls: the range fitted a call's budget", calls)
			}
			ts := recordTimes(t, recs)
			checkOrder(t, ts, len(fe.docs), order == "desc")
			seen := map[time.Time]bool{}
			for _, x := range ts {
				if seen[x] {
					t.Fatalf("record at %v returned twice", x)
				}
				seen[x] = true
			}
			if fe.maxIn > inFlight {
				t.Fatalf("%d requests in flight", fe.maxIn)
			}
		})
	}
}

// TestElasticMultiValuedTerms: a term pushed to the backend and the same
// predicate evaluated by the engine on the record's labels agree on every
// document: one value, several values of which one, all or none match, the
// field absent, an empty value.
func TestElasticMultiValuedTerms(t *testing.T) {
	tags := [][]string{nil, {""}, {"a"}, {"b"}, {"a", "b"}, {"b", "c"}, {"a", ""}, {"c", "c"}, {"a", "b", "c"}}
	fe := &fakeElastic{}
	for i := 0; i < 90; i++ {
		ts := t0.Add(time.Duration(i) * time.Second)
		d := esDoc{ts: ts.UnixNano(), id: fmt.Sprintf("d%03d", i), fields: map[string][]string{
			"message": {fmt.Sprintf("time=%s msg=\"doc %d\"", ts.Format(time.RFC3339Nano), i)}}}
		if tg := tags[i%len(tags)]; tg != nil {
			d.fields["tag"] = tg
		}
		fe.docs = append(fe.docs, d)
	}
	src := newElastic(t, fe, 2)
	f := newFixture(t, "x\n", nil)
	o := f.eng.o
	o.Sources = map[string]source.Source{"es": src}
	o.Trusted = func(_, name string, label bool) bool { return label && name == "tag" }
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	// The local semantics: = and in hold when some value is one of
	// the values, != when none is (an absent field included).
	want := func(op string, vals []string) int {
		n := 0
		for i := range fe.docs {
			tg := tags[i%len(tags)]
			hit := slices.ContainsFunc(tg, func(v string) bool { return slices.Contains(vals, v) })
			if op == OpNe {
				hit = !hit
			}
			if hit {
				n++
			}
		}
		return n
	}
	for _, tt := range []struct {
		op   string
		vals []string
	}{
		{OpEq, []string{"a"}}, {OpNe, []string{"a"}}, {OpEq, []string{"c"}}, {OpNe, []string{"c"}},
		{OpIn, []string{"a", "c"}}, {OpIn, []string{"x"}}, {OpNe, []string{"x"}},
		{OpEq, []string{""}}, {OpNe, []string{""}}, {OpIn, []string{"", "b"}},
	} {
		var v json.RawMessage
		if tt.op == OpIn {
			v = raw(tt.vals)
		} else {
			v = raw(tt.vals[0])
		}
		recs, _ := allRecords(t, eng, q(func(q *Query) {
			q.From, q.To = t0, t0.Add(10*time.Minute)
			q.Sources = []string{"es"}
			q.Where = []Pred{{Label: "tag", Op: tt.op, Value: v}}
			q.Limit = 200
		}))
		if got, w := len(recs), want(tt.op, tt.vals); got != w {
			t.Errorf("tag %s %q: %d records, want %d", tt.op, tt.vals, got, w)
		}
	}
	// Sorted: the docs' times are distinct.
	if !sort.SliceIsSorted(fe.docs, func(i, j int) bool { return fe.docs[i].ts < fe.docs[j].ts }) {
		t.Fatal("fake docs out of order")
	}
}
