package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

var ctx = context.Background()

func client(t *testing.T, h http.Handler, indices []string) *egress.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	routes, err := egress.ElasticRoutes(indices)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, routes, egress.Credentials{}, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func newSource(t *testing.T, f *fakeES, mod func(*Options)) *Source {
	t.Helper()
	p, _ := parse.New(parse.Options{})
	o := Options{Name: "es", Client: client(t, f, []string{"logs-*"}), Parser: p, Indices: []string{"logs-*"},
		TrustedFields: []string{"app", "level"}, Size: 7, Now: func() time.Time { return t0.Add(time.Hour) }}
	if mod != nil {
		mod(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func drain(t *testing.T, it source.Iterator) []source.RawRecord {
	t.Helper()
	defer it.Close()
	var out []source.RawRecord
	for {
		r, err := it.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
}

func scanAll(t *testing.T, s *Source, r source.Range, sel source.Selector) []source.RawRecord {
	t.Helper()
	plan, err := s.Plan(ctx, r, sel)
	if err != nil {
		t.Fatal(err)
	}
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		it, err := s.Scan(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, drain(t, it)...)
	}
	return out
}

func attr(r source.RawRecord, k string) string {
	v, _ := parse.Get(r.Event.Attrs, k)
	return v.Str
}

// walkKeys collects every object key of a JSON document.
func walkKeys(v any, out map[string]bool) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			out[k] = true
			walkKeys(x, out)
		}
	case []any:
		for _, x := range v {
			walkKeys(x, out)
		}
	}
}

func TestBodyBuildersKeepHostileValuesValues(t *testing.T) {
	hostile := []string{`x"}},"script":{"source":"ctx._source.x=1"}}`, `*`, `a OR b`, `{"query_string":{"query":"*"}}`, "é\\\"", `</script>`}
	f := Filter{In: []FieldValues{{Field: "app", Values: hostile}, {Field: "level", Values: hostile[:1]}},
		NotIn: []FieldValues{{Field: "level", Values: []string{`"]}`}}}}
	q, err := f.query("@timestamp", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b, err := searchJSON(SearchBody{Size: 10, Timeout: SearchTimeout, Fields: []string{"message"}, Query: q})
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	walkKeys(doc, keys)
	allowed := []string{"size", "timeout", "track_total_hits", "_source", "fields", "query", "bool", "filter", "must_not", "range", "term", "terms",
		"@timestamp", "gte", "lt", "format", "app", "level"}
	for k := range keys {
		if !slices.Contains(allowed, k) {
			t.Fatalf("key %q in the body %s", k, b)
		}
	}
	var back SearchBody
	if err := strictDecode(b, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Query.Bool.Filter[1].Terms["app"]; !slices.Equal(got, func() []string { s := slices.Clone(hostile); slices.Sort(s); return s }()) {
		t.Fatalf("values changed: %q", got)
	}
	if back.Query.Bool.Filter[2].Term["level"] != hostile[0] || back.Query.Bool.MustNot[0].Term["level"] != `"]}` {
		t.Fatalf("%s", b)
	}
	// Names, control characters, caps.
	for _, bad := range []Filter{
		{In: []FieldValues{{Field: "a b", Values: []string{"x"}}}},
		{In: []FieldValues{{Field: `a"`, Values: []string{"x"}}}},
		{In: []FieldValues{{Field: "a*", Values: []string{"x"}}}},
		{In: []FieldValues{{Field: "a", Values: []string{"x\ny"}}}},
		{In: []FieldValues{{Field: "a", Values: nil}}},
	} {
		if _, err := bad.Encode(); err == nil {
			t.Fatalf("%+v encoded", bad)
		}
	}
	for _, bad := range []SearchBody{
		{Size: MaxSize + 1, Timeout: SearchTimeout},
		{Size: 1},
		{Size: 1, Timeout: SearchTimeout, SearchAfter: []any{map[string]any{"script": 1}}},
		{Size: 0, Timeout: SearchTimeout, Aggs: map[string]Agg{"a": {Terms: &TermsAgg{Field: "app", Size: MaxTermsSize + 1}}}},
		{Size: 0, Timeout: SearchTimeout, Aggs: map[string]Agg{"a": {}}},
		{Size: 0, Timeout: SearchTimeout, Aggs: map[string]Agg{"a": {Terms: &TermsAgg{Field: "app", Size: 1}, DateHistogram: &DateHistogram{Field: "@timestamp"}}}},
		{Size: 0, Timeout: SearchTimeout, Query: Query{Bool: BoolQuery{Filter: []Clause{{}}}}},
		{Size: 0, Timeout: SearchTimeout, Query: Query{Bool: BoolQuery{Filter: []Clause{{Term: map[string]string{"a": "x", "b": "y"}}}}}},
	} {
		if _, err := searchJSON(bad); err == nil {
			t.Fatalf("%+v written", bad)
		}
	}
}

func TestStreamRoundTripsAndRefusesForeignStreams(t *testing.T) {
	s := newSource(t, newFake(nil), func(o *Options) { o.Selector = map[string]string{"env": "prod"} })
	sel := source.Selector{Terms: []source.Term{{Field: "level", Op: "in", Values: []string{"warn", "error", "warn"}},
		{Field: "app", Op: "!=", Values: []string{"x"}}, {Field: "pod", Op: "=", Values: []string{"pod-1"}}}}
	plan, err := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, sel)
	if err != nil {
		t.Fatal(err)
	}
	st := plan.Chunks[0].Stream
	f, err := s.streamFilter(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st, "pod") || len(f.In) != 2 || !slices.Equal(f.In[1].Values, []string{"error", "warn"}) || len(f.NotIn) != 1 {
		t.Fatalf("stream %s", st)
	}
	for _, bad := range []string{
		`{"in":[{"f":"env","v":["prod"]},{"f":"pod","v":["x"]}]}`, // untrusted
		`{"in":[{"f":"env","v":["prod"]}],"script":1}`,             // unknown key
		`{"in":[{"f":"level","v":["b","a"]},{"f":"env","v":["prod"]}]}`,
		`garbage`,
	} {
		if _, err := s.streamFilter(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	// A stream without the profile's selector is stale, not served.
	if _, err := s.streamFilter(`{"in":[{"f":"level","v":["a"]}]}`); !errors.Is(err, source.ErrStale) {
		t.Fatalf("%v", err)
	}
}

func TestPlanSlicesAlignedAndQueryIndependent(t *testing.T) {
	s := newSource(t, newFake(nil), nil)
	p, err := s.Plan(ctx, source.Range{From: t0.Add(17 * time.Second), To: t0.Add(24 * time.Hour)}, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	gs := p.Chunks[0].Granules
	if len(gs) != 288 || time.Duration(gs[0].End-gs[0].Start) != 5*time.Minute || gs[0].From != t0 || gs[0].Bytes != 0 {
		t.Fatalf("%d slices from %v", len(gs), gs[0].From)
	}
}

func TestScanPagesWithSearchAfter(t *testing.T) {
	for _, tie := range []string{"", "event.id"} {
		f := newFake(dataset(300))
		s := newSource(t, f, func(o *Options) { o.TieBreaker = tie })
		recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
		if len(recs) != 300 {
			t.Fatalf("tie %q: %d records, want 300", tie, len(recs))
		}
		seen := map[string]bool{}
		for i, r := range recs {
			if i > 0 && r.Event.Time.Before(recs[i-1].Event.Time) {
				t.Fatal("out of order")
			}
			if seen[r.Event.Raw] {
				t.Fatalf("duplicate %s", r.Event.Raw)
			}
			seen[r.Event.Raw] = true
			if v, ok := parse.Get(r.Event.Fields, "ts"); !ok || v.Str != "2020-01-01T00:00:00Z" || r.Event.Time.Year() != 2026 {
				t.Fatalf("time handling %+v", r.Event)
			}
			for _, a := range r.Event.Attrs {
				if a.Key != "app" && a.Key != "level" {
					t.Fatalf("untrusted attr %q returned", a.Key)
				}
			}
			if strings.Contains(r.Event.Raw, "@example.com") {
				t.Fatal("an untrusted field reached the record")
			}
		}
		paged := 0
		for _, b := range f.bodies {
			var sb SearchBody
			if strictDecode(b, &sb) == nil && sb.SearchAfter != nil {
				paged++
				if sb.Size != 7 || len(sb.SearchAfter) != len(sb.Sort) {
					t.Fatalf("page body %s", b)
				}
			}
			if strings.Contains(string(b), "user_email") || strings.Contains(string(b), `"pod"`) {
				t.Fatalf("an untrusted field asked: %s", b)
			}
		}
		if paged == 0 {
			t.Fatalf("tie %q: no search_after page", tie)
		}
		if f.maxIn > InFlight {
			t.Fatalf("%d requests in flight", f.maxIn)
		}
	}
}

func TestTiesBeyondAPageWithoutTiebreakerFail(t *testing.T) {
	docs := dataset(20)
	for i := range docs {
		docs[i].ts = t0
	}
	s := newSource(t, newFake(docs), nil)
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	defer it.Close()
	var err error
	for err == nil {
		_, err = it.Next()
	}
	if errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "tiebreaker") {
		t.Fatalf("%v", err)
	}
	// With a tiebreaker, every document comes back.
	s = newSource(t, newFake(docs), func(o *Options) { o.TieBreaker = "event.id" })
	if got := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{}); len(got) != 20 {
		t.Fatalf("%d records", len(got))
	}
}

func TestTrustedTermsGoServerSide(t *testing.T) {
	f := newFake(dataset(200))
	s := newSource(t, f, func(o *Options) { o.Selector = map[string]string{"app": "api"} })
	sel := source.Selector{Terms: []source.Term{
		{Field: "level", Op: "in", Values: []string{"error", "warn"}},
		{Field: "status", Op: "=", Values: []string{"500"}}, // not trusted: local
	}}
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, sel)
	want := 0
	for _, d := range f.docs {
		if d.fields["app"] == "api" && (d.fields["level"] == "error" || d.fields["level"] == "warn") {
			want++
		}
	}
	if len(recs) != want || want == 0 {
		t.Fatalf("%d records, want %d", len(recs), want)
	}
	for _, b := range f.bodies {
		if strings.Contains(string(b), "status") || strings.Contains(string(b), "500") {
			t.Fatalf("an untrusted term reached the backend: %s", b)
		}
	}
}

func TestResponsesKeepTrustedFieldsOnly(t *testing.T) {
	// A backend that answers more than asked: untrusted fields in
	// "fields", the whole _source, and objects where values should be.
	body := `{"timed_out":false,"_shards":{"failed":0},"hits":{"hits":[{"_index":"logs-a","_id":"1",
		"_source":{"user_email":"u@example.com","message":"m"},
		"fields":{"message":["hello"],"app":["api"],"user_email":["u@example.com"],"pod":["p1"],"level":[{"x":"y"}]},
		"sort":[1761825600000000000]}]}}`
	srv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	p, _ := parse.New(parse.Options{})
	s, err := New(Options{Name: "es", Client: client(t, srv, []string{"logs-a"}), Parser: p, Indices: []string{"logs-a"}, TrustedFields: []string{"app", "level"}})
	if err != nil {
		t.Fatal(err)
	}
	hs, _, err := s.fetchSlice(ctx, Filter{}, 0, 1<<62)
	if err != nil || len(hs) != 1 {
		t.Fatalf("%v %d", err, len(hs))
	}
	rec := s.record("{}", hs[0], 0)
	if rec.Event.Raw != "hello" || len(rec.Event.Attrs) != 1 || attr(rec, "app") != "api" {
		t.Fatalf("%+v", rec.Event)
	}
}

func TestPartialAnswersFail(t *testing.T) {
	for _, mod := range []func(*fakeES){func(f *fakeES) { f.timedOut = true }, func(f *fakeES) { f.shardFail = true }} {
		f := newFake(dataset(10))
		mod(f)
		s := newSource(t, f, nil)
		if _, _, err := s.fetchSlice(ctx, Filter{}, t0.UnixNano(), t0.Add(time.Hour).UnixNano()); err == nil {
			t.Fatal("a partial answer was served")
		}
		if _, err := s.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: t0, To: t0.Add(time.Hour)}, Bucket: time.Minute}); err == nil || errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("a partial count was served: %v", err)
		}
	}
}

type countLimiter struct{ n int32 }

func (c *countLimiter) Wait(context.Context) error { atomic.AddInt32(&c.n, 1); return nil }

func TestRequestsGoThroughTheCallLimiter(t *testing.T) {
	f := newFake(dataset(100))
	s := newSource(t, f, nil)
	l := &countLimiter{}
	lctx := source.WithLimiter(ctx, l)
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(lctx, plan.Chunks[0])
	drain(t, it)
	if _, err := s.IndexCounts(lctx, source.CountQuery{Range: source.Range{From: t0, To: t0.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check(lctx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Describe(lctx); err != nil {
		t.Fatal(err)
	}
	if int(l.n) != len(f.requests) || l.n == 0 {
		t.Fatalf("limiter saw %d of %d requests", l.n, len(f.requests))
	}
}

func TestProcessedCountsFetchedBytes(t *testing.T) {
	s := newSource(t, newFake(dataset(100)), nil)
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	var lines int
	for _, r := range drain(t, it) {
		lines += len(r.Event.Raw)
	}
	if it.Processed() <= int64(lines) {
		t.Fatalf("processed %d bytes for %d bytes of lines", it.Processed(), lines)
	}
}

func TestRereadAndAround(t *testing.T) {
	s := newSource(t, newFake(dataset(100)), nil)
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	for _, i := range []int{10, 11, 50} { // 11 shares its millisecond with 10
		got, err := s.Reread(ctx, recs[i].Ref)
		if err != nil || got.Event.Raw != recs[i].Event.Raw {
			t.Fatalf("reread %d: %v", i, err)
		}
	}
	bad := recs[11].Ref
	bad.Length = 9
	if _, err := s.Reread(ctx, bad); !errors.Is(err, source.ErrStale) {
		t.Fatalf("%v", err)
	}
	around, err := s.Around(ctx, recs[50].Ref, 3, 2)
	if err != nil || len(around) != 6 || around[3].Event.Raw != recs[50].Event.Raw || around[0].Event.Raw != recs[47].Event.Raw {
		t.Fatalf("around: %v %d", err, len(around))
	}
}

func TestCounts(t *testing.T) {
	docs := dataset(600)
	delete(docs[2].fields, "level") // absent
	f := newFake(docs)
	s := newSource(t, f, nil)
	r := source.Range{From: t0, To: t0.Add(20 * time.Minute)}
	sel := source.Selector{Terms: []source.Term{{Field: "app", Op: "=", Values: []string{"api"}}}}
	want := map[string]int64{}
	var total int64
	for _, d := range docs {
		if d.fields["app"] != "api" || !r.Contains(d.ts) {
			continue
		}
		lv, _ := d.fields["level"].(string)
		b := r.From.Add(d.ts.Sub(r.From) / (5 * time.Minute) * (5 * time.Minute))
		want[b.Format(time.RFC3339)+" "+lv]++
		total++
	}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"level"}, Bucket: 5 * time.Minute, Selector: sel})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, row := range res.Rows {
		got[row.Bucket.Format(time.RFC3339)+" "+row.Vals[0]] += row.N
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %d, want %d", k, got[k], v)
		}
	}
	if got[t0.Format(time.RFC3339)+" "] != 1 || want[t0.Format(time.RFC3339)+" "] != 1 {
		t.Fatalf("the absent level is not counted: %v", got)
	}
	// Selector only: a _count.
	n := len(f.requests)
	one, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Selector: sel})
	if err != nil || len(one.Rows) != 1 || one.Rows[0].N != total || !one.Rows[0].Bucket.Equal(r.From) {
		t.Fatalf("count: %v %+v", err, one.Rows)
	}
	if f.requests[n] != "POST /logs-*/_count" {
		t.Fatalf("selector-only count sent %s", f.requests[n])
	}
	// By without a bucket: terms over the range; buckets off the epoch: an offset.
	byOnly, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"level"}, Selector: sel})
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, row := range byOnly.Rows {
		sum += row.N
	}
	if sum != total {
		t.Fatalf("by-only total %d, want %d", sum, total)
	}
	off := source.Range{From: t0.Add(90 * time.Second), To: t0.Add(30 * time.Minute)}
	shifted, err := s.IndexCounts(ctx, source.CountQuery{Range: off, Bucket: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range shifted.Rows {
		if row.Bucket.Sub(off.From)%(10*time.Minute) != 0 {
			t.Fatalf("bucket %v not aligned to the range", row.Bucket)
		}
	}
	// Not served: untrusted fields, too many buckets, sub-millisecond bounds,
	// too many fields.
	for _, q := range []source.CountQuery{
		{Range: r, By: []string{"pod"}, Bucket: time.Minute},
		{Range: r, Selector: source.Selector{Terms: []source.Term{{Field: "pod", Op: "=", Values: []string{"x"}}}}},
		{Range: source.Range{From: t0, To: t0.Add(1001 * time.Minute)}, Bucket: time.Minute},
		{Range: source.Range{From: t0.Add(time.Microsecond), To: t0.Add(time.Hour)}},
		{Range: r, By: []string{"app", "level", "app"}},
	} {
		if _, err := s.IndexCounts(ctx, q); !errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("%+v: %v", q, err)
		}
	}
	for _, b := range f.bodies {
		var sb SearchBody
		if strictDecode(b, &sb) != nil {
			continue
		}
		for _, a := range sb.Aggs {
			if a.DateHistogram != nil && a.Terms == nil {
				for _, sub := range a.Aggs {
					if sub.Terms == nil || sub.Terms.Size > MaxTermsSize {
						t.Fatalf("aggs %s", b)
					}
				}
			}
		}
	}
}

func TestCountsOverflowAndMultiValues(t *testing.T) {
	var docs []fakeDoc
	for i := 0; i < 150; i++ {
		docs = append(docs, fakeDoc{index: "logs-a", id: string(rune('a' + i%26)), ts: t0.Add(time.Duration(i) * time.Second),
			fields: map[string]any{"app": "a" + strings.Repeat("x", i%120)}})
	}
	s := newSource(t, newFake(docs), nil)
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}
	var other, sum int64
	for _, row := range res.Rows {
		sum += row.N
		if row.Vals[0] == index.Other {
			other += row.N
		}
	}
	if sum != 150 || other == 0 || len(res.Rows) != MaxTermsSize+1 {
		t.Fatalf("sum %d other %d rows %d", sum, other, len(res.Rows))
	}
	docs[0].fields["app"] = []string{"p", "q"}
	s = newSource(t, newFake(docs), nil)
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"app"}, Bucket: time.Hour}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("multi-valued: %v", err)
	}
}

func TestCheckPrivileges(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mod        func(*fakeES)
		production bool
		ok         bool
	}{
		{"read-only key on production", nil, true, true},
		{"write key on production", func(f *fakeES) { f.privs["write"] = true }, true, false},
		{"manage cluster key on production", func(f *fakeES) { f.privs["cluster:manage"] = true }, true, false},
		{"api key manager on production", func(f *fakeES) { f.privs["cluster:manage_own_api_key"] = true }, true, false},
		{"write key off production", func(f *fakeES) { f.privs["write"] = true }, false, true},
		{"no read", func(f *fakeES) { f.privs["read"] = false }, false, false},
		{"security disabled on production", func(f *fakeES) { f.security = false }, true, false},
		{"security disabled off production", func(f *fakeES) { f.security = false }, false, true},
		{"opensearch readall on production", func(f *fakeES) { f.flavour, f.roles = "opensearch", []string{"readall"} }, true, true},
		{"opensearch all_access on production", func(f *fakeES) { f.flavour, f.roles = "opensearch", []string{"readall", "all_access"} }, true, false},
		{"opensearch custom role on production", func(f *fakeES) { f.flavour, f.roles = "opensearch", []string{"logs_reader"} }, true, false},
		{"opensearch security disabled off production", func(f *fakeES) { f.flavour, f.security = "opensearch", false }, false, true},
		{"text trusted field", func(f *fakeES) { f.types["level"] = "text" }, false, false},
		{"time field not a date", func(f *fakeES) { f.types["@timestamp"] = "keyword" }, false, false},
	} {
		f := newFake(nil)
		if tt.mod != nil {
			tt.mod(f)
		}
		s := newSource(t, f, nil)
		info, err := s.Check(ctx, tt.production)
		if (err == nil) != tt.ok {
			t.Errorf("%s: %+v %v", tt.name, info, err)
		}
	}
	// A vouched-for custom role passes.
	f := newFake(nil)
	f.flavour, f.roles = "opensearch", []string{"logs_reader"}
	s := newSource(t, f, func(o *Options) { o.ReadOnlyRoles = []string{"logs_reader"} })
	if info, err := s.Check(ctx, true); err != nil || info.Flavour != FlavourOpenSearch || !info.Verified {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestDescribe(t *testing.T) {
	f := newFake(dataset(50))
	s := newSource(t, f, nil)
	sch, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]source.FieldInfo{}
	for _, fi := range sch.Fields {
		names[fi.Name] = fi
	}
	if _, ok := names["_id"]; ok {
		t.Fatal("a metadata field listed")
	}
	if !slices.Equal(names["level"].Values, []string{"error", "info", "warn"}) || !names["level"].Trusted || names["pod"].Trusted || names["pod"].Values != nil || sch.Streams != 2 {
		t.Fatalf("%+v", sch)
	}
	for _, b := range f.bodies {
		if strings.Contains(string(b), "pod") || strings.Contains(string(b), "user_email") {
			t.Fatalf("values of an untrusted field asked: %s", b)
		}
	}
}

func TestAllowlistRefusals(t *testing.T) {
	f := newFake(nil)
	cl := client(t, f, []string{"logs-*"})
	for _, tt := range []struct{ method, path string }{
		{"POST", "/other/_search"},
		{"POST", "/_all/_search"},
		{"POST", "/logs-*/_delete_by_query"},
		{"POST", "/logs-*/_doc"},
		{"GET", "/logs-*/_search"},
		{"POST", "/logs-*/_update_by_query"},
		{"GET", "/_cat/indices"},
		{"POST", "/_security/user/_has_privileges"},
		{"GET", "/_cluster/settings"},
		{"POST", "/logs-*,.security/_search"},
		{"GET", "/logs-*/../_mapping"},
	} {
		if _, err := cl.Send(ctx, tt.method, tt.path, nil, []byte(`{}`)); !errors.Is(err, egress.ErrNotAllowed) {
			t.Errorf("%s %s: %v", tt.method, tt.path, err)
		}
	}
	if len(f.requests) != 0 {
		t.Fatalf("refused requests reached the backend: %v", f.requests)
	}
	p, _ := parse.New(parse.Options{})
	for _, idx := range [][]string{nil, {"_all"}, {".security"}, {"a,b"}, {"A"}, {"logs*x"}, {"remote:logs"}, {"*"}, {"a b"}} {
		if _, err := New(Options{Client: cl, Parser: p, Indices: idx}); err == nil {
			t.Errorf("indices %q accepted", idx)
		}
	}
	for _, o := range []Options{
		{Client: cl, Parser: p, Indices: []string{"a"}, TrustedFields: []string{"message"}},
		{Client: cl, Parser: p, Indices: []string{"a"}, TrustedFields: []string{"a*"}},
		{Client: cl, Parser: p, Indices: []string{"a"}, TimeField: `x"`},
		{Client: cl, Parser: p, Indices: []string{"a"}, Selector: map[string]string{"env": ""}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

func TestBackendErrorsCarryNoBody(t *testing.T) {
	srv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token-in-body u1@example.com", 500)
	})
	p, _ := parse.New(parse.Options{})
	s, _ := New(Options{Name: "es", Client: client(t, srv, []string{"logs"}), Parser: p, Indices: []string{"logs"}, Selector: map[string]string{"env": "prod"}})
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	_, err := it.Next()
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "@") || strings.Contains(err.Error(), "prod") {
		t.Fatalf("%v", err)
	}
}
