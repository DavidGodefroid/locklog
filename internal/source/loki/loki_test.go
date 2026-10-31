package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

type fakeEntry struct {
	ts     int64
	labels map[string]string
	meta   map[string]string
	line   string
}

// fakeLoki answers query_range (streams and the metric form locklog
// sends), labels and label values over an in-memory set of entries, with
// Loki's paging semantics (limit over all streams, forward, inclusive end).
type fakeLoki struct {
	mu       sync.Mutex
	entries  []fakeEntry
	requests []string
	queries  []string
	inflight int32
	maxIn    int32
	delay    time.Duration
}

func matches(ms [][3]string, l map[string]string) bool {
	for _, m := range ms {
		v, ok := l[m[0]]
		switch m[1] {
		case "=":
			if v != m[2] {
				return false
			}
		case "!=":
			if ok && v == m[2] {
				return false
			}
		case "=~", "!~":
			re := regexp.MustCompile("^(?:" + m[2] + ")$")
			if re.MatchString(v) != (m[1] == "=~") {
				return false
			}
		}
	}
	return true
}

var metricRe = regexp.MustCompile(`^sum by \(([^)]*)\) \(count_over_time\((.*) \[(\d+)s\]\)\)$`)

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := atomic.AddInt32(&f.inflight, 1)
	defer atomic.AddInt32(&f.inflight, -1)
	for {
		m := atomic.LoadInt32(&f.maxIn)
		if n <= m || atomic.CompareAndSwapInt32(&f.maxIn, m, n) {
			break
		}
	}
	time.Sleep(f.delay)
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.Path)
	f.mu.Unlock()
	q := r.URL.Query()
	categorize := r.Header.Get("X-Loki-Response-Encoding-Flags") == "categorize-labels"
	switch {
	case r.URL.Path == "/loki/api/v1/labels":
		set := map[string]bool{"__stream_shard__": true}
		for _, e := range f.entries {
			for k := range e.labels {
				set[k] = true
			}
		}
		var out []string
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": out})
	case strings.HasPrefix(r.URL.Path, "/loki/api/v1/label/"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/loki/api/v1/label/"), "/values")
		set := map[string]bool{}
		for _, e := range f.entries {
			if v, ok := e.labels[name]; ok {
				set[v] = true
			}
		}
		var out []string
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": out})
	case r.URL.Path == "/loki/api/v1/query":
		query := q.Get("query")
		at, _ := strconv.ParseInt(q.Get("time"), 10, 64)
		m := metricRe.FindStringSubmatch(query)
		if m == nil {
			http.Error(w, "unsupported", 400)
			return
		}
		rec := httptest.NewRecorder()
		f.metric(rec, m, at, at, "1")
		var mr map[string]any
		json.Unmarshal(rec.Body.Bytes(), &mr)
		var result []any
		for _, s := range mr["data"].(map[string]any)["result"].([]any) {
			sm := s.(map[string]any)
			vals := sm["values"].([]any)
			result = append(result, map[string]any{"metric": sm["metric"], "value": vals[0]})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
	case r.URL.Path == "/loki/api/v1/query_range":
		query := q.Get("query")
		f.mu.Lock()
		f.queries = append(f.queries, query)
		f.mu.Unlock()
		start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
		if m := metricRe.FindStringSubmatch(query); m != nil {
			f.metric(w, m, start, end, q.Get("step"))
			return
		}
		sel, err := parseQuery(query)
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var hits []fakeEntry
		for _, e := range f.entries {
			if e.ts >= start && e.ts <= end && matches(sel.stream, e.labels) && matches(sel.meta, e.meta) {
				hits = append(hits, e)
			}
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].ts < hits[j].ts })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		streams := map[string]map[string]any{}
		var order []string
		for _, e := range hits {
			labels := e.labels
			if !categorize {
				labels = map[string]string{}
				for k, v := range e.labels {
					labels[k] = v
				}
				for k, v := range e.meta {
					labels[k] = v
				}
			}
			k := labelsKey(labels)
			if streams[k] == nil {
				streams[k] = map[string]any{"stream": labels, "values": [][]any{}}
				order = append(order, k)
			}
			val := []any{strconv.FormatInt(e.ts, 10), e.line}
			if categorize {
				val = append(val, map[string]any{"structuredMetadata": e.meta})
			}
			streams[k]["values"] = append(streams[k]["values"].([][]any), val)
		}
		var result []any
		for _, k := range order {
			result = append(result, streams[k])
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeLoki) metric(w http.ResponseWriter, m []string, start, end int64, stepS string) {
	by := []string{}
	if m[1] != "" {
		by = strings.Split(m[1], ", ")
	}
	sel, _ := parseQuery(m[2])
	b, _ := strconv.ParseInt(m[3], 10, 64)
	step, _ := strconv.ParseInt(stepS, 10, 64)
	series := map[string]map[string]any{}
	for t := start; t <= end; t += step * 1e9 {
		counts := map[string]int{}
		metrics := map[string]map[string]string{}
		for _, e := range f.entries {
			if e.ts > t-b*1e9 && e.ts <= t && matches(sel.stream, e.labels) && matches(sel.meta, e.meta) {
				mm := map[string]string{}
				for _, l := range by {
					if v, ok := e.labels[l]; ok {
						mm[l] = v
					}
				}
				k := labelsKey(mm)
				counts[k]++
				metrics[k] = mm
			}
		}
		for k, c := range counts {
			if series[k] == nil {
				series[k] = map[string]any{"metric": metrics[k], "values": [][]any{}}
			}
			series[k]["values"] = append(series[k]["values"].([][]any), []any{float64(t) / 1e9, strconv.Itoa(c)})
		}
	}
	var result []any
	for _, s := range series {
		result = append(result, s)
	}
	json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": result}})
}

// dataset: two apps, levels, trace ids and e-mails in metadata, every
// tenth entry sharing its timestamp with the next.
func dataset(n int) []fakeEntry {
	var out []fakeEntry
	lv := []string{"info", "info", "warn", "error"}
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * 2 * time.Second).UnixNano()
		if i%10 == 1 {
			ts = out[i-1].ts // ties
		}
		app := []string{"api", "worker"}[i%2]
		out = append(out, fakeEntry{
			ts:     ts,
			labels: map[string]string{"env": "prod", "app": app, "level": lv[i%4], "pod": fmt.Sprintf("pod-%d", i%3)},
			meta:   map[string]string{"trace_id": fmt.Sprintf("t%d", i/5), "user_email": fmt.Sprintf("u%d@example.com", i%7)},
			line:   fmt.Sprintf(`{"ts":"2020-01-01T00:00:00Z","msg":"request %d","status":%d}`, i, 200+100*(i%4)),
		})
	}
	return out
}

func newSource(t *testing.T, f *fakeLoki, mod func(*Options)) *Source {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cl, err := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{},
		egress.Options{Headers: egress.LokiHeaders})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	o := Options{Name: "loki", Client: cl, Parser: p, Selector: map[string]string{"env": "prod"},
		TrustedLabels: []string{"app", "level"}, TrustedMetadata: []string{"trace_id"}, Limit: 7, Now: func() time.Time { return t0.Add(time.Hour) }}
	if mod != nil {
		mod(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var ctx = context.Background()

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

func TestRenderEscapesAndParsesBack(t *testing.T) {
	sel := Selector{Stream: []Matcher{{Name: "app", Op: "=", Values: []string{`a"} | line_format "{{.x}}`}},
		{Name: "level", Op: "=~", Values: []string{"error", "a.b|c", "é\\"}}},
		Meta: []Matcher{{Name: "trace_id", Op: "!=", Values: []string{"x\" or 1"}}}}
	q, err := sel.Render()
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseQuery(q)
	if err != nil || len(back.stream) != 2 || back.stream[0][2] != `a"} | line_format "{{.x}}` || len(back.meta) != 1 {
		t.Fatalf("%q -> %+v %v", q, back, err)
	}
	re := regexp.MustCompile("^(?:" + back.stream[1][2] + ")$")
	if !re.MatchString("a.b|c") || re.MatchString("aXb") || !re.MatchString(`é\`) {
		t.Fatalf("alternation %q", back.stream[1][2])
	}
	for _, bad := range []Selector{
		{},
		{Stream: []Matcher{{Name: "a-b", Op: "=", Values: []string{"x"}}}},
		{Stream: []Matcher{{Name: "a", Op: "=", Values: []string{"x\ny"}}}},
		{Stream: []Matcher{{Name: "a", Op: "|=", Values: []string{"x"}}}},
	} {
		if _, err := bad.Render(); err == nil {
			t.Fatalf("%+v rendered", bad)
		}
	}
}

func TestPlanSlicesAlignedAndQueryIndependent(t *testing.T) {
	s := newSource(t, &fakeLoki{}, nil)
	r := source.Range{From: t0.Add(17 * time.Second), To: t0.Add(24 * time.Hour)}
	p, err := s.Plan(ctx, r, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	gs := p.Chunks[0].Granules
	if len(gs) != 288 || time.Duration(gs[0].End-gs[0].Start) != 5*time.Minute || gs[0].From != t0 {
		t.Fatalf("%d slices of %v from %v", len(gs), time.Duration(gs[0].End-gs[0].Start), gs[0].From)
	}
	for _, g := range gs {
		if g.Bytes != 0 {
			t.Fatal("a remote slice has a planned size")
		}
	}
	if w := width(source.Range{From: t0, To: t0.Add(7 * 24 * time.Hour)}); w != time.Hour {
		t.Fatalf("7 d width %v", w)
	}
}

func TestScanReturnsEveryEntryOnceInOrder(t *testing.T) {
	f := &fakeLoki{entries: dataset(300)}
	s := newSource(t, f, nil)
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	if len(recs) != 300 {
		t.Fatalf("%d records, want 300", len(recs))
	}
	seen := map[string]bool{}
	for i, r := range recs {
		if i > 0 && r.Event.Time.Before(recs[i-1].Event.Time) {
			t.Fatal("out of order")
		}
		var e map[string]any
		json.Unmarshal([]byte(r.Event.Raw), &e)
		if seen[r.Event.Raw] {
			t.Fatalf("duplicate %s", r.Event.Raw)
		}
		seen[r.Event.Raw] = true
		// The entry's timestamp is the record time; the payload's own
		// ts stays a field.
		if v, ok := parse.Get(r.Event.Fields, "ts"); !ok || v.Str != "2020-01-01T00:00:00Z" || r.Event.Time.Year() != 2026 {
			t.Fatalf("time handling %+v", r.Event)
		}
		for _, a := range r.Event.Attrs {
			if !slices.Contains([]string{"app", "level", "trace_id"}, a.Key) {
				t.Fatalf("untrusted attr %q returned", a.Key)
			}
		}
	}
	if f.maxIn > InFlight {
		t.Fatalf("%d requests in flight", f.maxIn)
	}
}

func TestUntrustedMetadataDroppedWithoutEncodingFlag(t *testing.T) {
	// Without categorize-labels, Loki merges metadata into the stream's
	// labels: user_email then looks like a label, and is still dropped.
	f := &fakeLoki{entries: dataset(20)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cl, _ := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{}, egress.Options{})
	p, _ := parse.New(parse.Options{})
	s, _ := New(Options{Name: "l", Client: cl, Parser: p, Selector: map[string]string{"env": "prod"}, TrustedLabels: []string{"app"}})
	for _, r := range scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{}) {
		for _, a := range r.Event.Attrs {
			if a.Key != "app" {
				t.Fatalf("attr %q returned", a.Key)
			}
		}
	}
}

func TestTrustedTermsGoServerSide(t *testing.T) {
	f := &fakeLoki{entries: dataset(200)}
	s := newSource(t, f, nil)
	sel := source.Selector{Terms: []source.Term{
		{Field: "level", Op: "in", Values: []string{"error", "warn"}},
		{Field: "trace_id", Op: "=", Values: []string{"t3"}},
		{Field: "status", Op: "=", Values: []string{"500"}}, // not a label: evaluated locally
	}}
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, sel)
	for _, r := range recs {
		var lvl string
		for _, a := range r.Event.Attrs {
			if a.Key == "level" {
				lvl = a.Value.Str
			}
		}
		if lvl != "error" && lvl != "warn" {
			t.Fatalf("level %q", lvl)
		}
	}
	want := 0
	for _, e := range f.entries {
		if (e.labels["level"] == "error" || e.labels["level"] == "warn") && e.meta["trace_id"] == "t3" {
			want++
		}
	}
	if len(recs) != want || want == 0 {
		t.Fatalf("%d records, want %d", len(recs), want)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "status") || strings.Contains(q, "500") {
			t.Fatalf("an untrusted term reached Loki: %s", q)
		}
		if !strings.Contains(q, `env="prod"`) {
			t.Fatalf("the profile selector is missing: %s", q)
		}
	}
}

type countLimiter struct{ n int32 }

func (c *countLimiter) Wait(context.Context) error { atomic.AddInt32(&c.n, 1); return nil }

func TestRequestsGoThroughTheCallLimiter(t *testing.T) {
	f := &fakeLoki{entries: dataset(100)}
	s := newSource(t, f, nil)
	l := &countLimiter{}
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(source.WithLimiter(ctx, l), plan.Chunks[0])
	drain(t, it)
	if int(l.n) != len(f.requests) || l.n == 0 {
		t.Fatalf("limiter saw %d of %d requests", l.n, len(f.requests))
	}
}

func TestProcessedCountsFetchedBytes(t *testing.T) {
	f := &fakeLoki{entries: dataset(100)}
	s := newSource(t, f, nil)
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	recs := drain(t, it)
	var lines int
	for _, r := range recs {
		lines += len(r.Event.Raw)
	}
	if it.Processed() <= int64(lines) {
		t.Fatalf("processed %d bytes for %d bytes of lines", it.Processed(), lines)
	}
}

func TestRereadAndAround(t *testing.T) {
	f := &fakeLoki{entries: dataset(100)}
	s := newSource(t, f, nil)
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	// recs[11] shares its timestamp with recs[10].
	for _, i := range []int{10, 11, 50} {
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

func TestMetricCounts(t *testing.T) {
	f := &fakeLoki{entries: dataset(600)}
	s := newSource(t, f, nil)
	r := source.Range{From: t0, To: t0.Add(20 * time.Minute)}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"level"}, Bucket: 5 * time.Minute,
		Selector: source.Selector{Terms: []source.Term{{Field: "app", Op: "=", Values: []string{"api"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{}
	for _, e := range f.entries {
		ts := time.Unix(0, e.ts).UTC()
		if e.labels["app"] != "api" || ts.Before(r.From) || !ts.Before(r.To) {
			continue
		}
		// Loki's windows are (b, b+5m]: an entry exactly on a bucket
		// start belongs to the bucket before.
		b := r.From.Add((ts.Sub(r.From) - 1) / (5 * time.Minute) * (5 * time.Minute))
		if ts.Equal(r.From) {
			continue
		}
		want[b.Format(time.RFC3339)+" "+e.labels["level"]]++
	}
	got := map[string]int64{}
	for _, row := range res.Rows {
		got[row.Bucket.Format(time.RFC3339)+" "+row.Vals[0]] += row.N
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %d, want %d (got %v)", k, got[k], v, got)
		}
	}
	for _, q := range f.queries {
		if !strings.HasPrefix(q, "sum by (level) (count_over_time({") {
			t.Fatalf("query %s", q)
		}
	}
	// One bucket for the range: an instant query.
	one, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"level"},
		Selector: source.Selector{Terms: []source.Term{{Field: "app", Op: "=", Values: []string{"api"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var sum1, sum2 int64
	for _, row := range one.Rows {
		sum1 += row.N
	}
	for _, row := range res.Rows {
		sum2 += row.N
	}
	if sum1 != sum2 || sum1 == 0 {
		t.Fatalf("instant %d, range %d", sum1, sum2)
	}
	// Buckets off Loki's step grid are not served.
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: r.From.Add(time.Minute), To: r.To.Add(time.Minute)}, Bucket: 5 * time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("misaligned: %v", err)
	}
	// By metadata or by an untrusted label: not served by Loki.
	for _, by := range []string{"trace_id", "pod"} {
		if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{by}, Bucket: time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("by %s: %v", by, err)
		}
	}
}

func TestDescribeAsksValuesOfTrustedLabelsOnly(t *testing.T) {
	f := &fakeLoki{entries: dataset(50)}
	s := newSource(t, f, nil)
	sch, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range f.requests {
		if strings.HasPrefix(p, "/loki/api/v1/label/") && !strings.HasPrefix(p, "/loki/api/v1/label/app/") && !strings.HasPrefix(p, "/loki/api/v1/label/level/") {
			t.Fatalf("values of an untrusted label asked: %s", p)
		}
	}
	names := map[string]source.FieldInfo{}
	for _, fi := range sch.Fields {
		names[fi.Name] = fi
	}
	if _, ok := names["__stream_shard__"]; ok {
		t.Fatal("Loki's shard label shown")
	}
	if !slices.Equal(names["level"].Values, []string{"error", "info", "warn"}) || names["pod"].Values != nil || names["pod"].Trusted {
		t.Fatalf("%+v", sch.Fields)
	}
}

func TestBackendErrorsCarryNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token-in-body u1@example.com", 500)
	}))
	defer srv.Close()
	cl, _ := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{}, egress.Options{})
	p, _ := parse.New(parse.Options{})
	s, _ := New(Options{Name: "l", Client: cl, Parser: p, Selector: map[string]string{"env": "prod"}})
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	_, err := it.Next()
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "@") || strings.Contains(err.Error(), "env") {
		t.Fatalf("%v", err)
	}
	_ = url.Values{}
}
