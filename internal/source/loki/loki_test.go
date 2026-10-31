package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
// Loki's paging semantics (limit over all streams, forward, end excluded).
type fakeLoki struct {
	mu       sync.Mutex
	entries  []fakeEntry
	requests []string
	queries  []string
	inflight int32
	maxIn    int32
	delay    time.Duration
	// metaQueries are the query parameters of the label requests.
	metaQueries []string
	// ignoreFlags answers as a backend that ignores the encoding-flags
	// header (metadata merged into the stream labels, no encodingFlags).
	ignoreFlags bool
	// inject adds an entry before the request of that index (counting
	// /query and /query_range requests from 0): ingestion during a count.
	inject map[int]fakeEntry
	nQuery int
	// reverseTies returns the entries of one nanosecond in reverse
	// insertion order (Loki orders ties by its own label string).
	reverseTies bool
	// refuse answers metric queries with this status and message (a
	// Loki limit).
	refuseStatus int
	refuseMsg    string
	// offGrid writes metric points 1 s late (a backend whose grid is
	// not the one asked for).
	offGrid bool
	// onRange, when set, is called before a log query_range is answered.
	onRange func(start, end int64)
}

func matches(ms [][3]string, l map[string]string) bool {
	for _, m := range ms {
		v := l[m[0]]
		switch m[1] {
		case "=":
			if v != m[2] {
				return false
			}
		case "!=":
			// An absent label is "" (Loki and Prometheus): x!="" means
			// "present".
			if v == m[2] {
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

// merged is what a LogQL | name=... filter sees: the stream labels and the
// structured metadata of an entry (metadata wins on a shared name).
func merged(e fakeEntry) map[string]string {
	m := maps.Clone(e.labels)
	maps.Copy(m, e.meta)
	return m
}

var metricRe = regexp.MustCompile(`^sum by \(([^)]*)\) \(count_over_time\((.*) \[(\d+(?:ms|s))\]\)\)$`)

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
	categorize := r.Header.Get("X-Loki-Response-Encoding-Flags") == "categorize-labels" && !f.ignoreFlags
	// The label endpoints describe the streams their query selects (all
	// of them without one).
	var metaSel [][3]string
	if strings.HasPrefix(r.URL.Path, "/loki/api/v1/label") {
		f.mu.Lock()
		f.metaQueries = append(f.metaQueries, q.Get("query"))
		f.mu.Unlock()
		if qq := q.Get("query"); qq != "" {
			sel, err := parseQuery(qq)
			if err != nil {
				http.Error(w, "parse error", 400)
				return
			}
			metaSel = sel.stream
		}
	}
	switch {
	case r.URL.Path == "/loki/api/v1/labels":
		set := map[string]bool{"__stream_shard__": true}
		for _, e := range f.entries {
			if !matches(metaSel, e.labels) {
				continue
			}
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
			if v, ok := e.labels[name]; ok && matches(metaSel, e.labels) {
				set[v] = true
			}
		}
		var out []string
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": out})
	case (r.URL.Path == "/loki/api/v1/query" || r.URL.Path == "/loki/api/v1/query_range") && f.injectNow():
		f.ServeHTTP(w, r) // after the injection
	case f.refuseStatus != 0 && metricRe.MatchString(q.Get("query")):
		http.Error(w, f.refuseMsg, f.refuseStatus)
	case r.URL.Path == "/loki/api/v1/query":
		query := q.Get("query")
		at, _ := strconv.ParseInt(q.Get("time"), 10, 64)
		m := metricRe.FindStringSubmatch(query)
		if m == nil {
			http.Error(w, "unsupported", 400)
			return
		}
		rec := httptest.NewRecorder()
		f.metric(rec, m, at, at, "")
		var mr map[string]any
		json.Unmarshal(rec.Body.Bytes(), &mr)
		result := []any{}
		series, _ := mr["data"].(map[string]any)["result"].([]any)
		for _, s := range series {
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
		if f.onRange != nil {
			f.onRange(start, end)
		}
		sel, err := parseQuery(query)
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var hits []fakeEntry
		for _, e := range f.entries {
			// [start, end): grafana/loki:3.5.7 excludes a log query's end.
			if e.ts >= start && e.ts < end && matches(sel.stream, e.labels) && matches(sel.meta, merged(e)) {
				hits = append(hits, e)
			}
		}
		if f.reverseTies {
			slices.Reverse(hits)
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
		data := map[string]any{"resultType": "streams", "result": result}
		if categorize {
			data["encodingFlags"] = []string{"categorize-labels"}
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
	default:
		http.NotFound(w, r)
	}
}

// metric evaluates a metric query as grafana/loki:3.5.7 does: the query
// frontend rounds a range query's start down and its end up to the step
// (pkg/querier/queryrange/splitters.go, alignStartEnd); at each step t,
// count_over_time counts (t-range, t] to the nanosecond; the point's time
// is t in milliseconds, written as seconds with a millisecond fraction
// (model.Time.String). (Offsets are not modelled: locklog sends none.)
// injectNow adds the entry to inject at this request, once; it reports
// whether it did.
func (f *fakeLoki) injectNow() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.inject[f.nQuery]
	delete(f.inject, f.nQuery)
	f.nQuery++
	if ok {
		f.entries = append(f.entries, e)
		f.nQuery-- // the same request again
	}
	return ok
}

func (f *fakeLoki) metric(w http.ResponseWriter, m []string, start, end int64, stepS string) {
	by := []string{}
	if m[1] != "" {
		by = strings.Split(m[1], ", ")
	}
	sel, _ := parseQuery(m[2])
	d, err := time.ParseDuration(m[3])
	if err != nil {
		http.Error(w, "bad range", 400)
		return
	}
	rng := int64(d)
	step, _ := strconv.ParseInt(stepS, 10, 64)
	step *= 1e9
	if stepS != "" {
		start -= start % step
		if r := end % step; r != 0 {
			end += step - r
		}
	} else {
		step = 1
	}
	series := map[string]map[string]any{}
	for t := start; t <= end; t += step {
		counts := map[string]int{}
		metrics := map[string]map[string]string{}
		for _, e := range f.entries {
			if e.ts > t-rng && e.ts <= t && matches(sel.stream, e.labels) && matches(sel.meta, merged(e)) {
				// Loki groups on the stream labels plus the entry's
				// metadata, a metadata field taking the name of a label
				// the stream lacks (LabelsBuilder.Add; L_extracted
				// otherwise).
				mm := map[string]string{}
				for _, l := range by {
					if v, ok := e.labels[l]; ok {
						mm[l] = v
					} else if v, ok := e.meta[l]; ok {
						mm[l] = v
					}
				}
				k := labelsKey(mm)
				counts[k]++
				metrics[k] = mm
			}
		}
		ms := t / 1e6
		if f.offGrid {
			ms += 1000
		}
		for k, c := range counts {
			if series[k] == nil {
				series[k] = map[string]any{"metric": metrics[k], "values": [][]any{}}
			}
			series[k]["values"] = append(series[k]["values"].([][]any), []any{json.RawMessage(strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)), strconv.Itoa(c)})
		}
	}
	result := []any{}
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
	if w, err := width(source.Range{From: t0, To: t0.Add(7 * 24 * time.Hour)}); err != nil || w != time.Hour {
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

func TestCategorizeLabelsRequired(t *testing.T) {
	// The source asks for categorize-labels itself: a client built without
	// the fixed header still gets the metadata apart (trace_id is trusted
	// metadata, not a label).
	f := &fakeLoki{entries: dataset(20)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cl, _ := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{}, egress.Options{})
	p, _ := parse.New(parse.Options{})
	s, _ := New(Options{Name: "l", Client: cl, Parser: p, Selector: map[string]string{"env": "prod"}, TrustedLabels: []string{"app"}, TrustedMetadata: []string{"trace_id"}})
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	if len(recs) != 20 {
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		keys := []string{}
		for _, a := range r.Event.Attrs {
			keys = append(keys, a.Key)
		}
		if !slices.Equal(keys, []string{"app", "trace_id"}) {
			t.Fatalf("attrs %v", keys)
		}
	}
	// A backend that ignores the flag (metadata merged into the labels,
	// where an untrusted field could pass for a label): refused.
	f.ignoreFlags = true
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	defer it.Close()
	if _, err := it.Next(); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("an uncategorized response accepted: %v", err)
	}
}

func TestTrustedTermsGoServerSide(t *testing.T) {
	f := &fakeLoki{entries: dataset(200)}
	s := newSource(t, f, nil)
	sel := source.Selector{Terms: []source.Term{
		{Field: "level", Label: true, Op: "in", Values: []string{"error", "warn"}},
		{Field: "trace_id", Label: true, Op: "=", Values: []string{"t3"}}, // metadata: evaluated locally
		{Field: "status", Op: "=", Values: []string{"500"}},               // not a label: evaluated locally
		{Field: "app", Op: "=", Values: []string{"web"}},                  // a line field named like a label: local
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
		if e.labels["level"] == "error" || e.labels["level"] == "warn" {
			want++
		}
	}
	if len(recs) != want || want == 0 {
		t.Fatalf("%d records, want %d", len(recs), want)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "status") || strings.Contains(q, "500") || strings.Contains(q, "trace_id") || strings.Contains(q, "web") {
			t.Fatalf("a term other than a trusted label reached Loki: %s", q)
		}
		if !strings.Contains(q, `env="prod"`) {
			t.Fatalf("the profile selector is missing: %s", q)
		}
	}
}

func TestStreamLabelShadowingMetadata(t *testing.T) {
	// Anyone who writes to Loki can add a stream label named like trusted
	// metadata; a | trace_id="x" filter would match it. Metadata terms are
	// never pushed down, so it cannot select records or counts, and a
	// record's trace_id is its metadata only.
	f := &fakeLoki{entries: dataset(40)}
	for i := 0; i < 5; i++ {
		f.entries = append(f.entries, fakeEntry{ts: t0.Add(time.Duration(i) * time.Second).UnixNano(),
			labels: map[string]string{"env": "prod", "app": "api", "level": "info", "trace_id": "t3"},
			meta:   map[string]string{"trace_id": "forged"}, line: "shadow"})
		f.entries = append(f.entries, fakeEntry{ts: t0.Add(time.Duration(i) * time.Second).UnixNano(),
			labels: map[string]string{"env": "prod", "app": "api", "level": "info", "trace_id": "t3"}, line: "shadow, no metadata"})
	}
	s := newSource(t, f, nil)
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	sel := source.Selector{Terms: []source.Term{{Field: "trace_id", Label: true, Op: "=", Values: []string{"t3"}}}}
	recs := scanAll(t, s, r, sel)
	if len(recs) != len(f.entries) {
		t.Fatalf("%d records, want all %d (the engine filters)", len(recs), len(f.entries))
	}
	matched := 0
	for _, rec := range recs {
		vals := map[string]string{}
		for _, a := range rec.Event.Attrs {
			vals[a.Key] = a.Value.Str
		}
		if strings.HasPrefix(rec.Event.Raw, "shadow") && vals["trace_id"] == "t3" {
			t.Fatalf("a stream label passed for trusted metadata: %+v", rec.Event.Attrs)
		}
		if sel.Match(nil, vals) {
			matched++
		}
	}
	if matched != 5 { // dataset entries 15..19
		t.Fatalf("%d records match trace_id=t3 locally, want 5", matched)
	}
	for _, q := range f.queries {
		if strings.Contains(q, "trace_id") {
			t.Fatalf("a metadata term reached Loki: %s", q)
		}
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: t0, To: t0.Add(20 * time.Minute)}, Bucket: 5 * time.Minute, Selector: sel}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("a count on metadata served by Loki: %v", err)
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

// wantCounts counts the entries of f by [bucket, bucket+width) from r.From
// (the engine's buckets), for app=api, by level.
func wantCounts(f *fakeLoki, r source.Range, width time.Duration) map[string]int64 {
	want := map[string]int64{}
	for _, e := range f.entries {
		ts := time.Unix(0, e.ts).UTC()
		if e.labels["app"] != "api" || ts.Before(r.From) || !ts.Before(r.To) {
			continue
		}
		b := r.From.Add(ts.Sub(r.From) / width * width)
		want[b.Format(time.RFC3339)+" "+e.labels["level"]]++
	}
	return want
}

func gotCounts(res source.CountResult) map[string]int64 {
	got := map[string]int64{}
	for _, row := range res.Rows {
		got[row.Bucket.Format(time.RFC3339)+" "+row.Vals[0]] += row.N
	}
	return got
}

func TestMetricCounts(t *testing.T) {
	r := source.Range{From: t0, To: t0.Add(20 * time.Minute)}
	f := &fakeLoki{entries: dataset(700)} // past To, and an entry exactly on From and on each bucket boundary
	// The edges: the last nanosecond of a bucket, and exactly To.
	for _, at := range []time.Time{t0.Add(5*time.Minute - 1), t0.Add(10*time.Minute - 1), r.To, r.To.Add(-1)} {
		f.entries = append(f.entries, fakeEntry{ts: at.UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "edge"}, line: "edge"})
	}
	s := newSource(t, f, nil)
	sel := source.Selector{Terms: []source.Term{{Field: "app", Label: true, Op: "=", Values: []string{"api"}}}}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Bucket: 5 * time.Minute, Selector: sel})
	if err != nil {
		t.Fatal(err)
	}
	want, got := wantCounts(f, r, 5*time.Minute), gotCounts(res)
	if !maps.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	// The counts, the 1 ms guard, and the boundary entries (log queries
	// that never leave the source).
	guards, logs := 0, 0
	for _, q := range f.queries {
		switch {
		case strings.HasPrefix(q, "sum by (level) (count_over_time({") && strings.HasSuffix(q, `level!=""} [300s]))`):
		case strings.HasPrefix(q, "sum by () (count_over_time({") && strings.HasSuffix(q, `level=""} [300s]))`):
		case strings.HasPrefix(q, "sum by () (count_over_time({") && strings.HasSuffix(q, " [1ms]))"):
			guards++
		case strings.HasPrefix(q, "{"):
			logs++
		default:
			t.Fatalf("query %s", q)
		}
	}
	if guards != 2 || logs == 0 {
		t.Fatalf("%d guard queries, %d boundary fetches", guards, logs)
	}
	// One bucket for the range: an instant query, [From, To).
	one, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Selector: sel})
	if err != nil {
		t.Fatal(err)
	}
	if want, got := wantCounts(f, r, r.To.Sub(r.From)), gotCounts(one); !maps.Equal(got, want) {
		t.Fatalf("instant: got %v\nwant %v", got, want)
	}
	// Buckets off Loki's step grid are not served.
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: r.From.Add(time.Minute), To: r.To.Add(time.Minute)}, Bucket: 5 * time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("misaligned: %v", err)
	}
	// By a line field (even one named like a trusted label): not served.
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, By: []string{"level"}, Bucket: time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("by the field level: %v", err)
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Selector: source.Selector{Terms: []source.Term{{Field: "app", Op: "=", Values: []string{"api"}}}}}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("a field term named like a label: %v", err)
	}
	// By metadata or by an untrusted label: not served by Loki.
	for _, by := range []string{"trace_id", "pod"} {
		if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{by}, Bucket: time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("by %s: %v", by, err)
		}
	}
	// A backend whose points are not on the grid asked for: not served.
	f.offGrid = true
	for _, b := range []time.Duration{5 * time.Minute, 0} {
		if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Bucket: b, Selector: sel}); !errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("bucket %v off the grid: %v", b, err)
		}
	}
}

func TestDescribeAsksValuesOfTrustedLabelsOnly(t *testing.T) {
	// Another profile's stream: neither its label names nor its values
	// are described.
	f := &fakeLoki{entries: append(dataset(50), fakeEntry{ts: t0.UnixNano(), labels: map[string]string{"env": "dev", "level": "dev-only", "dev_secret_label": "x"}, line: "x"})}
	s := newSource(t, f, nil)
	sch, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := s.selector(source.Selector{}).Render()
	if len(f.metaQueries) < 2 {
		t.Fatalf("%d label requests", len(f.metaQueries))
	}
	for _, q := range f.metaQueries {
		if q != want {
			t.Fatalf("a label request carries query %q, want the profile selector %q", q, want)
		}
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
	if _, ok := names["dev_secret_label"]; ok {
		t.Fatal("a label of another profile's streams described")
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

// sameNanosecond is n entries at one nanosecond, then `later` entries
// one second apart.
func sameNanosecond(n, later int) []fakeEntry {
	var out []fakeEntry
	for i := 0; i < n; i++ {
		out = append(out, fakeEntry{ts: t0.Add(time.Minute).UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "pod": strconv.Itoa(i)},
			line: fmt.Sprintf("tie %d", i)})
	}
	for i := 0; i < later; i++ {
		out = append(out, fakeEntry{ts: t0.Add(time.Minute + time.Duration(i+1)*time.Second).UnixNano(), labels: map[string]string{"env": "prod", "app": "api"},
			line: fmt.Sprintf("later %d", i)})
	}
	return out
}

func TestPagingNeverTruncatesSilently(t *testing.T) {
	// More entries at one nanosecond than a page holds (Limit 7): an
	// explicit error, never a partial answer.
	s := newSource(t, &fakeLoki{entries: sameNanosecond(20, 5)}, nil)
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	n := 0
	var err error
	for _, c := range plan.Chunks {
		it, _ := s.Scan(ctx, c)
		for {
			if _, err = it.Next(); err != nil {
				break
			}
			n++
		}
		it.Close()
	}
	if errors.Is(err, io.EOF) || err == nil || !strings.Contains(err.Error(), "nanosecond") {
		t.Fatalf("scan returned %d of 25 entries, err %v: want an explicit error", n, err)
	}
	if _, err := s.Reread(ctx, source.RawRef{Source: "loki", Stream: plan.Chunks[0].Stream, Offset: t0.Add(time.Minute).UnixNano(), Length: 15}); err == nil || errors.Is(err, source.ErrStale) {
		t.Fatalf("reread at a crowded nanosecond: %v", err)
	}
	// Fewer than Limit at one nanosecond, starting a page: all of them.
	for _, tc := range []struct{ tie, later int }{{6, 5}, {6, 20}, {1, 30}} {
		s := newSource(t, &fakeLoki{entries: sameNanosecond(tc.tie, tc.later)}, nil)
		if recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{}); len(recs) != tc.tie+tc.later {
			t.Fatalf("%d ties + %d: %d records", tc.tie, tc.later, len(recs))
		}
		// And when the ties fall in the middle of a page.
		s = newSource(t, &fakeLoki{entries: append(sameNanosecond(tc.tie, tc.later), fakeEntry{ts: t0.Add(time.Second).UnixNano(),
			labels: map[string]string{"env": "prod"}, line: "first"}, fakeEntry{ts: t0.Add(2 * time.Second).UnixNano(), labels: map[string]string{"env": "prod"}, line: "second"})}, nil)
		if recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{}); len(recs) != tc.tie+tc.later+2 {
			t.Fatalf("2 + %d ties + %d: %d records", tc.tie, tc.later, len(recs))
		}
	}
}

func TestParseSeconds(t *testing.T) {
	for in, want := range map[string]int64{"1730289899.999": 1730289899999000000, "1730289900": 1730289900000000000, "1.000000001": 1000000001} {
		if got, ok := parseSeconds(json.RawMessage(in)); !ok || got != want {
			t.Errorf("%s: %d %t", in, got, ok)
		}
	}
	for _, bad := range []string{"", "-1", "1e9", "1.2.3", `"1"`, "1.0000000001"} {
		if _, ok := parseSeconds(json.RawMessage(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEmptyValuesNotPushedDown(t *testing.T) {
	// In Loki, x="" also matches an absent x and x!="" means present;
	// locally, = "" needs x present and empty. Such terms stay local.
	for _, term := range []source.Term{
		{Field: "level", Label: true, Op: "=", Values: []string{""}},
		{Field: "level", Label: true, Op: "!=", Values: []string{""}},
		{Field: "level", Label: true, Op: "in", Values: []string{"error", ""}},
		{Field: "trace_id", Label: true, Op: "!=", Values: []string{"t1", ""}},
	} {
		f := &fakeLoki{entries: dataset(40)}
		s := newSource(t, f, nil)
		recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{Terms: []source.Term{term}})
		if len(recs) != 40 {
			t.Fatalf("%+v: %d records, want all 40 (the engine filters)", term, len(recs))
		}
		for _, q := range f.queries {
			if strings.Contains(q, term.Field) {
				t.Fatalf("%+v pushed down: %s", term, q)
			}
		}
		if _, err := s.IndexCounts(ctx, source.CountQuery{Range: source.Range{From: t0, To: t0.Add(20 * time.Minute)}, Bucket: 5 * time.Minute,
			Selector: source.Selector{Terms: []source.Term{term}}}); !errors.Is(err, source.ErrNotIndexable) {
			t.Fatalf("%+v counted server-side: %v", term, err)
		}
	}
}

func TestMetadataNameThatIsALabelRefused(t *testing.T) {
	// A | name="v" filter also matches stream labels: a name both a label
	// and metadata would select on either.
	p, _ := parse.New(parse.Options{})
	for _, md := range []string{"level", "env"} {
		_, err := New(Options{Name: "l", Client: &egress.Client{}, Parser: p, Selector: map[string]string{"env": "prod"},
			TrustedLabels: []string{"app", "level"}, TrustedMetadata: []string{"trace_id", md}})
		if err == nil {
			t.Fatalf("trusted metadata %q accepted", md)
		}
	}
}

func TestResponseAndLineCaps(t *testing.T) {
	// The response cap (egress.MaxResponseBytes, 64 MiB; small here): a
	// page past it fails the scan.
	if egress.MaxResponseBytes != 64<<20 {
		t.Fatalf("response cap %d", egress.MaxResponseBytes)
	}
	f := &fakeLoki{entries: dataset(300)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cl, _ := egress.New(&config.Remote{URL: srv.URL, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{}, egress.Options{MaxResponseBytes: 4096})
	p, _ := parse.New(parse.Options{})
	s, _ := New(Options{Name: "l", Client: cl, Parser: p, Selector: map[string]string{"env": "prod"}, Limit: 100})
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	it, _ := s.Scan(ctx, plan.Chunks[0])
	if _, err := it.Next(); !errors.Is(err, egress.ErrResponseTooLarge) {
		t.Fatalf("over the response cap: %v", err)
	}
	it.Close()
	// The line cap (parse.MaxLineBytes, 256 KiB): a longer line is cut.
	long := strings.Repeat("x", parse.MaxLineBytes+1000)
	f = &fakeLoki{entries: []fakeEntry{{ts: t0.UnixNano(), labels: map[string]string{"env": "prod"}, line: long}}}
	recs := scanAll(t, newSource(t, f, nil), source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{})
	if len(recs) != 1 || len(recs[0].Event.Raw) != parse.MaxLineBytes || !recs[0].Event.Truncated {
		t.Fatalf("long line: %d records, %d bytes kept", len(recs), len(recs[0].Event.Raw))
	}
}

func TestPlanEnforcesMaxSlices(t *testing.T) {
	s := newSource(t, &fakeLoki{}, nil)
	day := 24 * time.Hour
	// 512 aligned days: 512 slices, the most.
	p, err := s.Plan(ctx, source.Range{From: t0.Truncate(day), To: t0.Truncate(day).Add(MaxSlices * day)}, source.Selector{})
	if err != nil || len(p.Chunks[0].Granules) != MaxSlices {
		t.Fatalf("512 days: %v", err)
	}
	// One more slice (here from a start off the day): refused.
	for _, r := range []source.Range{
		{From: t0, To: t0.Add(MaxSlices * day)},
		{From: t0, To: t0.Add(600 * day)},
	} {
		if p, err := s.Plan(ctx, r, source.Selector{}); err == nil {
			t.Fatalf("%v: %d slices planned", r.To.Sub(r.From), len(p.Chunks[0].Granules))
		}
	}
	// Every plan stays within MaxSlices.
	for _, d := range []time.Duration{time.Minute, 511 * time.Minute, 512 * time.Minute, 513 * time.Minute, 7 * day, 100 * day} {
		p, err := s.Plan(ctx, source.Range{From: t0.Add(17 * time.Second), To: t0.Add(17*time.Second + d)}, source.Selector{})
		if err != nil || len(p.Chunks[0].Granules) > MaxSlices {
			t.Fatalf("%v: %v", d, err)
		}
	}
}

func TestCountsNeverGroupOnMetadata(t *testing.T) {
	// A stream without the level label, whose entries carry a level in
	// their (untrusted) metadata: Loki would group them under it. They
	// count as level absent, as a scan sees them.
	r := source.Range{From: t0, To: t0.Add(10 * time.Minute)}
	f := &fakeLoki{entries: dataset(100)}
	for i := 0; i < 7; i++ {
		f.entries = append(f.entries, fakeEntry{ts: t0.Add(time.Duration(i) * time.Second).UnixNano(), labels: map[string]string{"env": "prod", "app": "api"},
			meta: map[string]string{"level": "forged"}, line: "no level label"})
	}
	s := newSource(t, f, nil)
	sel := source.Selector{Terms: []source.Term{{Field: "app", Label: true, Op: "=", Values: []string{"api"}}}}
	for _, b := range []time.Duration{5 * time.Minute, 0} {
		res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Bucket: b, Selector: sel})
		if err != nil {
			t.Fatal(err)
		}
		width := b
		if b == 0 {
			width = r.To.Sub(r.From)
		}
		want := wantCounts(f, r, width) // by the stream label: "" when absent
		if got := gotCounts(res); !maps.Equal(got, want) {
			t.Fatalf("bucket %v: got %v\nwant %v", b, got, want)
		}
	}
}

func TestCountsDetectIngestionDuringTheCount(t *testing.T) {
	// An entry arrives before each request of a count's sequence: on a
	// boundary inside the range, exactly at To (outside it), or in the
	// millisecond before a boundary. The answer is exact for the data
	// before or after it, or not served; never another count.
	r := source.Range{From: t0, To: t0.Add(10 * time.Minute)}
	base := func() []fakeEntry {
		var es []fakeEntry
		for i := 0; i < 3; i++ {
			es = append(es, fakeEntry{ts: t0.Add(7*time.Minute + time.Duration(i)*time.Second).UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: fmt.Sprint("e", i)},
				fakeEntry{ts: t0.Add(5 * time.Minute).UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: fmt.Sprint("on boundary ", i)})
		}
		return es
	}
	late := map[string]fakeEntry{
		"on a boundary": {ts: t0.Add(5 * time.Minute).UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: "late"},
		"at To":         {ts: r.To.UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: "late"},
		"before To":     {ts: r.To.UnixNano() - 1, labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: "late"},
		"at From":       {ts: r.From.UnixNano(), labels: map[string]string{"env": "prod", "app": "api", "level": "info"}, line: "late"},
	}
	for _, b := range []time.Duration{5 * time.Minute, 0} {
		width := b
		if b == 0 {
			width = r.To.Sub(r.From)
		}
		for name, e := range late {
			for at := 0; at < 12; at++ {
				f := &fakeLoki{entries: base(), inject: map[int]fakeEntry{at: e}}
				before := wantCounts(f, r, width)
				after := wantCounts(&fakeLoki{entries: append(base(), e)}, r, width)
				s := newSource(t, f, nil)
				res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Bucket: b})
				if errors.Is(err, source.ErrNotIndexable) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := gotCounts(res); !maps.Equal(got, before) && !maps.Equal(got, after) {
					t.Fatalf("bucket %v, %s before request %d: got %v, want %v or %v", b, name, at, got, before, after)
				}
			}
		}
	}
}

func TestBoundaryFetchLimits(t *testing.T) {
	r := source.Range{From: t0, To: t0.Add(100 * time.Minute)}
	// More boundaries to fetch than MaxBoundaryFetches: not served.
	f := &fakeLoki{}
	for i := 0; i <= 100; i++ {
		f.entries = append(f.entries, fakeEntry{ts: t0.Add(time.Duration(i) * time.Minute).UnixNano(), labels: map[string]string{"env": "prod"}, line: "x"})
	}
	s := newSource(t, f, nil)
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Bucket: time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("101 boundaries: %v", err)
	}
	// Under the cap: served, through the call's limiter.
	l := &countLimiter{}
	f.requests = nil
	if _, err := s.IndexCounts(source.WithLimiter(ctx, l), source.CountQuery{Range: source.Range{From: t0, To: t0.Add(10 * time.Minute)}, Bucket: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if int(l.n) != len(f.requests) {
		t.Fatalf("limiter saw %d of %d requests", l.n, len(f.requests))
	}
	// A page or more of entries at a boundary nanosecond (Limit 7): not
	// served (the engine scans), not an error.
	f = &fakeLoki{entries: sameNanosecond(20, 0)}
	for i := range f.entries {
		f.entries[i].ts = t0.Add(5 * time.Minute).UnixNano()
	}
	if _, err := newSource(t, f, nil).IndexCounts(ctx, source.CountQuery{Range: source.Range{From: t0, To: t0.Add(10 * time.Minute)}, Bucket: 5 * time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("crowded boundary: %v", err)
	}
}

func TestOrdinalsStableAcrossPages(t *testing.T) {
	// A page cut inside a nanosecond holding several streams (Limit 7: 5
	// entries, then A and B of {app="aaa"} and C of {app="zz"} at one
	// nanosecond): the scan's order, its ordinals, and Reread and Around
	// agree, whatever order Loki returns the ties in.
	tie := t0.Add(time.Minute).UnixNano()
	mk := func() []fakeEntry {
		var es []fakeEntry
		for i := 0; i < 5; i++ {
			es = append(es, fakeEntry{ts: t0.Add(time.Duration(i+1) * time.Second).UnixNano(), labels: map[string]string{"env": "prod", "app": "api"}, line: fmt.Sprint("early ", i)})
		}
		return append(es,
			fakeEntry{ts: tie, labels: map[string]string{"env": "prod", "app": "zz"}, line: "C"},
			fakeEntry{ts: tie, labels: map[string]string{"env": "prod", "app": "aaa"}, line: "B"},
			fakeEntry{ts: tie, labels: map[string]string{"env": "prod", "app": "aaa"}, line: "A"},
			fakeEntry{ts: t0.Add(2 * time.Minute).UnixNano(), labels: map[string]string{"env": "prod", "app": "api"}, line: "late"})
	}
	var orders [][]string
	for _, rev := range []bool{false, true} {
		s := newSource(t, &fakeLoki{entries: mk(), reverseTies: rev}, nil)
		recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
		var order []string
		for i, r := range recs {
			order = append(order, r.Event.Raw)
			got, err := s.Reread(ctx, r.Ref)
			if err != nil || got.Event.Raw != r.Event.Raw {
				t.Fatalf("reverse %t: record %d (%s): reread %q, %v", rev, i, r.Event.Raw, got.Event.Raw, err)
			}
			around, err := s.Around(ctx, r.Ref, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			var mid string
			for j, a := range around {
				if a.Ref == r.Ref {
					mid = a.Event.Raw
					if j > 0 && around[j-1].Event.Raw != recs[i-1].Event.Raw {
						t.Fatalf("around %d: before is %q", i, around[j-1].Event.Raw)
					}
				}
			}
			if mid != r.Event.Raw {
				t.Fatalf("reverse %t: around record %d (%s) is %q", rev, i, r.Event.Raw, mid)
			}
		}
		orders = append(orders, order)
	}
	if !slices.Equal(orders[0], orders[1]) {
		t.Fatalf("order depends on Loki's tie order: %v / %v", orders[0], orders[1])
	}
}

func TestSmallGuards(t *testing.T) {
	p, _ := parse.New(parse.Options{})
	// An empty profile-selector value would mean "absent" to Loki.
	if _, err := New(Options{Name: "l", Client: &egress.Client{}, Parser: p, Selector: map[string]string{"env": ""}}); err == nil {
		t.Fatal("an empty selector value accepted")
	}
	f := &fakeLoki{entries: dataset(50)}
	s := newSource(t, f, nil)
	r := source.Range{From: t0, To: t0.Add(10 * time.Minute)}
	// An unknown operator is never taken as applied by a count.
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Bucket: 5 * time.Minute,
		Selector: source.Selector{Terms: []source.Term{{Field: "app", Label: true, Op: "~", Values: []string{"api"}}}}}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("unknown op: %v", err)
	}
	// Loki's limit refusals of a metric query: not served (the engine
	// scans); other failures stay errors.
	for _, tc := range []struct {
		status int
		msg    string
		ok     bool
	}{
		{400, "maximum of series (500) reached for a single query", true},
		{400, "the query time range exceeds the limit (query length: 721h, limit: 720h)", true},
		{429, "too many outstanding requests", true},
		{504, "request timed out, decrease the duration of the request or add more label matchers", true},
		{400, "parse error at line 1", false},
		{500, "too many outstanding requests", false},
	} {
		f.refuseStatus, f.refuseMsg = tc.status, tc.msg
		_, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Bucket: 5 * time.Minute})
		if errors.Is(err, source.ErrNotIndexable) != tc.ok || err == nil {
			t.Fatalf("%d %q: %v", tc.status, tc.msg, err)
		}
	}
	f.refuseStatus = 0
	// The boundary fetches' bytes are capped per count.
	prev := maxBoundaryBytes
	maxBoundaryBytes = 100
	defer func() { maxBoundaryBytes = prev }()
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, Bucket: 5 * time.Minute}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("over the boundary byte cap: %v", err)
	}
}

// TestScanFetchesLazily: a scan fetches at most InFlight slices ahead of the
// one Next reads, however slowly it is consumed.
func TestScanFetchesLazily(t *testing.T) {
	f := &fakeLoki{entries: dataset(300)} // 10 minutes of a 1 h plan of 1 min slices
	var mu sync.Mutex
	firsts := map[int64]bool{}
	f.onRange = func(start, _ int64) {
		if start%int64(time.Minute) == 0 { // a slice's first page
			mu.Lock()
			firsts[start] = true
			mu.Unlock()
		}
	}
	started := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(firsts)
	}
	const inFlight = 2
	s := newSource(t, f, func(o *Options) { o.InFlight = inFlight })
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	if n := len(plan.Chunks[0].Granules); n != 60 {
		t.Fatalf("%d slices", n)
	}
	it, err := s.Scan(ctx, plan.Chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := started(); n > inFlight {
		t.Fatalf("%d slices fetched before any Next, want at most %d", n, inFlight)
	}
	// Reading slice 0 (30 entries): slices 1 and 2 ahead at most.
	for i := 0; i < 30; i++ {
		if _, err := it.Next(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := started(); n > 1+inFlight {
		t.Fatalf("%d slices fetched while the first is read, want at most %d", n, 1+inFlight)
	}
	recs := drain(t, it)
	if len(recs) != 270 || started() != 60 {
		t.Fatalf("%d more records, %d slices fetched", len(recs), started())
	}
	if f.maxIn > inFlight {
		t.Fatalf("%d requests in flight", f.maxIn)
	}
}

// TestProcessedPerPageAndByteLimit: Processed counts each page as it
// arrives (before the slice is complete), and a scan whose context carries
// a byte limit stops fetching past it with source.ErrByteLimit instead of
// buffering the slice whole.
func TestProcessedPerPageAndByteLimit(t *testing.T) {
	f := &fakeLoki{entries: dataset(300)}
	var n atomic.Int32
	release := make(chan struct{})
	f.onRange = func(int64, int64) {
		if n.Add(1) == 2 {
			<-release // the slice's second page waits
		}
	}
	s := newSource(t, f, func(o *Options) { o.InFlight = 1 })
	plan, _ := s.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	one := plan.Chunks[0]
	one.Granules = one.Granules[:1] // 30 entries: 5 pages of 7
	it, _ := s.Scan(ctx, one)
	deadline := time.Now().Add(5 * time.Second)
	for it.Processed() == 0 {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the first page is not counted before the slice completes")
		}
		time.Sleep(5 * time.Millisecond)
	}
	page := it.Processed()
	close(release)
	if recs := drain(t, it); len(recs) != 30 {
		t.Fatalf("%d records", len(recs))
	}
	total, pages := it.Processed(), n.Load()
	if pages < 4 || total <= page {
		t.Fatalf("%d pages, %d bytes (first page %d)", pages, total, page)
	}
	// A limit of about one and a half pages: two pages fetched, then the
	// scan fails; nothing of the slice is returned.
	f.onRange = nil
	queries := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.queries)
	}
	before := queries()
	it, _ = s.Scan(source.WithByteLimit(ctx, page*3/2), one)
	_, err := it.Next()
	it.Close()
	if !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("past the byte limit: %v", err)
	}
	if got := queries() - before; got != 2 {
		t.Fatalf("%d pages fetched under a limit of 1.5 pages", got)
	}
	if p := it.Processed(); p <= page*3/2 || p > 3*page {
		t.Fatalf("processed %d bytes under a limit of %d", p, page*3/2)
	}
	// Within the limit, the same scan completes.
	it, _ = s.Scan(source.WithByteLimit(ctx, total), one)
	if recs := drain(t, it); len(recs) != 30 {
		t.Fatalf("%d records within the limit", len(recs))
	}
}

// TestAroundByteLimit: Around fetches its window under the call's byte
// limit, or MaxAroundBytes without one, and fails past it.
func TestAroundByteLimit(t *testing.T) {
	f := &fakeLoki{entries: dataset(300)}
	s := newSource(t, f, nil)
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(time.Hour)}, source.Selector{})
	ref := recs[150].Ref
	if a, err := s.Around(ctx, ref, 2, 2); err != nil || len(a) != 5 {
		t.Fatalf("around: %d, %v", len(a), err)
	}
	if _, err := s.Around(source.WithByteLimit(ctx, 1000), ref, 2, 2); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("around past the call's limit: %v", err)
	}
	prev := MaxAroundBytes
	MaxAroundBytes = 1000
	defer func() { MaxAroundBytes = prev }()
	if _, err := s.Around(ctx, ref, 2, 2); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("around past MaxAroundBytes: %v", err)
	}
	// Reread reads one nanosecond: a page at most.
	if got, err := s.Reread(ctx, ref); err != nil || got.Event.Raw != recs[150].Event.Raw {
		t.Fatalf("reread: %v", err)
	}
}

// startsClient records the start of every request and answers no labels.
type startsClient struct{ starts []string }

func (c *startsClient) GetWith(_ context.Context, _ string, q url.Values, _ map[string]string) (egress.Response, error) {
	c.starts = append(c.starts, q.Get("start"))
	return egress.Response{Status: 200, Body: []byte(`{"status":"success","data":[]}`)}, nil
}

// TestDescribeLookback: Describe lists the labels of the last
// DescribeLookback by default, of Options.DescribeLookback when set.
func TestDescribeLookback(t *testing.T) {
	p, _ := parse.New(parse.Options{})
	now := t0.Add(time.Hour)
	for _, tc := range []struct {
		opt, want time.Duration
	}{{0, DescribeLookback}, {7 * 24 * time.Hour, 7 * 24 * time.Hour}} {
		c := &startsClient{}
		s, err := New(Options{Name: "l", Client: c, Parser: p, Selector: map[string]string{"env": "prod"}, DescribeLookback: tc.opt, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Describe(ctx); err != nil {
			t.Fatal(err)
		}
		want := strconv.FormatInt(now.Add(-tc.want).UnixNano(), 10)
		if len(c.starts) == 0 || c.starts[0] != want {
			t.Fatalf("lookback %v: starts %v, want %s", tc.opt, c.starts, want)
		}
	}
}

// TestSplit: a slice is cut into the epoch-aligned slices of the next
// narrower width, covering it exactly, down to MinSlice.
func TestSplit(t *testing.T) {
	s := &Source{}
	base := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC) // epoch-aligned to every width
	g := func(from time.Time, w time.Duration) source.Granule {
		return source.Granule{Start: from.UnixNano(), End: from.Add(w).UnixNano(), From: from, To: from.Add(w)}
	}
	for _, tc := range []struct {
		w, sub time.Duration
	}{{24 * time.Hour, 6 * time.Hour}, {6 * time.Hour, time.Hour}, {time.Hour, 15 * time.Minute}, {15 * time.Minute, 5 * time.Minute}, {5 * time.Minute, time.Minute}, {time.Minute, 10 * time.Second}, {10 * time.Second, time.Second}} {
		parent := g(base, tc.w)
		parts := s.Split(parent)
		if len(parts) != int(tc.w/tc.sub) {
			t.Fatalf("%v: %d parts, want %d", tc.w, len(parts), tc.w/tc.sub)
		}
		at := parent.Start
		for _, p := range parts {
			if p.Start != at || p.End-p.Start != int64(tc.sub) || p.Start%int64(tc.sub) != 0 || p.Bytes != 0 || !p.From.Equal(time.Unix(0, p.Start)) {
				t.Fatalf("%v: part %+v", tc.w, p)
			}
			at = p.End
		}
		if at != parent.End {
			t.Fatalf("%v: parts end at %d, want %d", tc.w, at, parent.End)
		}
	}
	if parts := s.Split(g(base, time.Second)); parts != nil {
		t.Fatalf("a 1 s slice split into %d", len(parts))
	}
	// A clipped (unaligned) slice is covered exactly.
	odd := source.Granule{Start: base.Add(1500 * time.Millisecond).UnixNano(), End: base.Add(4 * time.Second).UnixNano()}
	parts := s.Split(odd)
	if len(parts) != 3 || parts[0].Start != odd.Start || parts[0].End != base.Add(2*time.Second).UnixNano() || parts[2].End != odd.End {
		t.Fatalf("unaligned: %+v", parts)
	}
}
