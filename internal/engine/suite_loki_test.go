//go:build unix

package engine

// The suite fixture's Loki source: a fake Loki over HTTP (behind the real
// egress client) serving the corpus records of srcLoki, with Loki's
// semantics as grafana/loki:3.5.7 has them (internal/source/loki's own
// fake is the reference): query_range pages limited over all streams,
// forward, end excluded; streams in the categorize-labels encoding, the
// structured metadata apart; the metric form locklog sends; labels and
// label values. Each record carries an untrusted stream label and an
// untrusted metadata field holding its payload (both dropped by the
// source), and a trusted metadata field holding it too (shown after the
// detectors).
//
// With LOCKLOG_SUITE_LOKI_URL set (the CI suites job), the same entries are
// pushed to that real Loki instead, under a stream label of their own, and
// the source reads them there.

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

const (
	srcLoki = "loki"
	// lokiTrustedMeta is the trusted structured-metadata field of the
	// fixture's Loki entries; lokiUntrustedMeta and lokiUntrustedLabel
	// are dropped by the source.
	lokiTrustedMeta    = "request_note"
	lokiUntrustedMeta  = "user_note"
	lokiUntrustedLabel = "pod_note"
	// lokiPage is the fixture's query_range limit: small, so that every
	// slice pages.
	lokiPage = 50
)

// lokiApps are the values of the trusted "app" label.
var lokiApps = []string{"shop-api", "shop-pdf"}

type lokiEntry struct {
	ts     int64
	labels map[string]string
	meta   map[string]string
	line   string
}

// suiteLoki is the fake Loki. Its push API (for TestLokiIncident's
// scaled-down local runs) takes gzip JSON streams.
type suiteLoki struct {
	mu      sync.RWMutex
	entries []lokiEntry
}

func (f *suiteLoki) push(w http.ResponseWriter, r *http.Request) {
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "gzip", 400)
			return
		}
		body = zr
	}
	var req struct {
		Streams []struct {
			Stream map[string]string   `json:"stream"`
			Values [][]json.RawMessage `json:"values"`
		} `json:"streams"`
	}
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(w, "json", 400)
		return
	}
	var es []lokiEntry
	for _, st := range req.Streams {
		for _, v := range st.Values {
			var tsS, line string
			json.Unmarshal(v[0], &tsS)
			json.Unmarshal(v[1], &line)
			ts, _ := strconv.ParseInt(tsS, 10, 64)
			meta := map[string]string{}
			if len(v) > 2 {
				json.Unmarshal(v[2], &meta)
			}
			es = append(es, lokiEntry{ts: ts, labels: st.Stream, meta: meta, line: line})
		}
	}
	f.mu.Lock()
	f.entries = append(f.entries, es...)
	f.mu.Unlock()
	w.WriteHeader(204)
}

// lokiLabelMax bounds the payload an entry's untrusted label carries
// (Loki's max_label_value_length is 2048 bytes).
const lokiLabelMax = 1024

// lokiEntries renders the records of the Loki source: the line in the
// json source's form, the payload also in an untrusted label (its first
// lokiLabelMax bytes), an untrusted metadata field and a trusted one.
func lokiEntries(rs []suiteRecord, run string) []lokiEntry {
	out := make([]lokiEntry, 0, len(rs))
	for i, r := range rs {
		p := r.payload(false)
		lp := p
		for len(lp) > lokiLabelMax {
			lp = strings.ToValidUTF8(lp[:lokiLabelMax], "")
		}
		out = append(out, lokiEntry{
			ts:     r.TS.UnixNano(),
			labels: map[string]string{"env": "suite", "run": run, "app": lokiApps[i%len(lokiApps)], lokiUntrustedLabel: lp},
			meta:   map[string]string{lokiTrustedMeta: p, lokiUntrustedMeta: p},
			line:   render("json", r),
		})
	}
	return out
}

// newSuiteLoki starts the fake Loki over rs and returns the Loki source
// reading it through the egress client.
func newSuiteLoki(t testing.TB, rs []suiteRecord) *loki.Source {
	t.Helper()
	var id [8]byte
	rand.Read(id[:])
	run := hex.EncodeToString(id[:])
	es := lokiEntries(rs, run)
	url := os.Getenv("LOCKLOG_SUITE_LOKI_URL")
	if url == "" {
		srv := httptest.NewServer(&suiteLoki{entries: es})
		t.Cleanup(srv.Close)
		url = srv.URL
	} else {
		url = strings.TrimSuffix(url, "/")
		pushSuiteLoki(t, url, es)
	}
	cl, err := egress.New(&config.Remote{URL: url, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{},
		egress.Options{Headers: egress.LokiHeaders})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	src, err := loki.New(loki.Options{Name: srcLoki, Client: cl, Parser: p, Selector: map[string]string{"env": "suite", "run": run},
		TrustedLabels: []string{"app"}, TrustedMetadata: []string{lokiTrustedMeta}, InFlight: 2, Limit: lokiPage,
		Now: func() time.Time { return suiteNow }})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// logqlMatchers parses the grammar locklog's LogQL builder writes:
// '{' name op string (', ' name op string)* '}' (' | ' name op string)*.
func logqlMatchers(q string) (stream, meta [][3]string, err error) {
	if !strings.HasPrefix(q, "{") {
		return nil, nil, errors.New("no stream selector")
	}
	rest := q[1:]
	matcher := func() ([3]string, error) {
		i := 0
		for i < len(rest) && (rest[i] == '_' || rest[i] >= 'a' && rest[i] <= 'z' || rest[i] >= 'A' && rest[i] <= 'Z' || i > 0 && rest[i] >= '0' && rest[i] <= '9') {
			i++
		}
		name := rest[:i]
		rest = rest[i:]
		var op string
		for _, o := range []string{"=~", "!~", "!=", "="} {
			if strings.HasPrefix(rest, o) {
				op = o
				break
			}
		}
		if name == "" || op == "" {
			return [3]string{}, errors.New("bad matcher")
		}
		rest = rest[len(op):]
		lit, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return [3]string{}, err
		}
		rest = rest[len(lit):]
		v, _ := strconv.Unquote(lit)
		return [3]string{name, op, v}, nil
	}
	for {
		m, err := matcher()
		if err != nil {
			return nil, nil, err
		}
		stream = append(stream, m)
		if strings.HasPrefix(rest, ", ") {
			rest = rest[2:]
			continue
		}
		if !strings.HasPrefix(rest, "}") {
			return nil, nil, errors.New("unterminated stream selector")
		}
		rest = rest[1:]
		break
	}
	for rest != "" {
		if !strings.HasPrefix(rest, " | ") {
			return nil, nil, errors.New("unexpected text after the selector")
		}
		rest = rest[3:]
		m, err := matcher()
		if err != nil {
			return nil, nil, err
		}
		meta = append(meta, m)
	}
	return stream, meta, nil
}

func lokiMatch(ms [][3]string, l map[string]string) bool {
	for _, m := range ms {
		v := l[m[0]]
		switch m[1] {
		case "=":
			if v != m[2] {
				return false
			}
		case "!=":
			if v == m[2] {
				return false
			}
		case "=~", "!~":
			if regexp.MustCompile("^(?:"+m[2]+")$").MatchString(v) != (m[1] == "=~") {
				return false
			}
		}
	}
	return true
}

func lokiMerged(e lokiEntry) map[string]string {
	m := maps.Clone(e.labels)
	maps.Copy(m, e.meta)
	return m
}

func lokiLabelsKey(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strconv.Quote(m[k]) + ",")
	}
	return b.String()
}

var lokiMetricRe = regexp.MustCompile(`^sum by \(([^)]*)\) \(count_over_time\((.*) \[(\d+(?:ms|s))\]\)\)$`)

// writeJSON writes v without HTML escaping (as Loki does).
func writeJSON(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func (f *suiteLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/loki/api/v1/push" && r.Method == "POST" {
		f.push(w, r)
		return
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if r.URL.Path == "/loki/api/v1/query" && r.Header.Get("X-Loki-Response-Encoding-Flags") == "" {
		// The test's own count (lokiCount), not the source's.
		r.Header.Set("X-Loki-Response-Encoding-Flags", "categorize-labels")
	}
	if r.Header.Get("X-Loki-Response-Encoding-Flags") != "categorize-labels" {
		http.Error(w, "the fixture answers in the categorize-labels encoding only", 400)
		return
	}
	q := r.URL.Query()
	var sel [][3]string
	if qq := q.Get("query"); qq != "" && strings.HasPrefix(r.URL.Path, "/loki/api/v1/label") {
		s, _, err := logqlMatchers(qq)
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		sel = s
	}
	switch {
	case r.URL.Path == "/loki/api/v1/labels":
		set := map[string]bool{"__stream_shard__": true}
		for _, e := range f.entries {
			if lokiMatch(sel, e.labels) {
				for k := range e.labels {
					set[k] = true
				}
			}
		}
		writeJSON(w, map[string]any{"status": "success", "data": slices.Sorted(maps.Keys(set))})
	case strings.HasPrefix(r.URL.Path, "/loki/api/v1/label/"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/loki/api/v1/label/"), "/values")
		set := map[string]bool{}
		for _, e := range f.entries {
			if v, ok := e.labels[name]; ok && lokiMatch(sel, e.labels) {
				set[v] = true
			}
		}
		writeJSON(w, map[string]any{"status": "success", "data": slices.Sorted(maps.Keys(set))})
	case r.URL.Path == "/loki/api/v1/query":
		m := lokiMetricRe.FindStringSubmatch(q.Get("query"))
		if m == nil {
			http.Error(w, "unsupported", 400)
			return
		}
		at, _ := strconv.ParseInt(q.Get("time"), 10, 64)
		series, err := f.metric(m, at, at, "")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result := []any{}
		for _, s := range series {
			result = append(result, map[string]any{"metric": s.metric, "value": s.values[0]})
		}
		writeJSON(w, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
	case r.URL.Path == "/loki/api/v1/query_range":
		start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
		if m := lokiMetricRe.FindStringSubmatch(q.Get("query")); m != nil {
			series, err := f.metric(m, start, end, q.Get("step"))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			result := []any{}
			for _, s := range series {
				result = append(result, map[string]any{"metric": s.metric, "values": s.values})
			}
			writeJSON(w, map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": result}})
			return
		}
		stream, meta, err := logqlMatchers(q.Get("query"))
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var hits []lokiEntry
		for _, e := range f.entries {
			// [start, end): grafana/loki:3.5.7 excludes a log query's end.
			if e.ts >= start && e.ts < end && lokiMatch(stream, e.labels) && lokiMatch(meta, lokiMerged(e)) {
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
			k := lokiLabelsKey(e.labels)
			if streams[k] == nil {
				streams[k] = map[string]any{"stream": e.labels, "values": [][]any{}}
				order = append(order, k)
			}
			streams[k]["values"] = append(streams[k]["values"].([][]any), []any{strconv.FormatInt(e.ts, 10), e.line, map[string]any{"structuredMetadata": e.meta}})
		}
		result := []any{}
		for _, k := range order {
			result = append(result, streams[k])
		}
		writeJSON(w, map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result,
			"encodingFlags": []string{"categorize-labels"}}})
	default:
		http.NotFound(w, r)
	}
}

type lokiSeries struct {
	metric map[string]string
	values [][]any
}

// metric evaluates a metric query as grafana/loki:3.5.7 does: a range
// query's start rounded down and its end up to the step; at each step t,
// count_over_time counts (t-range, t]; the point's time is t in
// milliseconds, written as seconds with a millisecond fraction.
func (f *suiteLoki) metric(m []string, start, end int64, stepS string) ([]lokiSeries, error) {
	var by []string
	if m[1] != "" {
		by = strings.Split(m[1], ", ")
	}
	stream, meta, err := logqlMatchers(m[2])
	if err != nil {
		return nil, err
	}
	d, err := time.ParseDuration(m[3])
	if err != nil {
		return nil, err
	}
	rng := int64(d)
	step := int64(1)
	if stepS != "" {
		s, _ := strconv.ParseInt(stepS, 10, 64)
		step = s * 1e9
		start -= start % step
		if r := end % step; r != 0 {
			end += step - r
		}
	}
	if (end-start)/step > 11000 {
		return nil, fmt.Errorf("too many points")
	}
	series := map[string]*lokiSeries{}
	var order []string
	for t := start; t <= end; t += step {
		counts := map[string]int{}
		metrics := map[string]map[string]string{}
		for _, e := range f.entries {
			if e.ts > t-rng && e.ts <= t && lokiMatch(stream, e.labels) && lokiMatch(meta, lokiMerged(e)) {
				mm := map[string]string{}
				for _, l := range by {
					if v, ok := e.labels[l]; ok {
						mm[l] = v
					} else if v, ok := e.meta[l]; ok {
						mm[l] = v
					}
				}
				k := lokiLabelsKey(mm)
				counts[k]++
				metrics[k] = mm
			}
		}
		for _, k := range slices.Sorted(maps.Keys(counts)) {
			if series[k] == nil {
				series[k] = &lokiSeries{metric: metrics[k]}
				order = append(order, k)
			}
			series[k].values = append(series[k].values, []any{json.RawMessage(strconv.FormatFloat(float64(t/1e6)/1000, 'f', -1, 64)), strconv.Itoa(counts[k])})
		}
	}
	out := make([]lokiSeries, 0, len(order))
	for _, k := range order {
		out = append(out, *series[k])
	}
	return out, nil
}

// pushSuiteLoki writes the entries to a real Loki (its push API) and waits
// until it serves them all.
func pushSuiteLoki(t testing.TB, base string, es []lokiEntry) {
	t.Helper()
	streams := map[string]*pushStream{}
	var order []*pushStream
	for _, e := range es {
		k := lokiLabelsKey(e.labels)
		if streams[k] == nil {
			streams[k] = &pushStream{Stream: e.labels}
			order = append(order, streams[k])
		}
		streams[k].Values = append(streams[k].Values, []any{strconv.FormatInt(e.ts, 10), e.line, e.meta})
	}
	for i := 0; i < len(order); i += 200 {
		if err := lokiPush(base, order[i:min(i+200, len(order))]); err != nil {
			t.Fatal(err)
		}
	}
	if len(es) == 0 {
		return
	}
	run := es[0].labels["run"]
	lo, hi := es[0].ts, es[0].ts
	for _, e := range es {
		lo, hi = min(lo, e.ts), max(hi, e.ts)
	}
	from, to := time.Unix(0, lo).Truncate(time.Second), time.Unix(0, hi).Truncate(time.Second).Add(2*time.Second)
	for i := 0; ; i++ {
		n := lokiCount(t, base, `{run="`+run+`"}`, from, to)
		if n == int64(len(es)) {
			return
		}
		if i > 100 {
			t.Fatalf("Loki serves %d of the %d entries pushed", n, len(es))
		}
		time.Sleep(100 * time.Millisecond)
	}
}
