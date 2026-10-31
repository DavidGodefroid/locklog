//go:build unix

package engine

// TestLokiIncident (design §9.1, R6-P2) runs job 1 against a real Loki
// (grafana/loki:3.5.7 in Docker on the CI runner, with the overrides of
// test/loki/incident-config.yaml documented in docs/loki.md): a dense
// incident hour written at 5 GiB/day on top of a sparse 7-day background,
// pushed twice, once in streams with a `level` label and once without.
// The scripted agent follows the skill; the gates are the approval
// prompts (≤ 3) and the time to the answer (< 5 min).
//
// Variants: with the level label; without it (the error count over the
// narrowed hour is one approved scan, finishing on that one approval
// within its TTL); with a latency proxy (Toxiproxy) between the console
// and Loki; with the host slowed about 3× (a CPU hog).
//
// It runs when LOCKLOG_LOKI_INCIDENT_URL names that Loki (the CI
// loki-incident job); LOCKLOG_TOXIPROXY_URL names Toxiproxy's API for the
// latency variant. LOCKLOG_LOKI_INCIDENT_VOLUME scales the data (bytes per
// day of the dense hour; default 5GiB) and LOCKLOG_LOKI_INCIDENT_BACKGROUND
// the background (default 512MiB). With LOCKLOG_LOKI_INCIDENT_URL=fake, a
// scaled-down run uses the suites' fake Loki (no Docker; the gates then say
// nothing about Loki).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

const (
	// lokiIngestGate bounds the ingestion of both copies (§9.1).
	lokiIngestGate = 10 * time.Minute
	// lokiDataCap bounds the data in all (§9.1: ≤ 8 GiB).
	lokiDataCap = 8 << 30
	lokiApps2   = 2
	lokiPods    = 3
)

// lokiPlan is the incident's time line, from T (the last whole quarter
// hour before the push): the background covers [T-7d, T); the dense hour
// is [T-90m, T-30m); the incident (order 4812's PDF renderer timing out
// upstream) runs from T-70m to its end.
type lokiPlan struct {
	T, dense, incident, denseEnd time.Time
	bgStep, denseStep            time.Duration // per writer
}

func newLokiPlan(perDay, background int64) lokiPlan {
	T := time.Now().UTC().Truncate(15 * time.Minute)
	writers := lokiApps2 * lokiPods
	const line = 190 // bytes, about
	bgN := background / line / int64(writers)
	denseN := perDay / 24 / line / int64(writers)
	return lokiPlan{T: T, dense: T.Add(-90 * time.Minute), incident: T.Add(-70 * time.Minute), denseEnd: T.Add(-30 * time.Minute),
		bgStep: 7 * 24 * time.Hour / time.Duration(bgN), denseStep: time.Hour / time.Duration(max(denseN, 1))}
}

// lokiLine is one line of the shop's JSON log at ts, and its level.
func lokiLine(r *rand.Rand, p lokiPlan, app string, ts time.Time, seq int64) (string, string) {
	user := fmt.Sprintf("user%d@shop.example", r.IntN(500))
	trace := fmt.Sprintf("tr-%s-%d-%d", app[5:], seq>>40, seq&(1<<40-1))
	tsS := ts.Format(time.RFC3339Nano)
	if !ts.Before(p.incident) && ts.Before(p.denseEnd) && r.IntN(3) == 0 {
		return fmt.Sprintf(`{"ts":%q,"level":"error","app":%q,"order":4812,"user":%q,"trace":%q,"status":502,"msg":"render pdf for %s failed: upstream timed out (order 4812, trace %s)"}`,
			tsS, app, user, trace, user, trace), "error"
	}
	order := 4000 + r.IntN(1000)
	if r.IntN(2000) == 0 {
		return fmt.Sprintf(`{"ts":%q,"level":"warn","app":%q,"order":%d,"user":%q,"trace":%q,"status":402,"msg":"payment declined for order %d"}`,
			tsS, app, order, user, trace, order), "warn"
	}
	ms := 20 + r.IntN(400)
	return fmt.Sprintf(`{"ts":%q,"level":"info","app":%q,"order":%d,"user":%q,"trace":%q,"status":200,"latency_ms":%d,"msg":"order %d confirmed in %dms"}`,
		tsS, app, order, user, trace, ms, order, ms), "info"
}

type pushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]any           `json:"values"`
}

// lokiPush posts streams (gzip JSON) to Loki's push API.
func lokiPush(base string, streams []*pushStream) error {
	var body struct {
		Streams []*pushStream `json:"streams"`
	}
	for _, s := range streams {
		if len(s.Values) > 0 {
			body.Streams = append(body.Streams, s)
		}
	}
	if len(body.Streams) == 0 {
		return nil
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err := json.NewEncoder(zw).Encode(body); err != nil {
		return err
	}
	zw.Close()
	for attempt := 0; ; attempt++ {
		req, _ := http.NewRequest("POST", base+"/loki/api/v1/push", bytes.NewReader(buf.Bytes()))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode/100 == 2:
			return nil
		case (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < 20:
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		default:
			return fmt.Errorf("push: %d %s", resp.StatusCode, bytes.TrimSpace(msg))
		}
	}
}

// lokiIngest pushes both copies (run="lvl" with a level label, run="nolvl"
// without), one writer per (copy, app, pod), each in time order. It
// returns the line bytes and entries pushed per copy.
func lokiIngest(t *testing.T, base string, p lokiPlan) (bytesPushed int64, entries map[string]int64) {
	t.Helper()
	apps := []string{"shop-api", "shop-pdf"}
	var total atomic.Int64
	counts := map[string]*atomic.Int64{"lvl": {}, "nolvl": {}}
	var wg sync.WaitGroup
	errs := make(chan error, 2*lokiApps2*lokiPods)
	for _, run := range []string{"lvl", "nolvl"} {
		for ai, app := range apps {
			for pod := range lokiPods {
				wg.Add(1)
				go func() {
					defer wg.Done()
					w := ai*lokiPods + pod
					r := rand.New(rand.NewPCG(uint64(w), 4812))
					streams := map[string]*pushStream{}
					var order []*pushStream
					size := 0
					flush := func() error {
						err := lokiPush(base, order)
						for _, s := range order {
							s.Values = s.Values[:0]
						}
						size = 0
						return err
					}
					var seq int64
					emit := func(ts time.Time) error {
						seq++
						line, level := lokiLine(r, p, app, ts, int64(w)<<40|seq)
						labels := map[string]string{"run": run, "app": app, "pod": "p" + strconv.Itoa(pod)}
						key := level
						if run == "lvl" {
							labels["level"] = level
						} else {
							key = ""
						}
						s := streams[key]
						if s == nil {
							s = &pushStream{Stream: labels}
							streams[key] = s
							order = append(order, s)
						}
						s.Values = append(s.Values, []any{strconv.FormatInt(ts.UnixNano(), 10), line})
						size += len(line)
						total.Add(int64(len(line)))
						counts[run].Add(1)
						if size >= 1<<20 {
							return flush()
						}
						return nil
					}
					// Each writer's entries are offset within its step, so
					// that no two writers share a timestamp.
					off := func(step time.Duration) time.Duration { return step * time.Duration(w) / (lokiApps2 * lokiPods) }
					for ts := p.T.Add(-7 * 24 * time.Hour).Add(off(p.bgStep)); ts.Before(p.T); {
						if !ts.Before(p.dense) && ts.Before(p.denseEnd) {
							ts = p.denseEnd.Add(off(p.bgStep))
							continue
						}
						if err := emit(ts); err != nil {
							errs <- err
							return
						}
						next := ts.Add(p.bgStep)
						if ts.Before(p.dense) && !next.Before(p.dense) {
							// The dense hour, in order within the stream.
							for d := p.dense.Add(off(p.denseStep)); d.Before(p.denseEnd); d = d.Add(p.denseStep) {
								if err := emit(d); err != nil {
									errs <- err
									return
								}
							}
						}
						ts = next
					}
					if err := flush(); err != nil {
						errs <- err
					}
				}()
			}
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	return total.Load(), map[string]int64{"lvl": counts["lvl"].Load(), "nolvl": counts["nolvl"].Load()}
}

// lokiCount asks Loki (directly: the test's own check, not the console) how
// many entries a selector holds over [from, to).
func lokiCount(t testing.TB, base, sel string, from, to time.Time) int64 {
	t.Helper()
	q := fmt.Sprintf("sum by () (count_over_time(%s [%ds]))", sel, int64(to.Sub(from)/time.Second))
	resp, err := http.Get(base + "/loki/api/v1/query?query=" + urlEscape(q) + "&time=" + strconv.FormatInt(to.UnixNano()-1, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v struct {
		Data struct {
			Result []struct {
				Value [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &v); err != nil || resp.StatusCode != 200 {
		t.Fatalf("count: %d %s", resp.StatusCode, b)
	}
	if len(v.Data.Result) == 0 {
		return 0
	}
	var s string
	json.Unmarshal(v.Data.Result[0].Value[1], &s)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func urlEscape(s string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "{", "%7B", "}", "%7D", "\"", "%22", "=", "%3D", "[", "%5B", "]", "%5D", "(", "%28", ")", "%29", "+", "%2B", ",", "%2C").Replace(s)
}

// toxiproxy puts a latency proxy between the console and Loki: listen ->
// upstream, latency ± jitter on every response. It returns the proxy's URL.
func toxiproxy(t *testing.T, api, upstream string, latency, jitter time.Duration) string {
	t.Helper()
	post := func(path string, v any) {
		b, _ := json.Marshal(v)
		resp, err := http.Post(api+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		msg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode/100 != 2 && resp.StatusCode != 409 {
			t.Fatalf("toxiproxy %s: %d %s", path, resp.StatusCode, msg)
		}
	}
	const listen = "127.0.0.1:3101"
	post("/proxies", map[string]any{"name": "loki", "listen": listen, "upstream": strings.TrimPrefix(upstream, "http://"), "enabled": true})
	post("/proxies/loki/toxics", map[string]any{"name": "latency", "type": "latency", "stream": "downstream",
		"attributes": map[string]any{"latency": latency.Milliseconds(), "jitter": jitter.Milliseconds()}})
	t.Cleanup(func() {
		req, _ := http.NewRequest("DELETE", api+"/proxies/loki", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	return "http://" + listen
}

// lokiAgent is the scripted agent of the Loki incident: it follows the
// skill through Handle, turning each approval into a prompt.
type lokiAgent struct {
	t       *testing.T
	s       *suite
	con     *screens
	ctx     context.Context
	calls   int
	prompts int
	log     []string
}

// free runs a call to completion (or max pages), free; a refusal is
// returned.
func (a *lokiAgent) free(c agentCall, max int) ([]json.RawMessage, *Error) {
	start := time.Now()
	r := a.s.runPagesCtx(a.ctx, c, max)
	a.calls += len(r.pages) + 1
	a.log = append(a.log, fmt.Sprintf("%s: %d pages in %v", c.name, len(r.pages), time.Since(start).Round(time.Millisecond)))
	return r.pages, r.refusal
}

// mustFree is free with no refusal.
func (a *lokiAgent) mustFree(c agentCall, max int) []json.RawMessage {
	a.t.Helper()
	pages, r := a.free(c, max)
	if r != nil {
		for _, l := range a.log {
			a.t.Log(l)
		}
		a.t.Fatalf("%s: refused: %v", c.name, r)
	}
	return pages
}

// scan runs c as an approved scan to the end of its plan.
func (a *lokiAgent) scan(c agentCall) scanRun {
	a.t.Helper()
	start := time.Now()
	before := a.con.count()
	r := a.s.runScanReason(a.ctx, c, 0, "the errors of the narrowed hour: the source has no level label")
	a.prompts += a.con.count() - before
	a.calls += len(r.pages)
	a.log = append(a.log, fmt.Sprintf("scan %s: %d pages, %d approvals in %v", c.name, len(r.pages), a.con.count()-before, time.Since(start).Round(time.Millisecond)))
	if r.refusal != nil || r.err != nil {
		for _, l := range a.log {
			a.t.Log(l)
		}
		a.t.Fatalf("scan %s: %v %v", c.name, r.refusal, r.err)
	}
	return r
}

// spike returns the first bucket of a count where n(key) is over frac of
// the bucket's total (key "" : the bucket's total against the median
// bucket times frac).
func spike(t *testing.T, res CountResult, key string, frac float64) time.Time {
	all, hit := map[time.Time]int64{}, map[time.Time]int64{}
	for _, g := range res.Groups {
		all[g.Bucket] += g.N
		if key != "" && len(g.Key) == 1 && g.Key[0] != nil && *g.Key[0] == key {
			hit[g.Bucket] += g.N
		}
	}
	buckets := slices.SortedFunc(func(yield func(time.Time) bool) {
		for b := range all {
			if !yield(b) {
				return
			}
		}
	}, func(x, y time.Time) int { return x.Compare(y) })
	if key == "" {
		ns := make([]int64, 0, len(all))
		for _, n := range all {
			ns = append(ns, n)
		}
		slices.Sort(ns)
		med := ns[len(ns)/2]
		for _, b := range buckets {
			if float64(all[b]) > frac*float64(med) {
				return b
			}
		}
	}
	for _, b := range buckets {
		if float64(hit[b]) > frac*float64(all[b]) {
			return b
		}
	}
	t.Fatalf("no spike in %d buckets", len(buckets))
	return time.Time{}
}

var traceRe = regexp.MustCompile(`trace (tr-[a-z]+-\d+-\d+)`)

// lokiJob runs job 1 and returns the prompts and the time to the answer.
// With the level label: (1) count by the trusted level label per 15 min
// over 7 days, then per minute over the narrowed hour (Loki's metric
// queries, free); (2) patterns with text over the narrowed hour, continued
// free; (3) the order's records, then the trace of one of them. Without
// it: (1) the error count over 7 days is refused (a remote source's
// scanned range is at most 24 h); the volume by the trusted app label
// per 15 min narrows to the hour (free); the error count per minute over
// that hour is one approved scan, run to its end on that approval; then
// (2) and (3) as above.
func lokiJob(t *testing.T, s *suite, p lokiPlan, level bool) (int, time.Duration) {
	a := &lokiAgent{t: t, s: s, con: &screens{}}
	a.ctx = a.con.ctx(1000)
	start := time.Now()
	from := p.T.Add(-7 * 24 * time.Hour)
	var hourFrom time.Time
	var first time.Time
	if level {
		cq := CountQuery{Query: Query{From: from, To: p.T, Sources: []string{srcLoki}}, ByLabels: []string{"level"}, Bucket: "15m"}
		res := lastCount(t, a.mustFree(agentCall{"count by level per 15m over 7d", MethodCount, cq}, 0))
		if !res.FromIndex {
			t.Errorf("step 1: the 7-day count was scanned, not answered by Loki's counts")
		}
		hourFrom = spike(t, res, "error", 0.1)
		cq = CountQuery{Query: Query{From: hourFrom, To: hourFrom.Add(time.Hour), Sources: []string{srcLoki}}, ByLabels: []string{"level"}, Bucket: "1m"}
		first = spike(t, lastCount(t, a.mustFree(agentCall{"count by level per 1m over the hour", MethodCount, cq}, 0)), "error", 0.1)
	} else {
		// The errors, without a trusted level: by their text (the
		// production default redacts the values of untrusted fields).
		errs := CountQuery{Query: Query{From: from, To: p.T, Sources: []string{srcLoki}, Text: "failed"}, Bucket: "15m"}
		if _, r := a.free(agentCall{"count errors per 15m over 7d", MethodCount, errs}, 1); r == nil || r.Code != EOverBudget {
			t.Fatalf("step 1: the 7-day error count without a level label: %v", r)
		}
		cq := CountQuery{Query: Query{From: from, To: p.T, Sources: []string{srcLoki}}, ByLabels: []string{"app"}, Bucket: "15m"}
		res := lastCount(t, a.mustFree(agentCall{"count by app per 15m over 7d", MethodCount, cq}, 0))
		if !res.FromIndex {
			t.Errorf("step 1: the 7-day volume count was scanned, not answered by Loki's counts")
		}
		hourFrom = spike(t, res, "", 5)
		errs = CountQuery{Query: Query{From: hourFrom, To: hourFrom.Add(time.Hour), Sources: []string{srcLoki}, Text: "failed"}, Bucket: "1m"}
		r := a.scan(agentCall{"count errors per 1m over the hour", MethodCount, errs})
		if n := a.con.count(); n != 1 {
			t.Errorf("the scan took %d approvals, want 1 for its whole plan", n)
		}
		last := r.infos[len(r.infos)-1]
		if !last.Done || time.Now().After(last.ExpiresAt) {
			t.Errorf("the scan did not finish within its TTL: done %v, expires %v", last.Done, last.ExpiresAt)
		}
		var cr CountResult
		json.Unmarshal(r.results[len(r.results)-1], &cr)
		var b time.Time
		for _, g := range cr.Groups {
			if g.N > 0 && (b.IsZero() || g.Bucket.Before(b)) {
				b = g.Bucket
			}
		}
		first = b
		t.Logf("scan: %d calls, %d records scanned in its last call", len(r.pages), cr.Scanned.Records)
	}
	if !first.Equal(p.incident) {
		t.Errorf("step 1: started at %v, want %v", first, p.incident)
	}
	hourTo := hourFrom.Add(time.Hour)
	if hourTo.After(p.T) {
		hourTo = p.T
	}
	// Step 2: what failed, over the narrowed hour.
	pq := PatternsQuery{Query: Query{From: hourFrom, To: hourTo, Text: "failed", Sources: []string{srcLoki}}, Top: 10}
	pages := a.mustFree(agentCall{"patterns text over the hour", MethodPatterns, pq}, 0)
	var pr PatternsResult
	json.Unmarshal(pages[len(pages)-1], &pr)
	if len(pr.Patterns) == 0 || !strings.Contains(pr.Patterns[0].Pattern, "upstream timed out") {
		t.Errorf("step 2: top patterns %+v", pr.Patterns)
	}
	// Step 3: the order's records (a page), and one's trace.
	sq := Query{From: first, To: hourTo, Text: "4812", Sources: []string{srcLoki}, Limit: 50}
	var rec struct {
		TS  time.Time `json:"ts"`
		Msg string    `json:"msg"`
	}
	for _, pg := range a.mustFree(agentCall{"search the order", MethodSearch, sq}, 3) {
		var sr SearchResult
		json.Unmarshal(pg, &sr)
		for _, r := range sr.Records {
			if strings.Contains(string(r), "@shop.example") {
				t.Fatalf("step 3: an e-mail reached the agent: %s", r)
			}
			if rec.Msg == "" {
				json.Unmarshal(r, &rec)
			}
		}
	}
	// The request id the message shows.
	m := traceRe.FindStringSubmatch(rec.Msg)
	if m == nil {
		t.Fatalf("step 3: no record of the order with a trace id: %+v", rec)
	}
	trace := m[1]
	tq := TraceQuery{ID: trace, From: rec.TS.Add(-5 * time.Minute).Truncate(time.Second), To: rec.TS.Add(5 * time.Minute).Truncate(time.Second), Sources: []string{srcLoki}, Limit: 50}
	n := 0
	for _, pg := range a.mustFree(agentCall{"trace", MethodTrace, tq}, 0) {
		var sr SearchResult
		json.Unmarshal(pg, &sr)
		n += len(sr.Records)
	}
	if n == 0 {
		t.Errorf("step 3: the trace of %s found nothing", trace)
	}
	took := time.Since(start)
	for _, l := range a.log {
		t.Log(l)
	}
	t.Logf("job 1: %d calls, %d prompts, %v", a.calls, a.prompts, took.Round(time.Millisecond))
	return a.prompts, took
}

// runPagesCtx is runPages with the caller's context (its peer).
func (s *suite) runPagesCtx(ctx context.Context, c agentCall, max int) callResult {
	s.t.Helper()
	var params map[string]any
	b, _ := json.Marshal(c.params)
	json.Unmarshal(b, &params)
	var out callResult
	for i := 0; ; i++ {
		b, _ := json.Marshal(params)
		res, refusal, err := s.eng.Handle(ctx, c.method, b)
		if err != nil {
			s.t.Fatalf("%s: engine failure: %v", c.name, err)
		}
		if refusal != nil {
			out.refusal = refusal
			return out
		}
		page, _ := json.Marshal(res)
		out.pages = append(out.pages, page)
		var st struct {
			Complete bool   `json:"complete"`
			Cursor   string `json:"cursor"`
		}
		json.Unmarshal(page, &st)
		if st.Complete || max > 0 && len(out.pages) >= max {
			return out
		}
		if st.Cursor == "" {
			s.t.Fatalf("%s: an incomplete page without a cursor", c.name)
		}
		params["cursor"] = st.Cursor
		if i > 20000 {
			s.t.Fatalf("%s: never completes", c.name)
		}
	}
}

// lokiSource is the console's Loki source over base for one copy.
func lokiSource(t *testing.T, base, run string, level bool) *loki.Source {
	t.Helper()
	cl, err := egress.New(&config.Remote{URL: base, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{},
		egress.Options{Headers: egress.LokiHeaders})
	if err != nil {
		t.Fatal(err)
	}
	labels := []string{"app"}
	if level {
		labels = append(labels, "level")
	}
	p, _ := parse.New(parse.Options{})
	src, err := loki.New(loki.Options{Name: srcLoki, Client: cl, Parser: p, Selector: map[string]string{"run": run}, TrustedLabels: labels})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestLokiIncident(t *testing.T) {
	base := os.Getenv("LOCKLOG_LOKI_INCIDENT_URL")
	if base == "" {
		t.Skip("set LOCKLOG_LOKI_INCIDENT_URL to a Loki started with test/loki/incident-config.yaml (the CI loki-incident job)")
	}
	base = strings.TrimSuffix(base, "/")
	perDay := int64(5 << 30)
	if v := os.Getenv("LOCKLOG_LOKI_INCIDENT_VOLUME"); v != "" {
		perDay = parseSize(t, v)
	}
	background := int64(512 << 20)
	if v := os.Getenv("LOCKLOG_LOKI_INCIDENT_BACKGROUND"); v != "" {
		background = parseSize(t, v)
	}
	if base == "fake" {
		srv := httptest.NewServer(&suiteLoki{})
		t.Cleanup(srv.Close)
		base = srv.URL
	}
	p := newLokiPlan(perDay, background)
	start := time.Now()
	pushed, entries := lokiIngest(t, base, p)
	ingest := time.Since(start)
	t.Logf("pushed %.2f GiB of lines (%d + %d entries) in %v: the dense hour at %.1f GiB/day, a %d MiB background per copy",
		float64(pushed)/(1<<30), entries["lvl"], entries["nolvl"], ingest.Round(time.Second), float64(perDay)/(1<<30), background>>20)
	if pushed > lokiDataCap {
		t.Fatalf("%d bytes pushed, over the %d cap", pushed, int64(lokiDataCap))
	}
	// Everything pushed is readable before the clock runs.
	for _, run := range []string{"lvl", "nolvl"} {
		for i := 0; ; i++ {
			n := lokiCount(t, base, `{run="`+run+`"}`, p.T.Add(-7*24*time.Hour-time.Minute), p.T.Add(time.Minute))
			if n == entries[run] {
				break
			}
			if i > 60 {
				t.Fatalf("%s: Loki holds %d entries, %d pushed", run, n, entries[run])
			}
			time.Sleep(2 * time.Second)
		}
	}
	ingest = time.Since(start)
	t.Logf("ingested and readable in %v (gate %v)", ingest.Round(time.Second), lokiIngestGate)
	if ingest > lokiIngestGate {
		t.Errorf("ingestion took %v, gate %v", ingest, lokiIngestGate)
	}
	proxy := os.Getenv("LOCKLOG_TOXIPROXY_URL")
	for _, tc := range []struct {
		name         string
		level, slow  bool
		latency, hog bool
	}{
		{name: "level label", level: true},
		{name: "no level label", level: false},
		{name: "level label, latency proxy", level: true, latency: true},
		{name: "no level label, latency proxy", level: false, latency: true},
		{name: "level label, host slowed 3x", level: true, hog: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := base
			if tc.latency {
				if proxy == "" {
					t.Skip("set LOCKLOG_TOXIPROXY_URL (the CI loki-incident job)")
				}
				url = toxiproxy(t, proxy, base, 50*time.Millisecond, 10*time.Millisecond)
			}
			run := "nolvl"
			if tc.level {
				run = "lvl"
			}
			s := newSuite(t, nil, suiteConfig{Structured: mask.StructuredRedactUnknown, Workers: 2, NoAgentMeta: true, Calibrated: true,
				Now:     time.Now,
				Sources: map[string]source.Source{srcLoki: lokiSource(t, url, run, tc.level)},
				// The source's trusted labels are its only trusted names
				// (the level field of the lines is not trusted).
				Trusted: func(_, name string, label bool) bool { return label && (name == "app" || tc.level && name == "level") },
				// The console's defaults (design §3.3): budgets, and an
				// approved scan's own request rate from S3.
				Budgets: func(b *Budgets) { *b = DefaultBudgets() },
				Engine:  func(o *Options) { o.ScanRequestsPerMinute = DefaultBudgets().RemoteRequestsPerMinute }})
			if tc.hog {
				defer cpuHog()()
			}
			prompts, took := lokiJob(t, s, p, tc.level)
			if prompts > 3 {
				t.Errorf("%d approval prompts, want at most 3", prompts)
			}
			if took > incidentGate {
				t.Errorf("answered in %v, gate %v", took.Round(time.Second), incidentGate)
			}
		})
	}
}
