//go:build unix

package engine

// The local incidents (design §9.1): a scripted agent answers job 1 the
// way the skill teaches it — (1) a trusted-field count over the whole
// range, served from the local index, to find when it started; (2)
// patterns and a count with text over the narrowed hour, continued free;
// (3) the records of the order (trace joins once LL-14 is merged). The
// gates are the number of approval prompts and the time to the answer.
//
//   - Incident (a), "order 4812": nginx access log (file, combined), the
//     app's JSON log (file), journald and a Docker container, one day.
//   - Incident (b), realistic volume (R6-P1): 7 days of nginx access log
//     (daily rotated files) and journald history; warm (index built) and
//     cold (no index: the backfill runs newest first at full speed while
//     the agent works), each also with the host slowed about 3× (a CPU
//     hog). By default it runs on a small volume; LOCKLOG_INCIDENT_VOLUME
//     (bytes per day, e.g. 1GiB) sets the volume, and with
//     LOCKLOG_JOURNAL_REMOTE (the systemd-journal-remote binary) the
//     journal history is imported in export format with past timestamps,
//     as the CI incidents job does.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

// The incident: order 4812's PDF rendering times out upstream from 14:20
// to 15:00 on the last day; nginx answers 502 to a third of the API calls.
var (
	incidentStart = suiteBase.Add(20 * time.Minute)
	incidentEnd   = suiteBase.Add(time.Hour)
)

const (
	srcNginx = "combined"
	srcApp   = "json"
	// incidentGate is the time to the answer (§9.1: < 5 min).
	incidentGate = 5 * time.Minute
)

func inIncident(ts time.Time) bool { return !ts.Before(incidentStart) && ts.Before(incidentEnd) }

// incidentGen generates the incident's records, deterministically.
type incidentGen struct {
	r *rand.Rand
}

func newIncidentGen(seed uint64) *incidentGen { return &incidentGen{rand.New(rand.NewPCG(seed, 4812))} }

var incidentPaths = []string{"/", "/static/app.js", "/static/app.css", "/api/cart", "/api/orders/%d", "/api/orders/%d/pdf", "/login", "/api/search?q=shoes"}

// nginx returns one access-log line at ts.
func (g *incidentGen) nginx(ts time.Time) string {
	r := g.r
	ip := fmt.Sprintf("198.51.%d.%d", r.IntN(255), 1+r.IntN(254))
	method := "GET"
	if r.IntN(10) == 0 {
		method = "POST"
	}
	path := incidentPaths[r.IntN(len(incidentPaths))]
	order := 4000 + r.IntN(1000)
	status := []int{200, 200, 200, 200, 200, 200, 304, 301, 404, 403}[r.IntN(10)]
	if r.IntN(5000) == 0 {
		status = 500
	}
	if inIncident(ts) && strings.HasPrefix(path, "/api/orders") && r.IntN(3) > 0 {
		order, status = 4812, 502
	}
	if strings.Contains(path, "%d") {
		path = fmt.Sprintf(path, order)
	}
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "https://shop.example/" "Mozilla/5.0 (X11; Linux x86_64) shop-client/%d.%d"`,
		ip, ts.UTC().Format("02/Jan/2006:15:04:05 -0700"), method, path, status, 200+r.IntN(40000), r.IntN(9), r.IntN(30))
}

// journal returns one journald message of the shop's renderer at ts and
// its priority.
func (g *incidentGen) journal(ts time.Time) (string, int) {
	r := g.r
	user := fmt.Sprintf("user%d@shop.example", r.IntN(500))
	if inIncident(ts) && r.IntN(4) > 0 {
		if r.IntN(8) == 0 {
			return "pdf-renderer: worker killed (out of memory)", 2
		}
		return fmt.Sprintf("render pdf for %s failed: upstream timed out (order 4812)", user), 3
	}
	order := 4000 + r.IntN(1000)
	return fmt.Sprintf("rendered pdf for %s in %dms (order %d)", user, 20+r.IntN(400), order), 6
}

// app returns one line of the app's JSON log at ts.
func (g *incidentGen) app(ts time.Time) string {
	r := g.r
	user := fmt.Sprintf("user%d@shop.example", r.IntN(500))
	if inIncident(ts) && r.IntN(3) > 0 {
		return fmt.Sprintf(`{"ts":%q,"level":"error","order":4812,"user":%q,"msg":"payment confirmation failed for order 4812: upstream timed out"}`, ts.UTC().Format(time.RFC3339Nano), user)
	}
	order := 4000 + r.IntN(1000)
	return fmt.Sprintf(`{"ts":%q,"level":"info","order":%d,"user":%q,"msg":"order %d confirmed"}`, ts.UTC().Format(time.RFC3339Nano), order, user, order)
}

// nginxLineBytes is about the size of an access-log line.
const nginxLineBytes = 190

// writeNginx writes days daily-rotated access logs of perDay bytes ending
// at end, each file's mtime its last record's time.
func writeNginx(t testing.TB, dir string, g *incidentGen, end time.Time, days int, perDay int64) []string {
	t.Helper()
	n := max(perDay/nginxLineBytes, 1)
	step := 24 * time.Hour / time.Duration(n)
	var paths []string
	for d := days - 1; d >= 0; d-- {
		name := "access.log"
		if d > 0 {
			name += "." + strconv.Itoa(d)
		}
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriterSize(f, 1<<20)
		dayStart := end.Add(-time.Duration(d+1) * 24 * time.Hour)
		var last time.Time
		for i := range n {
			last = dayStart.Add(time.Duration(i) * step)
			w.WriteString(g.nginx(last))
			w.WriteByte('\n')
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		os.Chtimes(path, last, last)
		paths = append(paths, path)
	}
	return paths
}

// writeJournal writes days of journal history of about perDay bytes of
// messages ending at end under root/<machine-id>/: imported by
// systemd-journal-remote from export format when bin is set, else built
// in memory (small volumes).
func writeJournal(t testing.TB, root, bin string, g *incidentGen, end time.Time, days int, perDay int64) {
	t.Helper()
	dir := filepath.Join(root, suiteMachineID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	n := max(perDay/120, 1)
	step := 24 * time.Hour / time.Duration(n)
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	total := n * int64(days)
	if bin == "" {
		if total > 2_000_000 {
			t.Fatalf("%d journal entries: set LOCKLOG_JOURNAL_REMOTE to import them", total)
		}
		var es []journaltest.Entry
		for i := range total {
			ts := start.Add(time.Duration(i) * step)
			msg, prio := g.journal(ts)
			es = append(es, journaltest.Entry{Realtime: uint64(ts.UnixMicro()), Fields: []string{
				"MESSAGE=" + msg, "PRIORITY=" + strconv.Itoa(prio), "_SYSTEMD_UNIT=shop.service", "SYSLOG_IDENTIFIER=pdf-renderer"}})
		}
		if err := os.WriteFile(filepath.Join(dir, "system.journal"), journaltest.Build(journaltest.Options{Compact: true, PerArray: 4096}, es), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	cmd := exec.Command(bin, "--output="+filepath.Join(dir, "system.journal"), "--split-mode=none", "-")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(in, 1<<20)
	for i := range total {
		ts := start.Add(time.Duration(i) * step)
		msg, prio := g.journal(ts)
		fmt.Fprintf(w, "__REALTIME_TIMESTAMP=%d\n__MONOTONIC_TIMESTAMP=%d\n_BOOT_ID=%s\n_MACHINE_ID=%s\n_HOSTNAME=shop-1\nMESSAGE=%s\nPRIORITY=%d\n_SYSTEMD_UNIT=shop.service\nSYSLOG_IDENTIFIER=pdf-renderer\n\n",
			ts.UnixMicro(), i+1, suiteMachineID, suiteMachineID, msg, prio)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	in.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("systemd-journal-remote: %v: %s", err, stderr.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.journal"))
	if len(files) == 0 {
		t.Fatalf("systemd-journal-remote wrote no journal: %s", stderr.String())
	}
}

// jobAgent is the scripted agent: it runs the skill's job-1 sequence
// through Handle, counting calls, waits and prompts.
type jobAgent struct {
	t       *testing.T
	s       *suite
	calls   int
	waits   int
	retries int
	prompts int
	// deadline ends the retries and waits.
	deadline time.Time
	// backfill is set while the index backfill runs: an over-budget
	// count of the part not yet indexed is retried, as the refusal says.
	backfill bool
	log      []string
}

// ask runs a call to completion. A refusal over budget is retried while
// the backfill runs and it names the part not yet indexed; any other
// refusal over budget is what the skill turns into a scan request: one
// approval prompt (locklog_scan arrives with LL-19; until then the
// scripted agent stops there and the gate fails).
func (a *jobAgent) ask(c agentCall) []json.RawMessage {
	a.t.Helper()
	prompted := false
	for {
		start := time.Now()
		r := a.s.run(c)
		a.calls++
		a.log = append(a.log, fmt.Sprintf("%s: %d pages in %v", c.name, len(r.pages), time.Since(start).Round(time.Millisecond)))
		if r.refusal == nil {
			return r.pages
		}
		if time.Now().Before(a.deadline) {
			switch {
			case r.refusal.Code == EOverBudget && a.backfill && strings.Contains(r.refusal.Message, "once more is indexed"):
				a.waits++
				time.Sleep(time.Second)
				continue
			case r.refusal.Code == ESource && strings.HasSuffix(r.refusal.Message, "try again"):
				// The first granule ran past the deadline (a slowed
				// host): the cost model has recalibrated.
				a.retries++
				continue
			}
		}
		if r.refusal.Code == EOverBudget {
			// The skill turns this into a scan request: one approval
			// prompt. Until locklog_scan (LL-19), the approved scan of a
			// cold start is stood in for by waiting for the backfill,
			// which serves the same count; the prompt is counted once
			// per call.
			if !prompted {
				a.prompts++
				prompted = true
				a.log = append(a.log, fmt.Sprintf("%s: prompt: %v", c.name, r.refusal))
			}
			if a.backfill && time.Now().Before(a.deadline) {
				a.waits++
				time.Sleep(time.Second)
				continue
			}
		}
		a.t.Fatalf("%s: refused (%d prompts so far): %v", c.name, a.prompts, r.refusal)
	}
}

func lastCount(t testing.TB, pages []json.RawMessage) CountResult {
	var r CountResult
	if err := json.Unmarshal(pages[len(pages)-1], &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// whenItStarted is step (1): a count by status class over the range, in
// buckets, and the first bucket where 5xx is more than a tenth of the
// requests.
func (a *jobAgent) whenItStarted(from, to time.Time, bucket string) (time.Time, CountResult) {
	c := CountQuery{Query: Query{From: from, To: to, Sources: []string{srcNginx}}, By: []string{"status_class"}, Bucket: bucket}
	res := lastCount(a.t, a.ask(agentCall{"count by status_class per " + bucket, MethodCount, c}))
	all, bad := map[time.Time]int64{}, map[time.Time]int64{}
	for _, g := range res.Groups {
		all[g.Bucket] += g.N
		if len(g.Key) == 1 && g.Key[0] != nil && *g.Key[0] == "5xx" {
			bad[g.Bucket] += g.N
		}
	}
	var buckets []time.Time
	for b := range all {
		buckets = append(buckets, b)
	}
	slices.SortFunc(buckets, func(x, y time.Time) int { return x.Compare(y) })
	for _, b := range buckets {
		if bad[b]*10 > all[b] {
			return b, res
		}
	}
	a.t.Fatalf("no 5xx spike in %d buckets", len(buckets))
	return time.Time{}, res
}

// job1 runs the whole sequence over [from, to) and checks the answer: the
// start (to the minute), the upstream time-out as the top error pattern,
// the order's records in every source.
func (a *jobAgent) job1(from, to time.Time, srcs []string) {
	t := a.t
	b, res := a.whenItStarted(from, to, "15m")
	t.Logf("step 1: %d groups, from_index %v indexed_from %v, scanned %d bytes", len(res.Groups), res.FromIndex, res.IndexedFrom, res.Scanned.Bytes)
	if incidentStart.Before(b) || !incidentStart.Before(b.Add(15*time.Minute)) {
		t.Fatalf("step 1: started at %v, want the bucket of %v", b, incidentStart)
	}
	// The narrowed hour, then the minute.
	hourFrom, hourTo := b, b.Add(time.Hour)
	m, _ := a.whenItStarted(hourFrom, hourTo, "1m")
	if !m.Equal(incidentStart) {
		t.Fatalf("step 1: started at %v, want %v", m, incidentStart)
	}
	// Step 2: what failed, over the narrowed hour, with text.
	pq := PatternsQuery{Query: Query{From: hourFrom, To: hourTo, Text: "failed", Sources: srcs}, Top: 10}
	pages := a.ask(agentCall{"patterns text over the hour", MethodPatterns, pq})
	var pr PatternsResult
	json.Unmarshal(pages[len(pages)-1], &pr)
	if len(pr.Patterns) == 0 || !strings.Contains(pr.Patterns[0].Pattern, "upstream timed out") {
		t.Fatalf("step 2: top patterns %+v", pr.Patterns)
	}
	cq := CountQuery{Query: Query{From: hourFrom, To: hourTo, Text: "4812", Sources: srcs}, Bucket: "10m"}
	cr := lastCount(t, a.ask(agentCall{"count text over the hour", MethodCount, cq}))
	if len(cr.Groups) == 0 {
		t.Fatal("step 2: no record of order 4812 in the hour")
	}
	// Step 3: the order's records, in every source.
	sq := Query{From: incidentStart, To: hourTo, Text: "4812", Sources: srcs, Limit: 200}
	seen := map[string]bool{}
	for _, p := range a.ask(agentCall{"search the order", MethodSearch, sq}) {
		var sr SearchResult
		json.Unmarshal(p, &sr)
		for _, r := range sr.Records {
			var h struct {
				Source string `json:"source"`
			}
			json.Unmarshal(r, &h)
			seen[h.Source] = true
			if strings.Contains(string(r), "@shop.example") {
				t.Fatalf("step 3: an e-mail reached the agent: %s", r)
			}
		}
	}
	for _, src := range srcs {
		if !seen[src] {
			t.Errorf("step 3: no record of order 4812 from %s", src)
		}
	}
	// TODO(LL-14): step 3 continues with log.trace from a record's ref.
}

// runJob runs job 1 on s and applies the gates: at most maxPrompts
// approval prompts, the answer within gate. With cold, the index backfill
// runs at full speed from the start, as at a console's first start.
func runJob(t *testing.T, s *suite, cold bool, maxPrompts int, gate time.Duration, from, to time.Time, srcs []string) time.Duration {
	start := time.Now()
	a := &jobAgent{t: t, s: s, backfill: cold, deadline: start.Add(gate)}
	if cold {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			index.Run(ctx, s.indexers, index.RunOptions{BytesPerHour: 1 << 50, Flush: s.store.Flush, Idle: 100 * time.Millisecond,
				OnError: func(_ index.Indexer, err error) { t.Errorf("backfill: %v", err) }})
		}()
		defer func() { cancel(); wg.Wait() }()
	}
	a.job1(from, to, srcs)
	took := time.Since(start)
	for _, l := range a.log {
		t.Log(l)
	}
	t.Logf("job 1: %d calls, %d waits for the backfill, %d retries, %d prompts, %v (gate %v)", a.calls, a.waits, a.retries, a.prompts, took.Round(time.Millisecond), gate.Round(time.Second))
	if a.prompts > maxPrompts {
		t.Errorf("%d approval prompts, want at most %d", a.prompts, maxPrompts)
	}
	if took > gate {
		t.Errorf("answered in %v, gate %v", took, gate)
	}
	return took
}

// TestIncidentOrder4812 is incident (a): one day of nginx, app, journald
// and Docker logs; job 1 with the index built, no prompt.
func TestIncidentOrder4812(t *testing.T) {
	g := newIncidentGen(1)
	day := 24 * time.Hour
	end := suiteNow
	dir := t.TempDir()
	nginx := writeNginx(t, dir, g, end, 1, 8<<20)
	recs := map[string][]suiteRecord{}
	const perSec = 2 // app, journald and docker records per minute / 30
	for ts := end.Add(-day); ts.Before(end); ts = ts.Add(30 * time.Second / perSec) {
		recs[srcApp] = append(recs[srcApp], suiteRecord{TS: ts, Kind: "json", Payload: g.app(ts)})
		msg, _ := g.journal(ts)
		recs[srcJournal] = append(recs[srcJournal], suiteRecord{TS: ts, Kind: "plain", Payload: msg})
		recs[srcDocker] = append(recs[srcDocker], suiteRecord{TS: ts, Kind: "json", Payload: g.app(ts)})
	}
	s := newSuite(t, recs, suiteConfig{Structured: mask.StructuredRedactUnknown, Workers: 2, Index: true,
		Files: map[string][]string{srcNginx: nginx}, NoAgentMeta: true})
	runJob(t, s, false, 0, incidentGate, end.Add(-day+time.Minute), end, []string{srcNginx, srcApp, srcJournal, srcDocker})
}

// parseSize reads "1GiB", "512MiB" or a byte count.
func parseSize(t testing.TB, s string) int64 {
	mult := int64(1)
	for suf, m := range map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30} {
		if strings.HasSuffix(s, suf) {
			s, mult = strings.TrimSuffix(s, suf), m
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 {
		t.Fatalf("LOCKLOG_INCIDENT_VOLUME %q", s)
	}
	return int64(n * float64(mult))
}

// TestIncidentVolume is incident (b): 7 days of nginx (the volume per
// day) and journald (a quarter of it) history; job 1 warm and cold, idle
// and under a CPU hog; no prompt (the count is served from the index,
// the text calls cover the narrowed hour within the free budget).
//
// The gates (R6-P1: "each with its expected prompts and time"): warm,
// the answer within incidentGate; cold, within incidentGate plus the
// backfill's time, 1.5 times the index build the warm variant measured
// on the same data and host load (the count of 7 days cannot be answered
// before the index holds them, or a scan approval).
func TestIncidentVolume(t *testing.T) {
	perDay := int64(16 << 20)
	if v := os.Getenv("LOCKLOG_INCIDENT_VOLUME"); v != "" {
		perDay = parseSize(t, v)
	} else {
		heavySuite(t)
	}
	const days = 7
	end := suiteNow
	data := t.TempDir()
	g := newIncidentGen(2)
	start := time.Now()
	logs := filepath.Join(data, "nginx")
	os.MkdirAll(logs, 0o755)
	nginx := writeNginx(t, logs, g, end, days, perDay)
	jroot := filepath.Join(data, "journal")
	writeJournal(t, jroot, os.Getenv("LOCKLOG_JOURNAL_REMOTE"), g, end, days, perDay/4)
	var size int64
	filepath.Walk(data, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			size += fi.Size()
		}
		return nil
	})
	t.Logf("generated %.2f GiB in %v", float64(size)/(1<<30), time.Since(start).Round(time.Millisecond))
	from := end.Add(-days*24*time.Hour + time.Minute)
	srcs := []string{srcNginx, srcJournal}
	build := map[bool]time.Duration{} // by hog
	for _, tc := range []struct {
		name      string
		cold, hog bool
	}{
		{"warm", false, false},
		{"warm, host slowed 3x", false, true},
		{"cold", true, false},
		{"cold, host slowed 3x", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSuite(t, nil, suiteConfig{Structured: mask.StructuredRedactUnknown, Workers: 2,
				Files: map[string][]string{srcNginx: nginx}, JournalRoot: jroot, NoAgentMeta: true})
			if tc.hog {
				defer cpuHog()()
			}
			gate := incidentGate
			if tc.cold {
				b, ok := build[tc.hog]
				if !ok {
					t.Skip("no warm build time measured")
				}
				gate += b * 3 / 2
			} else {
				start := time.Now()
				s.indexAll()
				build[tc.hog] = time.Since(start)
				t.Logf("index built in %v", build[tc.hog].Round(time.Millisecond))
			}
			// §9.1: at most 3 prompts. Warm needs none; cold may need
			// one scan approval for the part not yet indexed.
			maxPrompts := 0
			if tc.cold {
				maxPrompts = 3
			}
			runJob(t, s, tc.cold, maxPrompts, gate, from, end, srcs)
		})
	}
}
