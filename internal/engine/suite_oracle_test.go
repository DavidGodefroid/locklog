//go:build unix

package engine

import (
	"fmt"
	"maps"
	"math"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
)

// oracleValues are one value of each corpus kind; a corpus planted with
// them is compared with the same corpus planted with others of the same
// kinds.
type oracleValues map[string]string

// oraclePair returns two sets of values of every kind: of the same length
// each (sameLen) or, for the kinds whose values vary in length, of
// different lengths.
func oraclePair(t testing.TB, sameLen bool) (oracleValues, oracleValues) {
	g := masktest.New(4242)
	a, b := oracleValues{}, oracleValues{}
	for _, k := range masktest.Kinds {
		a[k] = g.Value(k)
		for i := 0; ; i++ {
			v := g.Value(k)
			if v != a[k] && (len(v) == len(a[k])) == sameLen {
				b[k] = v
				break
			}
			if i > 10000 {
				if sameLen {
					t.Fatalf("no second %s of length %d", k, len(a[k]))
				}
				// A kind of fixed length: a value of the same length.
				b[k] = g.Value(k)
				break
			}
		}
	}
	return a, b
}

// oraclePad is the length the canaries and the padding of a record add up
// to: a value of another length leaves the record's bytes, and so every
// plan position, as they are. The padding is a secret-named field's value
// (masktest.SecretNameForCorpus), which the agent sees as ⟦secret⟧ whatever
// its length.
const oraclePad = 240

// oracleCorpus writes n records per source (json gets big, so that its
// plan has several granules): every third one names a planted value, in
// the message and in a field, the others a user of their own.
func oracleCorpus(vals oracleValues, n, jsonN int, srcs []string) map[string][]suiteRecord {
	out := map[string][]suiteRecord{}
	for _, src := range srcs {
		count := n
		if src == "json" {
			count = jsonN
		}
		for j := range count {
			v := fmt.Sprintf("user%d@example.com", j%40)
			if j%3 == 0 {
				v = vals[masktest.Kinds[(j/3)%len(masktest.Kinds)]]
			}
			pad := strings.Repeat("x", oraclePad-2*len(v))
			level := levels[j%len(levels)]
			status := 200 + 100*(j%4)
			msg := fmt.Sprintf("render pdf for %s failed: upstream timed out (order %d)", v, j)
			out[src] = append(out[src], suiteRecord{TS: suiteBase.Add(time.Duration(j) * time.Second), Kind: "json",
				Payload: fmt.Sprintf(`{"ts":"%s","level":"%s","status":%d,"user":%s,"msg":%s,"token":"%s"}`, tsMark, level, status, jsonString(v), jsonString(msg), pad),
				Logfmt:  fmt.Sprintf(`ts=%s level=%s status=%d user=%s msg=%s token=%s`, tsMark, level, status, jsonString(v), jsonString(msg), pad)})
		}
	}
	return out
}

// oracleCalls are the calls the oracle compares: every predicate kind, a
// count by trusted and by masked fields and by pattern, patterns; each
// through its stopping points (one granule per call).
func oracleCalls() []agentCall {
	sq := func(name string, mod func(*Query)) agentCall { return agentCall{name, MethodSearch, suiteQuery(mod)} }
	return []agentCall{
		sq("regex", func(q *Query) { q.Regex = "for .* failed"; q.Limit = 200 }),
		sq("text", func(q *Query) { q.Text = "upstream"; q.Limit = 70 }),
		sq("text in clear values", func(q *Query) { q.Text = "example"; q.Limit = 200 }),
		sq("contains", func(q *Query) {
			q.Where = []Pred{{Field: "msg", Op: OpContains, Value: raw("timed out (order 1")}}
			q.Limit = 200
		}),
		sq("exists", func(q *Query) { q.Where = []Pred{{Field: "user", Op: OpExists}}; q.Limit = 150 }),
		sq("where trusted", func(q *Query) {
			q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}, {Field: "status", Op: OpGe, Value: raw(400)}}
			q.Limit = 200
		}),
		sq("desc", func(q *Query) { q.Order = "desc"; q.Limit = 90; q.Fields = []string{"user", "msg"} }),
		{"count by level", MethodCount, CountQuery{Query: suiteQuery(nil), By: []string{"level"}, Bucket: "10m"}},
		{"count by masked field", MethodCount, CountQuery{Query: suiteQuery(nil), By: []string{"user"}, FirstLast: true}},
		{"count by pattern", MethodCount, CountQuery{Query: suiteQuery(nil), ByPattern: true}},
		{"count text", MethodCount, CountQuery{Query: suiteQuery(func(q *Query) { q.Text = "upstream" }), By: []string{"status"}, Bucket: "2m"}},
		{"patterns", MethodPatterns, PatternsQuery{Query: suiteQuery(nil), Top: MaxTop}},
		{"patterns text", MethodPatterns, PatternsQuery{Query: suiteQuery(func(q *Query) { q.Text = "upstream" })}},
	}
}

// TestSuiteOracle: a corpus whose planted values are swapped for others of
// the same kinds (same lengths; different lengths, the records' bytes kept)
// gives the same answers to every call, modulo pseudonym ids: the same
// records, counts and patterns, the same stopping points and cursor plan
// positions, the same scanned work and covered_until, and the same number
// of distinct pseudonyms of each kind.
func TestSuiteOracle(t *testing.T) {
	heavySuite(t)
	for _, tc := range []struct {
		name    string
		sameLen bool
		srcs    []string
	}{
		// Free text (plain, syslog, combined) shows a padding of another
		// length: different lengths are compared on the sources whose
		// records carry the padding in a secret-named field.
		{"same length", true, suiteSources()},
		{"different length", false, []string{"json", "logfmt", "cri", "docker-json", srcJournal, srcDocker, srcLoki}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := oraclePair(t, tc.sameLen)
			ep, err := pii.NewEpoch(suiteBase)
			if err != nil {
				t.Fatal(err)
			}
			cfg := suiteConfig{Structured: mask.StructuredDetect, Epoch: ep, Cost: oneGranuleCost(), Workers: 2}
			sa := newSuite(t, oracleCorpus(a, 300, 9000, tc.srcs), cfg)
			sb := newSuite(t, oracleCorpus(b, 300, 9000, tc.srcs), cfg)
			// The planted values are masked whole, as their kind.
			for _, k := range masktest.Kinds {
				for _, v := range []string{a[k], b[k]} {
					if got := sa.masker.Text(v); !placeholder.MatchString(got) || strings.Contains(got, v) {
						t.Fatalf("%s %q masks as %q", k, v, got)
					}
				}
			}
			for _, c := range oracleCalls() {
				x, nx := normalizePages(t, sa.eng, sa.mustRun(c))
				y, ny := normalizePages(t, sb.eng, sb.mustRun(c))
				if d := firstDiff(x, y); d != "" {
					t.Errorf("%s: the planted values change the answer: %s", c.name, d)
				}
				if !maps.Equal(nx, ny) {
					t.Errorf("%s: distinct pseudonyms %v vs %v", c.name, nx, ny)
				}
				if len(x) < 3 && !strings.HasPrefix(c.name, "patterns") {
					t.Errorf("%s: %d pages: no stopping point compared", c.name, len(x))
				}
			}
			// LL-14: context around the same records, trace by the
			// pseudonym the first record shows (a planted value) and
			// by a clear id, tail.
			comparePairedRefCalls(t, sa, sb, agentCall{"search", MethodSearch, suiteQuery(func(q *Query) { q.Limit = 60 })}, "1203", "the planted values")
		})
	}
}

// Latency: the time of a call does not tell the planted values apart. With
// mask-all (the default everywhere: no pre-filter), every record of the
// plan is masked whatever the predicates, so a needle found only in the
// clear form of one set of values costs the same on both. Timing cases run
// with LOCKLOG_SUITE_TIMING=1 (the CI suites job) and never with -short.

func timingCase(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("timing case: skipped with -short")
	}
	if os.Getenv("LOCKLOG_SUITE_TIMING") != "1" {
		t.Skip("timing case: set LOCKLOG_SUITE_TIMING=1 (run by the CI suites job)")
	}
}

// cpuHog keeps 2×GOMAXPROCS goroutines busy (the host slowed about 3×)
// until stop is called.
func cpuHog() (stop func()) {
	var done atomic.Bool
	var wg sync.WaitGroup
	for range 2 * runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 0
			for !done.Load() {
				for i := range 1 << 14 {
					x += i
				}
			}
			_ = x
		}()
	}
	return func() { done.Store(true); wg.Wait() }
}

// timeCall returns the wall time of a call run to completion.
func timeCall(s *suite, c agentCall) time.Duration {
	start := time.Now()
	s.mustRun(c)
	return time.Since(start)
}

// median of a sample (sorted in place).
func median(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	if len(d)%2 == 1 {
		return d[len(d)/2]
	}
	return (d[len(d)/2-1] + d[len(d)/2]) / 2
}

// mannWhitneyZ is the normal approximation of the Mann-Whitney U statistic
// of two samples (positive when a is slower).
func mannWhitneyZ(a, b []time.Duration) float64 {
	u := 0.0
	for _, x := range a {
		for _, y := range b {
			switch {
			case x > y:
				u++
			case x == y:
				u += 0.5
			}
		}
	}
	n1, n2 := float64(len(a)), float64(len(b))
	mu := n1 * n2 / 2
	sigma := (n1 * n2 * (n1 + n2 + 1) / 12)
	return (u - mu) / math.Sqrt(sigma)
}

// latencySamples times a call on two fixtures, interleaved (a, b, a, b,
// ...) after a warm-up, so that drift and noise fall on both alike.
func latencySamples(sa, sb *suite, c agentCall, n int) ([]time.Duration, []time.Duration) {
	timeCall(sa, c)
	timeCall(sb, c)
	var xa, xb []time.Duration
	for i := range n {
		if i%2 == 0 {
			xa = append(xa, timeCall(sa, c))
			xb = append(xb, timeCall(sb, c))
		} else {
			xb = append(xb, timeCall(sb, c))
			xa = append(xa, timeCall(sa, c))
		}
	}
	return xa, xb
}

// TestSuiteOracleLatency compares the time of calls whose needle is found
// in the clear form of one set of planted values only (in every record),
// on the production defaults (redact-unknown) and the non-production ones
// (detect), both with mask-all, idle and under a CPU hog, over 25
// interleaved runs each: a call fails when its medians are more than 5% +
// 5 ms apart and a Mann-Whitney test finds a difference (|z| > 4). The
// opt-in pre-filter
// (refused on production) is the control: there the needle's clear-text
// matches decide what is masked, and the harness must see it.
func TestSuiteOracleLatency(t *testing.T) {
	timingCase(t)
	a := oracleValues{}
	b := oracleValues{}
	for k, v := range map[string][2]string{
		"email": {"alice.martin@shop.example", "bruno.dupont@corp.example"},
	} {
		a[k], b[k] = v[0], v[1]
	}
	corpus := func(v string) map[string][]suiteRecord {
		out := map[string][]suiteRecord{}
		for _, src := range []string{"json", srcJournal, srcDocker, srcLoki} {
			for j := range 6000 {
				msg := fmt.Sprintf("render pdf for %s failed: upstream timed out (order %d)", v, j)
				out[src] = append(out[src], suiteRecord{TS: suiteBase.Add(time.Duration(j) * time.Second), Kind: "json",
					Payload: fmt.Sprintf(`{"ts":"%s","level":"%s","user":%s,"msg":%s}`, tsMark, levels[j%len(levels)], jsonString(v), jsonString(msg))})
			}
		}
		return out
	}
	calls := []agentCall{
		{"text", MethodSearch, suiteQuery(func(q *Query) { q.Text = "martin@shop"; q.Limit = 200 })},
		{"contains", MethodCount, CountQuery{Query: suiteQuery(func(q *Query) {
			q.Where = []Pred{{Field: "msg", Op: OpContains, Value: raw("shop.example")}}
		}), By: []string{"level"}}},
	}
	const n = 25
	for _, tc := range []struct {
		name       string
		structured string
		prefilter  bool
		hog        bool
	}{
		{"production", mask.StructuredRedactUnknown, false, false},
		{"production under a CPU hog", mask.StructuredRedactUnknown, false, true},
		{"non-production", mask.StructuredDetect, false, false},
		{"non-production under a CPU hog", mask.StructuredDetect, false, true},
		{"non-production pre-filter (control)", mask.StructuredDetect, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, _ := pii.NewEpoch(suiteBase)
			cfg := suiteConfig{Structured: tc.structured, Prefilter: tc.prefilter, Epoch: ep, Workers: 2}
			sa := newSuite(t, corpus(a["email"]), cfg)
			sb := newSuite(t, corpus(b["email"]), cfg)
			if tc.hog {
				defer cpuHog()()
			}
			for _, c := range calls {
				xa, xb := latencySamples(sa, sb, c, n)
				z := mannWhitneyZ(xa, xb)
				ma, mb := median(slices.Clone(xa)), median(slices.Clone(xb))
				t.Logf("%s: median %v vs %v, Mann-Whitney z %.2f", c.name, ma, mb, z)
				lo, hi := min(ma, mb), max(ma, mb)
				differ := hi-lo > lo/20+5*time.Millisecond && (z > 4 || z < -4)
				if tc.prefilter {
					// The control: the planted values' clear text holds
					// the text needle in A only, so A masks every record
					// and B none. (Counts never use the pre-filter: the
					// count call is only logged.)
					if c.name == "text" && (ma < 2*mb || z < 4) {
						t.Errorf("%s: the harness does not see the pre-filter's latency: %v vs %v (z %.2f)", c.name, ma, mb, z)
					}
					continue
				}
				if differ {
					t.Errorf("%s: latency tells the planted values apart: median %v vs %v, z %.2f", c.name, ma, mb, z)
				}
			}
		})
	}
}
