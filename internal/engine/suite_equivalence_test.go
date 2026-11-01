//go:build unix

package engine

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source/docker"
)

// equivalenceCorpus is the oracle corpus over every source of the fixture,
// with one fixed set of planted values.
func equivalenceCorpus(t testing.TB) map[string][]suiteRecord {
	a, _ := oraclePair(t, true)
	return oracleCorpus(a, 300, 3000, suiteSources())
}

// equivalenceCalls are every suite call and every oracle call.
func equivalenceCalls() []agentCall {
	cs := suiteCalls()
	for _, c := range oracleCalls() {
		c.name = "oracle " + c.name
		cs = append(cs, c)
	}
	return cs
}

// TestSuiteEquivalencePrefilter: the opt-in pre-filter (non-production
// only) gives the agent exactly what mask-all gives, page for page: the
// same records, counts and patterns, the same stopping points, cursor plan
// positions and scanned work, on every source and method.
func TestSuiteEquivalencePrefilter(t *testing.T) {
	heavySuite(t)
	recs := equivalenceCorpus(t)
	ep, err := pii.NewEpoch(suiteBase)
	if err != nil {
		t.Fatal(err)
	}
	cfg := suiteConfig{Structured: mask.StructuredDetect, Epoch: ep, Cost: oneGranuleCost(), Workers: 2}
	off := newSuite(t, recs, cfg)
	cfg.Prefilter = true
	on := newSuite(t, recs, cfg)
	for _, c := range equivalenceCalls() {
		x, nx := normalizePages(t, off.eng, off.mustRun(c))
		y, ny := normalizePages(t, on.eng, on.mustRun(c))
		if d := firstDiff(x, y); d != "" {
			t.Errorf("%s: the pre-filter changes the answer: %s", c.name, d)
		}
		if !maps.Equal(nx, ny) {
			t.Errorf("%s: distinct pseudonyms %v vs %v", c.name, nx, ny)
		}
	}
	comparePairedRefCalls(t, off, on, agentCall{"search", MethodSearch, suiteQuery(func(q *Query) { q.Limit = 60 })}, "1203", "the pre-filter")
}

// answer is what a call answers once run to completion, without how it
// was computed: the records of every page, in order, and the last page's
// groups (counts accumulate across continuations), patterns and untimed
// count. Plan positions, scanned work and index coverage are left out:
// they are what the index changes.
func answer(t testing.TB, e *Engine, pages []json.RawMessage) string {
	t.Helper()
	norm, _ := normalizePages(t, e, pages)
	var recs []any
	var last map[string]any
	for _, p := range norm {
		p, _, _ = strings.Cut(p, noisyMark)
		var m map[string]any
		if err := json.Unmarshal([]byte(p), &m); err != nil {
			t.Fatal(err)
		}
		if rs, ok := m["records"].([]any); ok {
			for _, r := range rs {
				rec := r.(map[string]any)
				delete(rec, "ref")
				recs = append(recs, rec)
			}
		}
		last = m
	}
	out := map[string]any{"records": recs}
	if n, ok := last["records"].(float64); ok {
		out["records_n"] = n // patterns: the records counted
	}
	for _, k := range []string{"groups", "patterns", "untimed", "distinct", "no_text", "truncated", "new", "gone", "complete"} {
		if v, ok := last[k]; ok {
			out[k] = v
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// TestSuiteEquivalenceIndex: the local index changes how a call is
// answered (counts by trusted fields and labels served from the index,
// without a scan), never what it answers: every call gives the same
// records, groups and patterns on a fully indexed fixture as on one
// without an index; the indexed fixture does serve its counts from the
// index.
func TestSuiteEquivalenceIndex(t *testing.T) {
	heavySuite(t)
	recs := equivalenceCorpus(t)
	ep, err := pii.NewEpoch(suiteBase)
	if err != nil {
		t.Fatal(err)
	}
	cfg := suiteConfig{Structured: mask.StructuredDetect, Epoch: ep, Workers: 2}
	scan := newSuite(t, recs, cfg)
	cfg.Index = true
	ix := newSuite(t, recs, cfg)
	calls := equivalenceCalls()
	// The indexed sources: files and docker (journald has no local index;
	// Loki's counts are its own, compared with a scan below).
	indexed := slices.DeleteFunc(suiteSources(), func(s string) bool { return s == srcJournal || s == srcLoki })
	cq := func(name string, mod func(*CountQuery)) agentCall {
		c := CountQuery{Query: suiteQuery(func(q *Query) { q.Sources = indexed })}
		mod(&c)
		return agentCall{name, MethodCount, c}
	}
	trusted := []agentCall{
		cq("index count by level", func(c *CountQuery) { c.By = []string{"level"}; c.Bucket = "2m" }),
		cq("index count by level per hour", func(c *CountQuery) { c.By = []string{"level"}; c.Bucket = "1h" }),
		cq("index count where level", func(c *CountQuery) {
			c.Where = []Pred{{Field: "level", Op: OpIn, Value: raw([]string{"error", "warn"})}}
			c.By = []string{"level"}
			c.Bucket = "10m"
		}),
		cq("index count by container", func(c *CountQuery) {
			c.Sources = []string{srcDocker}
			c.ByLabels = []string{docker.ContainerField}
			c.Bucket = "1h"
		}),
	}
	calls = append(calls, trusted...)
	for i, c := range calls {
		pa := scan.mustRun(c)
		pb := ix.mustRun(c)
		x, y := answer(t, scan.eng, pa), answer(t, ix.eng, pb)
		if x != y {
			d := firstDiff([]string{x}, []string{y})
			t.Errorf("%s: the index changes the answer: %s", c.name, d)
		}
		if i >= len(calls)-len(trusted) {
			var r CountResult
			json.Unmarshal(pb[len(pb)-1], &r)
			if !r.FromIndex {
				t.Errorf("%s: not served from the index", c.name)
			}
		}
	}
}

// TestSuiteEquivalenceLokiCounts: a count by Loki's trusted labels is
// answered by Loki's metric queries (server-side, no line fetched), and
// gives the groups a scan of the same lines gives (the same count with a
// predicate on every line, which only a scan can evaluate).
func TestSuiteEquivalenceLokiCounts(t *testing.T) {
	recs := map[string][]suiteRecord{srcLoki: equivalenceCorpus(t)[srcLoki]}
	s := newSuite(t, recs, suiteConfig{Structured: mask.StructuredDetect, Workers: 2})
	for _, tc := range []struct {
		name   string
		bucket string
		where  []Pred
	}{
		{"per hour", "1h", nil},
		{"per 2 min", "2m", nil},
		{"whole range", "", nil},
		{"where app", "10m", []Pred{{Label: "app", Op: OpEq, Value: raw("shop-pdf")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := CountQuery{Query: suiteQuery(func(q *Query) { q.Sources = []string{srcLoki}; q.Where = tc.where }),
				ByLabels: []string{"app"}, Bucket: tc.bucket}
			metric := s.mustRun(agentCall{"metric", MethodCount, c})
			if r := lastCount(t, metric); !r.FromIndex || r.Scanned.Bytes != 0 {
				t.Fatalf("not answered by Loki's counts: from_index %v, scanned %d", r.FromIndex, r.Scanned.Bytes)
			}
			c.Where = append(slices.Clone(c.Where), Pred{Field: "level", Op: OpExists})
			scanned := s.mustRun(agentCall{"scanned", MethodCount, c})
			r := lastCount(t, scanned)
			if r.FromIndex || r.Scanned.Bytes == 0 {
				t.Fatalf("the predicate on the lines did not scan: from_index %v", r.FromIndex)
			}
			var n int64
			for _, g := range r.Groups {
				n += g.N
			}
			if want := int64(len(recs[srcLoki])); tc.where == nil && n != want {
				t.Fatalf("scanned %d records, want %d", n, want)
			}
			if x, y := answer(t, s.eng, metric), answer(t, s.eng, scanned); x != y {
				t.Errorf("Loki's counts and a scan differ: %s", firstDiff([]string{x}, []string{y}))
			}
		})
	}
}
