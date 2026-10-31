//go:build unix

package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/file"
	"github.com/DavidGodefroid/locklog/internal/source/journald"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

var (
	t0  = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ctx = context.Background()
)

var levels = []string{"info", "info", "info", "warn", "error"}

// genLog writes n logfmt records, one per second from start; records name a
// user by e-mail and every 50th one carries a canary e-mail.
func genLog(start time.Time, n int, canary string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		user := fmt.Sprintf("user%d@example.com", i%40)
		if i%50 == 25 {
			user = canary
		}
		fmt.Fprintf(&b, "time=%s level=%s status=%d msg=\"render pdf for %s failed: upstream timed out (order %d)\"\n",
			start.Add(time.Duration(i)*time.Second).Format(time.RFC3339), levels[i%len(levels)], 200+100*(i%4), user, i)
	}
	return b.String()
}

type fixture struct {
	t      *testing.T
	root   string
	store  *index.Store
	src    *file.Source
	masker *mask.Masker
	eng    *Engine
	fp     string
	scans  *int
}

// countingSource counts Scan calls.
type countingSource struct {
	*file.Source
	n *int
}

func (c countingSource) Scan(ctx context.Context, ch source.Chunk) (source.Iterator, error) {
	*c.n++
	return c.Source.Scan(ctx, ch)
}

func (c countingSource) IndexCounts(ctx context.Context, q source.CountQuery) (source.CountResult, error) {
	return c.Source.IndexCounts(ctx, q)
}

func newFixture(t *testing.T, content string, opt func(*Options)) *fixture {
	t.Helper()
	return newFixtureMask(t, content, nil, opt)
}

// boomFinder is a secret finder that panics on a text holding BOOM: the
// masker withholds such a record whole (Failed).
type boomFinder struct{}

func (boomFinder) Find(s string) []pii.Match {
	if strings.Contains(s, "BOOM") {
		panic("boom")
	}
	return nil
}

func withBoom(o *mask.Options) { o.Secrets = boomFinder{} }

func newFixtureMask(t *testing.T, content string, mopt func(*mask.Options), opt func(*Options)) *fixture {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(root, "logs"), 0o755)
	if err := os.WriteFile(filepath.Join(root, "logs", "app.log"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := index.Open(filepath.Join(t.TempDir(), "idx"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	ep, err := pii.NewEpoch(t0)
	if err != nil {
		t.Fatal(err)
	}
	mo := mask.Options{Pseudonyms: ep, Values: mask.Detectors(pii.AllDetectors()),
		Trusted: []string{"level", "status"}, Structured: mask.StructuredDetect}
	if mopt != nil {
		mopt(&mo)
	}
	m, err := mask.New(mo)
	if err != nil {
		t.Fatal(err)
	}
	src, err := file.New(file.Options{Name: "app", Paths: []string{root + "/logs/app.log"}, Roots: []string{root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: st, Sensitive: func(f, v string) bool { return m.TrustedValue("app", f, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	sealer, _ := NewSealer(key)
	f := &fixture{t: t, root: root, store: st, src: src, masker: m, fp: "fp1", scans: new(int)}
	o := Options{
		Sources: map[string]source.Source{"app": countingSource{src, f.scans}},
		Trusted: func(s, fld string, label bool) bool { return !label && (fld == "level" || fld == "status") },
		Masker:  m, Sealer: sealer,
		Cost:       fixedCost(1), // fast: whole plans in one call
		PolicyFP:   func() string { return f.fp },
		Detect:     func(s string) bool { return m.Text(s) != s },
		NameMasked: func(_, p string) bool { return pii.LooksPersonal(p) },
		Limits:     DefaultLimits(),
	}
	if opt != nil {
		opt(&o)
	}
	f.eng, err = New(o)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// fixedCost is a cost model that does not recalibrate.
func fixedCost(ns float64) *CostModel {
	p, _ := parse.New(parse.Options{})
	c := &CostModel{nsPerByte: ns, at: time.Now().Add(1000 * time.Hour), now: time.Now, parser: p, mask: func(parse.Event) {}, fixed: true}
	c.corpus = []string{"x"}
	return c
}

// oneGranulePerCall sizes calls to one granule each.
func oneGranulePerCall(o *Options) {
	o.Cost = fixedCost(float64(o.Limits.Deadline.Nanoseconds()) / float64(source.GranuleBytes) * 1.1)
}

var day = source.Range{From: t0, To: t0.Add(24 * time.Hour)}

func q(mod func(*Query)) Query {
	qq := Query{From: day.From, To: day.To}
	if mod != nil {
		mod(&qq)
	}
	return qq
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var tokenRe = regexp.MustCompile(`⟦([a-z_]+):[A-Z0-9]+⟧`)

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestValidation(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "canary@example.org"), nil)
	for name, tc := range map[string]struct {
		q    Query
		code string
	}{
		"no range":        {Query{}, EBadQuery},
		"unknown source":  {q(func(q *Query) { q.Sources = []string{"nope"} }), EBadQuery},
		"range too long":  {Query{From: t0, To: t0.Add(8 * 24 * time.Hour)}, EOverBudget},
		"bad op":          {q(func(q *Query) { q.Where = []Pred{{Field: "level", Op: "~", Value: raw("x")}} }), EBadQuery},
		"order untrusted": {q(func(q *Query) { q.Where = []Pred{{Field: "order", Op: ">", Value: raw(3)}} }), EBadQuery},
		"pii value":       {q(func(q *Query) { q.Where = []Pred{{Field: "user", Op: "=", Value: raw("canary@example.org")}} }), EPIIInQuery},
		"pii text":        {q(func(q *Query) { q.Text = "for canary@example.org failed" }), EPIIInQuery},
		"masked name":     {q(func(q *Query) { q.Where = []Pred{{Field: "email", Op: "exists"}} }), EUnknownField},
		"long regex":      {q(func(q *Query) { q.Regex = strings.Repeat("a", MaxPattern+1) }), EBadQuery},
		"bad regex":       {q(func(q *Query) { q.Regex = "(" }), EBadQuery},
		"placeholder":     {q(func(q *Query) { q.Text = "⟦email" }), EBadQuery},
		"limit":           {q(func(q *Query) { q.Limit = 5000 }), EBadQuery},
		"exists value":    {q(func(q *Query) { q.Where = []Pred{{Field: "level", Op: "exists", Value: raw(1)}} }), EBadQuery},
	} {
		if _, err := f.eng.Search(ctx, tc.q); code(err) != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	// last resolves to an absolute range.
	f.eng.o.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	res, err := f.eng.Search(ctx, Query{Last: "2h", Where: []Pred{{Field: "level", Op: "=", Value: raw("error")}}})
	if err != nil || len(res.Records) != 20 {
		t.Fatalf("last: %v %d", err, len(res.Records))
	}
}

func allRecords(t *testing.T, e *Engine, qq Query) ([]json.RawMessage, []SearchResult) {
	t.Helper()
	var recs []json.RawMessage
	var pages []SearchResult
	for i := 0; ; i++ {
		res, err := e.Search(ctx, qq)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, res)
		recs = append(recs, res.Records...)
		if res.Complete {
			return recs, pages
		}
		qq.Cursor = res.Cursor
		if i > 1000 {
			t.Fatal("never completes")
		}
	}
}

func TestMaskedViewSemantics(t *testing.T) {
	canary := "canary@example.org"
	f := newFixture(t, genLog(t0, 1000, canary), nil)
	// Text matching inside a placeholder never matches.
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Text = "example.org" }))
	if err != nil || len(res.Records) != 0 {
		t.Fatalf("matched inside a placeholder: %v %d", err, len(res.Records))
	}
	// Clear text around placeholders matches.
	recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Text = "upstream timed out"; q.Limit = 200 }))
	if len(recs) != 1000 {
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		if strings.Contains(string(r), "@example") || strings.Contains(string(r), canary) {
			t.Fatalf("clear value in output: %s", r)
		}
	}
	// Pseudonym equality: the canary's token finds its records.
	tok := strings.TrimSpace(f.masker.Text(canary))
	if !strings.HasPrefix(tok, mask.Open) {
		t.Fatalf("token %q", tok)
	}
	got, _ := allRecords(t, f.eng, q(func(q *Query) {
		q.Regex = "for .* failed"
		q.Where = []Pred{{Field: "level", Op: "!=", Value: raw("debug")}}
	}))
	if len(got) != 1000 {
		t.Fatal(len(got))
	}
	n := 0
	for _, r := range recs {
		if strings.Contains(string(r), tok) {
			n++
		}
	}
	if n != 20 {
		t.Fatalf("canary token in %d records, want 20", n)
	}
	// Ordering on a trusted number.
	got, _ = allRecords(t, f.eng, q(func(q *Query) { q.Where = []Pred{{Field: "status", Op: ">=", Value: raw(500)}}; q.Limit = 200 }))
	if len(got) != 250 {
		t.Fatalf("status>=500: %d", len(got))
	}
	// Projection.
	res, _ = f.eng.Search(ctx, q(func(q *Query) { q.Fields = []string{"level", "msg"}; q.Limit = 1 }))
	var one map[string]any
	json.Unmarshal(res.Records[0], &one)
	if _, ok := one["fields"].(map[string]any)["status"]; ok || one["msg"] == nil || one["ref"] == nil || one["ts"] == nil {
		t.Fatalf("projection %s", res.Records[0])
	}
}

func TestCursorsContinueAndAgree(t *testing.T) {
	content := genLog(t0, 30000, "canary@example.org") // > 3 granules
	whole := newFixture(t, content, nil)
	want, _ := allRecords(t, whole.eng, q(func(q *Query) { q.Where = []Pred{{Field: "level", Op: "=", Value: raw("error")}}; q.Limit = 200 }))
	sliced := newFixture(t, content, oneGranulePerCall)
	got, pages := allRecords(t, sliced.eng, q(func(q *Query) { q.Where = []Pred{{Field: "level", Op: "=", Value: raw("error")}}; q.Limit = 200 }))
	if len(pages) < 4 {
		t.Fatalf("%d pages: deadlines did not slice the plan", len(pages))
	}
	strip := func(rs []json.RawMessage) []string {
		var out []string
		for _, r := range rs {
			var m map[string]any
			json.Unmarshal(r, &m)
			delete(m, "ref") // refs are sealed with fresh nonces
			b, _ := json.Marshal(m)
			// Each fixture has its own epoch: compare token shapes.
			out = append(out, tokenRe.ReplaceAllString(string(b), "⟦$1⟧"))
		}
		return out
	}
	if a, b := strip(got), strip(want); !slices.Equal(a, b) {
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("record %d differs:\n%s\n%s", i, a[i], b[i])
			}
		}
	}
	scanning := 0
	for _, p := range pages[:len(pages)-1] {
		if p.Complete || p.Cursor == "" {
			t.Fatalf("page %+v", p.Scanned)
		}
		if p.Scanned.Granules > 0 {
			scanning++
			if p.Scanned.Granules > 2 { // one granule, plus the short tail one when it fits
				t.Fatalf("a deadline-sliced call scanned %d granules", p.Scanned.Granules)
			}
		}
	}
	if scanning < 3 {
		t.Fatalf("%d scanning pages", scanning)
	}
}

func TestCursorRefusals(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
	qq := q(nil)
	res, err := f.eng.Search(ctx, qq)
	if err != nil || res.Complete {
		t.Fatal(err)
	}
	other := qq
	other.Text = "pdf"
	other.Cursor = res.Cursor
	if _, err := f.eng.Search(ctx, other); code(err) != EStale {
		t.Fatalf("cursor of another query: %v", err)
	}
	bad := qq
	bad.Cursor = res.Cursor[:len(res.Cursor)-2] + "AA"
	if _, err := f.eng.Search(ctx, bad); code(err) != EStale {
		t.Fatalf("forged cursor: %v", err)
	}
	f.fp = "fp2"
	qq.Cursor = res.Cursor
	if _, err := f.eng.Search(ctx, qq); code(err) != EPolicyChanged {
		t.Fatalf("policy change: %v", err)
	}
}

// TestStoppingPointsIndependentOfPredicates is the oracle v1 case: queries
// that differ only in which canary they look for stop at the same plan
// positions and report the same work.
func TestStoppingPointsIndependentOfPredicates(t *testing.T) {
	a, b := "alpha.canary@example.org", "b@example.net"
	content := genLog(t0, 30000, a)
	run := func(text string) []Scanned {
		f := newFixture(t, content, oneGranulePerCall)
		_, pages := allRecords(t, f.eng, q(func(q *Query) { q.Text = text }))
		// Pages served from the result cache do no work; the
		// scanning pages are compared.
		var out []Scanned
		for _, p := range pages {
			if p.Scanned.Granules > 0 {
				out = append(out, p.Scanned)
			}
		}
		return out
	}
	// The texts match different numbers of records (one occurs, the
	// other never), yet the plan positions are the same.
	x, y := run("order 1"), run("no such words")
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("stopping points depend on the predicate:\n%v\n%v", x, y)
	}
	for _, s := range x {
		if s.Bytes%source.GranuleBytes != 0 && s.Granules > 0 && s.Bytes > int64(len(content))%source.GranuleBytes+int64(s.Granules-1)*source.GranuleBytes {
			t.Fatalf("scanned bytes %d are not granule sums", s.Bytes)
		}
	}
	_ = b
}

// normalize renders a result for comparison: refs and cursors are opened
// (they are sealed with fresh nonces; plan and cache ids are random).
func normalize(t *testing.T, e *Engine, res any) string {
	t.Helper()
	b, _ := json.Marshal(res)
	var m map[string]any
	json.Unmarshal(b, &m)
	if c, ok := m["cursor"].(string); ok {
		var st cursorState
		if err := e.o.Sealer.Open("Lc1", c, &st); err != nil {
			t.Fatal(err)
		}
		m["cursor"] = fmt.Sprintf("chunk %d granule %d cached %v from %v to %v last %q", st.Chunk, st.Granule, st.Cache != "", st.From, st.To, st.Last)
	}
	if rs, ok := m["records"].([]any); ok {
		for _, r := range rs {
			rec := r.(map[string]any)
			var st refState
			if err := e.o.Sealer.Open("Lr1", rec["ref"].(string), &st); err != nil {
				t.Fatal(err)
			}
			rec["ref"] = st
		}
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// allPages runs a search to completion and returns its normalised pages.
func allPages(t *testing.T, e *Engine, qq Query) []string {
	t.Helper()
	_, pages := allRecords(t, e, qq)
	var out []string
	for _, p := range pages {
		out = append(out, normalize(t, e, p))
	}
	return out
}

// TestPrefilterEquivalence: the opt-in pre-filter changes nothing a call
// returns (records, counts, scanned work, completeness, cursor positions),
// whichever needle, including needles found only inside masked values; on
// a log with records masking fails on, only masked_failures differs (0 with
// the filter, see prefilter.go).
func TestPrefilterEquivalence(t *testing.T) {
	content := genLog(t0, 20000, "canary@example.org") + "time=2026-10-30T13:00:00Z level=info msg=\"caf\\u00e9 ok\"\n" +
		// Invisible runes and invalid bytes the masker drops join text.
		"time=2026-10-30T13:00:01Z level=info msg=\"ab\\u200bcd joined\"\n" +
		"{\"time\":\"2026-10-30T13:00:02Z\",\"msg\":\"x\",\"note\":\"ef\u00adgh\"}\n" +
		"time=2026-10-30T13:00:03Z level=info msg=\"ij\xffkl\"\n"
	t.Run("plain", func(t *testing.T) { prefilterEquivalence(t, newFixture(t, content, oneGranulePerCall), false) })
	t.Run("failing granule", func(t *testing.T) {
		prefilterEquivalence(t, newFixtureMask(t, boomLog(10000), withBoom, oneGranulePerCall), true)
	})
}

func prefilterEquivalence(t *testing.T, f *fixture, failing bool) {
	// noFailures drops masked_failures from a normalised search page,
	// checking that the filter reports none.
	noFailures := func(pages []string, on bool) []string {
		var out []string
		for _, p := range pages {
			var m map[string]any
			json.Unmarshal([]byte(p), &m)
			if on && m["masked_failures"] != nil {
				t.Fatalf("masked failures reported with the pre-filter: %v", m["masked_failures"])
			}
			delete(m, "masked_failures")
			b, _ := json.Marshal(m)
			out = append(out, string(b))
		}
		return out
	}
	queries := []Query{
		q(func(q *Query) { q.Text = "upstream"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "kaboom"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "order 12"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "café"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "abcd"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "efgh"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "ijkl"; q.Limit = 200 }),
		q(func(q *Query) {
			q.Where = []Pred{{Field: "msg", Op: "contains", Value: raw("timed out (order 4")}}
			q.Limit = 200
		}),
		// Found only inside masked values (the e-mails).
		q(func(q *Query) { q.Text = "example.org"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "canary"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "user1"; q.Limit = 200 }),
		q(func(q *Query) { q.Text = "no such words"; q.Limit = 200 }),
	}
	for _, qq := range queries {
		f.eng.o.Prefilter = false
		off := allPages(t, f.eng, qq)
		f.eng.o.Prefilter = true
		on := allPages(t, f.eng, qq)
		if failing {
			off, on = noFailures(off, false), noFailures(on, true)
		}
		if !slices.Equal(off, on) {
			t.Errorf("%q: the pre-filter changes the result:\n%v\n%v", qq.Text, off, on)
		}
		cq := CountQuery{Query: qq, By: []string{"level"}}
		cq.Limit = 0
		f.eng.o.Prefilter = false
		a, err := f.eng.Count(ctx, cq)
		if err != nil {
			t.Fatal(err)
		}
		f.eng.o.Prefilter = true
		b, err := f.eng.Count(ctx, cq)
		if err != nil {
			t.Fatal(err)
		}
		if x, y := normalize(t, f.eng, a), normalize(t, f.eng, b); x != y {
			t.Errorf("%q: the pre-filter changes the count:\n%s\n%s", qq.Text, x, y)
		}
	}
	if failing {
		return
	}
	f.eng.o.Prefilter = true
	// scanned.records counts every record of the plan.
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Text = "canary"; q.Limit = 200 }))
	if err != nil || res.Scanned.Records < 4000 || res.Complete {
		t.Fatalf("scanned %+v: %v", res.Scanned, err)
	}
}

// TestPrefilterMaskFailures: with the pre-filter, masked failures (and
// E_MASK) do not depend on whether the failing records' clear text holds
// the needle.
func TestPrefilterMaskFailures(t *testing.T) {
	content := genLog(t0, 100, "c@example.org") +
		"time=2026-10-30T12:05:00Z level=info msg=\"kaboom BOOM 1\"\n" +
		"time=2026-10-30T12:05:01Z level=info msg=\"kaboom BOOM 2\"\n"
	f := newFixtureMask(t, content, withBoom, func(o *Options) { o.Prefilter = true })
	var got []string
	for _, text := range []string{"kaboom", "upstream", "nowhere"} {
		res, err := f.eng.Search(ctx, q(func(q *Query) { q.Text = text }))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("failures %d scanned %+v", res.MaskedFailures, res.Scanned))
	}
	if got[0] != got[1] || got[1] != got[2] {
		t.Fatalf("failures depend on the needle: %v", got)
	}
}

func TestAdmissionBeforeData(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), func(o *Options) { o.Limits.LocalBytes = 1 << 20 })
	_, err := f.eng.Search(ctx, q(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != EOverBudget || e.Estimate == nil || e.Estimate.Granules != 4 {
		t.Fatalf("%v", err)
	}
	if *f.scans != 0 {
		t.Fatal("data touched before admission")
	}
}

func TestPagingThroughCache(t *testing.T) {
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), nil)
	recs, pages := allRecords(t, f.eng, q(func(q *Query) { q.Limit = 30 }))
	if len(recs) != 1000 || len(pages) != 34 {
		t.Fatalf("%d records in %d pages", len(recs), len(pages))
	}
	if pages[1].Scanned.Granules != 0 {
		t.Fatal("a cached page rescanned")
	}
}

func TestOutputCap(t *testing.T) {
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), func(o *Options) { o.Limits.MaxOutput = 4 << 10 })
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 200 }))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if len(b) > 6<<10 || len(res.Records) == 0 || res.Complete {
		t.Fatalf("%d bytes, %d records", len(b), len(res.Records))
	}
}

// TestNoDigestOnTheSocket: plan hashes, record digests and the policy
// fingerprint are never in a result (round-6 amendment); refs and cursors
// are opaque and keyed.
func TestNoDigestOnTheSocket(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
	f.fp = "POLICYFINGERPRINT"
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 3 }))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(res)
	var first map[string]any
	json.Unmarshal(res.Records[0], &first)
	rref, digest, err := f.eng.Ref(first["ref"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"POLICYFINGERPRINT", digest, rref.Stream} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("%q on the socket", secret)
		}
	}
	// The record digest is keyed: another key gives another digest.
	k := make([]byte, 32)
	rand.Read(k)
	s2, _ := NewSealer(k)
	if s2.Digest("locklog/record/v1", []byte("x")) == f.eng.o.Sealer.Digest("locklog/record/v1", []byte("x")) {
		t.Fatal("digest not keyed")
	}
	rec, err := f.src.Reread(ctx, rref)
	if err != nil || f.eng.RecordDigest(rec.Event.Raw) != digest {
		t.Fatal("ref does not bind the record")
	}
}

func TestCountFromIndexEqualsScan(t *testing.T) {
	// The last granule holds records the masker fails on: the index
	// counts them by their trusted values, and so must a scan.
	content := boomLog(30000)
	// A string value: numeric terms are never served from the index.
	cq := CountQuery{Query: q(func(q *Query) { q.Where = []Pred{{Field: "status", Op: "!=", Value: raw("200")}} }), Bucket: "1h", By: []string{"level"}}
	scan := newFixtureMask(t, content, withBoom, nil)
	want, err := scan.eng.Count(ctx, cq)
	if err != nil || !want.Complete || want.FromIndex == false && want.Scanned.Granules == 0 {
		t.Fatalf("%v %+v", err, want.Scanned)
	}
	// Cold: nothing indexed — the residual is the whole plan.
	if !want.FromIndex || want.IndexedFrom != nil {
		t.Fatalf("cold count: from_index %v indexed_from %v", want.FromIndex, want.IndexedFrom)
	}
	if want.MaskedFailures != 3 || total(want.Groups) != 22503 {
		t.Fatalf("cold count: %d records, %d masked failures", total(want.Groups), want.MaskedFailures)
	}
	ix := newFixtureMask(t, content, withBoom, nil)
	for i := 0; ; i++ {
		got, err := ix.eng.Count(ctx, cq)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(strip(got.Groups), strip(want.Groups)) {
			t.Fatalf("step %d: index + scan differs from scan:\n%v\n%v", i, strip(got.Groups), strip(want.Groups))
		}
		if got.Scanned.Granules == 0 {
			if got.IndexedFrom == nil || !got.IndexedFrom.Equal(t0) {
				t.Fatalf("fully indexed from %v", got.IndexedFrom)
			}
			break
		}
		if _, _, err := ix.src.IndexStep(ctx, 1<<20, true); err != nil {
			t.Fatal(err)
		}
		if i > 10 {
			t.Fatal("never fully indexed")
		}
	}
	// A count with text cannot use the index; it withholds the records
	// masking failed on (a masked predicate cannot be evaluated on
	// them) and reports them.
	cq.Text = "upstream"
	got, _ := ix.eng.Count(ctx, cq)
	if got.FromIndex || got.Scanned.Granules == 0 {
		t.Fatal("text count served from the index")
	}
	if total(got.Groups) != total(want.Groups)-3 || got.MaskedFailures != 3 {
		t.Fatalf("text count: %d records, %d masked failures", total(got.Groups), got.MaskedFailures)
	}
}

func total(gs []Group) int64 {
	var n int64
	for _, g := range gs {
		n += g.N
	}
	return n
}

func strip(gs []Group) []string {
	var out []string
	for _, g := range gs {
		k := ""
		for _, v := range g.Key {
			if v != nil {
				k += *v
			}
		}
		out = append(out, fmt.Sprintf("%s %s %d", g.Bucket.Format(time.RFC3339), k, g.N))
	}
	return out
}

func TestCalibration(t *testing.T) {
	f := newFixture(t, "x\n", nil)
	p, _ := parse.New(parse.Options{})
	c := NewCostModel(p, func(ev parse.Event) { f.masker.Mask("app", ev) }, 2, time.Now)
	ns := c.NsPerByte()
	if ns < minCostPerByte || ns > DefaultNsPerByte*10 {
		t.Fatalf("calibrated %.1f ns/byte", ns)
	}
	if b := c.Budget(time.Second); b <= 0 || c.Time(b) > time.Second+time.Millisecond {
		t.Fatalf("budget %d, time %v", b, c.Time(b))
	}
	for _, doc := range c.corpus {
		if len(doc) > parse.MaxEventBytes {
			t.Fatalf("corpus event of %d bytes over the cap", len(doc))
		}
	}
}

func TestHandle(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	res, ref, err := f.eng.Handle(ctx, MethodCount, json.RawMessage(`{"from":"2026-10-30T12:00:00Z","to":"2026-10-30T13:00:00Z","by":["level"]}`))
	if err != nil || ref != nil || len(res.(CountResult).Groups) != 3 {
		t.Fatalf("%v %v %+v", err, ref, res)
	}
	if _, ref, _ := f.eng.Handle(ctx, MethodSearch, json.RawMessage(`{"from":"2026-10-30T12:00:00Z","to":"2026-10-30T13:00:00Z","nope":1}`)); ref == nil || ref.Code != EBadQuery {
		t.Fatalf("unknown field: %v", ref)
	}
	if _, ref, _ := f.eng.Handle(ctx, "log.write", nil); ref == nil {
		t.Fatal("unknown method accepted")
	}
}

// TestCalibrationInBackground: a stale model never makes a query wait for a
// calibration, and concurrent queries start only one.
func TestCalibrationInBackground(t *testing.T) {
	p, _ := parse.New(parse.Options{})
	var calls atomic.Int32
	release := make(chan struct{})
	c := &CostModel{nsPerByte: 7, now: time.Now, parser: p, corpus: []string{"x"}, workers: 1,
		mask: func(parse.Event) { calls.Add(1); <-release }}
	// at is zero: stale.
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ns := c.NsPerByte(); ns != 7 {
				t.Errorf("ns %v", ns)
			}
			c.Recalibrate()
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("queries waited %v for a calibration", d)
	}
	close(release)
	for deadline := time.Now().Add(5 * time.Second); c.running.Load(); {
		if time.Now().After(deadline) {
			t.Fatal("calibration never finished")
		}
		time.Sleep(time.Millisecond)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d calibrations ran", n)
	}
}

// TestNumericTermsColdEqualsIndexed: numbers compare by exact value in the
// evaluator; the index holds raw literals, so numeric terms are never pushed
// down nor served from it, and cold and indexed answers agree.
func TestNumericTermsColdEqualsIndexed(t *testing.T) {
	content := genLog(t0, 10000, "c@example.org") // 3 granules
	type tc struct {
		name string
		pred Pred
		want int
	}
	var cases []tc
	for _, lit := range []string{"200", "200.0", "2e2"} {
		cases = append(cases,
			tc{"= " + lit, Pred{Field: "status", Op: "=", Value: json.RawMessage(lit)}, 2500},
			tc{"in " + lit, Pred{Field: "status", Op: "in", Value: json.RawMessage("[" + lit + ", 3e2]")}, 5000},
			tc{"!= " + lit, Pred{Field: "status", Op: "!=", Value: json.RawMessage(lit)}, 7500})
	}
	f := newFixture(t, content, nil)
	answers := func() map[string][2]int {
		out := map[string][2]int{}
		for _, c := range cases {
			recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Where = []Pred{c.pred}; q.Limit = 200; q.Fields = []string{"status"} }))
			res, err := f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Where = []Pred{c.pred} })})
			for err == nil && !res.Complete {
				t.Fatalf("%s: count incomplete", c.name)
			}
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, g := range res.Groups {
				n += int(g.N)
			}
			out[c.name] = [2]int{len(recs), n}
		}
		return out
	}
	cold := answers()
	for i := 0; ; i++ {
		_, done, err := f.src.IndexStep(ctx, 64<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		if done || i > 20 {
			break
		}
	}
	indexed := answers()
	for _, c := range cases {
		if cold[c.name] != [2]int{c.want, c.want} || indexed[c.name] != cold[c.name] {
			t.Errorf("%s: cold %v, indexed %v, want %d", c.name, cold[c.name], indexed[c.name], c.want)
		}
	}
}

// errSource injects source errors.
type errSource struct {
	countingSource
	plan, scan, count func() error
}

func (s errSource) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	if s.plan != nil {
		if err := s.plan(); err != nil {
			return source.Byteplan{}, err
		}
	}
	return s.countingSource.Plan(ctx, r, sel)
}

func (s errSource) Scan(ctx context.Context, ch source.Chunk) (source.Iterator, error) {
	if s.scan != nil {
		if err := s.scan(); err != nil {
			return nil, err
		}
	}
	return s.countingSource.Scan(ctx, ch)
}

func (s errSource) IndexCounts(ctx context.Context, cq source.CountQuery) (source.CountResult, error) {
	if s.count != nil {
		if err := s.count(); err != nil {
			return source.CountResult{}, err
		}
	}
	return s.countingSource.IndexCounts(ctx, cq)
}

// TestSourceErrorsAreContentFree: errors of sources (which may name files)
// reach the agent as fixed messages of their class only.
func TestSourceErrorsAreContentFree(t *testing.T) {
	const secret = "/srv/customer-acme/billing"
	pathErr := func() error {
		return fmt.Errorf("file source: %w", &fs.PathError{Op: "open", Path: secret + "/app.log", Err: syscall.EIO})
	}
	permErr := func() error {
		return &fs.PathError{Op: "open", Path: secret + "/app.log", Err: syscall.EACCES}
	}
	staleErr := func() error { return fmt.Errorf("%s: %w", secret, source.ErrStale) }
	for name, tc := range map[string]struct {
		es    func(*errSource)
		count bool
		code  string
	}{
		"plan":       {func(s *errSource) { s.plan = pathErr }, false, ESource},
		"scan":       {func(s *errSource) { s.scan = pathErr }, false, ESource},
		"permission": {func(s *errSource) { s.scan = permErr }, false, ESource},
		"stale":      {func(s *errSource) { s.scan = staleErr }, false, EStale},
		"index":      {func(s *errSource) { s.count = pathErr }, true, ESource},
		"count scan": {func(s *errSource) { s.scan = pathErr }, true, ESource},
	} {
		f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
		es := errSource{countingSource: f.eng.o.Sources["app"].(countingSource)}
		tc.es(&es)
		f.eng.o.Sources["app"] = es
		var err error
		if tc.count {
			_, err = f.eng.Count(ctx, CountQuery{Query: q(nil), By: []string{"level"}})
		} else {
			_, err = f.eng.Search(ctx, q(nil))
		}
		var e *Error
		if !errors.As(err, &e) || e.Code != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
			continue
		}
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "customer-acme") || strings.Contains(e.Error(), "/srv") {
			t.Errorf("%s: path in the agent's error: %s", name, b)
		}
	}
}

// TestLastCursorsContinue: a query by last keeps the window resolved at its
// first call; continuations made while the clock moves continue it.
func TestLastCursorsContinue(t *testing.T) {
	content := genLog(t0, 30000, "c@example.org") // 8h20m, 4 granules
	f := newFixture(t, content, oneGranulePerCall)
	now := t0.Add(3 * time.Hour)
	f.eng.o.Now = func() time.Time { now = now.Add(time.Minute); return now }
	// [t0+1h, t0+3h) once resolved: 7200 records.
	qq := Query{Last: "2h", Limit: 200, Fields: []string{"level"}}
	n, pages := 0, 0
	for {
		res, err := f.eng.Search(ctx, qq)
		if err != nil {
			t.Fatalf("search page %d: %v", pages, err)
		}
		n += len(res.Records)
		pages++
		if res.Complete {
			break
		}
		qq.Cursor = res.Cursor
	}
	if want := 7200; n != want || pages < 3 {
		t.Fatalf("search: %d records in %d pages, want %d", n, pages, want)
	}
	cq := CountQuery{Query: Query{Last: "2h", Text: "upstream"}, By: []string{"level"}}
	var total int64
	for pages = 0; ; pages++ {
		res, err := f.eng.Count(ctx, cq)
		if err != nil {
			t.Fatalf("count page %d: %v", pages, err)
		}
		if res.Complete {
			for _, g := range res.Groups {
				total += g.N
			}
			break
		}
		cq.Cursor = res.Cursor
	}
	if pages < 1 || total != 7200 {
		t.Fatalf("count: %d in %d continuations", total, pages)
	}
}

// TestFailedContinuationKeepsItsState: a continuation that fails leaves its
// cached page and partial count in place; retrying the cursor completes.
func TestFailedContinuationKeepsItsState(t *testing.T) {
	content := genLog(t0, 30000, "c@example.org")
	flaky := func(f *fixture) {
		calls := 0
		es := errSource{countingSource: f.eng.o.Sources["app"].(countingSource)}
		es.scan = func() error {
			calls++
			if calls == 2 {
				return errors.New("transient")
			}
			return nil
		}
		f.eng.o.Sources["app"] = es
	}
	// Search: the first page leaves matches in the cache, the
	// continuation scans more and fails.
	f := newFixture(t, content, oneGranulePerCall)
	flaky(f)
	qq := q(func(q *Query) {
		q.Where = []Pred{{Field: "level", Op: "=", Value: raw("error")}, {Field: "status", Op: "=", Value: raw(500)}}
		q.Limit = 200
		q.Fields = []string{"level"}
	})
	n, failed := 0, 0
	for i := 0; ; i++ {
		res, err := f.eng.Search(ctx, qq)
		if err != nil {
			// Retry the same cursor: its cached page is still there.
			if failed++; code(err) != ESource || failed > 1 || qq.Cursor == "" {
				t.Fatal(err)
			}
			continue
		}
		n += len(res.Records)
		if res.Complete {
			break
		}
		qq.Cursor = res.Cursor
		if i > 100 {
			t.Fatal("never completes")
		}
	}
	if failed != 1 || n != 1500 {
		t.Fatalf("search: %d records after %d failed continuations, want 1500", n, failed)
	}
	// Count: the partial aggregate survives the failed continuation.
	f = newFixture(t, content, oneGranulePerCall)
	flaky(f)
	cq := CountQuery{Query: q(func(q *Query) { q.Text = "upstream" }), By: []string{"level"}}
	c, err := f.eng.Count(ctx, cq)
	if err != nil || c.Complete {
		t.Fatal(err)
	}
	cq.Cursor = c.Cursor
	if _, err := f.eng.Count(ctx, cq); code(err) != ESource {
		t.Fatalf("injected failure: %v", err)
	}
	for i := 0; !c.Complete; i++ {
		if c, err = f.eng.Count(ctx, cq); err != nil {
			t.Fatal(err)
		}
		cq.Cursor = c.Cursor
		if i > 100 {
			t.Fatal("never completes")
		}
	}
	var total int64
	for _, g := range c.Groups {
		total += g.N
	}
	if total != 30000 {
		t.Fatalf("count: %d after a failed continuation, want 30000", total)
	}
}

// boomLog is genLog(t0, n) with three records the masker fails on in its
// last granule.
func boomLog(n int) string {
	var b strings.Builder
	b.WriteString(genLog(t0, n, "c@example.org"))
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, "time=2026-10-30T21:00:0%dZ level=error status=500 msg=\"kaboom upstream BOOM %d\"\n", i, i)
	}
	return b.String()
}

// TestMaskFailuresWithheldPerRecord: a record masking fails on is withheld
// whole and counted; every other record of its granule is answered, and no
// call is refused, so cursors always get past it.
func TestMaskFailuresWithheldPerRecord(t *testing.T) {
	f := newFixtureMask(t, boomLog(30000), withBoom, oneGranulePerCall)
	qq := q(func(q *Query) { q.Text = "upstream"; q.Limit = 200; q.Fields = []string{"level"} })
	recs, pages := allRecords(t, f.eng, qq)
	failed := 0
	for _, p := range pages {
		failed += p.MaskedFailures
	}
	if len(recs) != 30000 || failed != 3 {
		t.Fatalf("%d records, %d masked failures", len(recs), failed)
	}
	cq := CountQuery{Query: qq}
	cq.Limit = 0
	var n int64
	failed = 0
	for i := 0; ; i++ {
		res, err := f.eng.Count(ctx, cq)
		if err != nil {
			t.Fatal(err)
		}
		failed += res.MaskedFailures
		if res.Complete {
			for _, g := range res.Groups {
				n += g.N
			}
			break
		}
		cq.Cursor = res.Cursor
		if i > 100 {
			t.Fatal("never completes")
		}
	}
	if n != 30000 || failed != 3 {
		t.Fatalf("count %d with %d failures", n, failed)
	}
}

// TestLastCursorMismatch: a cursor of a query by last continues only the
// same last; another last, or the resolved from/to, is another query.
func TestLastCursorMismatch(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
	f.eng.o.Now = func() time.Time { return t0.Add(3 * time.Hour) }
	res, err := f.eng.Search(ctx, Query{Last: "2h", Limit: 200})
	if err != nil || res.Complete {
		t.Fatal(err)
	}
	for name, qq := range map[string]Query{
		"other last": {Last: "3h", Limit: 200},
		"from/to":    {From: t0.Add(time.Hour), To: t0.Add(3 * time.Hour), Limit: 200},
	} {
		qq.Cursor = res.Cursor
		if _, err := f.eng.Search(ctx, qq); code(err) != EStale {
			t.Errorf("search, %s: %v", name, err)
		}
	}
	c, err := f.eng.Count(ctx, CountQuery{Query: Query{Last: "2h", Text: "upstream"}})
	if err != nil || c.Complete {
		t.Fatal(err)
	}
	if _, err := f.eng.Count(ctx, CountQuery{Query: Query{Last: "3h", Text: "upstream", Cursor: c.Cursor}}); code(err) != EStale {
		t.Errorf("count, other last: %v", err)
	}
	if _, err := f.eng.Count(ctx, CountQuery{Query: Query{Last: "2h", Text: "upstream", Cursor: c.Cursor}}); err != nil {
		t.Errorf("count, same last: %v", err)
	}
}

// labelSource is a fake label-bearing source (as Loki): its records have a
// line field and a stream label both named env, with different values. Its
// IndexCounts answers label-only counts, as a metric query would.
type labelSource struct {
	recs []source.RawRecord
	sels *[]source.Selector
}

func (s labelSource) Name() string                                    { return "loki" }
func (s labelSource) Kind() string                                    { return "loki" }
func (s labelSource) Describe(context.Context) (source.Schema, error) { return source.Schema{}, nil }
func (s labelSource) Plan(_ context.Context, _ source.Range, sel source.Selector) (source.Byteplan, error) {
	*s.sels = append(*s.sels, sel)
	return source.Byteplan{Chunks: []source.Chunk{{Source: "loki", Stream: "s", Bytes: 4096,
		Granules: []source.Granule{{Start: 0, End: 1, Bytes: 4096}}}}}, nil
}
func (s labelSource) Scan(context.Context, source.Chunk) (source.Iterator, error) {
	return &sliceIter{recs: s.recs}, nil
}
func (s labelSource) Reread(context.Context, source.RawRef) (source.RawRecord, error) {
	return source.RawRecord{}, source.ErrStale
}
func (s labelSource) Around(context.Context, source.RawRef, int, int) ([]source.RawRecord, error) {
	return nil, source.ErrStale
}
func (s labelSource) IndexCounts(_ context.Context, q source.CountQuery) (source.CountResult, error) {
	*s.sels = append(*s.sels, q.Selector)
	if len(q.By) > 0 {
		return source.CountResult{}, source.ErrNotIndexable
	}
	for _, t := range q.Selector.Terms {
		if !t.Label {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	rows := map[string]*source.CountRow{}
	var res source.CountResult
	for _, r := range s.recs {
		labels := map[string]string{}
		for _, a := range r.Event.Attrs {
			labels[a.Key] = a.Value.Str
		}
		if !q.Range.Contains(r.Event.Time) || !q.Selector.Match(nil, labels) {
			continue
		}
		var vals []string
		for _, l := range q.ByLabels {
			vals = append(vals, labels[l])
		}
		k := strings.Join(vals, "|")
		if rows[k] == nil {
			rows[k] = &source.CountRow{Bucket: q.Range.From, Vals: vals}
		}
		rows[k].N++
	}
	for _, r := range rows {
		res.Rows = append(res.Rows, *r)
	}
	return res, nil
}

type sliceIter struct {
	recs []source.RawRecord
	i    int
}

func (it *sliceIter) Next() (source.RawRecord, error) {
	if it.i >= len(it.recs) {
		return source.RawRecord{}, io.EOF
	}
	it.i++
	return it.recs[it.i-1], nil
}
func (it *sliceIter) Processed() int64 { return 4096 }
func (it *sliceIter) Close() error     { return nil }

// TestLabelsAndFieldsAreSeparate: a label predicate or group reads the
// source's labels, a field one the line's fields, whether the search or
// count is answered by a scan or by the source's index; pushed terms keep
// the distinction.
func TestLabelsAndFieldsAreSeparate(t *testing.T) {
	f := newFixture(t, "x\n", nil)
	p, _ := parse.New(parse.Options{})
	var recs []source.RawRecord
	for i := 0; i < 60; i++ {
		ts := t0.Add(time.Duration(i) * time.Minute)
		ev := p.Line(fmt.Sprintf("time=%s env=f%d msg=\"hello %d\"", ts.Format(time.RFC3339), i%2, i))
		ev.Attrs = []parse.Member{{Key: "env", Value: parse.Value{Kind: parse.KindString, Str: fmt.Sprintf("l%d", i%3)}}}
		recs = append(recs, source.RawRecord{Ref: source.RawRef{Source: "loki", Stream: "s", Offset: int64(i)}, Event: ev})
	}
	var sels []source.Selector
	o := f.eng.o
	o.Sources = map[string]source.Source{"loki": labelSource{recs: recs, sels: &sels}}
	o.Trusted = func(_, name string, label bool) bool { return label && name == "env" }
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	search := func(p Pred) int {
		recs, _ := allRecords(t, eng, q(func(q *Query) { q.Where = []Pred{p}; q.Limit = 200 }))
		return len(recs)
	}
	if n := search(Pred{Label: "env", Op: "=", Value: raw("l0")}); n != 20 {
		t.Fatalf("label search: %d", n)
	}
	if !sels[len(sels)-1].Terms[0].Label {
		t.Fatal("a label predicate was pushed as a field term")
	}
	if n := search(Pred{Field: "env", Op: "=", Value: raw("f0")}); n != 30 {
		t.Fatalf("field search: %d", n)
	}
	// Only the label env is trusted: the field env is not pushed at all.
	if len(sels[len(sels)-1].Terms) != 0 {
		t.Fatalf("an untrusted field predicate was pushed: %+v", sels[len(sels)-1].Terms)
	}
	count := func(cq CountQuery) ([]string, bool) {
		res, err := eng.Count(ctx, cq)
		if err != nil || !res.Complete {
			t.Fatalf("%v %v", err, res.Complete)
		}
		return strip(res.Groups), res.Scanned.Granules == 0
	}
	lab := CountQuery{Query: q(func(q *Query) { q.Where = []Pred{{Label: "env", Op: "in", Value: raw([]string{"l0", "l1"})}} }), ByLabels: []string{"env"}}
	fromIndex, indexed := count(lab)
	lab.Text = "hello" // not trusted-only: scanned
	scanned, scanOnly := count(lab)
	want := []string{t0.Format(time.RFC3339) + " l0 20", t0.Format(time.RFC3339) + " l1 20"}
	if !indexed || scanOnly || !slices.Equal(fromIndex, want) || !slices.Equal(scanned, want) {
		t.Fatalf("label count: index %v (%v), scan %v (%v)", fromIndex, indexed, scanned, !scanOnly)
	}
	// A field group is not a label: the source cannot count it, the
	// scan groups on the line field.
	byField, indexed := count(CountQuery{Query: q(func(q *Query) { q.Where = []Pred{{Label: "env", Op: "=", Value: raw("l0")}} }), By: []string{"env"}})
	if indexed || !slices.Equal(byField, []string{t0.Format(time.RFC3339) + " f0 10", t0.Format(time.RFC3339) + " f1 10"}) {
		t.Fatalf("field count: %v (index %v)", byField, indexed)
	}
}

// TestTrustedLabelDoesNotTrustField: a trusted label never makes the line
// field of the same name trusted. A count by that field is not trusted-only,
// so a record masking fails on is left out rather than counted by its raw,
// untrusted value (which would reach the agent in clear).
func TestTrustedLabelDoesNotTrustField(t *testing.T) {
	content := "time=2026-10-30T12:00:00Z level=info env=customer-acme-1 msg=\"ok 1\"\n" +
		"time=2026-10-30T12:00:01Z level=info env=customer-acme-2 msg=\"ok 2\"\n" +
		"time=2026-10-30T12:00:02Z level=info env=customer-acme-0 msg=\"kaboom BOOM\"\n"
	f := newFixtureMask(t, content, func(o *mask.Options) {
		withBoom(o)
		o.Structured = mask.StructuredRedactUnknown
	}, func(o *Options) {
		o.Trusted = func(_, name string, label bool) bool {
			return label && name == "env" || !label && (name == "level" || name == "status")
		}
	})
	res, err := f.eng.Count(ctx, CountQuery{Query: q(nil), By: []string{"env"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range strip(res.Groups) {
		if strings.Contains(g, "customer-acme") {
			t.Fatalf("an untrusted field value reached the agent: %v", strip(res.Groups))
		}
	}
	if res.MaskedFailures != 1 {
		t.Fatalf("masked failures %d, want 1 (groups %v)", res.MaskedFailures, strip(res.Groups))
	}
}

// TestDecodeRefusalEchoesNothing: a params decode error never quotes what
// the agent wrote, not even masked (a pseudonym of a guessed value would
// tell whether it is in the logs).
func TestDecodeRefusalEchoesNothing(t *testing.T) {
	f := newFixture(t, genLog(t0, 10, "c@example.org"), nil)
	for _, p := range []string{
		`{"jane.doe@example.com":1}`,
		`{"from":"jane.doe@example.com"}`,
		`{"limit":"jane.doe@example.com"}`,
		`{"from":`,
	} {
		_, ref, err := f.eng.Handle(ctx, MethodSearch, json.RawMessage(p))
		if err != nil || ref == nil || ref.Code != EBadQuery {
			t.Fatalf("%s: %v %v", p, ref, err)
		}
		if b, _ := json.Marshal(ref); strings.Contains(string(b), "⟦") || strings.Contains(string(b), "jane") {
			t.Fatalf("%s: the refusal echoes the agent's text: %s", p, b)
		}
	}
}

// TestCacheNeverCutsMatches: matches the page cache cannot keep refuse the
// call (narrow the query) instead of being lost while the search reports
// complete.
func TestCacheNeverCutsMatches(t *testing.T) {
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), nil)
	f.eng.cache = newResultCache(100 << 10)
	_, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 30 }))
	var e *Error
	if !errors.As(err, &e) || e.Code != EOverBudget {
		t.Fatalf("a call with more matches than the cache holds: %v", err)
	}
	// One that fits pages through every match.
	f.eng.cache = newResultCache(1 << 20)
	if recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Limit = 30 })); len(recs) != 1000 {
		t.Fatalf("%d records", len(recs))
	}
}

// TestAmbiguousTrustedValuesScanned: a repeated key or an array at a
// trusted path is unknown to the index (never pruned nor counted by it), so
// index and scan give the same answers.
func TestAmbiguousTrustedValuesScanned(t *testing.T) {
	content := genLog(t0, 50, "c@example.org") +
		"{\"time\":\"2026-10-30T12:30:00Z\",\"level\":[\"fatal\"],\"msg\":\"array\"}\n" +
		"time=2026-10-30T12:31:00Z level=info level=fatal msg=\"dup\"\n"
	f := newFixture(t, content, nil)
	sq := q(func(q *Query) { q.Where = []Pred{{Field: "level", Op: "=", Value: raw("fatal")}}; q.Limit = 200 })
	cq := CountQuery{Query: sq, By: []string{"level"}}
	cq.Limit = 0
	before, _ := allRecords(t, f.eng, sq)
	cb, err := f.eng.Count(ctx, cq)
	if err != nil {
		t.Fatal(err)
	}
	f.indexAll()
	after, _ := allRecords(t, f.eng, sq)
	ca, err := f.eng.Count(ctx, cq)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 || len(after) != 2 {
		t.Fatalf("search: %d unindexed, %d indexed, want 2", len(before), len(after))
	}
	if x, y := strip(cb.Groups), strip(ca.Groups); !slices.Equal(x, y) {
		t.Fatalf("count: unindexed %v, indexed %v", x, y)
	}
}

func (f *fixture) indexAll() {
	f.t.Helper()
	for i := 0; ; i++ {
		_, done, err := f.src.IndexStep(ctx, 64<<20, true)
		if err != nil {
			f.t.Fatal(err)
		}
		if done || i > 20 {
			return
		}
	}
}

// TestDottedKeysReadAlike: the scan (leaves) and the index (index.Value)
// read a dotted path the same way, a key holding dots at any level
// included (docker's attrs "com.docker.compose.service").
func TestDottedKeysReadAlike(t *testing.T) {
	f := newFixture(t, "x\n", nil)
	p, _ := parse.New(parse.Options{})
	str := func(s string) parse.Value { return parse.Value{Kind: parse.KindString, Str: s} }
	obj := func(ms ...parse.Member) parse.Value { return parse.Value{Kind: parse.KindObject, Members: ms} }
	ev := p.Line(`{"k8s.app":{"name":"web"},"a":{"b.c":{"d":"x"}},"level":"info","msg":"m"}`)
	ev.Attrs = []parse.Member{{Key: "attrs", Value: obj(parse.Member{Key: "com.docker.compose.service", Value: str("shop")})}}
	rec := f.masker.Mask("app", ev)
	for _, c := range []struct {
		path  string
		label bool
		want  string
	}{
		{"k8s.app.name", false, "web"},
		{"a.b.c.d", false, "x"},
		{"level", false, "info"},
		{"attrs.com.docker.compose.service", true, "shop"},
		{"attrs.com.docker", true, index.Absent},
	} {
		fs := rec.Fields()
		if c.label {
			fs = rec.Attrs()
		}
		got := leaves(fs, c.path)
		iv := index.Value(ev, index.TermKey(c.path, c.label))
		if iv != c.want {
			t.Errorf("%s: index %q, want %q", c.path, iv, c.want)
		}
		if c.want == index.Absent {
			if len(got) != 0 {
				t.Errorf("%s: scan %v, want none", c.path, got)
			}
			continue
		}
		if len(got) != 1 || got[0].text != c.want {
			t.Errorf("%s: scan %v, want %q", c.path, got, c.want)
		}
	}
}

// TestScannedCountKeepsRemoteRange: a trusted-only count on a remote source
// with counts that is scanned instead (a bucket off whole minutes, a query
// its counts cannot answer) keeps the remote range.
func TestScannedCountKeepsRemoteRange(t *testing.T) {
	f := newFixture(t, "x\n", nil)
	var sels []source.Selector
	o := f.eng.o
	o.Sources = map[string]source.Source{"loki": labelSource{sels: &sels}}
	o.Trusted = func(_, name string, label bool) bool { return label && name == "env" }
	o.Now = func() time.Time { return t0.Add(30 * 24 * time.Hour) }
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	long := Query{From: t0, To: t0.Add(20 * 24 * time.Hour)}
	if _, err := eng.Count(ctx, CountQuery{Query: long, ByLabels: []string{"env"}}); err != nil {
		t.Fatalf("served by the source's counts: %v", err)
	}
	for _, cq := range []CountQuery{
		{Query: long, ByLabels: []string{"env"}, Bucket: "30m30s"},
		{Query: long, By: []string{"env"}},
	} {
		_, err := eng.Count(ctx, cq)
		var e *Error
		if !errors.As(err, &e) || e.Code != EOverBudget {
			t.Fatalf("%+v: a scanned 20-day remote count: %v", cq, err)
		}
	}
}

// TestHugeExponentsAreNotNumbers: a number literal beyond the bounds is not
// parsed (its cost grows with the exponent, and log content chooses it).
func TestHugeExponentsAreNotNumbers(t *testing.T) {
	for _, n := range []string{"1e999999", "0x1p9999999", "1p9999999", "0x1p-9999999", "1/3", "0o17", "0b1", "1_000", "+1", ".5", "01"} {
		if _, ok := parseNumber(n); ok {
			t.Fatalf("%s parsed", n)
		}
	}
	for _, n := range []string{"0", "-1", "200", "2.5", "1e400", "-3.25E-7"} {
		if _, ok := parseNumber(n); !ok {
			t.Fatalf("%s not parsed", n)
		}
	}
	if n, ok := parseNumber("2.5e3"); !ok || n.FloatString(0) != "2500" {
		t.Fatal(n, ok)
	}
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "{\"time\":\"2026-10-30T12:%02d:%02dZ\",\"n\":1e999999,\"msg\":\"m\"}\n", i/60, i%60)
	}
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "{\"time\":\"2026-10-30T13:%02d:%02dZ\",\"status\":\"0x1p9999999\",\"msg\":\"m\"}\n", i/60, i%60)
	}
	f := newFixture(t, b.String(), nil)
	start := time.Now()
	recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Where = []Pred{{Field: "n", Op: "=", Value: raw(200)}} }))
	// A hex string in a trusted field is not the number 2^9999999.
	gt, _ := allRecords(t, f.eng, q(func(q *Query) { q.Where = []Pred{{Field: "status", Op: ">", Value: raw(200)}} }))
	if len(recs) != 0 || len(gt) != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("%d, %d records in %v", len(recs), len(gt), time.Since(start))
	}
}

// TestInMatchesEqual: the in predicate's set lookup answers as comparing
// value by value would, numbers by exact value, text by text.
func TestInMatchesEqual(t *testing.T) {
	p := &Pred{Field: "v", Op: OpIn}
	for _, r := range []string{`1`, `2.50`, `"3"`, `"x"`, `1e2`, `"⟦email:ABC⟧"`} {
		s, n, err := scalarValue(json.RawMessage(r))
		if err != nil {
			t.Fatal(err)
		}
		p.vals, p.nums = append(p.vals, s), append(p.nums, n)
	}
	for _, v := range []val{
		{mask.Number, "1"}, {mask.Number, "1.0"}, {mask.Number, "2.5"}, {mask.Number, "100"}, {mask.Number, "3"},
		{mask.String, "3"}, {mask.String, "1"}, {mask.String, "x"}, {mask.String, "⟦email:ABC⟧"}, {mask.Number, "4"},
		{mask.String, "2.5"}, {mask.Number, "0x1p3"}, {mask.Object, ""}, {mask.Bool, "true"},
	} {
		want := false
		for i := range p.vals {
			want = want || equal(p, i, v)
		}
		if got := p.inMatch(v); got != want {
			t.Errorf("%+v: in %v, value by value %v", v, got, want)
		}
	}
}

// TestNumericInOnLongArrays: an in predicate with many numeric values on
// records with long numeric arrays stays linear in the leaves.
func TestNumericInOnLongArrays(t *testing.T) {
	var b strings.Builder
	for r := 0; r < 4; r++ {
		fmt.Fprintf(&b, "{\"time\":\"2026-10-30T12:00:0%dZ\",\"v\":[", r)
		for i := 0; i < 5000; i++ {
			b.WriteString("1,")
		}
		b.WriteString("2],\"msg\":\"m\"}\n")
	}
	f := newFixture(t, b.String(), nil)
	vals := make([]int, 64)
	for i := range vals {
		vals[i] = 1000 + i
	}
	vals[63] = 2
	var preds []Pred
	for i := 0; i < 32; i++ {
		preds = append(preds, Pred{Field: "v", Op: OpIn, Value: raw(vals)})
	}
	before := numberParses.Load()
	recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Where = preds }))
	// Each leaf is parsed at most once per predicate (never once per
	// value): leaves × predicates, plus the predicates' own values.
	parses, bound := numberParses.Load()-before, int64(4*5001*32+32*64)
	if len(recs) != 4 || parses > bound {
		t.Fatalf("%d records, %d number parses (bound %d)", len(recs), parses, bound)
	}
}

// heavyRecords returns n records each holding a v array of leaves strings
// of "ab ab …", the last one ending in "ab END".
func heavyRecords(n, leaves int) string {
	var b strings.Builder
	item := strings.TrimSpace(strings.Repeat("ab ", 6))
	for r := 0; r < n; r++ {
		fmt.Fprintf(&b, "{\"time\":\"2026-10-30T12:00:%02dZ\",\"v\":[", r)
		for i := 0; i < leaves-1; i++ {
			b.WriteString("\"" + item + "\",")
		}
		b.WriteString("\"ab END\"],\"msg\":\"m\"}\n")
	}
	return b.String()
}

// heavyPreds are 31 regexes matching only the last leaf of heavyRecords and
// one matching none: every leaf is evaluated by every predicate.
func heavyPreds() []Pred {
	const g = "[ab ]{1,100}[ab ]{1,100}[ab ]{1,100}"
	var preds []Pred
	for i := 0; i < 31; i++ {
		preds = append(preds, Pred{Field: "v", Op: OpMatches, Value: raw(fmt.Sprintf("%s(E|q%d)ND", g, i))})
	}
	return append(preds, Pred{Field: "v", Op: OpMatches, Value: raw(g + "ENDZ")})
}

// TestEvalDeadlineInsideRecords: predicates costing seconds per record
// stop at the hard deadline (checked within a record), not after the work.
func TestEvalDeadlineInsideRecords(t *testing.T) {
	// The work takes over 5 s (much more under the race detector, which
	// also slows masking: the deadline is scaled with it).
	d := time.Second
	if raceEnabled {
		d = 4 * time.Second
	}
	// Masking without value detectors: the cost is the evaluation's.
	f := newFixtureMask(t, heavyRecords(12, 2400), func(o *mask.Options) { o.Values = nil },
		func(o *Options) { o.Limits.Deadline = d })
	start := time.Now()
	_, err := f.eng.Search(ctx, q(func(q *Query) { q.Where = heavyPreds() }))
	if took := time.Since(start); code(err) != EOverBudget || took > 3*d {
		t.Fatalf("search: %v after %v", err, took)
	}
	start = time.Now()
	_, err = f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Where = heavyPreds() })})
	if took := time.Since(start); code(err) != EOverBudget || took > 3*d {
		t.Fatalf("count: %v after %v", err, took)
	}
	// Cancellation is seen within a record too.
	f.eng.o.Limits.Deadline = 10 * time.Minute
	cctx, cancel := context.WithTimeout(ctx, d/2)
	defer cancel()
	start = time.Now()
	_, err = f.eng.Search(cctx, q(func(q *Query) { q.Where = heavyPreds() }))
	if took := time.Since(start); err == nil || took > 2*d {
		t.Fatalf("cancelled: %v after %v", err, took)
	}
}

// TestRegexSizeBounds: large repetition counts and expanded sizes are
// refused; bounded patterns are taken.
func TestRegexSizeBounds(t *testing.T) {
	f := newFixture(t, genLog(t0, 10, "c@example.org"), nil)
	for re, want := range map[string]string{
		"[ab ]{1,250}END":      EBadQuery,
		"a{101}":               EBadQuery,
		"(a{50}){50}":          EBadQuery,
		"(((ab){10}){10}){10}": EBadQuery,
		"[ab ]{1,100}END":      "",
		"(ab){10}x{3,}":        "",
		"upstream|timeout":     "",
	} {
		_, err := f.eng.Search(ctx, q(func(q *Query) { q.Regex = re }))
		if code(err) != want {
			t.Errorf("regex %q: %v, want %q", re, err, want)
		}
		_, err = f.eng.Search(ctx, q(func(q *Query) { q.Where = []Pred{{Field: "msg", Op: OpMatches, Value: raw(re)}} }))
		if code(err) != want {
			t.Errorf("matches %q: %v, want %q", re, err, want)
		}
	}
}

// epochMasker is a masker under another pseudonym epoch.
type epochMasker struct {
	*mask.Masker
	epoch string
}

func (m epochMasker) Epoch() string { return m.epoch }

// TestRefStaleAfterEpochChange: a ref made under another pseudonym epoch is
// refused as stale.
func TestRefStaleAfterEpochChange(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 1 }))
	if err != nil || len(res.Records) != 1 {
		t.Fatal(err)
	}
	var first map[string]any
	json.Unmarshal(res.Records[0], &first)
	ref := first["ref"].(string)
	if _, _, err := f.eng.Ref(ref); err != nil {
		t.Fatal(err)
	}
	f.eng.o.Masker = epochMasker{f.masker, "another-epoch"}
	if _, _, err := f.eng.Ref(ref); code(err) != EStale {
		t.Fatalf("ref after the epoch changed: %v", err)
	}
}

// TestCallerPredicatesUntouched: Search and Count do not write into the
// caller's predicates.
func TestCallerPredicatesUntouched(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	where := []Pred{{Field: "status", Op: OpIn, Value: raw([]int{500, 502})}, {Field: "msg", Op: OpMatches, Value: raw("up")}}
	if _, err := f.eng.Search(ctx, q(func(q *Query) { q.Where = where })); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Where = where })}); err != nil {
		t.Fatal(err)
	}
	for _, p := range where {
		if p.re != nil || p.in != nil || p.vals != nil || p.nums != nil {
			t.Fatalf("predicate written into: %+v", p)
		}
	}
}

// processedSource records the bytes its iterators processed.
type processedSource struct {
	source.Source
	n *int64
}

type processedIter struct {
	source.Iterator
	n *int64
}

func (s processedSource) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	it, err := s.Source.Scan(ctx, c)
	if err != nil {
		return nil, err
	}
	return processedIter{it, s.n}, nil
}

func (it processedIter) Close() error {
	*it.n += it.Processed()
	return it.Iterator.Close()
}

// TestUnmeasuredCompressedBudget: a compressed file never measured, planned
// by estimate, that expands beyond the call's byte budget is refused once
// the budget is processed, never buffered whole.
func TestUnmeasuredCompressedBudget(t *testing.T) {
	// About 30:1: repeated blocks, each with a random id.
	var pb strings.Builder
	block := genLog(t0, 50, "c@example.org")
	for i := 0; i < 2500; i++ {
		id := make([]byte, 96)
		rand.Read(id)
		fmt.Fprintf(&pb, "time=2026-10-30T12:30:00Z level=info msg=\"batch %x\"\n%s", id, block)
	}
	plain := pb.String()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(plain))
	w.Close()
	budget := int64(gz.Len())*10 + 1<<20
	if int64(len(plain)) < 3*budget {
		t.Fatalf("fixture: %d plain bytes (%d compressed) for a %d budget", len(plain), gz.Len(), budget)
	}
	var processed int64
	f := newFixture(t, gz.String(), func(o *Options) {
		o.Limits.LocalBytes = budget
		o.Sources["app"] = processedSource{o.Sources["app"], &processed}
	})
	if _, err := f.eng.Search(ctx, q(func(q *Query) { q.Text = "upstream" })); code(err) != EOverBudget {
		t.Fatalf("search: %v", err)
	}
	if _, err := f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Text = "upstream" })}); code(err) != EOverBudget {
		t.Fatalf("count: %v", err)
	}
	// Each call stopped about its budget (a read buffer past it).
	if processed > 2*(budget+1<<20) {
		t.Fatalf("processed %d bytes for two calls of %d", processed, budget)
	}
	// Within the budget, the same file is searched whole (masking it in
	// one group takes long under the race detector: the deadline is not
	// what this tests).
	f.eng.o.Limits.LocalBytes = 4 * int64(len(plain))
	f.eng.o.Limits.Deadline = 10 * time.Minute
	if _, err := f.eng.Search(ctx, q(func(q *Query) { q.Text = "upstream" })); err != nil {
		t.Fatalf("within the budget: %v", err)
	}
}

// TestTrustedValueMaskedInIndex: a trusted value the masker masks as a
// field (a card number in exponent form) is never shown nor matched clear
// through the index, nor accepted as a predicate value.
func TestTrustedValueMaskedInIndex(t *testing.T) {
	const card = "4.111111111111111E15"
	var b strings.Builder
	for i := 0; i < 200; i++ {
		st := "200"
		if i%10 == 0 {
			st = card
		}
		fmt.Fprintf(&b, "time=2026-10-30T12:%02d:%02dZ level=info status=%s msg=\"req %d\"\n", i/60, i%60, st, i)
	}
	f := newFixture(t, b.String(), nil)
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Fields = []string{"status"}; q.Limit = 200 }))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), card) || strings.Contains(string(out), "4111111111111111") || !strings.Contains(string(out), "⟦card:") {
		t.Fatalf("search does not mask the card: %.300s", out)
	}
	count := func() string {
		c, err := f.eng.Count(ctx, CountQuery{Query: q(nil), By: []string{"status"}})
		if err != nil {
			t.Fatal(err)
		}
		js, _ := json.Marshal(c)
		return string(js)
	}
	cold := count()
	for i := 0; ; i++ {
		_, done, err := f.src.IndexStep(ctx, 64<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		if done || i > 20 {
			break
		}
	}
	indexed := count()
	if !strings.Contains(indexed, `"from_index":true`) {
		t.Fatalf("not answered from the index: %s", indexed)
	}
	for name, js := range map[string]string{"cold": cold, "indexed": indexed} {
		if strings.Contains(js, card) || strings.Contains(js, "4111111111111111") {
			t.Fatalf("%s count shows the card clear: %s", name, js)
		}
	}
	for _, v := range []json.RawMessage{raw(card), raw("4111111111111111")} {
		_, err := f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Where = []Pred{{Field: "status", Op: OpEq, Value: v}} })})
		if code(err) != EPIIInQuery {
			t.Errorf("status = %s: %v", v, err)
		}
	}
	// An index holding the value raw (built with a Sensitive that missed
	// it) still never shows it.
	if v := f.eng.indexValue("app", "status", card); *v != mask.Redacted {
		t.Fatalf("index value shown as %q", *v)
	}
	if v := f.eng.indexValue("app", "status", "200"); *v != "200" {
		t.Fatalf("plain index value shown as %q", *v)
	}
}

// TestCountMemoryBound: a count's groups are bounded in bytes (long keys
// fold into ⟦other⟧ past MaxGroupBytes), and the partial counts kept
// between continuations in total.
func TestCountMemoryBound(t *testing.T) {
	long := strings.Repeat("x", 64<<10)
	a := newAgg()
	for i := 0; i < 1000; i++ {
		k := fmt.Sprintf("%d%s", i, long)
		a.add(t0, []*string{&k}, 1, t0, true)
	}
	if a.bytes > MaxGroupBytes || len(a.groups) >= 1000 {
		t.Fatalf("%d groups, %d bytes", len(a.groups), a.bytes)
	}
	o := Other
	if g := a.groups[groupKey(t0, []*string{&o})]; g == nil || g.N == 0 {
		t.Fatal("no ⟦other⟧ group")
	}
	var c aggCache
	for i := 0; i < maxAggs; i++ {
		c.put(a.clone())
	}
	if c.bytes > maxAggBytes || len(c.o) > maxAggBytes/int(a.bytes)+1 {
		t.Fatalf("cache: %d partial counts, %d bytes", len(c.o), c.bytes)
	}
	for len(c.o) > 0 {
		c.drop(c.o[0])
	}
	if c.bytes != 0 {
		t.Fatalf("cache bytes after dropping all: %d", c.bytes)
	}
}

// recordTimes returns the ts of every record, failing on an untimed one.
func recordTimes(t *testing.T, recs []json.RawMessage) []time.Time {
	t.Helper()
	var out []time.Time
	for _, r := range recs {
		var m struct {
			TS time.Time `json:"ts"`
		}
		if err := json.Unmarshal(r, &m); err != nil || m.TS.IsZero() {
			t.Fatalf("record without ts: %.200s", r)
		}
		out = append(out, m.TS)
	}
	return out
}

// checkOrder fails on the first record out of the query's order.
func checkOrder(t *testing.T, ts []time.Time, want int, desc bool) {
	t.Helper()
	if len(ts) != want {
		t.Fatalf("%d records, want %d", len(ts), want)
	}
	for i := 1; i < len(ts); i++ {
		if desc && ts[i].After(ts[i-1]) || !desc && ts[i].Before(ts[i-1]) {
			t.Fatalf("record %d at %v after one at %v", i, ts[i], ts[i-1])
		}
	}
}

// TestOrderAcrossCalls: pages follow the query's order across calls, for a
// descending search over a stream larger than a call (plain and
// compressed) and for an ascending one over a stream the index prunes into
// several chunks.
func TestOrderAcrossCalls(t *testing.T) {
	errors := q(func(q *Query) {
		q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
		q.Limit = 200
	})
	desc := errors
	desc.Order = "desc"
	t.Run("desc", func(t *testing.T) {
		f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
		recs, pages := allRecords(t, f.eng, desc)
		if len(pages) < 3 {
			t.Fatalf("%d pages: the stream fits one call", len(pages))
		}
		checkOrder(t, recordTimes(t, recs), 6000, true)
	})
	t.Run("desc compressed", func(t *testing.T) {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		w.Write([]byte(genLog(t0, 30000, "c@example.org")))
		w.Close()
		f := newFixture(t, gz.String(), oneGranulePerCall)
		for i := 0; ; i++ { // measured: granules of known bytes
			_, done, err := f.src.IndexStep(ctx, 64<<20, true)
			if err != nil {
				t.Fatal(err)
			}
			if done || i > 20 {
				break
			}
		}
		recs, _ := allRecords(t, f.eng, desc)
		checkOrder(t, recordTimes(t, recs), 6000, true)
	})
	t.Run("desc compressed proportionate", func(t *testing.T) {
		// Reading granules newest first re-decompresses what precedes
		// each one, charged at decompression cost: a budget of twice
		// the stream admits it as it admits an ascending read.
		plain := genLog(t0, 40000, "c@example.org")
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		w.Write([]byte(plain))
		w.Close()
		f := newFixture(t, gz.String(), func(o *Options) {
			oneGranulePerCall(o)
			o.Limits.LocalBytes = 2 * int64(len(plain))
		})
		for i := 0; ; i++ {
			_, done, err := f.src.IndexStep(ctx, 64<<20, true)
			if err != nil {
				t.Fatal(err)
			}
			if done || i > 20 {
				break
			}
		}
		recs, pages := allRecords(t, f.eng, desc)
		if len(pages) < 3 {
			t.Fatalf("%d pages: the stream fits one call", len(pages))
		}
		checkOrder(t, recordTimes(t, recs), 8000, true)
		// A count reads its plan in stream order, whatever its order.
		count := func(order string) string {
			cq := CountQuery{Query: q(func(q *Query) { q.Order = order }), By: []string{"level"}}
			var groups []Group
			for i := 0; ; i++ {
				c, err := f.eng.Count(ctx, cq)
				if err != nil {
					t.Fatalf("count %s: %v", order, err)
				}
				groups = append(groups, c.Groups...)
				if c.Complete || i > 1000 {
					break
				}
				cq.Cursor = c.Cursor
			}
			js, _ := json.Marshal(groups)
			return string(js)
		}
		if a, d := count("asc"), count("desc"); a != d {
			t.Fatalf("counts differ by order:\n%s\n%s", a, d)
		}
	})
	t.Run("asc pruned", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 45000; i++ {
			lvl := "error"
			if i >= 15000 && i < 30000 {
				lvl = "info"
			}
			fmt.Fprintf(&b, "time=%s level=%s msg=\"m %d\"\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), lvl, i)
		}
		f := newFixture(t, b.String(), oneGranulePerCall)
		for i := 0; ; i++ {
			_, done, err := f.src.IndexStep(ctx, 64<<20, true)
			if err != nil {
				t.Fatal(err)
			}
			if done || i > 20 {
				break
			}
		}
		qq := errors
		qq.To = t0.Add(48 * time.Hour)
		f.eng.o.Limits.LocalRange = 72 * time.Hour
		recs, _ := allRecords(t, f.eng, qq)
		checkOrder(t, recordTimes(t, recs), 30000, false)
		qq.Order = "desc"
		recs, _ = allRecords(t, f.eng, qq)
		checkOrder(t, recordTimes(t, recs), 30000, true)
	})
}

// unknownGranules is a local source whose granules carry no bytes (only
// their chunk's), as journald planned them before.
type unknownGranules struct{ source.Source }

func (u unknownGranules) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	p, err := u.Source.Plan(ctx, r, sel)
	for i := range p.Chunks {
		gs := slices.Clone(p.Chunks[i].Granules)
		for j := range gs {
			gs[j].Bytes = 0
		}
		p.Chunks[i].Granules = gs
	}
	return p, err
}

// TestUnknownGranuleBytesStillGrouped: granules of unknown bytes in a chunk
// of known bytes are sized by their share of it: a call takes the groups
// that fit, never the whole chunk, and order holds across calls.
func TestUnknownGranuleBytesStillGrouped(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.Sources["app"] = unknownGranules{o.Sources["app"]}
	})
	for _, order := range []string{"asc", "desc"} {
		qq := q(func(q *Query) {
			q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
			q.Limit = 200
			q.Order = order
		})
		res, err := f.eng.Search(ctx, qq)
		if err != nil || res.Complete || res.Scanned.Granules != 1 {
			t.Fatalf("%s: first call %+v, %v", order, res.Scanned, err)
		}
		recs, _ := allRecords(t, f.eng, qq)
		checkOrder(t, recordTimes(t, recs), 6000, order == "desc")
	}
}

// TestDedupRecordsBounded: journald shares one DATA object between entries,
// so records can hold far more bytes than the stream processes: a call
// buffers at most its budget of record bytes, then refuses.
func TestDedupRecordsBounded(t *testing.T) {
	frames := strings.Repeat("stack frame at service.handler(line 42) ", 5000) // ~200 KB
	for name, fields := range map[string][]string{
		"message":       {"MESSAGE=" + frames, "PRIORITY=3"},
		"trusted field": {"MESSAGE=frame x", "CODE_FUNC=" + frames, "PRIORITY=3"},
	} {
		t.Run(name, func(t *testing.T) {
			var es []journaltest.Entry
			base := uint64(t0.Add(time.Hour).UnixMicro())
			for i := 0; i < 2048; i++ {
				es = append(es, journaltest.Entry{Realtime: base + uint64(i)*1000, Fields: fields})
			}
			root := t.TempDir()
			const mid = "0123456789abcdef0123456789abcdef"
			os.Mkdir(filepath.Join(root, mid), 0o755)
			if err := os.WriteFile(filepath.Join(root, mid, "system.journal"), journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es), 0o644); err != nil {
				t.Fatal(err)
			}
			p, _ := parse.New(parse.Options{Format: "plain"})
			js, err := journald.New(journald.Options{Name: "journal", Roots: []string{root}, Parser: p})
			if err != nil {
				t.Fatal(err)
			}
			f := newFixture(t, genLog(t0, 10, "c@example.org"), func(o *Options) {
				o.Sources["journal"] = js
				o.Limits.LocalBytes = 4 << 20
			})
			start := time.Now()
			_, err = f.eng.Search(ctx, q(func(q *Query) { q.Sources = []string{"journal"}; q.Text = "frame" }))
			if code(err) != EOverBudget || time.Since(start) > 10*time.Second {
				t.Fatalf("search: %v after %v", err, time.Since(start))
			}
		})
	}
}

// TestDescCompressedTailAdmission: reading the newest granule of a large
// compressed stream decompresses all before it; a descending query whose
// granule cannot be read within the byte budget is refused at admission,
// as the ascending one is, before reading anything.
func TestDescCompressedTailAdmission(t *testing.T) {
	start := t0.Add(-30 * time.Hour)
	plain := genLog(start, 120000, "c@example.org") // ~14 MiB, 33 h
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(plain))
	w.Close()
	var processed int64
	f := newFixture(t, gz.String(), func(o *Options) {
		o.Sources["app"] = processedSource{o.Sources["app"], &processed}
		o.Limits.LocalBytes = 4 << 20
	})
	for i := 0; ; i++ {
		_, done, err := f.src.IndexStep(ctx, 64<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		if done || i > 40 {
			break
		}
	}
	end := start.Add(120000 * time.Second)
	for _, order := range []string{"asc", "desc"} {
		processed = 0
		_, err := f.eng.Search(ctx, Query{From: end.Add(-5 * time.Hour), To: end, Text: "upstream", Order: order})
		if code(err) != EOverBudget || processed != 0 {
			t.Errorf("%s: %v, %d bytes processed", order, err, processed)
		}
	}
	// The head of the stream is read either way.
	for _, order := range []string{"asc", "desc"} {
		if _, err := f.eng.Search(ctx, Query{From: start, To: start.Add(10 * time.Minute), Text: "upstream", Order: order}); err != nil {
			t.Errorf("%s head: %v", order, err)
		}
	}
}

// remoteSlices is a fake remote source (as Loki): its plan is one chunk of
// n time slices of unknown bytes, each holding per records of about 1 KiB
// (the first of each at level error); its iterators count the bytes of the
// records they yield, as they yield them, and fail with source.ErrByteLimit
// past the byte limit of their context (as the Loki source does).
type remoteSlices struct {
	n, per int
	p      *parse.Parser
	mu     sync.Mutex
	// limits are the byte limits the scans' contexts carried, processed
	// the bytes each scan processed.
	limits    []int64
	processed []int64
}

func (s *remoteSlices) Name() string                                    { return "rem" }
func (s *remoteSlices) Kind() string                                    { return "loki" }
func (s *remoteSlices) Describe(context.Context) (source.Schema, error) { return source.Schema{}, nil }
func (s *remoteSlices) Plan(_ context.Context, r source.Range, _ source.Selector) (source.Byteplan, error) {
	w := r.To.Sub(r.From) / time.Duration(s.n)
	var gs []source.Granule
	for i := 0; i < s.n; i++ {
		from := r.From.Add(time.Duration(i) * w)
		gs = append(gs, source.Granule{Start: from.UnixNano(), End: from.Add(w).UnixNano(), From: from, To: from.Add(w)})
	}
	return source.Byteplan{Chunks: []source.Chunk{{Source: "rem", Stream: "s", Granules: gs}}}, nil
}

func (s *remoteSlices) records(g source.Granule) []source.RawRecord {
	var out []source.RawRecord
	step := (g.End - g.Start) / int64(s.per)
	for j := 0; j < s.per; j++ {
		ts := time.Unix(0, g.Start+int64(j)*step).UTC()
		lvl := "info"
		if j == 0 {
			lvl = "error"
		}
		ev := s.p.Line(fmt.Sprintf("time=%s level=%s msg=\"slice %d record %d\" pad=%s", ts.Format(time.RFC3339Nano), lvl, g.Start, j, strings.Repeat("x", 1000)))
		ev.SetTime(ts)
		out = append(out, source.RawRecord{Ref: source.RawRef{Source: "rem", Stream: "s", Offset: ts.UnixNano(), Length: int64(j + 1)}, Event: ev})
	}
	return out
}

func (s *remoteSlices) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	s.mu.Lock()
	s.limits = append(s.limits, source.ByteLimitFrom(ctx))
	s.processed = append(s.processed, 0)
	i := len(s.processed) - 1
	s.mu.Unlock()
	var recs []source.RawRecord
	for _, g := range c.Granules {
		recs = append(recs, s.records(g)...)
	}
	return &remoteIter{s: s, i: i, recs: recs, limit: source.ByteLimitFrom(ctx)}, nil
}

func (s *remoteSlices) Reread(context.Context, source.RawRef) (source.RawRecord, error) {
	return source.RawRecord{}, source.ErrStale
}
func (s *remoteSlices) Around(context.Context, source.RawRef, int, int) ([]source.RawRecord, error) {
	return nil, source.ErrStale
}

type remoteIter struct {
	s     *remoteSlices
	i     int
	recs  []source.RawRecord
	n     int64
	limit int64
}

func (it *remoteIter) Next() (source.RawRecord, error) {
	if len(it.recs) == 0 {
		return source.RawRecord{}, io.EOF
	}
	r := it.recs[0]
	it.recs = it.recs[1:]
	it.n += int64(len(r.Event.Raw))
	it.s.mu.Lock()
	it.s.processed[it.i] = it.n
	it.s.mu.Unlock()
	if it.limit > 0 && it.n > it.limit {
		return source.RawRecord{}, fmt.Errorf("fake: %w", source.ErrByteLimit)
	}
	return r, nil
}
func (it *remoteIter) Processed() int64 { return it.n }
func (it *remoteIter) Close() error     { return nil }

// TestRemoteSlicesPaged: a remote plan of many slices of unknown bytes whose
// total exceeds the call's byte budget is served in pages, each stopping on
// a slice boundary with a cursor, each scan bounded by what is left of the
// budget (never the whole plan buffered); ascending and descending.
func TestRemoteSlicesPaged(t *testing.T) {
	const n, per = 40, 16
	const budget = 64 << 10
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			p, _ := parse.New(parse.Options{})
			rem := &remoteSlices{n: n, per: per, p: p}
			f := newFixture(t, "x\n", func(o *Options) {
				o.Sources["rem"] = rem
				o.Limits.RemoteBytes = budget
			})
			sliceBytes := int64(0)
			for _, r := range rem.records(source.Granule{Start: 0, End: 1 << 30}) {
				sliceBytes += int64(len(r.Event.Raw))
			}
			if n*sliceBytes < 4*budget {
				t.Fatalf("fixture: %d bytes for a %d budget", n*sliceBytes, budget)
			}
			qq := q(func(q *Query) {
				q.Sources = []string{"rem"}
				q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
				q.Limit = 200
				q.Order = order
			})
			first, err := f.eng.Search(ctx, qq)
			if err != nil {
				t.Fatalf("first call: %v", err)
			}
			if first.Complete || first.Cursor == "" || first.Scanned.Granules < 1 || first.Scanned.Granules >= n {
				t.Fatalf("first call: complete %t, cursor %t, %+v", first.Complete, first.Cursor != "", first.Scanned)
			}
			if first.Scanned.Bytes > budget+sliceBytes || len(first.Records) != first.Scanned.Granules {
				t.Fatalf("first call: %d records, %+v", len(first.Records), first.Scanned)
			}
			// Each scan is one slice, bounded by what is left of the
			// budget; the call processed at most its budget and a slice.
			var callBytes int64
			for i, l := range rem.limits {
				if l <= 0 || l > budget || rem.processed[i] > l+sliceBytes {
					t.Fatalf("scan %d: limit %d, processed %d", i, l, rem.processed[i])
				}
				callBytes += rem.processed[i]
			}
			if callBytes > budget+2*sliceBytes {
				t.Fatalf("the call processed %d bytes for a %d budget", callBytes, budget)
			}
			ts := recordTimes(t, first.Records)
			newest := t0.Add(24 * time.Hour).Add(-24 * time.Hour / n)
			if order == "desc" && !ts[0].Equal(newest) || order == "asc" && !ts[0].Equal(t0) {
				t.Fatalf("%s: the first page starts at %v", order, ts[0])
			}
			recs, pages := allRecords(t, f.eng, qq)
			if len(pages) < 4 {
				t.Fatalf("%d pages", len(pages))
			}
			checkOrder(t, recordTimes(t, recs), n, order == "desc")
		})
	}
}
