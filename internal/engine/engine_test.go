//go:build unix

package engine

import (
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
		Trusted: []string{"level", "status"}, Index: st, Sensitive: func(_, v string) bool { return m.Text(v) != v }})
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
	content := genLog(t0, 20000, "canary@example.org") + "time=2026-10-30T13:00:00Z level=info msg=\"caf\\u00e9 ok\"\n"
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
