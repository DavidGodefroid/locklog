package engine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

func TestTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"render pdf for ⟦email:7F3KQ2M9ZD4X⟧ from ⟦ip:K2M9ZDQ81RTA⟧ failed: upstream timed out": "render pdf for ⟦email:…⟧ from ⟦ip:…⟧ failed: upstream timed out",
		"order 4812 failed (attempt 3/5)":              "order <*> failed (attempt <*>/<*>)",
		"status=502 took=13ms host=10.0.0.1":           "status=<*> took=<*> host=<*>",
		"key ⟦secret⟧ and ⟦redacted⟧ for ⟦key:AB12⟧=x": "key ⟦secret⟧ and ⟦redacted⟧ for ⟦key:…⟧=x",
		"  many   blanks\tand\nlines  ":                "many blanks and lines",
		"user42@host v1.2.3 ⟦email:X⟧.":                "<*>@host <*> ⟦email:…⟧.",
		"glued⟦email:ABCD⟧tail 12⟦ip:Z⟧":               "glued⟦email:…⟧tail <*>⟦ip:…⟧",
		"broken ⟦ placeholder":                         "broken ⟦ placeholder",
		"":                                             "",
		"same words only":                              "same words only",
		"2026-10-30T14:02:11Z started":                 "<*>:<*>:<*> started",
		"\"quoted 7\" and 'single 8'":                  "\"quoted <*>\" and 'single <*>'",
		"élan 9 naïve":                                 "élan <*> naïve",
	} {
		if got := Template(in); got != want {
			t.Errorf("Template(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("w ", MaxTemplateTokens+10)
	if got := Template(long); !strings.HasSuffix(got, " "+TemplateCut) || strings.Count(got, "w") != MaxTemplateTokens {
		t.Errorf("token cap: %q", got)
	}
	wide := strings.Repeat("é", 400) + " " + strings.Repeat("ü", 400)
	if got := Template(wide); len(got) > MaxTemplateBytes+len(TemplateCut) || !strings.HasSuffix(got, TemplateCut) || !utfValid(got) {
		t.Errorf("byte cap: %d bytes", len(got))
	}
	// Idempotent: a template of a template is itself.
	for _, s := range []string{"order 4812 failed (attempt 3/5)", "for ⟦email:7F3K⟧ x=1"} {
		if Template(Template(s)) != Template(s) {
			t.Errorf("not idempotent on %q", s)
		}
	}
}

func utfValid(s string) bool { return strings.ToValidUTF8(s, "\x00") == s }

func BenchmarkTemplate(b *testing.B) {
	line := "render pdf for ⟦email:7F3KQ2M9ZD4X⟧ from ⟦ip:K2M9ZDQ81RTA⟧ failed: upstream timed out (order 4812, attempt 3/5) took=13ms"
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		Template(line)
	}
}

// patternLog writes one record a second from start: msgs in turn.
func patternLog(start time.Time, n int, msgs ...string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		m := msgs[i%len(msgs)]
		if strings.Contains(m, "%d") {
			m = fmt.Sprintf(m, i)
		}
		fmt.Fprintf(&b, "time=%s level=%s status=%d msg=%q\n", start.Add(time.Duration(i)*time.Second).Format(time.RFC3339), levels[i%len(levels)], 200+100*(i%4), m)
	}
	return b.String()
}

func allPatterns(t *testing.T, e *Engine, pq PatternsQuery) (PatternsResult, []PatternsResult) {
	t.Helper()
	var pages []PatternsResult
	for i := 0; ; i++ {
		r, err := e.Patterns(ctx, pq)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, r)
		if r.Complete {
			return r, pages
		}
		pq.Cursor = r.Cursor
		if i > 1000 {
			t.Fatal("never complete")
		}
	}
}

func TestPatternsTopAndMasked(t *testing.T) {
	canary := "alpha.canary@example.org"
	content := patternLog(t0, 600,
		"render pdf for "+canary+" failed: upstream timed out (order %d)",
		"render pdf for user%d@example.com failed: upstream timed out (order 1)",
		"cache miss for key %d",
		"cache miss for key %d",
		"started worker")
	f := newFixture(t, content, nil)
	res, err := f.eng.Patterns(ctx, PatternsQuery{Query: q(nil), Top: 2})
	if err != nil || !res.Complete {
		t.Fatalf("%v %+v", err, res)
	}
	got := fmt.Sprint(res.Patterns)
	want := "[240 cache miss for key <*> 240 render pdf for ⟦email:…⟧ failed: upstream timed out (order <*>)]"
	if got != want || res.Distinct != 3 || res.Records != 600 {
		t.Fatalf("top 2 = %s (distinct %d, records %d)", got, res.Distinct, res.Records)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "canary") || strings.Contains(string(b), "example") {
		t.Fatalf("clear value in %s", b)
	}
	if res.Patterns[0].First == nil || !res.Patterns[0].First.Equal(t0.Add(2*time.Second)) {
		t.Errorf("first = %v", res.Patterns[0].First)
	}
	// Predicates narrow what is counted.
	res, _ = f.eng.Patterns(ctx, PatternsQuery{Query: q(func(q *Query) { q.Text = "upstream" })})
	if fmt.Sprint(res.Patterns) != "[240 render pdf for ⟦email:…⟧ failed: upstream timed out (order <*>)]" {
		t.Fatalf("text-narrowed: %v", res.Patterns)
	}
}

func TestPatternsBaseline(t *testing.T) {
	// Hour 1: A and B; hour 2: A and C.
	content := patternLog(t0, 3600, "alpha %d", "beta %d", "beta again") + patternLog(t0.Add(time.Hour), 3600, "alpha %d", "gamma %d")
	f := newFixture(t, content, nil)
	w := q(func(q *Query) { q.From, q.To = t0.Add(time.Hour), t0.Add(2*time.Hour) })
	res, err := f.eng.Patterns(ctx, PatternsQuery{Query: w, Baseline: "1h"})
	if err != nil || !res.Complete {
		t.Fatalf("%v %+v", err, res)
	}
	if !res.BaselineFrom.Equal(t0) || !res.BaselineTo.Equal(t0.Add(time.Hour)) {
		t.Errorf("baseline window %v %v", res.BaselineFrom, res.BaselineTo)
	}
	desc := func(gs []PatternGroup) string {
		var out []string
		for _, g := range gs {
			out = append(out, fmt.Sprintf("%s:%d/%d", g.Pattern, g.N, *g.BaselineN))
		}
		return strings.Join(out, " ")
	}
	if got := desc(res.Patterns); got != "alpha <*>:1800/1200 gamma <*>:1800/0" {
		t.Errorf("patterns %s", got)
	}
	if got := desc(res.New); got != "gamma <*>:1800/0" {
		t.Errorf("new %s", got)
	}
	if got := desc(res.Gone); got != "beta <*>:0/1200 beta again:0/1200" {
		t.Errorf("gone %s", got)
	}
	for _, bad := range []string{"30m", "x", "-1h", "10000h"} {
		if _, err := f.eng.Patterns(ctx, PatternsQuery{Query: w, Baseline: bad}); code(err) != EBadQuery {
			t.Errorf("baseline %q: %v", bad, err)
		}
	}
	for _, top := range []int{-1, MaxTop + 1} {
		if _, err := f.eng.Patterns(ctx, PatternsQuery{Query: w, Top: top}); code(err) != EBadQuery {
			t.Errorf("top %d: %v", top, err)
		}
	}
}

// Continuations give the one-call answer; stopping points depend on the
// plan, never on what the predicates match.
func TestPatternsContinuationAndStoppingPoints(t *testing.T) {
	content := genLog(t0, 30000, "alpha.canary@example.org")
	one := newFixture(t, content, nil)
	want, err := one.eng.Patterns(ctx, PatternsQuery{Query: q(nil), Baseline: "24h"})
	if err != nil || !want.Complete || want.Records != 30000 || int(want.Scanned.Bytes) != len(content) {
		t.Fatalf("%v: %d records, %+v (a granule both plans hold is read once)", err, want.Records, want.Scanned)
	}
	run := func(text string) (PatternsResult, []Scanned) {
		f := newFixture(t, content, oneGranulePerCall)
		last, pages := allPatterns(t, f.eng, PatternsQuery{Query: q(func(q *Query) { q.Text = text }), Baseline: "24h"})
		var sc []Scanned
		for _, p := range pages {
			sc = append(sc, p.Scanned)
		}
		if len(pages) < 3 {
			t.Fatalf("%d pages: the plan is not split", len(pages))
		}
		return last, sc
	}
	got, x := run("")
	strip := func(r PatternsResult) PatternsResult {
		r.Scanned, r.Cursor, r.CoveredUntil, r.Epoch = Scanned{}, "", nil, ""
		return r
	}
	if !reflect.DeepEqual(strip(got), strip(want)) {
		t.Fatalf("continued answer differs:\n%+v\n%+v", strip(got), strip(want))
	}
	_, y := run("no such words")
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("stopping points depend on the predicate:\n%v\n%v", x, y)
	}
}

func TestCountByPatternEqualsPatterns(t *testing.T) {
	content := patternLog(t0, 900, "alpha %d", "beta", "gamma %d for ⟦x⟧") + "time=2026-10-30T12:20:00Z level=info status=200\n"
	f := newFixture(t, content, nil)
	pr, err := f.eng.Patterns(ctx, PatternsQuery{Query: q(nil)})
	if err != nil {
		t.Fatal(err)
	}
	cr, err := f.eng.Count(ctx, CountQuery{Query: q(nil), By: []string{"level"}, ByPattern: true})
	if err != nil || cr.FromIndex {
		t.Fatalf("%v from_index=%v", err, cr.FromIndex)
	}
	per := map[string]int64{}
	var noText int64
	for _, g := range cr.Groups {
		if g.Key[1] == nil {
			noText += g.N
			continue
		}
		per[*g.Key[1]] += g.N
	}
	if len(per) != len(pr.Patterns) || noText != pr.NoText || pr.NoText != 1 {
		t.Fatalf("count %v (no text %d), patterns %v (no text %d)", per, noText, pr.Patterns, pr.NoText)
	}
	for _, p := range pr.Patterns {
		if per[p.Pattern] != p.N {
			t.Errorf("%s: count %d, patterns %d", p.Pattern, per[p.Pattern], p.N)
		}
	}
	// Source brackets never forge a placeholder (U+FFFD before masking).
	if !strings.Contains(fmt.Sprint(pr.Patterns), "gamma <*> for \ufffdx\ufffd") {
		t.Errorf("patterns %v", pr.Patterns)
	}
	if _, err := f.eng.Count(ctx, CountQuery{Query: q(nil), By: []string{"level", "status"}, ByPattern: true}); code(err) != EBadQuery {
		t.Errorf("three keys: %v", err)
	}
}

func TestHandlePatterns(t *testing.T) {
	f := newFixture(t, patternLog(t0, 10, "hello %d"), nil)
	params, _ := json.Marshal(map[string]any{"from": day.From, "to": day.To, "top": 5})
	res, refusal, err := f.eng.Handle(ctx, MethodPatterns, params)
	if err != nil || refusal != nil {
		t.Fatalf("%v %v", refusal, err)
	}
	if r := res.(PatternsResult); fmt.Sprint(r.Patterns) != "[10 hello <*>]" {
		t.Fatalf("%v", r.Patterns)
	}
	if _, refusal, _ := f.eng.Handle(ctx, MethodPatterns, json.RawMessage(`{"from":"2026-10-30T12:00:00Z","to":"2026-10-30T13:00:00Z","bogus":1}`)); refusal == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestWithBaselineReadsGranulesOnce(t *testing.T) {
	g := func(a, b int64) source.Granule { return source.Granule{Start: a, End: b, Bytes: b - a} }
	win := source.Byteplan{Chunks: []source.Chunk{{Source: "s", Stream: "x", Granules: []source.Granule{g(10, 20), g(20, 30)}, Bytes: 20}}}
	base := source.Byteplan{Chunks: []source.Chunk{
		{Source: "s", Stream: "x", Granules: []source.Granule{g(0, 10), g(10, 20), g(30, 40), g(40, 50)}, Bytes: 40},
		{Source: "s", Stream: "gz", Granules: []source.Granule{g(0, 10), g(10, 20)}, Bytes: 99},
		{Source: "s", Stream: "y", Granules: []source.Granule{g(10, 20)}, Bytes: 10},
	}}
	got := withBaseline(win, base, func(c source.Chunk) bool { return c.Stream == "gz" })
	var desc []string
	for _, c := range got.Chunks {
		desc = append(desc, fmt.Sprintf("%s[%d,%d)=%d", c.Stream, c.Start(), c.End(), c.Bytes))
	}
	if want := "x[10,30)=20 x[0,10)=10 x[30,50)=20 gz[0,20)=99 y[10,20)=10"; strings.Join(desc, " ") != want {
		t.Fatalf("%s", strings.Join(desc, " "))
	}
}
