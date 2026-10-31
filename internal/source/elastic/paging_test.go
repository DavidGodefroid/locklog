package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// padded is n documents a second apart from t0, each message pad bytes.
func padded(n, pad int) []fakeDoc {
	docs := dataset(n)
	for i := range docs {
		docs[i].ts = t0.Add(time.Duration(i) * time.Second)
		docs[i].fields["message"] = fmt.Sprintf("doc %d %s", i, strings.Repeat("x", pad))
	}
	return docs
}

// countingClient counts the requests a source starts and has in flight.
type countingClient struct {
	inner           Client
	started, active atomic.Int64
}

func (c *countingClient) Send(ctx context.Context, method, path string, q url.Values, body []byte) (egress.Response, error) {
	c.started.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.inner.Send(ctx, method, path, q, body)
}

// searchedSlices returns the distinct range starts of the searches sent.
func searchedSlices(f *fakeES) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.bodies {
		var sb SearchBody
		if strictDecode(b, &sb) != nil {
			continue
		}
		for _, c := range sb.Query.Bool.Filter {
			for _, r := range c.Range {
				if !slices.Contains(out, r.GTE) {
					out = append(out, r.GTE)
				}
			}
		}
	}
	return out
}

func TestScanFetchesLazilyAndStopsAtTheByteLimit(t *testing.T) {
	f := newFake(padded(600, 2000)) // 10 minutes: 10 slices
	cc := &countingClient{}
	s := newSource(t, f, func(o *Options) { o.InFlight = 2; cc.inner = o.Client; o.Client = cc })
	plan, err := s.Plan(ctx, source.Range{From: t0, To: t0.Add(10 * time.Minute)}, source.Selector{})
	if err != nil || len(plan.Chunks[0].Granules) != 10 {
		t.Fatalf("%v %+v", err, plan)
	}
	// Nothing read: at most InFlight slices are fetched ahead.
	it, err := s.Scan(ctx, plan.Chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(searchedSlices(f)); n > 2 || n == 0 {
		t.Fatalf("%d slices fetched before any Next", n)
	}
	if err := it.Close(); err != nil {
		t.Fatal(err)
	}
	// Close waited for the fetches: none is in flight, none starts after
	// it. (Counted on the client: the server may still log a request the
	// client already cancelled.)
	n := cc.started.Load()
	if a := cc.active.Load(); a != 0 {
		t.Fatalf("%d requests in flight after Close", a)
	}
	time.Sleep(50 * time.Millisecond)
	if cc.started.Load() != n {
		t.Fatal("a fetch started after Close")
	}

	// Under a byte limit, the scan fails with ErrByteLimit, having
	// fetched at most the limit plus a page per slice in flight.
	const limit = 64 << 10
	it, _ = s.Scan(source.WithByteLimit(ctx, limit), plan.Chunks[0])
	defer it.Close()
	recs := 0
	for {
		_, err = it.Next()
		if err != nil {
			break
		}
		recs++
	}
	if !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("%v after %d records", err, recs)
	}
	// A page: 7 hits, each message twice (fields and _source).
	if page := int64(7 * (2*2000 + 600)); it.Processed() > limit+2*page || it.Processed() <= limit {
		t.Fatalf("processed %d bytes under a limit of %d", it.Processed(), limit)
	}
	// Without a limit, every document once.
	if got := scanAll(t, s, source.Range{From: t0, To: t0.Add(10 * time.Minute)}, source.Selector{}); len(got) != 600 {
		t.Fatalf("%d records", len(got))
	}
}

func TestAroundIsBounded(t *testing.T) {
	f := newFake(padded(600, 2000))
	s := newSource(t, f, nil)
	recs := scanAll(t, s, source.Range{From: t0, To: t0.Add(10 * time.Minute)}, source.Selector{})
	ref := recs[300].Ref
	if _, err := s.Around(source.WithByteLimit(ctx, 32<<10), ref, 2, 2); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("around under a call's limit: %v", err)
	}
	old := MaxAroundBytes
	MaxAroundBytes = 32 << 10
	defer func() { MaxAroundBytes = old }()
	if _, err := s.Around(ctx, ref, 2, 2); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("around under MaxAroundBytes: %v", err)
	}
	MaxAroundBytes = old
	if got, err := s.Around(ctx, ref, 2, 2); err != nil || len(got) != 5 || got[2].Event.Raw != recs[300].Event.Raw {
		t.Fatalf("%v %d", err, len(got))
	}
	// Reread is bounded the same way.
	if _, err := s.Reread(source.WithByteLimit(ctx, 1000), ref); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("reread under a call's limit: %v", err)
	}
	MaxAroundBytes = 1000
	if _, err := s.Reread(ctx, ref); !errors.Is(err, source.ErrByteLimit) {
		t.Fatalf("reread under MaxAroundBytes: %v", err)
	}
	MaxAroundBytes = old
	if got, err := s.Reread(ctx, ref); err != nil || got.Event.Raw != recs[300].Event.Raw {
		t.Fatalf("reread: %v", err)
	}
}

func TestWidthEnforcesMaxSlices(t *testing.T) {
	s := newSource(t, newFake(nil), nil)
	day := t0.Truncate(24 * time.Hour)
	if _, err := s.Plan(ctx, source.Range{From: day, To: day.Add(MaxSlices * 24 * time.Hour)}, source.Selector{}); err != nil {
		t.Fatalf("the widest width: %v", err)
	}
	if _, err := s.Plan(ctx, source.Range{From: day, To: day.Add(MaxSlices*24*time.Hour + time.Second)}, source.Selector{}); err == nil {
		t.Fatal("a range of more than MaxSlices slices was planned")
	}
	if p, err := s.Plan(ctx, source.Range{From: t0, To: t0}, source.Selector{}); err != nil || len(p.Chunks) != 0 {
		t.Fatalf("empty range: %v %+v", err, p)
	}
	// A partial last slice counts: an aligned 512 minutes is one width,
	// one second more the next.
	w, _ := width(source.Range{From: t0, To: t0.Add(MaxSlices * time.Minute)})
	w2, _ := width(source.Range{From: t0.Add(time.Second), To: t0.Add(MaxSlices * time.Minute).Add(time.Second)})
	if w != time.Minute || w2 != 5*time.Minute {
		t.Fatalf("%v %v", w, w2)
	}
}

// TestMultiValuedTermsServerSide: for every term the source pushes, the
// backend's answer is exactly the documents the engine's local evaluation
// of the term on the record's labels accepts (= and in: some value is one
// of the values; !=: none is, an absent field included); a term with an
// empty value is not pushed.
func TestMultiValuedTermsServerSide(t *testing.T) {
	tags := [][]string{nil, {""}, {"a"}, {"b"}, {"a", "b"}, {"b", "c"}, {"a", ""}, {"c", "c"}}
	var docs []fakeDoc
	for i := 0; i < 64; i++ {
		d := fakeDoc{index: "logs-a", id: fmt.Sprintf("d%02d", i), ts: t0.Add(time.Duration(i) * time.Second), fields: map[string]any{"message": fmt.Sprintf("m%d", i)}}
		if tg := tags[i%len(tags)]; tg != nil {
			d.fields["tag"] = tg
		}
		docs = append(docs, d)
	}
	f := newFake(docs)
	f.types["tag"] = "keyword"
	f.mapping = `{"logs-a":{"mappings":{"properties":{"@timestamp":{"type":"date"},"tag":{"type":"keyword"}}}}}`
	s := newChecked(t, f, func(o *Options) { o.TrustedFields = []string{"tag"} })
	local := func(term source.Term, rec source.RawRecord) bool {
		var vals []string
		for _, a := range rec.Event.Attrs {
			if a.Key != "tag" {
				continue
			}
			if len(a.Value.Items) > 0 {
				for _, it := range a.Value.Items {
					vals = append(vals, it.Str)
				}
			} else {
				vals = append(vals, a.Value.Str)
			}
		}
		hit := slices.ContainsFunc(vals, func(v string) bool { return slices.Contains(term.Values, v) })
		if term.Op == "!=" {
			return !hit
		}
		return hit
	}
	all := scanAll(t, s, source.Range{From: t0, To: t0.Add(2 * time.Minute)}, source.Selector{})
	if len(all) != len(docs) {
		t.Fatalf("%d records", len(all))
	}
	for _, term := range []source.Term{
		{Field: "tag", Label: true, Op: "=", Values: []string{"a"}},
		{Field: "tag", Label: true, Op: "!=", Values: []string{"a"}},
		{Field: "tag", Label: true, Op: "!=", Values: []string{"c"}},
		{Field: "tag", Label: true, Op: "in", Values: []string{"a", "c"}},
		{Field: "tag", Label: true, Op: "in", Values: []string{"x"}},
		{Field: "tag", Label: true, Op: "!=", Values: []string{"x"}},
		{Field: "tag", Label: true, Op: "=", Values: []string{""}},
		{Field: "tag", Label: true, Op: "!=", Values: []string{""}},
		{Field: "tag", Label: true, Op: "in", Values: []string{"", "b"}},
	} {
		sel := source.Selector{Terms: []source.Term{term}}
		pushed := s.pushable(term)
		if want := !slices.Contains(term.Values, ""); pushed != want {
			t.Fatalf("%+v: pushable %t", term, pushed)
		}
		f.mu.Lock()
		f.bodies = nil
		f.mu.Unlock()
		got := scanAll(t, s, source.Range{From: t0, To: t0.Add(2 * time.Minute)}, sel)
		var want []string
		for _, r := range all {
			if !pushed || local(term, r) {
				want = append(want, r.Event.Raw)
			}
		}
		var have []string
		for _, r := range got {
			have = append(have, r.Event.Raw)
		}
		if !slices.Equal(have, want) {
			t.Errorf("%s %q: backend %v, local %v", term.Op, term.Values, have, want)
		}
		for _, b := range f.bodies {
			if sent := strings.Contains(string(b), `"term":{"tag"`) || strings.Contains(string(b), `"terms":{"tag"`); sent != pushed {
				t.Errorf("%s %q: term sent %t, pushable %t", term.Op, term.Values, sent, pushed)
			}
		}
	}
	// Labels: one value a string, several an array (as Attrs).
	for i, r := range all {
		tg := tags[i%len(tags)]
		n := 0
		for _, a := range r.Event.Attrs {
			if a.Key == "tag" {
				n++
				if len(tg) > 1 && len(a.Value.Items) != len(tg) || len(tg) == 1 && a.Value.Str != tg[0] {
					t.Fatalf("doc %d: tag %+v, want %q", i, a.Value, tg)
				}
			}
		}
		if (n == 1) != (tg != nil) {
			t.Fatalf("doc %d: %d tag labels for %q", i, n, tg)
		}
	}
}

func TestPrivilegeGlobs(t *testing.T) {
	for _, tt := range []struct {
		grant, name string
		want        bool
	}{
		{"logs-*", "logs-a", true},
		{"logs-*", "logs-*", true},
		{"logs-a", "logs-*", true},   // a future index of the pattern
		{"logs-a", "logs-b*", false}, // cannot start with logs-b
		{"lo?s-b", "logs-b", true},
		{"lo?s-b", "logs-c", false},
		{"*", "x", true},
		{"metrics-*", "logs-*", false},
		{"*-a", "logs-*", true},
		{"/logs.*/", "x", true}, // a regex: everything
		{"<logs-{now/d}>", "x", true},
		{"remote:logs-*", "x", true},
		{"logs-a", "logs-a", true},
		{"logs-a", "logs-ab", false},
		{"logs-ab", "logs-a", false},
	} {
		if got := globMatches(tt.grant, tt.name); got != tt.want {
			t.Errorf("globMatches(%q, %q) = %t", tt.grant, tt.name, got)
		}
	}
}

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
	// Sub-slices scan to the parent's documents, refs unchanged.
	f := newFake(dataset(60)) // two minutes, some ties
	src := newSource(t, f, nil)
	plan, _ := src.Plan(ctx, source.Range{From: t0, To: t0.Add(time.Minute)}, source.Selector{})
	c := plan.Chunks[0]
	whole := drain(t, mustScan(t, src, c))
	c.Granules = src.Split(c.Granules[0])
	split := drain(t, mustScan(t, src, c))
	if len(whole) != len(split) || len(whole) == 0 {
		t.Fatalf("%d records whole, %d split", len(whole), len(split))
	}
	for i := range whole {
		if whole[i].Ref != split[i].Ref || whole[i].Event.Raw != split[i].Event.Raw {
			t.Fatalf("record %d: %+v vs %+v", i, whole[i].Ref, split[i].Ref)
		}
	}
}

func mustScan(t *testing.T, s *Source, c source.Chunk) source.Iterator {
	t.Helper()
	it, err := s.Scan(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// TestCheckMappings: every keyword field the source names must be a
// concrete keyword field without a normalizer in every index (an alias
// judged by its target), never a runtime field; ignore_above on the field
// or the index keeps its terms local; a field missing from one index is
// refused on production.
const stdDefaults = `"defaults":{"index.mode":"standard","index.mapping.ignore_above":"2147483647"}`

func TestCheckMappings(t *testing.T) {
	both := func(a, b string) string {
		return `{"logs-a":{"mappings":` + a + `},"logs-b":{"mappings":` + b + `}}`
	}
	good := `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`
	lv := source.Term{Field: "level", Label: true, Op: "=", Values: []string{"error"}}
	for _, tt := range []struct {
		name, mapping, settings string
		production, ok, local   bool
	}{
		{"good", both(good, good), "", true, true, false},
		{"alias to a keyword field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"lvl":{"type":"keyword"},"level":{"type":"alias","path":"lvl"}}}`), "", true, true, false},
		{"alias to a normalized field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"lvl":{"type":"keyword","normalizer":"lowercase"},"level":{"type":"alias","path":"lvl"}}}`), "", false, false, false},
		{"alias to a text field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"msg":{"type":"text"},"level":{"type":"alias","path":"msg"}}}`), "", false, false, false},
		{"alias to nothing", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"alias","path":"gone"}}}`), "", true, false, false},
		{"runtime field", both(good, `{"runtime":{"level":{"type":"keyword","script":{"source":"emit('x')"}}},"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"}}}`), "", false, false, false},
		{"runtime field shadowing a mapped one", both(good, `{"runtime":{"level":{"type":"keyword"}},"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"field missing in one index on production", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"}}}`), "", true, false, false},
		{"field missing in one index off production", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"}}}`), "", false, true, true},
		{"text in one index", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"text"}}}`), "", false, false, false},
		{"ignore_above on the field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword","ignore_above":1024}}}`), "", true, true, true},
		{"copy_to into a trusted field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"other":{"type":"keyword","copy_to":"level"}}}`), "", false, false, false},
		{"copy_to array from a multi-field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"msg":{"type":"text","fields":{"kw":{"type":"keyword","copy_to":["x","app"]}}}}}`), "", false, false, false},
		{"copy_to from a nested property", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"o":{"properties":{"p":{"type":"keyword","copy_to":"level"}}}}}`), "", false, false, false},
		{"copy_to above a trusted field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"z":{"type":"keyword","copy_to":"level.x"}}}`), "", false, false, false},
		{"copy_to elsewhere", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"z":{"type":"keyword","copy_to":"all_text"}}}`), "", true, true, false},
		{"copy_to not a string", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"z":{"type":"keyword","copy_to":{"a":1}}}}`), "", true, false, false},
		{"composite runtime subfield", both(good, `{"runtime":{"level":{"type":"composite","script":"emit(...)","fields":{"x":{"type":"keyword"}}}},"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"}}}`), "", false, false, false},
		{"composite runtime parent of a trusted field", both(good, `{"runtime":{"lv":{"type":"composite","fields":{"x":{"type":"keyword"}}}},"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"alias","path":"lv.x"}}}`), "", false, false, false},
		{"script on a keyword field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword","script":{"source":"emit('a')"}}}}`), "", false, false, false},
		{"null_value on a trusted field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword","null_value":"none"}}}`), "", true, true, true},
		{"nested settings object", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index":{"mode":"standard"}},` + stdDefaults + `}}`, true, true, true},
		{"dynamic template with copy_to", both(good, `{"dynamic_templates":[{"strings":{"match_mapping_type":"string","mapping":{"type":"keyword","copy_to":"env"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"dynamic template mapping runtime", both(good, `{"dynamic_templates":[{"r":{"match":"*","runtime":{"type":"keyword"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"dynamic template of type runtime", both(good, `{"dynamic_templates":[{"r":{"match":"*","mapping":{"type":"runtime"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"harmless dynamic template", both(good, `{"dynamic_templates":[{"strings":{"match_mapping_type":"string","mapping":{"type":"keyword","ignore_above":1024}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, true, false},
		{"dynamic templates not single-key", both(good, `{"dynamic_templates":[{"a":{},"b":{}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"template: copy_to under properties", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"object","properties":{"a":{"type":"keyword","copy_to":"env"}}}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"template: copy_to under fields", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"text","fields":{"kw":{"type":"keyword","copy_to":["level"]}}}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"template: dynamic Runtime", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"object","dynamic":"Runtime"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: dynamic runtime in a nested object", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"object","properties":{"o":{"type":"object","dynamic":"RUNTIME"}}}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: unknown dynamic value", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"object","dynamic":"sometimes"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: dynamic a number", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"object","dynamic":1}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: script under fields", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"text","fields":{"kw":{"type":"keyword","script":{"source":"emit(1)"}}}}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: type Runtime", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"Runtime"}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"template: undecodable mapping", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"keyword","properties":[1,2]}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"template: mapping not an object", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":"keyword"}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, false, false},
		{"template: accepted good one", both(good, `{"dynamic_templates":[{"t":{"match":"*","mapping":{"type":"text","dynamic":"Strict","fields":{"kw":{"type":"keyword","ignore_above":256}},"properties":{"x":{"type":"keyword","dynamic":false}}}}}],"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, true, false},
		{"dynamic Runtime on an object", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"o":{"dynamic":"Runtime","properties":{}}}}`), "", false, false, false},
		{"dynamic unknown at the top", both(good, `{"dynamic":"maybe","properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"dynamic STRICT at the top", both(good, `{"dynamic":"STRICT","properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, true, false},
		{"dynamic runtime at the top", both(good, `{"dynamic":"runtime","properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"dynamic runtime on an object", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"o":{"dynamic":"runtime","properties":{}}}}`), "", false, false, false},
		{"dynamic true", both(good, `{"dynamic":true,"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", true, true, false},
		{"copy_to into the time field", both(good, `{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},"t":{"type":"date","copy_to":"@timestamp"}}}`), "", false, false, false},
		{"runtime time field", both(good, `{"runtime":{"@timestamp":{"type":"date"}},"properties":{"app":{"type":"keyword"},"level":{"type":"keyword"}}}`), "", false, false, false},
		{"index-level ignore_above", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index.mapping.ignore_above":"256"},` + stdDefaults + `}}`, true, true, true},
		// A logsdb index's settings, in the shape Elasticsearch
		// documents (not recorded from a server): no explicit
		// ignore_above, the mode among the settings.
		{"logsdb index", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index.mode":"logsdb"},"defaults":{"index.mapping.ignore_above":"8191"}}}`, true, true, true},
		{"logsdb mode, ignore_above defaults unread", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index.mode":"logsdb"}}}`, true, true, true},
		{"time_series index", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index.mode":"time_series","index.routing_path":["app"]},"defaults":{}}}`, true, true, true},
		{"unknown mode", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{},"defaults":{"index.mode":"future_mode"}}}`, true, true, true},
		{"mode absent (Elasticsearch)", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{},"defaults":{}}}`, true, true, true},
		{"mode not a string", both(good, good), `{"logs-a":{"settings":{},` + stdDefaults + `},"logs-b":{"settings":{"index.mode":1},"defaults":{}}}`, true, true, true},
	} {
		f := newFake(nil)
		f.mapping, f.settings = tt.mapping, tt.settings
		s := newSource(t, f, nil)
		_, err := s.Check(ctx, tt.production)
		if (err == nil) != tt.ok {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if tt.ok {
			if got := !s.pushable(lv); got != tt.local {
				t.Errorf("%s: level kept local %t, want %t", tt.name, got, tt.local)
			}
			// The index-level setting holds for every keyword field.
			if app := s.pushable(source.Term{Field: "app", Label: true, Op: "=", Values: []string{"api"}}); app != (tt.settings == "") {
				t.Errorf("%s: app pushable %t", tt.name, app)
			}
		}
	}
}

func TestIndexIgnoresAbove(t *testing.T) {
	j := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, tt := range []struct {
		settings, defaults, flavour string
		want                        bool
	}{
		{`{}`, `{"index.mode":"standard","index.mapping.ignore_above":"2147483647"}`, FlavourElasticsearch, false},
		{`{"index.mode":"standard"}`, `{}`, FlavourElasticsearch, false},
		{`{}`, `{}`, FlavourElasticsearch, true},
		{`{}`, `{}`, FlavourOpenSearch, false},
		{`{"index.mode":"logsdb"}`, `{}`, FlavourOpenSearch, true},
		{`{"index.mode":"logsdb"}`, `{}`, FlavourElasticsearch, true},
		{`{"index.mode":"time_series"}`, `{}`, FlavourElasticsearch, true},
		{`{}`, `{"index.mode":"lookup"}`, FlavourElasticsearch, true},
		{`{"index.mapping.ignore_above":"512"}`, `{"index.mode":"standard"}`, FlavourElasticsearch, true},
		{`{}`, `{"index.mode":"standard","index.mapping.ignore_above":"8191"}`, FlavourElasticsearch, true},
		{`{"index.mapping.ignore_above":512}`, `{"index.mode":"standard"}`, FlavourElasticsearch, true},
	} {
		if got := indexIgnoresAbove(j(tt.settings), j(tt.defaults), tt.flavour); got != tt.want {
			t.Errorf("%s %s %s: %t", tt.settings, tt.defaults, tt.flavour, got)
		}
	}
}

func TestSelectorMappingRules(t *testing.T) {
	for _, tt := range []struct {
		name, props string
		ok          bool
	}{
		{"keyword selector", `"env":{"type":"keyword"}`, true},
		{"null_value on the selector", `"env":{"type":"keyword","null_value":"prod"}`, false},
		{"copy_to into the selector", `"env":{"type":"keyword"},"other":{"type":"keyword","copy_to":"env"}`, false},
		{"script on the selector", `"env":{"type":"keyword","script":{"source":"emit('prod')"}}`, false},
	} {
		f := newFake(nil)
		f.types["env"] = "keyword"
		props := `{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword"},` + tt.props + `}`
		f.mapping = `{"logs-a":{"mappings":{"properties":` + props + `}},"logs-b":{"mappings":{"properties":` + props + `}}}`
		s := newSource(t, f, func(o *Options) { o.Selector = map[string]string{"env": "prod"} })
		if _, err := s.Check(ctx, true); (err == nil) != tt.ok {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

func TestNothingServerSideBeforeCheck(t *testing.T) {
	f := newFake(dataset(40))
	s := newSource(t, f, nil)
	lv := source.Term{Field: "level", Label: true, Op: "=", Values: []string{"error"}}
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	if s.pushable(lv) {
		t.Fatal("pushable before Check")
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("count before Check: %v", err)
	}
	// A failed Check leaves it so.
	f.types["level"] = "text"
	if _, err := s.Check(ctx, false); err == nil {
		t.Fatal("check passed")
	}
	if s.pushable(lv) {
		t.Fatal("pushable after a failed Check")
	}
	f.types["level"] = "keyword"
	if _, err := s.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !s.pushable(lv) {
		t.Fatal("not pushable after Check")
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}}); err != nil {
		t.Fatal(err)
	}
	// A field kept local is not counted on the server.
	f.mapping = `{"logs-a":{"mappings":{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword","ignore_above":256}}}}}`
	if _, err := s.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}}); !errors.Is(err, source.ErrNotIndexable) {
		t.Fatalf("count by a local field: %v", err)
	}
	if _, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"app"}}); err != nil {
		t.Fatalf("count by app: %v", err)
	}
	// Mappings unreadable off production: every term local.
	f.mapping = "nope"
	if _, err := s.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	if s.pushable(lv) || s.pushable(source.Term{Field: "app", Label: true, Op: "=", Values: []string{"api"}}) {
		t.Fatal("pushable with unreadable mappings")
	}
}

// TestStreamsStaleAfterReCheck: a stream planned with a pushed term is
// stale once the current state keeps that field local (a re-Check found
// it so, or a Check is running or failed); the selector's own term is
// always accepted.
func TestStreamsStaleAfterReCheck(t *testing.T) {
	f := newFake(dataset(40))
	f.types["env"] = "keyword"
	s := newChecked(t, f, func(o *Options) { o.Selector = map[string]string{"app": "api"} })
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	sel := source.Selector{Terms: []source.Term{{Field: "level", Label: true, Op: "!=", Values: []string{"info"}}}}
	plan, err := s.Plan(ctx, r, sel)
	if err != nil {
		t.Fatal(err)
	}
	pushed := plan.Chunks[0]
	if !strings.Contains(pushed.Stream, "level") {
		t.Fatalf("not pushed: %s", pushed.Stream)
	}
	selOnly, _ := s.Plan(ctx, r, source.Selector{})
	// Now level is kept local.
	f.mapping = `{"logs-a":{"mappings":{"properties":{"@timestamp":{"type":"date"},"app":{"type":"keyword"},"level":{"type":"keyword","ignore_above":10}}}}}`
	if _, err := s.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(ctx, pushed); !errors.Is(err, source.ErrStale) {
		t.Fatalf("scan of a stale stream: %v", err)
	}
	ref := source.RawRef{Source: "es", Stream: pushed.Stream, Offset: t0.UnixNano(), Length: 1}
	if _, err := s.Reread(ctx, ref); !errors.Is(err, source.ErrStale) {
		t.Fatalf("reread: %v", err)
	}
	if _, err := s.Around(ctx, ref, 1, 1); !errors.Is(err, source.ErrStale) {
		t.Fatalf("around: %v", err)
	}
	if _, err := s.Scan(ctx, selOnly.Chunks[0]); err != nil {
		t.Fatalf("the selector's stream: %v", err)
	}
	// A failed Check: every pushed term is stale.
	f.mapping = "nope"
	if _, err := s.Check(ctx, true); err == nil {
		t.Fatal("check passed")
	}
	if _, err := s.Scan(ctx, pushed); !errors.Is(err, source.ErrStale) {
		t.Fatalf("scan after a failed Check: %v", err)
	}
}

// TestCountsUnderConcurrentReCheck: a count with a pushed term, run while
// Check runs again and again, is exact or not served, never the
// unfiltered total.
func TestCountsUnderConcurrentReCheck(t *testing.T) {
	f := newFake(dataset(40))
	s := newChecked(t, f, nil)
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	q := source.CountQuery{Range: r, Selector: source.Selector{Terms: []source.Term{{Field: "level", Label: true, Op: "=", Values: []string{"error"}}}}}
	var want int64
	for _, d := range f.docs {
		if d.fields["level"] == "error" {
			want++
		}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = s.Check(ctx, false)
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	served := 0
	for i := 0; i < 300; i++ {
		res, err := s.IndexCounts(ctx, q)
		if errors.Is(err, source.ErrNotIndexable) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var n int64
		for _, row := range res.Rows {
			n += row.N
		}
		if n != want {
			t.Fatalf("count %d, want %d (the term was dropped)", n, want)
		}
		served++
	}
	close(stop)
	<-done
	t.Logf("%d of 300 counts served, the others refused", served)

	// Deterministically: a Check that starts (and fails) between the
	// validation and the filter's build changes nothing in this count.
	if _, err := s.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	testHookCountFilter = func() {
		f.mu.Lock()
		f.types["level"] = "text"
		f.mu.Unlock()
		_, _ = s.Check(ctx, false)
	}
	defer func() { testHookCountFilter = nil }()
	res, err := s.IndexCounts(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, row := range res.Rows {
		n += row.N
	}
	if n != want {
		t.Fatalf("count %d across a re-Check, want %d", n, want)
	}
}
