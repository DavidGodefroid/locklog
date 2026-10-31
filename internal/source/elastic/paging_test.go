package elastic

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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
	s := newSource(t, f, func(o *Options) { o.InFlight = 2 })
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
	// Close waited for the fetches: nothing is sent after it.
	f.mu.Lock()
	n := len(f.requests)
	f.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	if len(f.requests) != n {
		t.Fatal("a fetch ran after Close")
	}
	f.mu.Unlock()

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
	s := newSource(t, f, func(o *Options) { o.TrustedFields = []string{"tag"} })
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
