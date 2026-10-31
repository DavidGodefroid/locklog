//go:build unix

package engine

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/file"
	"github.com/DavidGodefroid/locklog/internal/source/journald"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

// rec decodes one output record.
func rec(t *testing.T, r json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func firstRef(t *testing.T, f *fixture, mod func(*Query)) (string, map[string]any) {
	t.Helper()
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 1; mod(q) }))
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("%v %d", err, len(res.Records))
	}
	m := rec(t, res.Records[0])
	return m["ref"].(string), m
}

func TestContext(t *testing.T) {
	canary := "canary@example.org"
	f := newFixture(t, genLog(t0, 1000, canary), nil)
	ref, hit := firstRef(t, f, func(q *Query) { q.Text = "(order 525)" })
	res, err := f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 3, After: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 8 || res.Target != 3 || !res.Complete || res.Epoch == "" {
		t.Fatalf("%d records, target %d, complete %v", len(res.Records), res.Target, res.Complete)
	}
	for i, r := range res.Records {
		m := rec(t, r)
		if want := fmt.Sprintf("(order %d)", 522+i); !strings.Contains(m["msg"].(string), want) {
			t.Fatalf("record %d: %v, want %s", i, m["msg"], want)
		}
		if strings.Contains(string(r), "@example") {
			t.Fatalf("clear value: %s", r)
		}
		if m["ref"] == nil {
			t.Fatal("no ref")
		}
	}
	if rec(t, res.Records[3])["msg"] != hit["msg"] {
		t.Fatal("target differs from the search's record")
	}
	if res.Scanned.Records != 8 || res.Scanned.Granules != 1 || res.Scanned.Bytes != 1<<20 {
		t.Fatalf("scanned %+v", res.Scanned)
	}
	if strings.Join(res.Masking.Kinds, ",") != "email" {
		t.Fatalf("kinds %v", res.Masking.Kinds)
	}
	// A context ref continues: the context of a context record.
	res2, err := f.eng.Context(ctx, ContextQuery{Ref: rec(t, res.Records[0])["ref"].(string), After: 1})
	if err != nil || len(res2.Records) != 2 || res2.Target != 0 {
		t.Fatalf("%v %+v", err, res2)
	}
	// The first record of the stream: nothing before it.
	ref0, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 0)" })
	res, err = f.eng.Context(ctx, ContextQuery{Ref: ref0, Before: 5, After: 0})
	if err != nil || len(res.Records) != 1 || res.Target != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	// Projection.
	res, err = f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 1, Fields: []string{"level"}})
	if err != nil {
		t.Fatal(err)
	}
	if m := rec(t, res.Records[0]); m["msg"] != nil || m["fields"].(map[string]any)["level"] == nil {
		t.Fatalf("projection %s", res.Records[0])
	}
}

func TestContextRefusals(t *testing.T) {
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), nil)
	ref, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 10)" })
	for _, tc := range []struct {
		name string
		cq   ContextQuery
		code string
	}{
		{"before", ContextQuery{Ref: ref, Before: 51}, EBadQuery},
		{"after", ContextQuery{Ref: ref, After: -1}, EBadQuery},
		{"tampered", ContextQuery{Ref: ref[:len(ref)-2] + "AA"}, EStale},
		{"empty", ContextQuery{}, EStale},
		{"cursor as ref", ContextQuery{Ref: "Lc1." + strings.SplitN(ref, ".", 2)[1]}, EStale},
		{"masked field", ContextQuery{Ref: ref, Fields: []string{"user.email"}}, EUnknownField},
	} {
		if _, err := f.eng.Context(ctx, tc.cq); code(err) != tc.code {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	// A ref of another console (another K_ref).
	k := make([]byte, 32)
	rand.Read(k)
	other, _ := NewSealer(k)
	forged, _ := other.Seal("Lr1", refState{Source: "app", Stream: "x", Offset: 0, Length: 10, Epoch: f.masker.Epoch(), PolicyFP: f.fp})
	if _, err := f.eng.Context(ctx, ContextQuery{Ref: forged}); code(err) != EStale {
		t.Fatalf("foreign ref: %v", err)
	}
	// The policy changed.
	f.fp = "fp2"
	if _, err := f.eng.Context(ctx, ContextQuery{Ref: ref}); code(err) != EPolicyChanged {
		t.Fatalf("policy change: %v", err)
	}
	f.fp = "fp1"
	// The stream was rewritten: same length, other record.
	path := filepath.Join(f.root, "logs", "app.log")
	b, _ := os.ReadFile(path)
	b2 := []byte(strings.Replace(string(b), "(order 10)", "(order 9X)", 1))
	if err := os.WriteFile(path, b2, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eng.Context(ctx, ContextQuery{Ref: ref}); code(err) != EStale {
		t.Fatalf("rewritten stream: %v", err)
	}
}

// TestContextOutputCap: past the output cap, the records farthest from
// the target are dropped.
func TestContextOutputCap(t *testing.T) {
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), func(o *Options) { o.Limits.MaxOutput = 2048 })
	ref, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 500)" })
	res, err := f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 50, After: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete || len(res.Records) >= 101 || len(res.Records) < 3 {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
	if !strings.Contains(rec(t, res.Records[res.Target])["msg"].(string), "(order 500)") {
		t.Fatal("target lost")
	}
	if d := len(res.Records) - 1 - 2*res.Target; d < -1 || d > 1 {
		t.Fatalf("not centred: target %d of %d", res.Target, len(res.Records))
	}
}

var orderRe = regexp.MustCompile(`\(order (\d+)\)`)

func TestTrace(t *testing.T) {
	canary := "canary@example.org"
	f := newFixture(t, genLog(t0, 30000, canary), oneGranulePerCall)
	tok := strings.TrimSpace(f.masker.Text(canary))
	if !strings.HasPrefix(tok, mask.Open) {
		t.Fatal(tok)
	}
	all := func(tq TraceQuery) []json.RawMessage {
		var out []json.RawMessage
		for i := 0; ; i++ {
			res, err := f.eng.Trace(ctx, tq)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, res.Records...)
			if res.Complete {
				return out
			}
			tq.Cursor = res.Cursor
			if i > 100 {
				t.Fatal("never completes")
			}
		}
	}
	// By pseudonym: every record carrying it, and only those.
	got := all(TraceQuery{ID: tok, From: day.From, To: day.To, Limit: 200})
	if len(got) != 600 {
		t.Fatalf("%d records, want 600", len(got))
	}
	for _, r := range got {
		if !strings.Contains(string(r), tok) || strings.Contains(string(r), canary) {
			t.Fatalf("record %s", r)
		}
	}
	// By a clear id: a whole word only (125, not 1250 nor 12500).
	got = all(TraceQuery{ID: "125", From: day.From, To: day.To})
	if len(got) != 1 || orderRe.FindStringSubmatch(rec(t, got[0])["msg"].(string))[1] != "125" {
		t.Fatalf("%d records", len(got))
	}
	// A trusted value equal to the id (status 500).
	got = all(TraceQuery{ID: "500", From: day.From, To: t0.Add(time.Hour)})
	for _, r := range got {
		m := rec(t, r)
		if m["fields"].(map[string]any)["status"] != float64(500) && !strings.Contains(m["msg"].(string), "(order 500)") {
			t.Fatalf("record %s", r)
		}
	}
	if len(got) != 900+1 {
		t.Fatalf("%d records", len(got))
	}
	// One call's page is in time order.
	res, err := f.eng.Trace(ctx, TraceQuery{ID: tok, From: day.From, To: day.To, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for _, r := range res.Records {
		ts := rec(t, r)["ts"].(string)
		if ts < last {
			t.Fatal("not in time order")
		}
		last = ts
	}
}

func TestTraceRefusals(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
	for _, tc := range []struct {
		id, code string
	}{
		{"someone@example.com", EPIIInQuery},
		{"", EBadQuery},
		{" 125", EBadQuery},
		{"a⟦b", EBadQuery},
		{strings.Repeat("x", 300), EBadQuery},
	} {
		if _, err := f.eng.Trace(ctx, TraceQuery{ID: tc.id, From: day.From, To: day.To}); code(err) != tc.code {
			t.Errorf("%q: %v, want %s", tc.id, err, tc.code)
		}
	}
	// A trace cursor never continues a search, nor another trace.
	res, err := f.eng.Trace(ctx, TraceQuery{ID: "125", From: day.From, To: day.To})
	if err != nil || res.Complete {
		t.Fatalf("%v %v", err, res.Complete)
	}
	if _, err := f.eng.Search(ctx, q(func(q *Query) { q.Cursor = res.Cursor })); code(err) != EStale {
		t.Fatalf("search with a trace cursor: %v", err)
	}
	if _, err := f.eng.Trace(ctx, TraceQuery{ID: "126", From: day.From, To: day.To, Cursor: res.Cursor}); code(err) != EStale {
		t.Fatalf("trace with another trace's cursor: %v", err)
	}
	// Over the range budget.
	if _, err := f.eng.Trace(ctx, TraceQuery{ID: "125", From: day.From, To: day.From.Add(8 * 24 * time.Hour)}); code(err) != EOverBudget {
		t.Fatalf("range: %v", err)
	}
}

// TestTraceNoOracle: a clear id never matches a masked value, wherever it
// sits (inside a placeholder of the message or as a masked leaf); clear
// words match exactly.
func TestTraceNoOracle(t *testing.T) {
	content := `{"time":"2026-10-30T12:00:01Z","user":{"email":"zorglub@example.org"},"msg":"hello zorglub42 from zorglub@example.org"}` + "\n" +
		`{"time":"2026-10-30T12:00:02Z","msg":"login 10 ok"}` + "\n"
	f := newFixture(t, content, nil)
	tok := strings.TrimSpace(f.masker.Text("zorglub@example.org"))
	for id, want := range map[string]int{
		"zorglub": 0, "example.org": 0, "example": 0, "org": 0, "zorglub4": 0,
		"10": 1, "ok": 1, "hello": 1, "zorglub42": 1, tok: 1,
	} {
		res, err := f.eng.Trace(ctx, TraceQuery{ID: id, From: day.From, To: day.To})
		if err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		if len(res.Records) != want {
			t.Errorf("%q: %d records, want %d", id, len(res.Records), want)
		}
		for _, r := range res.Records {
			if strings.Contains(string(r), "@example") {
				t.Fatalf("clear value: %s", r)
			}
		}
	}
	// A word inside a placeholder never matches: the e-mail's local part
	// and domain, over many records.
	g := newFixture(t, genLog(t0, 100, "zorglub@example.org"), nil)
	for _, id := range []string{"zorglub", "example", "org", "user1"} {
		res, err := g.eng.Trace(ctx, TraceQuery{ID: id, From: day.From, To: day.To})
		if err != nil || len(res.Records) != 0 {
			t.Fatalf("%q: %v %d", id, err, len(res.Records))
		}
	}
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	for _, l := range lines {
		fh.WriteString(l + "\n")
	}
}

// nextSecond waits for the next whole second: a tail is new from its
// start's second, so records written before it in the same second are new
// to the next tail.
func nextSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now))
}

func liveLine(i int, user string) string {
	return fmt.Sprintf("time=%s level=error status=502 msg=\"live %d for %s\"", time.Now().UTC().Format(time.RFC3339Nano), i, user)
}

func TestTail(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 100, "c@example.org"), func(o *Options) { o.TailPoll = 100 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(400 * time.Millisecond)
		appendLines(t, path, liveLine(1, "a@example.com"), liveLine(2, "b@example.com"))
		time.Sleep(400 * time.Millisecond)
		appendLines(t, path, liveLine(3, "a@example.com"))
	}()
	start := time.Now()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "2s", Where: []Pred{{Field: "level", Op: "=", Value: raw("error")}}})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 2*time.Second || took > 5*time.Second {
		t.Fatalf("took %s", took)
	}
	if len(res.Records) != 3 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
	for i, r := range res.Records {
		m := rec(t, r)
		if !strings.Contains(m["msg"].(string), fmt.Sprintf("live %d ", i+1)) || strings.Contains(string(r), "@example") {
			t.Fatalf("record %d: %s", i, r)
		}
	}
	if res.Scanned.Granules == 0 {
		t.Fatal("no work reported")
	}
}

func TestTailStopsAtMax(t *testing.T) {
	f := newFixture(t, "", func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"), liveLine(2, "x"), liveLine(3, "x"))
	}()
	start := time.Now()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "10s", Max: 2})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second || len(res.Records) != 2 || res.Complete {
		t.Fatalf("%s, %d records, complete %v", time.Since(start), len(res.Records), res.Complete)
	}
}

// TestTailNewByTime: new records are those timestamped from the start;
// records already there are not returned, nor appended ones dated before
// the start; a line without a time is not tailed.
func TestTailNewByTime(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, `time=2020-01-01T00:00:00Z level=info msg="old dated"`, liveLine(1, "x"))
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || !res.Complete || !strings.Contains(string(res.Records[0]), "live 1 ") {
		t.Fatalf("%s, complete %v", res.Records, res.Complete)
	}
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, `no time at all here`, liveLine(2, "x"))
	}()
	res, err = f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil || len(res.Records) != 1 || !strings.Contains(string(res.Records[0]), "live 2 ") {
		t.Fatalf("%v %s", err, res.Records)
	}
}

// TestTailPartialLine: a line half written when a poll runs is returned
// whole once complete.
func TestTailPartialLine(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		fh, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		fh.WriteString(fmt.Sprintf("time=%s level=error msg=\"first half", time.Now().UTC().Format(time.RFC3339Nano)))
		time.Sleep(300 * time.Millisecond)
		fh.WriteString(" second half\"\n")
		fh.Close()
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || !res.Complete || !strings.Contains(string(res.Records[0]), "first half second half") {
		t.Fatalf("%s, complete %v", res.Records, res.Complete)
	}
	// Still unterminated at the end: left out, incomplete.
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		fh, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		fh.WriteString(fmt.Sprintf("time=%s level=error msg=\"never ends", time.Now().UTC().Format(time.RFC3339Nano)))
		fh.Close()
	}()
	res, err = f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil || len(res.Records) != 0 || res.Complete {
		t.Fatalf("%v %s, complete %v", err, res.Records, res.Complete)
	}
}

// TestTailRotation: a copytruncate rotation under a glob source returns
// neither the old records of the copy nor the live ones again.
func TestTailRotation(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 50, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/app.log*"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(300 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
		appendLines(t, path, liveLine(2, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Complete || !strings.Contains(string(res.Records[0]), "live 1 ") || !strings.Contains(string(res.Records[1]), "live 2 ") {
		t.Fatalf("%d records, complete %v: %s", len(res.Records), res.Complete, res.Records)
	}

	// Records follow the held one before the rotation: each still once.
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(3, "x"))
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(4, "x"))
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".2", b, 0o644)
		os.Truncate(path, 0)
		appendLines(t, path, liveLine(5, "x"))
	}()
	res, err = eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || res.Complete {
		t.Fatalf("%d records, complete %v: %s", len(res.Records), res.Complete, res.Records)
	}
	for i, r := range res.Records {
		if !strings.Contains(string(r), fmt.Sprintf("live %d ", i+3)) {
			t.Fatalf("record %d: %s", i, r)
		}
	}
}

// TestTailNewFileSameLine: a file that appears during the tail with the
// same line, in the same second, as a returned record is not a copy: both
// are returned.
func TestTailNewFileSameLine(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/*.log"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "logs", "app.log")
	l := fmt.Sprintf(`time=%s level=error msg="GET /health 200"`, time.Now().UTC().Add(time.Second).Truncate(time.Second).Format(time.RFC3339))
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, l)
		time.Sleep(300 * time.Millisecond)
		os.WriteFile(filepath.Join(f.root, "logs", "worker2.log"), []byte(l+"\n"), 0o644)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

// TestTailIdenticalLines: identical records of one stream (same text, same
// time) are distinct records: each is returned.
func TestTailIdenticalLines(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		l := liveLine(1, "x")
		appendLines(t, path, l, l)
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, l)
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || !res.Complete {
		t.Fatalf("%d records, complete %v: %s", len(res.Records), res.Complete, res.Records)
	}
}

// TestTailHeldAtGranuleEnd: a poll that sees a stream ending exactly on a
// granule's end holds its last record; that record is still returned once
// later records follow it.
func TestTailHeldAtGranuleEnd(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	for _, short := range []int64{0, 100} {
		nextSecond()
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		target := (st.Size()/source.GranuleBytes+1)*source.GranuleBytes - short
		go func() {
			time.Sleep(200 * time.Millisecond)
			// Old records up to the live one, which ends exactly at
			// target.
			l := liveLine(1, "x")
			old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			base := fmt.Sprintf("time=%s level=info msg=\"", old)
			var lines []string
			for n := target - st.Size() - int64(len(l)) - 1; n > 0; {
				ln := int64(453) // with its newline: 454
				if n <= 900 {
					ln = n - 1
				}
				lines = append(lines, base+strings.Repeat("p", int(ln)-len(base)-1)+"\"")
				n -= ln + 1
			}
			appendLines(t, path, append(lines, l)...)
			time.Sleep(300 * time.Millisecond)
			appendLines(t, path, liveLine(2, "x"), liveLine(3, "x"))
		}()
		res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
		if err != nil {
			t.Fatal(err)
		}
		if st2, _ := os.Stat(path); short == 0 && st2.Size() <= target {
			t.Fatalf("size %d", st2.Size())
		}
		if len(res.Records) != 3 || !res.Complete || !strings.Contains(string(res.Records[0]), "live 1 ") {
			t.Fatalf("short %d: %d records, complete %v", short, len(res.Records), res.Complete)
		}
	}
}

// TestTailJournald: journald positions are entries, not bytes: only the
// entries dated from the start are new.
func TestTailJournald(t *testing.T) {
	root := t.TempDir()
	const mid = "0123456789abcdef0123456789abcdef"
	os.Mkdir(filepath.Join(root, mid), 0o755)
	jpath := filepath.Join(root, mid, "system.journal")
	var es []journaltest.Entry
	old := uint64(time.Now().Add(-time.Hour).UnixMicro())
	for i := 0; i < 10; i++ {
		es = append(es, journaltest.Entry{Realtime: old + uint64(i)*1000, Fields: []string{fmt.Sprintf("MESSAGE=entry %d", i), "PRIORITY=6"}})
	}
	if err := os.WriteFile(jpath, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{Format: "plain"})
	js, err := journald.New(journald.Options{Name: "journal", Roots: []string{root}, Parser: p})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, "", func(o *Options) { o.Sources["journal"] = js; o.TailPoll = 50 * time.Millisecond })
	go func() {
		time.Sleep(300 * time.Millisecond)
		now := uint64(time.Now().UnixMicro())
		es2 := append(slices.Clone(es),
			journaltest.Entry{Realtime: now, Fields: []string{"MESSAGE=entry 10", "PRIORITY=6"}},
			journaltest.Entry{Realtime: now + 1000, Fields: []string{"MESSAGE=entry 11", "PRIORITY=6"}})
		tmp := jpath + ".tmp"
		os.WriteFile(tmp, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es2), 0o644)
		os.Rename(tmp, jpath)
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Sources: []string{"journal"}, Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || !strings.Contains(string(res.Records[0]), "entry 10") || !strings.Contains(string(res.Records[1]), "entry 11") {
		t.Fatalf("%d records: %s", len(res.Records), res.Records)
	}
}

// TestTailJournaldGranuleEnd: a journal ending exactly on a granule's end
// (256 entries) at a poll loses no entry: entries are never held.
func TestTailJournaldGranuleEnd(t *testing.T) {
	root := t.TempDir()
	const mid = "0123456789abcdef0123456789abcdef"
	os.Mkdir(filepath.Join(root, mid), 0o755)
	jpath := filepath.Join(root, mid, "system.journal")
	var es []journaltest.Entry
	old := uint64(time.Now().Add(-time.Hour).UnixMicro())
	for i := 0; i < 255; i++ {
		es = append(es, journaltest.Entry{Realtime: old + uint64(i)*1000, Fields: []string{fmt.Sprintf("MESSAGE=entry %d", i), "PRIORITY=6"}})
	}
	write := func(es []journaltest.Entry) {
		tmp := jpath + ".tmp"
		os.WriteFile(tmp, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es), 0o644)
		os.Rename(tmp, jpath)
	}
	write(es)
	p, _ := parse.New(parse.Options{Format: "plain"})
	js, err := journald.New(journald.Options{Name: "journal", Roots: []string{root}, Parser: p})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, "", func(o *Options) { o.Sources["journal"] = js; o.TailPoll = 50 * time.Millisecond })
	go func() {
		time.Sleep(300 * time.Millisecond)
		live := func(m string) journaltest.Entry {
			return journaltest.Entry{Realtime: uint64(time.Now().UnixMicro()), Fields: []string{"MESSAGE=" + m, "PRIORITY=6"}}
		}
		es = append(es, live("live A"))
		write(es)
		time.Sleep(300 * time.Millisecond)
		es = append(es, live("live B"), live("live C"))
		write(es)
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Sources: []string{"journal"}, Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || !res.Complete || !strings.Contains(string(res.Records[0]), "live A") {
		t.Fatalf("%d records, complete %v: %s", len(res.Records), res.Complete, res.Records)
	}
}

// TestTailReplicas: the same line written by two replicas (two streams
// known at the start) in the same second is returned from each.
func TestTailReplicas(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	bpath := filepath.Join(f.root, "logs", "b.log")
	if err := os.WriteFile(bpath, []byte(genLog(time.Now().Add(-time.Hour), 5, "c@example.org")), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/*.log"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		l := liveLine(1, "x")
		appendLines(t, path, l)
		appendLines(t, bpath, l)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

// TestTailBudgetOnNewData: admission applies to what a poll scans for new
// records, not to the whole unindexed file.
func TestTailBudgetOnNewData(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	content := genLog(time.Now().Add(-30*time.Hour), 80000, "c@example.org") // > 8 MiB, unindexed
	f := newFixture(t, content, func(o *Options) { o.TailPoll = 50 * time.Millisecond; o.Limits.LocalBytes = 4 << 20 })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("%v %d", err, len(res.Records))
	}
}

// TestTailWorkFollowsNewData: polls scan only what grew, not the stream.
func TestTailWorkFollowsNewData(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	content := genLog(time.Now().Add(-30*time.Hour), 80000, "c@example.org") // > 8 granules
	f := newFixture(t, content, func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
	}()
	start := time.Now()
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || time.Since(start) > 4*time.Second {
		t.Fatalf("%d records in %s", len(res.Records), time.Since(start))
	}
	if res.Scanned.Granules > 2 {
		t.Fatalf("scanned %d granules for one appended line", res.Scanned.Granules)
	}
}

func TestTailCancelled(t *testing.T) {
	f := newFixture(t, "", func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	c, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.eng.Tail(c, TailQuery{Duration: "10s"}); code(err) != ESource {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation not honoured")
	}
}

func TestTailRefusals(t *testing.T) {
	f := newFixture(t, "", nil)
	for _, tc := range []TailQuery{
		{Duration: "51s"}, {Duration: "-1s"}, {Duration: "soon"}, {Max: 201}, {Max: -1},
		{Text: "someone@example.com"},
	} {
		if _, err := f.eng.Tail(ctx, tc); code(err) != EBadQuery && code(err) != EPIIInQuery {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	if _, err := f.eng.Tail(ctx, TailQuery{Text: "someone@example.com"}); code(err) != EPIIInQuery {
		t.Fatalf("pii: %v", err)
	}
}

func TestHandleAround(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	ref, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 50)" })
	p, _ := json.Marshal(ContextQuery{Ref: ref, Before: 1, After: 1})
	res, r, err := f.eng.Handle(ctx, MethodContext, p)
	if err != nil || r != nil || len(res.(ContextResult).Records) != 3 {
		t.Fatalf("%v %v %+v", err, r, res)
	}
	res, r, err = f.eng.Handle(ctx, MethodTrace, json.RawMessage(`{"id":"50","from":"2026-10-30T12:00:00Z","to":"2026-10-30T13:00:00Z"}`))
	if err != nil || r != nil || len(res.(SearchResult).Records) != 1 {
		t.Fatalf("%v %v %+v", err, r, res)
	}
	if _, r, _ := f.eng.Handle(ctx, MethodTail, json.RawMessage(`{"duration":"1m"}`)); r == nil || r.Code != EBadQuery {
		t.Fatalf("tail: %v", r)
	}
	if _, r, _ := f.eng.Handle(ctx, MethodContext, json.RawMessage(`{"ref":"x","nope":1}`)); r == nil || r.Code != EBadQuery {
		t.Fatalf("unknown field: %v", r)
	}
}

// TestNoDigestInAroundResults: refs of context, trace and tail results are
// opaque; no digest or policy fingerprint is on the socket (#26).
func TestNoDigestInAroundResults(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	f.fp = "POLICYFINGERPRINT"
	ref, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 50)" })
	_, digest, err := f.eng.Ref(ref)
	if err != nil {
		t.Fatal(err)
	}
	cres, err := f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 2, After: 2})
	if err != nil || len(cres.Records) != 5 {
		t.Fatalf("context: %v", err)
	}
	tres, err := f.eng.Trace(ctx, TraceQuery{ID: "50", From: day.From, To: day.To})
	if err != nil || len(tres.Records) != 1 {
		t.Fatalf("trace: %v", err)
	}
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
	}()
	lres, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil || len(lres.Records) != 1 {
		t.Fatalf("tail: %v %d", err, len(lres.Records))
	}
	for _, v := range []any{cres, tres, lres} {
		out, _ := json.Marshal(v)
		for _, s := range []string{"POLICYFINGERPRINT", digest, "app.log"} {
			if strings.Contains(string(out), s) {
				t.Fatalf("%q on the socket", s)
			}
		}
	}
}

// TestTraceAcrossSources: a trace merges the records of several sources
// in time order, matching labels too.
func TestTraceAcrossSources(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "time=%s level=info msg=\"req abc123 step %d\"\n", t0.Add(time.Duration(2*i)*time.Second).Format(time.RFC3339), 2*i)
	}
	f := newFixture(t, b.String(), nil)
	p, _ := parse.New(parse.Options{})
	var recs []source.RawRecord
	for i := 0; i < 10; i++ {
		ev := p.Line(fmt.Sprintf("time=%s msg=\"step %d\"", t0.Add(time.Duration(2*i+1)*time.Second).Format(time.RFC3339), 2*i+1))
		ev.Attrs = []parse.Member{{Key: "trace_id", Value: parse.Value{Kind: parse.KindString, Str: "abc123"}}}
		recs = append(recs, source.RawRecord{Ref: source.RawRef{Source: "loki", Stream: "s", Offset: int64(i), Length: 1}, Event: ev})
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": f.eng.o.Sources["app"], "loki": labelSource{recs: recs, sels: new([]source.Selector)}}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := eng.Trace(ctx, TraceQuery{ID: "abc123", From: t0, To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 20 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
	for i, r := range res.Records {
		if !strings.Contains(rec(t, r)["msg"].(string), fmt.Sprintf("step %d", i)) {
			t.Fatalf("record %d: %s", i, r)
		}
	}
}

// TestContextEpochAndWork: a ref of another pseudonym epoch is refused; the
// work of a context call counts the granules read back.
func TestContextEpochAndWork(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), nil)
	old := f.eng.seal("Lr1", refState{Source: "app", Stream: "x", Offset: 0, Length: 10, Epoch: "older", PolicyFP: f.fp})
	if _, err := f.eng.Context(ctx, ContextQuery{Ref: old}); code(err) != EStale {
		t.Fatalf("old epoch: %v", err)
	}
	ref, _ := firstRef(t, f, func(q *Query) { q.Text = "(order 20000)" })
	res, err := f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned.Granules < 2 || res.Scanned.Bytes != int64(res.Scanned.Granules)<<20 {
		t.Fatalf("scanned %+v: the read-back granule is not counted", res.Scanned)
	}
	// Sparse records: 50 before needs the read-back of 16 granules.
	var b strings.Builder
	pad := strings.Repeat("p", 200<<10)
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "time=%s level=info msg=\"rec %d %s\"\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), i, pad)
	}
	g := newFixture(t, b.String(), nil)
	ref, _ = firstRef(t, g, func(q *Query) { q.Text = "rec 110 " })
	res, err = g.eng.Context(ctx, ContextQuery{Ref: ref, Before: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned.Granules < 17 {
		t.Fatalf("scanned %+v: read-back not counted", res.Scanned)
	}
}

func rotEngine(t *testing.T) (*Engine, string) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 50, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/app.log*"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return eng, filepath.Join(f.root, "logs", "app.log")
}

// Two identical lines; first returned, second held; copytruncate.
func TestTailCopytruncateIdentical(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, path := rotEngine(t)
	go func() {
		time.Sleep(200 * time.Millisecond)
		l := liveLine(1, "x")
		appendLines(t, path, l, l)
		time.Sleep(300 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
		appendLines(t, path, liveLine(2, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, r := range res.Records {
		s = append(s, string(r))
	}
	if len(res.Records) != 3 || res.Complete {
		t.Fatalf("want 3 got %d complete=%v\n%s", len(res.Records), res.Complete, strings.Join(s, "\n"))
	}
}

// Rename rotation (create): app.log -> app.log.1, new app.log.
func TestTailRenameRotation(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, path := rotEngine(t)
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"), liveLine(2, "x"))
		time.Sleep(300 * time.Millisecond)
		os.Rename(path, path+".1")
		os.WriteFile(path, nil, 0o644)
		appendLines(t, path, liveLine(3, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, r := range res.Records {
		s = append(s, string(r))
	}
	if len(res.Records) != 3 || res.Complete {
		t.Fatalf("want 3 got %d complete=%v\n%s", len(res.Records), res.Complete, strings.Join(s, "\n"))
	}
}

// Truncate and regrow larger than before between polls (no copy).
func TestTailTruncateRegrow(t *testing.T) {
	eng, path := rotEngine(t)
	var wrote atomic.Int64
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(300 * time.Millisecond)
		st, _ := os.Stat(path)
		os.Truncate(path, 0)
		var lines []string
		n := int64(0)
		for i := 2; n < st.Size()+100; i++ {
			l := liveLine(i, "x")
			lines = append(lines, l)
			n += int64(len(l) + 1)
		}
		appendLines(t, path, lines...)
		wrote.Store(int64(len(lines)))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms", Max: 200})
	if err != nil {
		t.Fatal(err)
	}
	// The truncated stream is gone: what it held after its last read
	// cannot be known, so the tail is not complete; what was written
	// after is returned.
	if n := int64(len(res.Records)); n != 1+wrote.Load() || res.Complete {
		t.Fatalf("got %d of %d, complete=%v", n, 1+wrote.Load(), res.Complete)
	}
}

// L returned, then an identical L appended just before a copytruncate.
func TestTailIdenticalAcrossCopy(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, path := rotEngine(t)
	go func() {
		time.Sleep(200 * time.Millisecond)
		nextSecondHalf()
		l := liveLine(1, "x")
		appendLines(t, path, l, liveLine(9, "y"))
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, l)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
		appendLines(t, path, liveLine(2, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 || res.Complete {
		t.Fatalf("want 4 got %d complete=%v: %s", len(res.Records), res.Complete, res.Records)
	}
}

// nextSecondHalf waits until early in a second, so that two writes 200 ms
// apart share it.
func nextSecondHalf() {
	now := time.Now()
	if now.Sub(now.Truncate(time.Second)) > 300*time.Millisecond {
		time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now))
	}
}

// Two copytruncate rotations in one tail (logrotate rotate N: .1 -> .2, copy -> .1).
func TestTailDoubleCopytruncate(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, path := rotEngine(t)
	ct := func() {
		os.Rename(path+".1", path+".2")
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(300 * time.Millisecond)
		ct()
		appendLines(t, path, liveLine(2, "x"), liveLine(3, "x"))
		time.Sleep(300 * time.Millisecond)
		ct()
		appendLines(t, path, liveLine(4, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 || res.Complete {
		t.Fatalf("want 4 got %d complete=%v: %s", len(res.Records), res.Complete, res.Records)
	}
}

// stallSource stalls its next Scan (a slow poll).
type stallSource struct {
	source.Source
	stall atomic.Int64
}

func (s *stallSource) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	if d := s.stall.Swap(0); d > 0 {
		time.Sleep(time.Duration(d))
	}
	return s.Source.Scan(ctx, c)
}

// TestTailSlowLastPoll: a poll planned before the end that completes after
// it does not end the tail: records written after its plan are read by one
// more poll.
func TestTailSlowLastPoll(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	ss := &stallSource{Source: f.eng.o.Sources["app"]}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": ss}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(600 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		ss.stall.Store(int64(700 * time.Millisecond))
		time.Sleep(200 * time.Millisecond) // planned, stalled
		appendLines(t, path, liveLine(2, "x"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

func globEngine(t *testing.T, glob string) (*Engine, string) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 50, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + glob}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return eng, filepath.Join(f.root, "logs")
}

// TestTailNewFileCopytruncate: a file created during the tail with one line,
// then copytruncated: the line is returned once.
func TestTailNewFileCopytruncate(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, dir := globEngine(t, "/logs/*.log*")
	path := filepath.Join(dir, "svc.log")
	go func() {
		time.Sleep(200 * time.Millisecond)
		os.WriteFile(path, []byte(liveLine(1, "x")+"\n"), 0o644)
		time.Sleep(400 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Complete {
		t.Fatalf("want 1 got %d complete=%v", len(res.Records), res.Complete)
	}
}

// TestTailOneLineCopytruncate: one new line, then copytruncate: returned once.
func TestTailOneLineCopytruncate(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	eng, dir := globEngine(t, "/logs/app.log*")
	path := filepath.Join(dir, "app.log")
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(400 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Complete {
		t.Fatalf("want 1 got %d complete=%v", len(res.Records), res.Complete)
	}
}

// TestTailGranuleEndCopytruncate: app.log ends exactly on a granule end at
// the start; one line appended, then copytruncate: returned once.
func TestTailGranuleEndCopytruncate(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	eng, dir := globEngine(t, "/logs/app.log*")
	path := filepath.Join(dir, "app.log")
	st, _ := os.Stat(path)
	target := (st.Size()/source.GranuleBytes + 1) * source.GranuleBytes
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	base := "time=" + old + " level=info msg=\""
	var lines []string
	for n := target - st.Size(); n > 0; {
		ln := int64(453)
		if n <= 900 {
			ln = n - 1
		}
		lines = append(lines, base+strings.Repeat("p", int(ln)-len(base)-1)+"\"")
		n -= ln + 1
	}
	appendLines(t, path, lines...)
	st2, _ := os.Stat(path)
	if st2.Size() != target {
		t.Fatalf("size %d want %d", st2.Size(), target)
	}
	// Indexed, as a running console would have it.
	eng.Search(ctx, Query{Limit: 1})
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(400 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.Truncate(path, 0)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Complete {
		t.Fatalf("want 1 got %d complete=%v", len(res.Records), res.Complete)
	}
}

// TestTailRenameAway: a file that only the source path matches is renamed away (create rotation) after
// a line was appended since the last poll.
func TestTailRenameAway(t *testing.T) {
	eng, dir := globEngine(t, "/logs/app.log")
	path := filepath.Join(dir, "app.log")
	nextSecond()
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"))
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(2, "x"))
		os.Rename(path, path+".1")
		os.WriteFile(path, nil, 0o644)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	// live 2 was in the stream renamed away: the tail may have missed
	// it, and says so.
	if len(res.Records) < 1 || res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

// indexDuringTail appends one matching line (when match) and about 2.7 MiB
// of non-matching ones, then indexes them, as the console's indexer does
// during a tail: indexed granules that cannot match drop out of the polls'
// filtered plans.
func indexDuringTail(t *testing.T, f *fixture, match bool) {
	path := filepath.Join(f.root, "logs", "app.log")
	time.Sleep(300 * time.Millisecond)
	var lines []string
	if match {
		lines = append(lines, liveLine(1, "x"))
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for range 6000 {
		lines = append(lines, fmt.Sprintf("time=%s level=info msg=\"%s\"", now, strings.Repeat("p", 400)))
	}
	appendLines(t, path, lines...)
	time.Sleep(400 * time.Millisecond)
	for {
		_, done, err := f.src.IndexStep(context.Background(), 1<<30, false)
		if err != nil {
			t.Error(err)
			return
		}
		if done {
			return
		}
	}
}

// TestTailIndexedDuringTail: a filtered tail over a stream indexed meanwhile
// returns its match once, complete; with no match, it is complete and
// empty.
func TestTailIndexedDuringTail(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	for _, match := range []bool{true, false} {
		f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 100 * time.Millisecond })
		go indexDuringTail(t, f, match)
		res, err := f.eng.Tail(ctx, TailQuery{Duration: "2s", Where: []Pred{{Field: "level", Op: "=", Value: raw("error")}}})
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if match {
			want = 1
		}
		if len(res.Records) != want || !res.Complete {
			t.Fatalf("match %v: %d records, complete %v", match, len(res.Records), res.Complete)
		}
	}
}

// TestTailReplicasStartDuringTail: two files created during the tail with the
// same first record (same offset, same second) are two streams: the second is
// not taken for a copy of the first.
func TestTailReplicasStartDuringTail(t *testing.T) {
	// The streams change during this tail: every record once, and
	// complete:false (the tail says rotation may have cost records).
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/*.log"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	nextSecondHalf()
	l := fmt.Sprintf(`time=%s level=error msg="replica starting"`, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
	go func() {
		time.Sleep(150 * time.Millisecond)
		os.WriteFile(filepath.Join(f.root, "logs", "a.log"), []byte(l+"\n"), 0o644)
		time.Sleep(250 * time.Millisecond)
		os.WriteFile(filepath.Join(f.root, "logs", "b.log"), []byte(l+"\n"+liveLine(7, "b")+"\n"), 0o644)
		time.Sleep(250 * time.Millisecond)
		appendLines(t, filepath.Join(f.root, "logs", "b.log"), liveLine(8, "b"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 || res.Complete {
		t.Fatalf("%d of 4 records, complete %v: %s", len(res.Records), res.Complete, res.Records)
	}
}

// TestTailSameContentNewFiles: two files created during the tail with the
// same content: a second one no longer than the first may be its copy, and
// the tail says it may have missed records.
func TestTailSameContentNewFiles(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	p, _ := parse.New(parse.Options{})
	src, err := file.New(file.Options{Name: "app", Paths: []string{f.root + "/logs/*.log"}, Roots: []string{f.root}, Parser: p,
		Trusted: []string{"level", "status"}, Index: f.store, Sensitive: func(fl, v string) bool { return f.masker.TrustedValue("app", fl, v) != v }})
	if err != nil {
		t.Fatal(err)
	}
	o := f.eng.o
	o.Sources = map[string]source.Source{"app": src}
	eng, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	l := fmt.Sprintf(`time=%s level=error msg="replica starting"`, time.Now().UTC().Add(time.Second).Truncate(time.Second).Format(time.RFC3339))
	go func() {
		time.Sleep(150 * time.Millisecond)
		os.WriteFile(filepath.Join(f.root, "logs", "a.log"), []byte(l+"\n"), 0o644)
		time.Sleep(250 * time.Millisecond)
		os.WriteFile(filepath.Join(f.root, "logs", "b.log"), []byte(l+"\n"), 0o644)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) == 2 && res.Complete || len(res.Records) < 1 || len(res.Records) > 2 {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
	if len(res.Records) == 1 && res.Complete {
		t.Fatal("a record may be missing, and the tail says complete")
	}
}

// TestTailRenameAwaySameHeader: a file with a constant header is renamed out
// of the paths and a new one with the same header takes its place: the tail
// is not complete.
func TestTailRenameAwaySameHeader(t *testing.T) {
	eng, dir := globEngine(t, "/logs/svc.log")
	path := filepath.Join(dir, "svc.log")
	hdr := "# svc log v1"
	nextSecond()
	go func() {
		time.Sleep(150 * time.Millisecond)
		os.WriteFile(path, []byte(hdr+"\n"), 0o644)
		time.Sleep(250 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"), liveLine(2, "x"), liveLine(3, "x"), liveLine(4, "x"), liveLine(5, "x"))
		time.Sleep(250 * time.Millisecond)
		os.Rename(path, path+".1")
		os.WriteFile(path, []byte(hdr+"\n"+liveLine(6, "x")+"\n"+liveLine(7, "x")+"\n"), 0o644)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("complete with %d records", len(res.Records))
	}
}

// TestTailFutureIndexed: records dated ahead (a writer's clock, a zone read
// as UTC), indexed before the next poll, are still tailed.
func TestTailFutureIndexed(t *testing.T) {
	if raceEnabled {
		t.Skip("timing: the race detector slows masking several fold")
	}
	for _, idx := range []bool{false, true} {
		f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 700 * time.Millisecond })
		path := filepath.Join(f.root, "logs", "app.log")
		go func() {
			time.Sleep(200 * time.Millisecond)
			fut := time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
			lines := []string{"time=" + fut + " level=error msg=\"skewed\""}
			for range 6000 {
				lines = append(lines, "time="+fut+" level=info msg=\""+strings.Repeat("p", 400)+"\"")
			}
			appendLines(t, path, lines...)
			if idx {
				for {
					_, done, err := f.src.IndexStep(context.Background(), 1<<30, false)
					if err != nil || done {
						return
					}
				}
			}
		}()
		res, err := f.eng.Tail(ctx, TailQuery{Duration: "2s", Where: []Pred{{Field: "level", Op: "=", Value: raw("error")}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Records) != 1 || !res.Complete {
			t.Fatalf("indexed %v: %d records, complete %v", idx, len(res.Records), res.Complete)
		}
	}
}

// TestTailStaleCopyThenRenameAway: a backup copy made during the tail, more
// lines, then the original renamed out of the paths: not complete.
func TestTailStaleCopyThenRenameAway(t *testing.T) {
	eng, dir := globEngine(t, "/logs/app.log*")
	path := filepath.Join(dir, "app.log")
	nextSecond()
	go func() {
		time.Sleep(150 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"), liveLine(2, "x"))
		time.Sleep(250 * time.Millisecond)
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".bak", b, 0o644)
		time.Sleep(250 * time.Millisecond)
		appendLines(t, path, liveLine(3, "x"))
		os.Rename(path, filepath.Join(dir, "old-app"))
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("complete with %d records", len(res.Records))
	}
}

// TestTailTwoCopies: two copies made at once, then truncation: not complete.
func TestTailTwoCopies(t *testing.T) {
	eng, dir := globEngine(t, "/logs/app.log*")
	path := filepath.Join(dir, "app.log")
	nextSecond()
	go func() {
		time.Sleep(150 * time.Millisecond)
		appendLines(t, path, liveLine(1, "x"), liveLine(2, "x"))
		time.Sleep(250 * time.Millisecond)
		appendLines(t, path, liveLine(3, "x"))
		b, _ := os.ReadFile(path)
		os.WriteFile(path+".1", b, 0o644)
		os.WriteFile(path+".bak", b, 0o644)
		os.Truncate(path, 0)
	}()
	res, err := eng.Tail(ctx, TailQuery{Duration: "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("complete with %d records", len(res.Records))
	}
}

// TestTailMaxSlowPoll: max reached by a poll planned before the end, which
// completes after it, leaves the end uncovered: not complete.
func TestTailMaxSlowPoll(t *testing.T) {
	root := t.TempDir()
	const mid = "0123456789abcdef0123456789abcdef"
	os.Mkdir(filepath.Join(root, mid), 0o755)
	jpath := filepath.Join(root, mid, "system.journal")
	var es []journaltest.Entry
	old := uint64(time.Now().Add(-time.Hour).UnixMicro())
	for i := 0; i < 10; i++ {
		es = append(es, journaltest.Entry{Realtime: old + uint64(i)*1000, Fields: []string{"MESSAGE=old", "PRIORITY=6"}})
	}
	write := func(es []journaltest.Entry) {
		tmp := jpath + ".tmp"
		os.WriteFile(tmp, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es), 0o644)
		os.Rename(tmp, jpath)
	}
	write(es)
	p, _ := parse.New(parse.Options{Format: "plain"})
	js, err := journald.New(journald.Options{Name: "journal", Roots: []string{root}, Parser: p})
	if err != nil {
		t.Fatal(err)
	}
	ss := &stallSource{Source: js}
	f := newFixture(t, "", func(o *Options) { o.Sources["journal"] = ss; o.TailPoll = 50 * time.Millisecond })
	live := func(m string) journaltest.Entry {
		return journaltest.Entry{Realtime: uint64(time.Now().UnixMicro()), Fields: []string{"MESSAGE=" + m, "PRIORITY=6"}}
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		es = append(es, live("live A"), live("live B"))
		ss.stall.Store(int64(700 * time.Millisecond))
		write(es)
		time.Sleep(250 * time.Millisecond) // planned, stalled
		es = append(es, live("live C"))
		write(es)
	}()
	res, err := f.eng.Tail(ctx, TailQuery{Sources: []string{"journal"}, Duration: "1s", Max: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("complete:true with max reached while live C (written before the end) was never scanned")
	}
}

// TestTailSameSecondBaseline: a record dated in the start's second that was
// written just before the call is not new, whether the stream grows or not.
func TestTailSameSecondBaseline(t *testing.T) {
	for _, grow := range []bool{false, true} {
		f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
		path := filepath.Join(f.root, "logs", "app.log")
		nextSecond()
		appendLines(t, path, liveLine(1, "x"))
		if grow {
			go func() {
				time.Sleep(300 * time.Millisecond)
				appendLines(t, path, liveLine(2, "x"))
			}()
		}
		res, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
		if err != nil {
			t.Fatal(err)
		}
		has1 := len(res.Records) > 0 && strings.Contains(string(res.Records[0]), "live 1 ")
		want := 0
		if grow {
			want = 1 // live 2
		}
		if has1 || len(res.Records) != want || !res.Complete {
			t.Fatalf("grow %v: %d records, live 1 returned %v, complete %v", grow, len(res.Records), has1, res.Complete)
		}
	}
}

// TestTailStartSecondEarlierGranule: journal entries already there when the
// tail starts, dated in its second and across a 256-entry granule end, are
// not new: none is returned, deterministically.
func TestTailStartSecondEarlierGranule(t *testing.T) {
	root := t.TempDir()
	const mid = "0123456789abcdef0123456789abcdef"
	os.Mkdir(filepath.Join(root, mid), 0o755)
	jpath := filepath.Join(root, mid, "system.journal")
	p, _ := parse.New(parse.Options{Format: "plain"})
	js, err := journald.New(journald.Options{Name: "journal", Roots: []string{root}, Parser: p})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, "", func(o *Options) { o.Sources["journal"] = js; o.TailPoll = 50 * time.Millisecond })
	nextSecond()
	var es []journaltest.Entry
	old := uint64(time.Now().Add(-time.Hour).UnixMicro())
	now := uint64(time.Now().UnixMicro())
	for i := 0; i < 250; i++ {
		es = append(es, journaltest.Entry{Realtime: old + uint64(i)*1000, Fields: []string{fmt.Sprintf("MESSAGE=old %d", i), "PRIORITY=6"}})
	}
	for i := 250; i < 260; i++ {
		es = append(es, journaltest.Entry{Realtime: now + uint64(i), Fields: []string{fmt.Sprintf("MESSAGE=new %d", i), "PRIORITY=6"}})
	}
	if err := os.WriteFile(jpath, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := f.eng.Tail(ctx, TailQuery{Sources: []string{"journal"}, Duration: "500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

// TestTailStartSecondFileBoundary: lines already there when the tail starts,
// dated in its second and across a 1 MiB granule end, are not new.
func TestTailStartSecondFileBoundary(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond })
	path := filepath.Join(f.root, "logs", "app.log")
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	var lines []string
	st, _ := os.Stat(path)
	n := st.Size()
	for n < (1<<20)-3000 {
		l := fmt.Sprintf("time=%s level=info msg=\"%s\"", old, strings.Repeat("p", 400))
		lines = append(lines, l)
		n += int64(len(l) + 1)
	}
	appendLines(t, path, lines...)
	nextSecond()
	var live []string
	for i := 0; i < 20; i++ {
		live = append(live, fmt.Sprintf("time=%s level=error msg=\"live %d %s\"", time.Now().UTC().Format(time.RFC3339Nano), i, strings.Repeat("q", 300)))
	}
	appendLines(t, path, live...)
	res, err := f.eng.Tail(ctx, TailQuery{Duration: "500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
}

// writeRaw appends s as is (no newline).
func writeRaw(t *testing.T, path, s string) {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(s)
	fh.Close()
}

// TestTailPrefilterPartialAtGranuleEnd: a partial line ending on a 1 MiB
// granule end whose first part lacks the needle is returned once complete,
// with the pre-filter on or off (tails do not pre-filter).
func TestTailPrefilterPartialAtGranuleEnd(t *testing.T) {
	for _, pre := range []bool{false, true} {
		f := newFixture(t, genLog(time.Now().Add(-time.Hour), 5, "c@example.org"), func(o *Options) { o.TailPoll = 50 * time.Millisecond; o.Prefilter = pre })
		path := filepath.Join(f.root, "logs", "app.log")
		nextSecond()
		go func() {
			time.Sleep(300 * time.Millisecond)
			st, _ := os.Stat(path)
			target := int64(1 << 20)
			partial := fmt.Sprintf("time=%s level=error msg=\"live part", time.Now().UTC().Format(time.RFC3339Nano))
			old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			base := fmt.Sprintf("time=%s level=info msg=\"", old)
			var b strings.Builder
			for n := target - st.Size() - int64(len(partial)); n > 0; {
				ln := int64(453)
				if n <= 900 {
					ln = n - 1
				}
				b.WriteString(base + strings.Repeat("p", int(ln)-len(base)-1) + "\"\n")
				n -= ln + 1
			}
			writeRaw(t, path, b.String()+partial)
			time.Sleep(400 * time.Millisecond)
			writeRaw(t, path, " needle\"\n")
			appendLines(t, path, fmt.Sprintf("time=%s level=info msg=\"after\"", time.Now().UTC().Format(time.RFC3339Nano)))
		}()
		res, err := f.eng.Tail(ctx, TailQuery{Text: "needle", Duration: "1500ms"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Records) != 1 || !res.Complete {
			t.Errorf("prefilter %v: %d records, complete %v", pre, len(res.Records), res.Complete)
		}
	}
}
