//go:build unix

package engine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// remoteStub shows a local source as a remote one.
type remoteStub struct{ source.Source }

func (remoteStub) Kind() string { return "loki" }

// used is what the console's local bytes budget has charged.
func used(e *Engine) int64 {
	return e.ledger.b.LocalBytesPerHour - e.ledger.bytesLeft("", false)
}

// TestRollingBudgetRefusesBeforeReading: repeated free calls draw on the
// hourly byte budget by their plan (granule-rounded, whatever matched);
// once the next call's plan does not fit, it is refused with its estimate
// before any data is read.
func TestRollingBudgetRefusesBeforeReading(t *testing.T) {
	f := newFixture(t, genLog(t0, 3000, "canary@example.org"), nil)
	match := q(func(q *Query) { q.Text = "upstream timed out"; q.Limit = 5 })
	none := q(func(q *Query) { q.Text = "no such text anywhere"; q.Limit = 5 })
	a, err := f.eng.Search(ctx, match)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.eng.Search(ctx, none)
	if err != nil {
		t.Fatal(err)
	}
	if a.Scanned.Bytes == 0 || a.Scanned.Bytes != b.Scanned.Bytes {
		t.Fatalf("charges depend on matches: %d vs %d", a.Scanned.Bytes, b.Scanned.Bytes)
	}
	if got := used(f.eng); got != a.Scanned.Bytes+b.Scanned.Bytes {
		t.Fatalf("charged %d, want %d", got, a.Scanned.Bytes+b.Scanned.Bytes)
	}
	// Room for one more plan and a half.
	f.eng.ledger.b.LocalBytesPerHour = used(f.eng) + a.Scanned.Bytes*3/2
	if _, err := f.eng.Count(ctx, CountQuery{Query: q(func(q *Query) { q.Text = "timed out" })}); err != nil {
		t.Fatal(err)
	}
	before := *f.scans
	_, err = f.eng.Patterns(ctx, PatternsQuery{Query: q(nil)})
	var e *Error
	if code(err) != EOverBudget {
		t.Fatalf("over the budget: %v", err)
	}
	if errors.As(err, &e); e.Estimate == nil || e.Estimate.Bytes != a.Scanned.Bytes {
		t.Fatalf("estimate %+v, want %d bytes", e.Estimate, a.Scanned.Bytes)
	}
	if *f.scans != before {
		t.Fatal("the refused call read data")
	}
	// The same for a trace and a search.
	if _, err := f.eng.Trace(ctx, TraceQuery{From: t0, To: t0.Add(24 * time.Hour), ID: "order"}); code(err) != EOverBudget {
		t.Fatalf("trace: %v", err)
	}
	if _, err := f.eng.Search(ctx, match); code(err) != EOverBudget || *f.scans != before {
		t.Fatalf("search: %v", err)
	}
	st := f.eng.BudgetStatus()
	if st.Local == nil || st.Local.BytesLeft >= a.Scanned.Bytes || len(st.Sources) != 1 || st.Sources[0].BytesLeft != st.Local.BytesLeft {
		t.Fatalf("status %+v", st)
	}
	// An hour later the budget is whole again.
	f.eng.ledger.now = func() time.Time { return time.Now().Add(time.Hour + time.Minute) }
	if _, err := f.eng.Search(ctx, match); err != nil {
		t.Fatal(err)
	}
}

// TestRollingBudgetContinuations: a continuation draws on the rolling
// budget too, and is refused once the budget cannot hold its next part.
func TestRollingBudgetContinuations(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), oneGranulePerCall)
	qq := q(func(q *Query) { q.Text = "order 29999)" })
	res, err := f.eng.Search(ctx, qq)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete || res.Cursor == "" {
		t.Fatal("want a partial page")
	}
	f.eng.ledger.b.LocalBytesPerHour = used(f.eng) + 1
	qq.Cursor = res.Cursor
	if _, err := f.eng.Search(ctx, qq); code(err) != EOverBudget {
		t.Fatalf("continuation: %v", err)
	}
}

// TestRollingBudgetContextAndTail: context re-reads and tail polls are
// charged their reported work.
func TestRollingBudgetContextAndTail(t *testing.T) {
	f := newFixture(t, genLog(time.Now().Add(-time.Hour), 500, "c@example.org"), func(o *Options) { o.TailPoll = 100 * time.Millisecond })
	ref, _ := firstRef(t, f, func(q *Query) {
		q.From, q.To = time.Now().Add(-2*time.Hour), time.Now()
		q.Text = "(order 250)"
	})
	u := used(f.eng)
	cres, err := f.eng.Context(ctx, ContextQuery{Ref: ref, Before: 2, After: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := used(f.eng) - u; got != cres.Scanned.Bytes || got == 0 {
		t.Fatalf("context charged %d, reported %d", got, cres.Scanned.Bytes)
	}
	u = used(f.eng)
	path := filepath.Join(f.root, "logs", "app.log")
	go func() {
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(1, "a@example.com"))
	}()
	tres, err := f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if got := used(f.eng) - u; got != tres.Scanned.Bytes || got == 0 {
		t.Fatalf("tail charged %d, reported %d", got, tres.Scanned.Bytes)
	}
	// A context re-read over the budget is refused before the stream is read.
	f.eng.ledger.b.LocalBytesPerHour = used(f.eng)
	if _, err := f.eng.Context(ctx, ContextQuery{Ref: ref}); code(err) != EOverBudget {
		t.Fatalf("context over budget: %v", err)
	}
	// A tail poll over the budget ends the tail incomplete (its new
	// records are not read).
	go func() {
		time.Sleep(300 * time.Millisecond)
		appendLines(t, path, liveLine(2, "a@example.com"))
	}()
	tres, err = f.eng.Tail(ctx, TailQuery{Duration: "1s"})
	if err != nil && code(err) != EOverBudget {
		t.Fatal(err)
	}
	if err == nil && (tres.Complete || len(tres.Records) != 0) {
		t.Fatalf("tail over budget: complete %v, %d records", tres.Complete, len(tres.Records))
	}
}

// TestCallBytesNoSources: a call naming no source has the remote per-call
// budget when a remote source is configured.
func TestCallBytesNoSources(t *testing.T) {
	f := newFixture(t, "", func(o *Options) {
		o.Limits.LocalBytes, o.Limits.RemoteBytes = 1000, 10
		o.Sources["lk"] = remoteStub{o.Sources["app"]}
	})
	if n := f.eng.callBytes(context.Background(), nil); n != 10 {
		t.Fatalf("no sources: %d, want the remote budget", n)
	}
	if n := f.eng.callBytes(context.Background(), []string{"app"}); n != 1000 {
		t.Fatalf("local only: %d", n)
	}
}

// TestRequestLimiter: the per-minute request budget paces a call's
// requests, and fails one that would wait past the call's deadline.
func TestRequestLimiter(t *testing.T) {
	l := newLedger(Budgets{RemoteRequestsPerMinute: 2}, time.Now)
	r := requestLimiter{l: l, src: "lk"}
	cctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		if err := r.Wait(cctx); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := r.Wait(cctx); err != errRequestBudget {
		t.Fatalf("third request: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("it waited instead of refusing")
	}
	if l.requestsLeft("lk") != 0 {
		t.Fatal("requests left")
	}
	// The metric budget refuses at once.
	m := newLedger(Budgets{MetricQueriesPerHour: 1}, time.Now)
	mr := requestLimiter{l: m, src: "lk", metric: true}
	if err := mr.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mr.Wait(context.Background()); err != errMetricBudget {
		t.Fatalf("second metric query: %v", err)
	}
}
