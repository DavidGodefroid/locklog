//go:build unix

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// TestCountOutputCap: a count whose groups do not fit one answer keeps the
// groups with the most records within Limits.MaxOutput, marks the answer
// truncated and tells how many groups and records it left out (#47).
func TestCountOutputCap(t *testing.T) {
	const capBytes = 4 << 10
	f := newFixture(t, genLog(t0, 1000, "c@example.org"), func(o *Options) { o.Limits.MaxOutput = capBytes })
	cq := CountQuery{Query: q(func(q *Query) { q.To = t0.Add(1000 * time.Second) }), By: []string{"level"}, Bucket: "10s"}
	res, err := f.eng.Count(ctx, cq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if len(b) > capBytes {
		t.Fatalf("%d bytes over the %d cap", len(b), capBytes)
	}
	if !res.Truncated || res.OmittedGroups == 0 || len(res.Groups) == 0 || !res.Complete {
		t.Fatalf("truncated %v, %d omitted, %d kept, complete %v", res.Truncated, res.OmittedGroups, len(res.Groups), res.Complete)
	}
	var n int64
	minKept := int64(1 << 62)
	for i, g := range res.Groups {
		n += g.N
		minKept = min(minKept, g.N)
		if i > 0 && g.Bucket.Before(res.Groups[i-1].Bucket) {
			t.Fatal("kept groups out of order")
		}
	}
	if n+res.OmittedN != 1000 {
		t.Fatalf("%d kept + %d omitted records, want 1000", n, res.OmittedN)
	}
	// The kept groups are the largest: every group of the whole answer
	// with more records than the smallest kept one is kept.
	whole := *f
	o := f.eng.o
	o.Limits.MaxOutput = 1 << 20
	whole.eng, _ = New(o)
	all, err := whole.eng.Count(ctx, cq)
	if err != nil || all.Truncated {
		t.Fatalf("%v, truncated %v", err, all.Truncated)
	}
	if len(all.Groups) != len(res.Groups)+res.OmittedGroups {
		t.Fatalf("%d groups, %d kept + %d omitted", len(all.Groups), len(res.Groups), res.OmittedGroups)
	}
	larger := 0
	for _, g := range all.Groups {
		if g.N > minKept {
			larger++
		}
	}
	kept := 0
	for _, g := range res.Groups {
		if g.N > minKept {
			kept++
		}
	}
	if kept != larger {
		t.Fatalf("%d groups larger than the smallest kept, %d kept", larger, kept)
	}
}

// TestOversizedRecord: a record whose rendering alone exceeds the output
// cap is returned as a stub (source, ref, ts, oversized, bytes) within the
// cap, never cut nor dropped; its ref opens and a projection on some of its
// fields returns them (#48).
func TestOversizedRecord(t *testing.T) {
	big := fmt.Sprintf("time=%s level=error msg=\"%s\"\n", t0.Add(5*time.Second).Format(time.RFC3339), strings.Repeat("word ", 30000))
	f := newFixture(t, genLog(t0, 5, "c@example.org")+big+genLog(t0.Add(6*time.Second), 5, "c@example.org"), nil)
	res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 200 }))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 11 || !res.Complete {
		t.Fatalf("%d records, complete %v", len(res.Records), res.Complete)
	}
	page, _ := json.Marshal(res)
	if len(page) > f.eng.o.Limits.MaxOutput {
		t.Fatalf("a %d-byte page over the %d cap", len(page), f.eng.o.Limits.MaxOutput)
	}
	var stub struct {
		Source    string    `json:"source"`
		Ref       string    `json:"ref"`
		TS        time.Time `json:"ts"`
		Oversized bool      `json:"oversized"`
		Bytes     int       `json:"bytes"`
	}
	oversized := 0
	for _, r := range res.Records {
		if !strings.Contains(string(r), `"oversized"`) {
			continue
		}
		oversized++
		if err := json.Unmarshal(r, &stub); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(r), "word") {
			t.Fatalf("the stub holds content: %.200s", r)
		}
	}
	if oversized != 1 || !stub.Oversized || stub.Source != "app" || stub.Bytes <= 64<<10 || !stub.TS.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("%d stubs: %+v", oversized, stub)
	}
	if _, _, err := f.eng.Ref(stub.Ref); err != nil {
		t.Fatalf("the stub's ref: %v", err)
	}
	// Some of its fields fit.
	res, err = f.eng.Search(ctx, q(func(q *Query) { q.Limit = 200; q.Fields = []string{"level"} }))
	if err != nil || strings.Contains(string(mustJSON(res)), "oversized") || len(res.Records) != 11 {
		t.Fatalf("%v: %d records", err, len(res.Records))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// slowPlan is a source whose Plan takes d, or until ctx ends when it
// honours ctx.
type slowPlan struct {
	source.Source
	d       time.Duration
	honours bool
}

func (s slowPlan) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	if s.honours {
		select {
		case <-ctx.Done():
			return source.Byteplan{}, ctx.Err()
		case <-time.After(s.d):
		}
	} else {
		time.Sleep(s.d)
		ctx = context.WithoutCancel(ctx)
	}
	return s.Source.Plan(ctx, r, sel)
}

// TestPlanningUnderDeadline: a call's deadline covers its planning (#49).
// A plan that runs past it is cut at the deadline and refused as over
// budget; a plan that ignores it leaves the call no time, which stops
// before any work with its cursor, and the continuation reads the frozen
// plan without planning again.
func TestPlanningUnderDeadline(t *testing.T) {
	const deadline = 300 * time.Millisecond
	for _, honours := range []bool{true, false} {
		t.Run(fmt.Sprint("honours ", honours), func(t *testing.T) {
			f := newFixture(t, genLog(t0, 100, "c@example.org"), func(o *Options) {
				o.Limits.Deadline = deadline
				o.Sources["app"] = slowPlan{Source: o.Sources["app"], d: 2 * deadline, honours: honours}
			})
			start := time.Now()
			res, err := f.eng.Search(ctx, q(func(q *Query) { q.Limit = 200 }))
			took := time.Since(start)
			if honours {
				var e *Error
				if !errors.As(err, &e) || e.Code != EOverBudget || e.Message != errPlanDeadline().Message {
					t.Fatalf("%v", err)
				}
				if took > deadline+deadline/2 {
					t.Fatalf("the call took %v for a %v deadline", took, deadline)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Complete || res.Cursor == "" || res.Scanned.Granules != 0 || *f.scans != 0 {
				t.Fatalf("complete %v, %d granules, %d scans after the deadline", res.Complete, res.Scanned.Granules, *f.scans)
			}
			recs, _ := allRecords(t, f.eng, q(func(q *Query) { q.Limit = 200; q.Cursor = res.Cursor }))
			if len(recs) != 100 {
				t.Fatalf("%d records", len(recs))
			}
		})
	}
}

// TestBusy: the engine runs at most Options.MaxCalls calls at once; one
// more is refused at once with E_BUSY, before any work, and runs once a slot
// is free (#50). A scan waits for its approval without a slot and takes one
// once approved.
func TestBusy(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), func(o *Options) { o.MaxCalls = 1 })
	params, _ := json.Marshal(q(func(q *Query) { q.Limit = 5 }))
	release, r := f.eng.calls.acquire()
	if r != nil {
		t.Fatal(r)
	}
	for _, m := range []string{MethodSearch, MethodCount, MethodPatterns, MethodTrace, MethodContext, MethodTail} {
		_, ref, err := f.eng.Handle(ctx, m, params)
		if err != nil || ref == nil || ref.Code != EBusy || !strings.Contains(ref.Message, "1 calls") {
			t.Fatalf("%s: %v %v", m, ref, err)
		}
	}
	if *f.scans != 0 {
		t.Fatal("a busy call read data")
	}
	// A scan is approved without a slot, and refused busy once
	// approved; its reissue resumes the approved plan.
	a := &approver{}
	pctx := peerCtx(1, a)
	sq := scanQ(t, ScanSearch, q(func(q *Query) { q.Limit = 5 }))
	if _, err := f.eng.Scan(pctx, sq); code(err) != EBusy || a.count() != 1 {
		t.Fatalf("scan: %v, %d approvals", err, a.count())
	}
	release()
	if _, ref, err := f.eng.Handle(ctx, MethodSearch, params); err != nil || ref != nil {
		t.Fatalf("%v %v", ref, err)
	}
	res, err := f.eng.Scan(pctx, sq)
	if err != nil || !res.Scan.Reattached || a.count() != 1 {
		t.Fatalf("%v: %+v, %d approvals", err, res.Scan, a.count())
	}
	// Calls in parallel: never more than MaxCalls run, every other is
	// refused busy.
	g := newFixture(t, genLog(t0, 100, "c@example.org"), func(o *Options) { o.MaxCalls = 2 })
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[string]int{}
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ref, err := g.eng.Handle(ctx, MethodSearch, params)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				codes["error"]++
			case ref != nil:
				codes[ref.Code]++
			default:
				codes["ok"]++
			}
		}()
	}
	wg.Wait()
	if codes["ok"] == 0 || codes["ok"]+codes[EBusy] != 16 {
		t.Fatalf("%v", codes)
	}
	if len(g.eng.calls) != 0 {
		t.Fatalf("%d slots held after every call answered", len(g.eng.calls))
	}
}

// TestBrowseThroughCache: a query without predicates whose matches outgrow
// the page cache stops before the group that did and goes on from there,
// instead of being refused: every record is returned once, in order (#46).
// A query with a predicate matching as much is still refused (its matches
// never decide where a call stops).
func TestBrowseThroughCache(t *testing.T) {
	const n = 30000
	f := newFixture(t, genLog(t0, n, "c@example.org"), nil)
	browse := q(func(q *Query) { q.To = t0.Add(n * time.Second); q.Limit = 200 })
	// The matches of the whole plan, rendered.
	recs, _ := allRecords(t, f.eng, browse)
	size := 0
	for _, r := range recs {
		size += len(r) + 64
	}
	// A cache of 60 % of them: a browsing group (a granule here) fits,
	// the whole plan does not.
	f.eng.cache = newResultCache(size * 6 / 10)
	recs, pages := allRecords(t, f.eng, browse)
	ts := recordTimes(t, recs)
	checkOrder(t, ts, n, false)
	for i := 1; i < len(ts); i++ {
		if !ts[i].After(ts[i-1]) {
			t.Fatalf("record at %v returned twice", ts[i])
		}
	}
	scans := 0
	for _, p := range pages {
		if p.Scanned.Granules > 0 {
			scans++
		}
	}
	if scans < 2 {
		t.Fatalf("%d scanning calls: the plan fitted the cache", scans)
	}
	_, err := f.eng.Search(ctx, q(func(q *Query) {
		q.To = t0.Add(n * time.Second)
		q.Limit = 200
		q.Where = []Pred{{Field: "level", Op: OpExists}}
	}))
	if code(err) != EOverBudget {
		t.Fatalf("a predicate matching every record: %v", err)
	}
}

// TestLokiSplitDropsOutsideRange: a dense second just outside the query
// range, in the same 1-minute slice, is never read: the split of the
// over-budget slice drops its narrower slices outside the range, and the
// range completes, ascending, descending, and as a count (#73).
func TestLokiSplitDropsOutsideRange(t *testing.T) {
	for _, order := range []string{"asc", "desc", "count"} {
		t.Run(order, func(t *testing.T) {
			d := &denseLoki{every: 5 * time.Second, denseEvery: time.Millisecond, denseFor: time.Second,
				dense: t0.Add(45 * time.Second), pad: 4 << 10}
			f := denseFixture(t, d, 256<<10)
			qq := q(func(q *Query) {
				q.From, q.To = t0, t0.Add(30*time.Second)
				q.Sources = []string{"lk"}
				q.Limit = 200
				if order != "count" {
					q.Order = order
				}
			})
			if order == "count" {
				// Text: scanned, not answered by Loki's counts.
				cq := CountQuery{Query: qq}
				cq.Limit, cq.Text = 0, "entry"
				for calls := 0; ; calls++ {
					res, err := f.eng.Count(ctx, cq)
					if err != nil {
						t.Fatalf("call %d: %v", calls, err)
					}
					if res.Complete {
						if len(res.Groups) != 1 || res.Groups[0].N != 6 {
							t.Fatalf("%+v", res.Groups)
						}
						return
					}
					if calls > 20 {
						t.Fatal("never completes")
					}
					cq.Cursor = res.Cursor
				}
			}
			recs, _ := allRecords(t, f.eng, qq)
			checkOrder(t, recordTimes(t, recs), 6, order == "desc")
		})
	}
}
