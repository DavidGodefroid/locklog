//go:build unix

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

// approver counts approvals and approves (or denies with errDenied).
type approver struct {
	mu   sync.Mutex
	n    int
	deny bool
	last Approval
	// hook runs before the answer (a change under the approval).
	hook func()
}

var errDenied = errors.New("denied by the human")

func (a *approver) approve(_ context.Context, ap Approval) error {
	a.mu.Lock()
	a.n++
	a.last = ap
	h := a.hook
	a.mu.Unlock()
	if h != nil {
		h()
	}
	if a.deny {
		return errDenied
	}
	return nil
}

func (a *approver) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func peerCtx(uid int, a *approver) context.Context {
	p := Peer{UID: uid}
	if a != nil {
		p.Approve = a.approve
	}
	return WithPeer(context.Background(), p)
}

func scanQ(t *testing.T, tool string, v any) ScanQuery {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return ScanQuery{Tool: tool, Query: b, Reason: "find the first error"}
}

var hex24 = regexp.MustCompile(`^[0-9a-f]{24}$`)

// TestApprovedScanLocal: a scan over the free per-call budget is approved
// once for its whole plan; it completes across continuations on that one
// approval within its TTL; a reissued scan with the same plan re-attaches
// without a new approval; another peer uid, or a changed plan, does not
// continue it.
func TestApprovedScanLocal(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "canary@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline // one granule per call
		o.Limits.LocalRange = time.Hour    // the range is over the free budget
	})
	errQ := q(func(q *Query) {
		q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
		q.Limit = 200
	})
	if _, err := f.eng.Search(peerCtx(1, nil), errQ); code(err) != EOverBudget {
		t.Fatalf("free: %v", err)
	}
	a := &approver{}
	c1 := peerCtx(1, a)
	sq := scanQ(t, ScanSearch, errQ)
	res, err := f.eng.Scan(c1, sq)
	if err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || a.last.Class != "read" || a.last.NeverAuto {
		t.Fatalf("approvals %d %+v", a.count(), a.last)
	}
	if !hex24.MatchString(res.Scan.ID) || res.Scan.Done || res.Scan.Reattached {
		t.Fatalf("scan %+v", res.Scan)
	}
	first := res.Result.(SearchResult)
	if first.Complete || first.Cursor == "" {
		t.Fatal("want a continuation")
	}
	// Reissued without the cursor: the same approved plan, no new
	// prompt, resumed at its live position (the next part, not the start).
	re, err := f.eng.Scan(c1, sq)
	if err != nil || a.count() != 1 || !re.Scan.Reattached || re.Scan.ID != res.Scan.ID {
		t.Fatalf("reissue: %v approvals %d %+v", err, a.count(), re.Scan)
	}
	if b1, b2 := rec(t, first.Records[0]), rec(t, re.Result.(SearchResult).Records[0]); b1["msg"] == b2["msg"] {
		t.Fatal("the reissue restarted the scan")
	}
	cur := re.Result.(SearchResult).Cursor
	// An older cursor does not continue it: one live position.
	stale := errQ
	stale.Cursor = first.Cursor
	if _, err := f.eng.Scan(c1, scanQ(t, ScanSearch, stale)); code(err) != EStale {
		t.Fatalf("older cursor: %v", err)
	}
	// Another peer uid cannot continue it.
	other := errQ
	other.Cursor = cur
	if _, err := f.eng.Scan(peerCtx(2, a), scanQ(t, ScanSearch, other)); code(err) != EStale {
		t.Fatalf("other uid: %v", err)
	}
	// Nor can a changed plan.
	changed := errQ
	changed.Text = "timed out"
	changed.Cursor = cur
	if _, err := f.eng.Scan(c1, scanQ(t, ScanSearch, changed)); code(err) != EStale {
		t.Fatalf("changed plan: %v", err)
	}
	// Nor a free search.
	if _, err := f.eng.Search(c1, other); err == nil {
		t.Fatalf("free continuation of a scan cursor: %v", err)
	}
	// Another uid asking for the same plan is asked for its own approval.
	b := &approver{deny: true}
	if _, err := f.eng.Scan(peerCtx(2, b), sq); !errors.Is(err, errDenied) || b.count() != 1 {
		t.Fatalf("other uid's own scan: %v %d", err, b.count())
	}
	// The scan runs to its end on the one approval.
	n, calls := len(first.Records)+len(re.Result.(SearchResult).Records), 0
	for !re.Scan.Done {
		next := errQ
		next.Cursor = re.Result.(SearchResult).Cursor
		if re, err = f.eng.Scan(c1, scanQ(t, ScanSearch, next)); err != nil {
			t.Fatalf("call %d: %v", calls, err)
		}
		n += len(re.Result.(SearchResult).Records)
		calls++
		if calls > 100 {
			t.Fatal("does not end")
		}
	}
	if n != 6000 || a.count() != 1 || calls < 4 {
		t.Fatalf("%d records in %d calls, %d approvals", n, calls, a.count())
	}
	if f.eng.BudgetStatus().Scans != 0 {
		t.Fatal("the scan did not end")
	}
	// The rolling budget was not drawn on by the scan.
	if used(f.eng) != 0 {
		t.Fatalf("the scan charged the rolling budget: %d", used(f.eng))
	}
	// Once it ended, the same scan needs a new approval.
	if _, err := f.eng.Scan(c1, sq); err != nil || a.count() != 2 {
		t.Fatalf("after the end: %v %d", err, a.count())
	}
}

// TestApprovedScanTTL: a scan expires 30 minutes (ScanTTL) after its
// approval; its cursor is then refused.
func TestApprovedScanTTL(t *testing.T) {
	now := t0.Add(48 * time.Hour)
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
		o.Now = func() time.Time { return now }
	})
	a := &approver{}
	qq := q(func(q *Query) { q.Text = "timed out"; q.Limit = 10 })
	res, err := f.eng.Scan(peerCtx(1, a), scanQ(t, ScanCount, CountQuery{Query: qq}))
	if err != nil {
		t.Fatal(err)
	}
	cres := res.Result.(CountResult)
	if cres.Complete {
		t.Fatal("want a partial count")
	}
	if !res.Scan.ExpiresAt.Equal(now.Add(DefaultScanTTL)) {
		t.Fatalf("expires %v", res.Scan.ExpiresAt)
	}
	now = now.Add(DefaultScanTTL)
	qq.Cursor = cres.Cursor
	if _, err := f.eng.Scan(peerCtx(1, a), scanQ(t, ScanCount, CountQuery{Query: qq})); code(err) != EStale {
		t.Fatalf("expired: %v", err)
	}
	if f.eng.BudgetStatus().Scans != 0 {
		t.Fatal("an expired scan is live")
	}
}

// TestApprovedScanTTLOfALongPlan (#104): a scan whose plan takes longer
// than ScanTTL at the cost model's worst-case rate lives as long as its
// plan's bound (twice that time: the calls stop before a group that would
// not fit), at most MaxScanTTL; the approval screen says so.
func TestApprovedScanTTLOfALongPlan(t *testing.T) {
	now := t0.Add(48 * time.Hour)
	for _, c := range []struct {
		ns   float64 // worst-case cost per byte
		want func(plan int64) time.Duration
	}{
		{1, func(int64) time.Duration { return DefaultScanTTL }}, // a short plan
		{1e6, func(plan int64) time.Duration { return 2 * time.Duration(float64(plan)*1e6) }},
		{1e9, func(int64) time.Duration { return MaxScanTTL }},
	} {
		f := newFixture(t, genLog(t0, 30000, "c@example.org"), func(o *Options) {
			oneGranulePerCall(o)
			o.ScanDeadline = o.Limits.Deadline
			o.Now = func() time.Time { return now }
		})
		f.eng.o.Cost = fixedCost(c.ns)
		a := &approver{}
		qq := q(func(q *Query) { q.Text = "timed out"; q.Limit = 10 })
		res, err := f.eng.Scan(peerCtx(1, a), scanQ(t, ScanCount, CountQuery{Query: qq}))
		if err != nil {
			t.Fatal(err)
		}
		plan := f.eng.scans.m[res.Scan.ID].plan.Bytes()
		want := c.want(plan)
		if want > DefaultScanTTL && want < MaxScanTTL {
			want = want.Round(time.Second)
		}
		if got := res.Scan.ExpiresAt.Sub(now); got != want {
			t.Fatalf("cost %v ns/B, plan %d B: expires in %v, want %v", c.ns, plan, got, want)
		}
		if !strings.Contains(strings.Join(a.last.Body, "\n"), "until it ends or "+want.String()+" from now") {
			t.Fatalf("the screen does not say %v: %q", want, a.last.Body)
		}
	}
}

// TestApprovedScanRefusals: no approver, a denial, a bad tool.
func TestApprovedScanRefusals(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	sq := scanQ(t, ScanSearch, q(nil))
	if _, err := f.eng.Scan(peerCtx(1, nil), sq); code(err) != EApproval {
		t.Fatalf("no approver: %v", err)
	}
	if _, err := f.eng.Scan(peerCtx(1, &approver{deny: true}), sq); !errors.Is(err, errDenied) {
		t.Fatalf("denied: %v", err)
	}
	bad := sq
	bad.Tool = "tail"
	if _, err := f.eng.Scan(peerCtx(1, &approver{}), bad); code(err) != EBadQuery {
		t.Fatalf("tail: %v", err)
	}
	bad = sq
	bad.Query = json.RawMessage(`{"from":"x"}`)
	if _, err := f.eng.Scan(peerCtx(1, &approver{}), bad); code(err) != EBadQuery {
		t.Fatalf("bad query: %v", err)
	}
	// The deadline is what the 570 s request budget leaves.
	sc := &scanCall{e: f.eng, start: time.Now().Add(-569 * time.Second)}
	if d := sc.deadline(); d != 0 {
		t.Fatalf("deadline %v, want no time left", d)
	}
	sc.start = time.Now().Add(-270 * time.Second)
	if d := sc.deadline(); d > 201*time.Second || d < 199*time.Second {
		t.Fatalf("deadline %v, want about 200 s", d)
	}
}

// TestApprovedScanRemoteNoLevelLabel: a Loki source without a level label
// (the level is in the line): a search for errors over an hour is over
// the free budgets (the rolling request budget per minute leaves it no
// room), and one approved scan completes it at its own request rate,
// within the TTL (design R6-P2).
func TestApprovedScanRemoteNoLevelLabel(t *testing.T) {
	bl := &bigLoki{every: 5 * time.Second, pad: 512}
	p, _ := parse.New(parse.Options{})
	src, err := loki.New(loki.Options{Name: "lk", Client: bl, Parser: p, Selector: map[string]string{"env": "prod"},
		InFlight: 4, Limit: 4, Now: func() time.Time { return t0.Add(2 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, "x\n", func(o *Options) {
		o.Sources["lk"] = src
		o.Limits.RemoteBytes = 64 << 10
		o.Budgets = DefaultBudgets()
		o.Budgets.RemoteRequestsPerMinute = 5
		// The scan's own rate (the profile's remote rate in a session).
		o.ScanRequestsPerMinute = 300
	})
	errQ := q(func(q *Query) {
		q.From, q.To = t0, t0.Add(time.Hour)
		q.Sources = []string{"lk"}
		q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
		q.Limit = 200
	})
	// Free, the rolling request budget stops it (refused, or a small
	// part at the group boundary the pacing leaves room for).
	if fr, err := f.eng.Search(peerCtx(1, nil), errQ); code(err) != EOverBudget && (err != nil || fr.Complete) {
		t.Fatalf("free: %v complete %v", err, fr.Complete)
	}
	bl.mu.Lock()
	freeBytes := bl.served
	bl.served = 0
	bl.mu.Unlock()
	a := &approver{}
	start := time.Now()
	res, err := f.eng.Scan(peerCtx(1, a), scanQ(t, ScanSearch, errQ))
	if err != nil {
		t.Fatal(err)
	}
	n, calls := len(res.Result.(SearchResult).Records), 1
	var scanned int64 = res.Result.(SearchResult).Scanned.Bytes
	for !res.Scan.Done {
		next := errQ
		next.Cursor = res.Result.(SearchResult).Cursor
		if res, err = f.eng.Scan(peerCtx(1, a), scanQ(t, ScanSearch, next)); err != nil {
			t.Fatalf("call %d: %v", calls, err)
		}
		n += len(res.Result.(SearchResult).Records)
		scanned += res.Result.(SearchResult).Scanned.Bytes
		calls++
		if calls > 200 {
			t.Fatal("does not end")
		}
	}
	if n != 60 || a.count() != 1 {
		t.Fatalf("%d records, %d approvals", n, a.count())
	}
	if took := time.Since(start); took > DefaultScanTTL {
		t.Fatalf("took %v", took)
	}
	bl.mu.Lock()
	served := bl.served
	bl.mu.Unlock()
	// Far more requests than the rolling budget's 5 per minute.
	if served < 10*freeBytes || scanned != served {
		t.Fatalf("served %d (free call %d), scanned %d", served, freeBytes, scanned)
	}
}

// TestApprovedScanReissuesBounded: however often a scan is reissued, it
// processes at most its frozen plan, on its one approval, and never draws
// on the rolling budget; past its plan it is refused.
func TestApprovedScanReissuesBounded(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "c@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
	})
	a := &approver{}
	c := peerCtx(1, a)
	qq := q(func(q *Query) { q.Text = "timed out"; q.Limit = 10 })
	sq := scanQ(t, ScanCount, CountQuery{Query: qq})
	res, err := f.eng.Scan(c, sq)
	if err != nil {
		t.Fatal(err)
	}
	f.eng.scans.mu.Lock()
	s := f.eng.scans.m[res.Scan.ID]
	f.eng.scans.mu.Unlock()
	planBytes := s.plan.Bytes()
	calls := 1
	for !res.Scan.Done {
		if res, err = f.eng.Scan(c, sq); err != nil { // reissued, never continued
			t.Fatalf("reissue %d: %v", calls, err)
		}
		calls++
		if calls > 50 {
			t.Fatal("does not end")
		}
	}
	f.eng.scans.mu.Lock()
	processed := s.bytes
	f.eng.scans.mu.Unlock()
	if calls < 3 || a.count() != 1 || processed > planBytes || processed == 0 || used(f.eng) != 0 {
		t.Fatalf("%d calls, %d approvals, processed %d of a %d-byte plan, rolling %d", calls, a.count(), processed, planBytes, used(f.eng))
	}
	// A scan that has processed its plan is refused before reading more.
	res, err = f.eng.Scan(c, sq)
	if err != nil {
		t.Fatal(err)
	}
	f.eng.scans.mu.Lock()
	s = f.eng.scans.m[res.Scan.ID]
	s.bytes = s.plan.Bytes()
	f.eng.scans.mu.Unlock()
	before := *f.scans
	if _, err := f.eng.Scan(c, sq); code(err) != EOverBudget || *f.scans != before {
		t.Fatalf("past its plan: %v", err)
	}
}

func tokenCtx(uid int, tok string, a *approver) context.Context {
	p := Peer{UID: uid, Token: tok}
	if a != nil {
		p.Approve = a.approve
	}
	return WithPeer(context.Background(), p)
}

// TestApprovedScanTokenBinding: in hub mode a scan is bound to the agent's
// token as to its uid: another agent of the same uid neither re-attaches
// to it nor continues it with its cursor.
func TestApprovedScanTokenBinding(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "canary@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
	})
	qq := q(func(q *Query) { q.Text = "timed out"; q.Limit = 10 })
	sq := scanQ(t, ScanCount, CountQuery{Query: qq})
	a := &approver{}
	res, err := f.eng.Scan(tokenCtx(1, "tok-a", a), sq)
	if err != nil || a.count() != 1 {
		t.Fatalf("first: %v %d", err, a.count())
	}
	// The same agent re-attaches.
	if re, err := f.eng.Scan(tokenCtx(1, "tok-a", a), sq); err != nil || !re.Scan.Reattached || a.count() != 1 {
		t.Fatalf("same token: %v %+v", err, re.Scan)
	}
	// Another agent of the same uid is asked for its own approval.
	b := &approver{deny: true}
	if _, err := f.eng.Scan(tokenCtx(1, "tok-b", b), sq); !errors.Is(err, errDenied) || b.count() != 1 {
		t.Fatalf("other token reissue: %v %d", err, b.count())
	}
	// Nor does its cursor continue it.
	// (its live position: the reissue went on from the first page)
	next := qq
	f.eng.scans.mu.Lock()
	next.Cursor = f.eng.scans.m[res.Scan.ID].cursor
	f.eng.scans.mu.Unlock()
	if _, err := f.eng.Scan(tokenCtx(1, "tok-b", a), scanQ(t, ScanCount, CountQuery{Query: next})); code(err) != EStale {
		t.Fatalf("other token continuation: %v", err)
	}
	if _, err := f.eng.Scan(tokenCtx(1, "tok-a", a), scanQ(t, ScanCount, CountQuery{Query: next})); err != nil {
		t.Fatalf("own continuation: %v", err)
	}
}

// TestApprovedScanLostAnswer: a continuation with the cursor of a page
// answered already (its answer lost) is refused saying so; a reissue
// resumes after it and says it resumed.
func TestApprovedScanLostAnswer(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "canary@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
	})
	qq := q(func(q *Query) { q.Text = "timed out"; q.Limit = 10 })
	a := &approver{}
	c := peerCtx(1, a)
	res, err := f.eng.Scan(c, scanQ(t, ScanCount, CountQuery{Query: qq}))
	if err != nil {
		t.Fatal(err)
	}
	first := qq
	first.Cursor = res.Result.(CountResult).Cursor
	if _, err := f.eng.Scan(c, scanQ(t, ScanCount, CountQuery{Query: first})); err != nil {
		t.Fatal(err)
	}
	// The answer of that call was lost: the agent asks with its cursor
	// again.
	_, err = f.eng.Scan(c, scanQ(t, ScanCount, CountQuery{Query: first}))
	var e *Error
	if !errors.As(err, &e) || e.Code != EStale || !strings.Contains(e.Message, "answered already") {
		t.Fatalf("lost answer: %v", err)
	}
	re, err := f.eng.Scan(c, scanQ(t, ScanCount, CountQuery{Query: qq}))
	if err != nil || !re.Scan.Reattached || !re.Scan.Resumed {
		t.Fatalf("reissue: %v %+v", err, re.Scan)
	}
	// A reissue before any answer starts its plan: not resumed.
	g := newFixture(t, genLog(t0, 30000, "canary@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
	})
	if r, err := g.eng.Scan(c, scanQ(t, ScanCount, CountQuery{Query: qq})); err != nil || r.Scan.Resumed || r.Scan.Reattached {
		t.Fatalf("first call: %v %+v", err, r.Scan)
	}
}

// TestScanScreen: the reason is masked like an unmask's; a renewal names
// the scan's inputs unchecked (it holds no query to plan again); a
// patterns scan against a baseline names the baseline window too.
func TestScanScreen(t *testing.T) {
	f := newFixture(t, genLog(t0, 30000, "canary@example.org"), func(o *Options) {
		oneGranulePerCall(o)
		o.ScanDeadline = o.Limits.Deadline
		o.Limits.LocalRange = time.Hour
	})
	a := &approver{}
	sq := scanQ(t, ScanCount, CountQuery{Query: q(func(q *Query) { q.Text = "timed out" })})
	sq.Reason = "why did canary@example.org fail"
	if _, err := f.eng.Scan(peerCtx(1, a), sq); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.last.Note, "canary@example.org") || !strings.Contains(a.last.Note, "⟦email:") {
		t.Fatalf("note %q", a.last.Note)
	}
	if strings.Join(a.last.Moving, ",") != "tool,query,budget" {
		t.Fatalf("moving %v", a.last.Moving)
	}
	pq := PatternsQuery{Query: q(func(q *Query) { q.To = q.From.Add(2 * time.Hour) }), Baseline: "6h"}
	if _, err := f.eng.Scan(peerCtx(1, a), scanQ(t, ScanPatterns, pq)); err != nil {
		t.Fatal(err)
	}
	want := []string{"tool: patterns", "sources: app", "range: 2026-10-30T12:00:00Z → 2026-10-30T14:00:00Z (2h0m0s)",
		"baseline: 2026-10-30T06:00:00Z → 2026-10-30T08:00:00Z (2h0m0s) (the same window 6h earlier)"}
	if len(a.last.Body) < len(want) {
		t.Fatalf("body %q", a.last.Body)
	}
	for i, w := range want {
		if a.last.Body[i] != w {
			t.Errorf("line %d: %q, want %q", i, a.last.Body[i], w)
		}
	}
}

// A scan over several remote sources paces each under its own name.
func TestScanLimiterPerSource(t *testing.T) {
	f := newFixture(t, "x\n", func(o *Options) { o.ScanRequestsPerMinute = 10 })
	sc := &scanCall{e: f.eng, s: &scanState{id: "s1"}}
	a, b := sc.limiter("a").(requestLimiter), sc.limiter("b").(requestLimiter)
	if a.src != "a" || b.src != "b" || a.l != b.l || sc.limiter("a").(requestLimiter) != a {
		t.Fatalf("limiters %+v %+v", a, b)
	}
}
