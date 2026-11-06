//go:build unix

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func withUnmask(o *Options) { o.Unmask = UnmaskApproved }

// recordWith is the first record (and its ref) of a search for text, and
// the pseudonyms of kind it shows.
func recordWith(t *testing.T, f *fixture, text, kind string) (string, []string) {
	t.Helper()
	ref, m := firstRef(t, f, func(q *Query) { q.Text = text })
	b, _ := json.Marshal(m)
	var toks []string
	for _, x := range tokenRe.FindAllStringSubmatch(string(b), -1) {
		if x[1] == kind {
			toks = append(toks, x[0])
		}
	}
	return ref, toks
}

// TestUnmask: an approved unmask returns exactly the clear values of the
// pseudonyms it names, after a read-pii approval that auto mode never
// gives; the screen marks the spans and shows the reason masked.
func TestUnmask(t *testing.T) {
	const canary = "canary@example.org"
	f := newFixture(t, genLog(t0, 100, canary), withUnmask)
	ref, toks := recordWith(t, f, "(order 25)", "email")
	if len(toks) != 1 {
		t.Fatalf("tokens %v", toks)
	}
	a := &approver{}
	res, err := f.eng.Unmask(peerCtx(1, a), UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "the user asked who failed, mail bob@example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Values) != 1 || res.Values[0].Value != canary || res.Values[0].Pseudonym != toks[0] {
		t.Fatalf("values %+v", res.Values)
	}
	ap := a.last
	if a.count() != 1 || ap.Class != "read-pii" || !ap.NeverAuto {
		t.Fatalf("approval %+v", ap)
	}
	body := strings.Join(ap.Body, "\n")
	if !strings.Contains(body, "»"+toks[0]+"«") || strings.Contains(body, canary) {
		t.Fatalf("screen body %q", body)
	}
	// The clear view, for the console's terminal only: the record with
	// the canary in clear.
	if len(ap.Clear) != 1 || !strings.Contains(ap.Clear[0], canary) || strings.Contains(ap.Clear[0], toks[0]) {
		t.Fatalf("clear view %q", ap.Clear)
	}
	if strings.Contains(ap.Note, "bob@example.net") || !strings.Contains(ap.Note, "⟦email:") {
		t.Fatalf("reason not masked: %q", ap.Note)
	}
	if !strings.Contains(strings.Join(ap.Warnings, "\n"), "link this value to every record") {
		t.Fatalf("warnings %v", ap.Warnings)
	}
	if got := res.AuditPseudonyms(); len(got) != 1 || got[0] != toks[0] {
		t.Fatalf("audit %v", got)
	}
}

// TestUnmaskRefusals: unmask = "never" refuses (before anything else); a
// pseudonym not in the record, a tampered ref, another epoch, a secret
// and a denial are refused; a record changed under the approval (a span
// swapped) is stale.
func TestUnmaskRefusals(t *testing.T) {
	never := newFixture(t, genLog(t0, 100, "c@example.org"), nil)
	if _, err := never.eng.Unmask(peerCtx(1, &approver{}), UnmaskQuery{Ref: "garbage", Pseudonyms: []string{"⟦email:X⟧"}, Reason: "x"}); code(err) != EUnmaskNever {
		t.Fatalf("never: %v", err)
	}
	f := newFixture(t, genLog(t0, 100, "canary@example.org"), withUnmask)
	ref, toks := recordWith(t, f, "(order 25)", "email")
	_, others := recordWith(t, f, "(order 26)", "email")
	a := &approver{}
	c := peerCtx(1, a)
	for name, tc := range map[string]struct {
		q    UnmaskQuery
		code string
	}{
		"no pseudonyms":     {UnmaskQuery{Ref: ref, Reason: "x"}, EBadQuery},
		"not a pseudonym":   {UnmaskQuery{Ref: ref, Pseudonyms: []string{"canary@example.org"}, Reason: "x"}, EBadQuery},
		"secret":            {UnmaskQuery{Ref: ref, Pseudonyms: []string{"⟦secret⟧"}, Reason: "x"}, EBadQuery},
		"key":               {UnmaskQuery{Ref: ref, Pseudonyms: []string{"⟦key:ABC⟧"}, Reason: "x"}, EBadQuery},
		"no reason":         {UnmaskQuery{Ref: ref, Pseudonyms: toks}, EBadQuery},
		"other record's":    {UnmaskQuery{Ref: ref, Pseudonyms: others, Reason: "x"}, EStale},
		"tampered ref":      {UnmaskQuery{Ref: ref[:len(ref)-2] + "AA", Pseudonyms: toks, Reason: "x"}, EStale},
		"twice":             {UnmaskQuery{Ref: ref, Pseudonyms: []string{toks[0], toks[0]}, Reason: "x"}, EBadQuery},
		"too many":          {UnmaskQuery{Ref: ref, Pseudonyms: make([]string, MaxUnmask+1), Reason: "x"}, EBadQuery},
		"no approver (uid)": {UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"}, ""},
	} {
		ctx := c
		if name == "no approver (uid)" {
			ctx = peerCtx(1, nil)
			tc.code = EApproval
		}
		if _, err := f.eng.Unmask(ctx, tc.q); code(err) != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	if a.count() != 0 {
		t.Fatalf("refused unmasks asked the human %d times", a.count())
	}
	if _, err := f.eng.Unmask(peerCtx(1, &approver{deny: true}), UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"}); !errors.Is(err, errDenied) {
		t.Fatalf("denied: %v", err)
	}
	// Another epoch: the ref is stale.
	saved := f.eng.o.Masker
	f.eng.o.Masker = epochMasker{f.masker, "another-epoch"}
	if _, err := f.eng.Unmask(c, UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"}); code(err) != EStale {
		t.Fatalf("other epoch: %v", err)
	}
	f.eng.o.Masker = saved
	// The record changes while the human approves (the value swapped for
	// another of the same length): nothing is revealed.
	path := filepath.Join(f.root, "logs", "app.log")
	swap := &approver{hook: func() {
		b, _ := os.ReadFile(path)
		os.WriteFile(path, bytes.Replace(b, []byte("canary@example.org"), []byte("kanary@example.org"), 1), 0o644)
	}}
	if _, err := f.eng.Unmask(peerCtx(1, swap), UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"}); code(err) != EStale {
		t.Fatalf("swapped under the approval: %v", err)
	}
}

// TestUnmaskSecretSpan: a value that held a secret span (redacted inside
// the pseudonymised value) is never unmasked.
func TestUnmaskSecretSpan(t *testing.T) {
	line := "time=2026-10-30T12:00:01Z level=error msg=\"login failed\" email=\"bob password=hunter2hunter2\"\n"
	f := newFixture(t, line, withUnmask)
	ref, m := firstRef(t, f, func(q *Query) { q.Text = "login failed" })
	b, _ := json.Marshal(m)
	toks := tokenRe.FindAllString(string(b), -1)
	if len(toks) != 1 {
		t.Fatalf("want one pseudonym in %s", b)
	}
	a := &approver{}
	// Refused after the approval (before it, the refusal would tell which
	// pseudonym held a secret), naming none of them.
	_, err := f.eng.Unmask(peerCtx(1, a), UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"})
	var e *Error
	if code(err) != EBadQuery || a.count() != 1 || !errors.As(err, &e) || e.Span != "pseudonyms" {
		t.Fatalf("a value that held a secret: %v (%d approvals)", err, a.count())
	}
}

// TestLookup: a clear value of a detector kind gives the pseudonym the
// records show; other kinds, secrets and values not of the kind are
// refused; the limits are per peer uid and per console, by distinct value.
func TestLookup(t *testing.T) {
	const canary = "canary@example.org"
	f := newFixture(t, genLog(t0, 100, canary), func(o *Options) {
		o.Budgets = DefaultBudgets()
		o.Budgets.LookupsPerHour, o.Budgets.LookupsPerHourPerUID = 3, 2
	})
	_, toks := recordWith(t, f, "(order 25)", "email")
	res, err := f.eng.Lookup(peerCtx(1, nil), LookupQuery{Kind: "email", Values: []string{canary}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pseudonyms) != 1 || res.Pseudonyms[0] != toks[0] {
		t.Fatalf("lookup %v, record %v", res.Pseudonyms, toks)
	}
	// Searching by it finds the canary's records.
	sres, err := f.eng.Trace(ctx, TraceQuery{From: day.From, To: day.To, ID: res.Pseudonyms[0]})
	if err != nil || len(sres.Records) != 2 {
		t.Fatalf("search by the pseudonym: %v %d", err, len(sres.Records))
	}
	for name, lq := range map[string]LookupQuery{
		"key kind":      {Kind: "key", Values: []string{"x"}},
		"text token":    {Kind: "w", Values: []string{"x"}},
		"secret kind":   {Kind: "secret", Values: []string{"x"}},
		"personal kind": {Kind: "personal", Values: []string{"x"}},
		"not an email":  {Kind: "email", Values: []string{"hello world"}},
		"two values":    {Kind: "email", Values: []string{"a@example.com b@example.com"}},
		"other kind":    {Kind: "ip", Values: []string{canary}},
		"a secret":      {Kind: "email", Values: []string{"AKIAIOSFODNN7EXAMPLE"}},
		"no values":     {Kind: "email"},
		"too long":      {Kind: "email", Values: []string{strings.Repeat("a", MaxLookupValue) + "@example.com"}},
	} {
		if _, err := f.eng.Lookup(peerCtx(1, nil), lq); code(err) != EBadQuery {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Limits: 2 distinct values per uid, 3 per console.
	look := func(uid int, v string) error {
		_, err := f.eng.Lookup(peerCtx(uid, nil), LookupQuery{Kind: "email", Values: []string{v}})
		return err
	}
	if err := look(1, "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := look(1, "c@example.com"); code(err) != EOverBudget {
		t.Fatalf("third value for uid 1: %v", err)
	}
	if err := look(1, canary); err != nil {
		t.Fatalf("a value looked up already: %v", err)
	}
	if err := look(2, "c@example.com"); err != nil {
		t.Fatalf("uid 2: %v", err)
	}
	if err := look(2, "d@example.com"); code(err) != EOverBudget {
		t.Fatalf("over the console's: %v", err)
	}
	if f.eng.BudgetStatus().LookupsLeft != 0 {
		t.Fatal("lookups left")
	}
	// lookup = "approved": a read-pii approval for every call.
	g := newFixture(t, genLog(t0, 100, canary), func(o *Options) { o.LookupApproved = true })
	a := &approver{}
	if _, err := g.eng.Lookup(peerCtx(1, a), LookupQuery{Kind: "email", Values: []string{canary}, Reason: "the user named them"}); err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || a.last.Class != "read-pii" || !a.last.NeverAuto {
		t.Fatalf("approval %+v", a.last)
	}
	if _, err := g.eng.Lookup(peerCtx(1, nil), LookupQuery{Kind: "email", Values: []string{canary}}); code(err) != EApproval {
		t.Fatalf("no approver: %v", err)
	}
}

var (
	normToken = regexp.MustCompile(`⟦([a-z_]+):[A-Z0-9]+⟧`)
	normSeal  = regexp.MustCompile(`L[rc]1\.[A-Za-z0-9_.-]+`)
	normScan  = regexp.MustCompile(`"id":"[0-9a-f]{24}"`)
	normTime  = regexp.MustCompile(`"expires_at":"[^"]+"`)
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	b64digest = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// normalise replaces what differs by design between two consoles: the
// pseudonyms (another epoch key), refs and cursors (sealed under another
// K_ref), scan ids and their expiry, the epoch.
func normalise(b []byte, epoch string) string {
	s := normToken.ReplaceAllString(string(b), "⟦$1:ID⟧")
	s = normSeal.ReplaceAllString(s, "SEALED")
	s = normScan.ReplaceAllString(s, `"id":"SCAN"`)
	s = normTime.ReplaceAllString(s, `"expires_at":"T"`)
	return strings.ReplaceAll(s, epoch, "EPOCH")
}

// digestFree fails on a string of out (but refs and cursors) shaped like a
// digest: 64 hex digits or an unpadded base64url SHA-256.
func digestFree(t *testing.T, name string, out []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var walk func(k string, v any)
	walk = func(k string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(k, e)
			}
		case []any:
			for _, e := range x {
				walk(k, e)
			}
		case string:
			if k == "ref" || k == "cursor" {
				return
			}
			if hex64.MatchString(x) || b64digest.MatchString(x) {
				t.Fatalf("%s: digest-shaped %q at %q", name, x, k)
			}
		}
	}
	walk("", v)
}

// TestOracleScanUnmaskLookup (#26): two consoles whose logs differ only in
// a masked value (same kind, same length) give byte-identical answers to
// the agent, apart from pseudonyms and refs, for scans, unmasks, lookups,
// their refusals and the status; no digest-shaped field (plan hash, record
// digest) reaches the agent but sealed refs and cursors.
func TestOracleScanUnmaskLookup(t *testing.T) {
	outs := [2][]string{}
	for i, canary := range []string{"canary@example.org", "kanary@example.org"} {
		f := newFixture(t, genLog(t0, 30000, canary), func(o *Options) {
			oneGranulePerCall(o)
			o.ScanDeadline = o.Limits.Deadline
			o.Unmask = UnmaskApproved
		})
		f.fp = "POLICYFINGERPRINT"
		epoch := f.masker.Epoch()
		a := &approver{}
		c := peerCtx(1, a)
		add := func(name string, v any, err error) {
			var b []byte
			if err != nil {
				var e *Error
				if !errors.As(err, &e) {
					t.Fatalf("%s: %v", name, err)
				}
				b, _ = json.Marshal(e)
			} else {
				b, _ = json.Marshal(v)
			}
			digestFree(t, name, b)
			outs[i] = append(outs[i], name+": "+normalise(b, epoch))
		}
		// A scan by the canary's pseudonym, to its end.
		lres, err := f.eng.Lookup(c, LookupQuery{Kind: "email", Values: []string{canary}})
		add("lookup", lres, err)
		sq := TraceQuery{From: day.From, To: day.To, ID: lres.Pseudonyms[0], Limit: 50}
		res, err := f.eng.Scan(c, scanQ(t, ScanTrace, sq))
		add("scan", res, err)
		for err == nil && !res.Scan.Done {
			id := res.Scan.ID
			// The plan hash and the query digests never reach the agent.
			f.eng.scans.mu.Lock()
			hash, qd := f.eng.scans.m[id].hash, f.eng.scans.m[id].query
			f.eng.scans.mu.Unlock()
			b, _ := json.Marshal(res)
			if bytes.Contains(b, []byte(hash)) || bytes.Contains(b, []byte(qd)) || bytes.Contains(b, []byte(f.fp)) {
				t.Fatal("a plan hash on the socket")
			}
			next := sq
			next.Cursor = res.Result.(SearchResult).Cursor
			res, err = f.eng.Scan(c, scanQ(t, ScanTrace, next))
			add("scan page", res, err)
		}
		// The same scan asked by another uid: its own approval.
		_, err = f.eng.Scan(peerCtx(2, a), scanQ(t, ScanTrace, sq))
		add("scan by another uid (its own approval)", nil, err)
		// Unmask: another record's pseudonym (refused), a pseudonym of
		// the record that is not the canary (revealed), never-mode.
		ref, toks := recordWith(t, f, "(order 25)", "email")
		_, others := recordWith(t, f, "(order 26)", "email")
		_, err = f.eng.Unmask(c, UnmaskQuery{Ref: ref, Pseudonyms: others, Reason: "x"})
		add("unmask other record", nil, err)
		ref26, _ := recordWith(t, f, "(order 26)", "email")
		ures, err := f.eng.Unmask(c, UnmaskQuery{Ref: ref26, Pseudonyms: others, Reason: "x"})
		add("unmask", ures, err)
		f.eng.o.Unmask = UnmaskNever
		_, err = f.eng.Unmask(c, UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "x"})
		add("unmask never", nil, err)
		// Lookup refusals.
		_, err = f.eng.Lookup(c, LookupQuery{Kind: "email", Values: []string{"not an address"}})
		add("lookup refused", nil, err)
		_, err = f.eng.Lookup(c, LookupQuery{Kind: "key", Values: []string{canary}})
		add("lookup kind", nil, err)
		st := f.eng.BudgetStatus()
		add("status", st, nil)
		if a.count() != 3 {
			t.Fatalf("approvals %d", a.count())
		}
	}
	if testing.Verbose() {
		t.Log(strings.Join(outs[0], "\n"))
	}
	if len(outs[0]) != len(outs[1]) {
		t.Fatalf("%d vs %d answers", len(outs[0]), len(outs[1]))
	}
	for i := range outs[0] {
		if outs[0][i] != outs[1][i] {
			t.Fatalf("answers differ:\n%s\n%s", outs[0][i], outs[1][i])
		}
	}
}

// TestLookupApprovedBudget: an approved lookup is charged once approved:
// a denied (or pending) one uses none of the budget, and its run is
// charged once; one over the budget is refused before the human is asked.
func TestLookupApprovedBudget(t *testing.T) {
	f := newFixture(t, genLog(t0, 100, "c@example.org"), func(o *Options) {
		o.LookupApproved = true
		o.Budgets = DefaultBudgets()
		o.Budgets.LookupsPerHour, o.Budgets.LookupsPerHourPerUID = 3, 1
	})
	lq := LookupQuery{Kind: "email", Values: []string{"a@example.com"}, Reason: "r"}
	deny := &approver{deny: true}
	for range 3 {
		if _, err := f.eng.Lookup(peerCtx(1, deny), lq); !errors.Is(err, errDenied) {
			t.Fatalf("denied: %v", err)
		}
	}
	if f.eng.BudgetStatus().LookupsLeft != 3 {
		t.Fatalf("a denied lookup was charged: %d left", f.eng.BudgetStatus().LookupsLeft)
	}
	a := &approver{}
	// The pending call and the ticket's run: charged once.
	for range 2 {
		if _, err := f.eng.Lookup(peerCtx(1, a), lq); err != nil {
			t.Fatal(err)
		}
	}
	if left := f.eng.BudgetStatus().LookupsLeft; left != 2 {
		t.Fatalf("lookups left %d, want 2", left)
	}
	// uid 1 has used its one value: refused before anyone is asked.
	other := LookupQuery{Kind: "email", Values: []string{"b@example.com"}, Reason: "r"}
	if _, err := f.eng.Lookup(peerCtx(1, a), other); code(err) != EOverBudget || a.count() != 2 {
		t.Fatalf("over budget: %v, asked %d", err, a.count())
	}
	st := f.eng.BudgetStatusFor(peerCtx(1, nil))
	if st.LookupsLeftPeer == nil || *st.LookupsLeftPeer != 0 || st.LookupsLeft != 2 {
		t.Fatalf("status for uid 1: %+v", st)
	}
	if st := f.eng.BudgetStatusFor(peerCtx(2, nil)); st.LookupsLeftPeer == nil || *st.LookupsLeftPeer != 1 {
		t.Fatalf("status for uid 2: %+v", st)
	}
	if f.eng.BudgetStatusFor(context.Background()).LookupsLeftPeer != nil {
		t.Fatal("a peer's lookups with no peer")
	}
}

// TestUnmaskScreenExposure: the unmask screen says, for each pseudonym,
// how many records holding it agents were given in this epoch (the
// console's count); the screen, line by line.
func TestUnmaskScreenExposure(t *testing.T) {
	const canary = "canary@example.org"
	f := newFixture(t, genLog(t0, 100, canary), withUnmask)
	ref, toks := recordWith(t, f, "(order 25)", "email")
	since := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	var asked []string
	count := func(epoch string, ps []string) ([]int, bool, time.Time) {
		if epoch != f.eng.o.Masker.Epoch() {
			t.Errorf("counted for epoch %q", epoch)
		}
		asked = ps
		return []int{2}, true, since
	}
	a := &approver{}
	ctx := WithExposureCount(peerCtx(1, a), count)
	if _, err := f.eng.Unmask(ctx, UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "who failed"}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != toks[0] {
		t.Fatalf("counted %v", asked)
	}
	want := []string{"source: app", "record: 2026-10-30T12:00:25Z", "reveal: " + toks[0], "spans: 1 in this record (marked » «)",
		"returned to agents in this epoch: " + toks[0] + " in 2 records (counted by this console since 2026-11-06T08:00:00Z)"}
	if len(a.last.Body) != len(want)+1 {
		t.Fatalf("screen %q", a.last.Body)
	}
	for i, w := range want {
		if a.last.Body[i] != w {
			t.Errorf("line %d: %q, want %q", i, a.last.Body[i], w)
		}
	}
	if !strings.Contains(a.last.Body[len(want)], "»"+toks[0]+"«") {
		t.Errorf("record line %q", a.last.Body[len(want)])
	}
	// Lower bounds, one record, and no count.
	ctx = WithExposureCount(peerCtx(1, a), func(string, []string) ([]int, bool, time.Time) { return []int{1}, false, since })
	if _, err := f.eng.Unmask(ctx, UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "who failed"}); err != nil {
		t.Fatal(err)
	}
	if got := a.last.Body[4]; !strings.Contains(got, toks[0]+" in at least 1 records") {
		t.Errorf("lower bound: %q", got)
	}
	ctx = WithExposureCount(peerCtx(1, a), func(string, []string) ([]int, bool, time.Time) { return []int{1}, true, since })
	if _, err := f.eng.Unmask(ctx, UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "who failed"}); err != nil {
		t.Fatal(err)
	}
	if got := a.last.Body[4]; !strings.Contains(got, toks[0]+" in 1 record (") {
		t.Errorf("one record: %q", got)
	}
	if _, err := f.eng.Unmask(peerCtx(1, a), UnmaskQuery{Ref: ref, Pseudonyms: toks, Reason: "who failed"}); err != nil {
		t.Fatal(err)
	}
	if got := a.last.Body[4]; got != "returned to agents in this epoch: not counted by this console" {
		t.Errorf("no count: %q", got)
	}
	// The record's key: the same record, the same key, its epoch.
	k1, ep, ok := f.eng.RefRecord(ref)
	ref2, _ := recordWith(t, f, "(order 25)", "email")
	k2, _, _ := f.eng.RefRecord(ref2)
	if !ok || ep != f.eng.o.Masker.Epoch() || k1 == "" || k1 != k2 || strings.Contains(k1, canary) {
		t.Fatalf("record key %q %q %q %v", k1, k2, ep, ok)
	}
	if _, _, ok := f.eng.RefRecord("Lr1.forged"); ok {
		t.Fatal("a forged ref opened")
	}
}
