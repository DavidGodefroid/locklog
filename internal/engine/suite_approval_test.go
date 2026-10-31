//go:build unix

package engine

// The approval tools in the suites (LL-16b): log.scan (its request, its
// approval screen and its continuations), log.unmask and log.lookup go
// through the leak, oracle and injection checks of the other suites, over
// the same fixture (every local source and Loki). Change requests are the
// console's own (lockkit's change.request); suite_change_test.go runs them
// through a lockkit console.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
)

// screens is a console that approves (or denies) and keeps every screen it
// was shown.
type screens struct {
	mu   sync.Mutex
	list []Approval
	deny bool
}

func (s *screens) approve(_ context.Context, a Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, a)
	if s.deny {
		return errDenied
	}
	return nil
}

func (s *screens) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.list)
}

// take returns the screens shown since the last take.
func (s *screens) take() []Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.list
	s.list = nil
	return out
}

func (s *screens) ctx(uid int) context.Context {
	return WithPeer(context.Background(), Peer{UID: uid, Known: true, Approve: s.approve})
}

// approvalAnswer is one approval-tool call through Handle: its answer, the
// engine's refusal, or the console's own answer (a denial).
type approvalAnswer struct {
	res     json.RawMessage
	refusal *Error
	err     error
}

func (s *suite) handle(ctx context.Context, method string, params any) approvalAnswer {
	s.t.Helper()
	b, ok := params.(json.RawMessage)
	if !ok {
		var err error
		if b, err = json.Marshal(params); err != nil {
			s.t.Fatal(err)
		}
	}
	res, refusal, err := s.eng.Handle(ctx, method, b)
	if refusal != nil {
		return approvalAnswer{refusal: refusal}
	}
	if err != nil {
		return approvalAnswer{err: err}
	}
	out, err := json.Marshal(res)
	if err != nil {
		s.t.Fatal(err)
	}
	return approvalAnswer{res: out}
}

// scanTool is the scan tool of an agent method.
func scanTool(method string) string {
	return map[string]string{MethodSearch: ScanSearch, MethodCount: ScanCount, MethodPatterns: ScanPatterns, MethodTrace: ScanTrace}[method]
}

// scanRun is an approved scan run to its end: the scan answers (each the
// tool's result wrapped with the scan's info) and the refusal or console
// answer that ended it, if any.
type scanRun struct {
	pages   []json.RawMessage // ScanResult, whole
	results []json.RawMessage // its tool result
	infos   []ScanInfo
	refusal *Error
	err     error
}

// runScan asks for c as an approved scan and follows its cursor (within the
// approved plan, free) to the end of the plan, or until it has max pages
// (0: no maximum).
func (s *suite) runScan(ctx context.Context, c agentCall, max int) scanRun {
	return s.runScanReason(ctx, c, max, "suite "+c.name)
}

// runScanReason is runScan with the agent's reason.
func (s *suite) runScanReason(ctx context.Context, c agentCall, max int, reason string) scanRun {
	s.t.Helper()
	tool := scanTool(c.method)
	if tool == "" {
		s.t.Fatalf("%s: no scan tool for %s", c.name, c.method)
	}
	var params map[string]any
	if raw, ok := c.params.(json.RawMessage); ok {
		a := s.handle(ctx, MethodScan, map[string]any{"tool": tool, "query": raw, "reason": reason})
		return scanRun{refusal: a.refusal, err: a.err, pages: nonNil(a.res)}
	}
	b, _ := json.Marshal(c.params)
	json.Unmarshal(b, &params)
	var out scanRun
	for i := 0; ; i++ {
		a := s.handle(ctx, MethodScan, map[string]any{"tool": tool, "query": params, "reason": reason})
		if a.refusal != nil || a.err != nil {
			out.refusal, out.err = a.refusal, a.err
			return out
		}
		var sr struct {
			Scan   ScanInfo        `json:"scan"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(a.res, &sr); err != nil {
			s.t.Fatal(err)
		}
		out.pages = append(out.pages, a.res)
		out.results = append(out.results, sr.Result)
		out.infos = append(out.infos, sr.Scan)
		var st struct {
			Complete bool   `json:"complete"`
			Cursor   string `json:"cursor"`
		}
		json.Unmarshal(sr.Result, &st)
		if sr.Scan.Done != st.Complete {
			s.t.Fatalf("%s: scan done %v, result complete %v", c.name, sr.Scan.Done, st.Complete)
		}
		if st.Complete || max > 0 && len(out.pages) >= max {
			return out
		}
		if st.Cursor == "" {
			s.t.Fatalf("%s: an incomplete scan page without a cursor", c.name)
		}
		params["cursor"] = st.Cursor
		if i > 20000 {
			s.t.Fatalf("%s: the scan never ends", c.name)
		}
	}
}

func nonNil(b json.RawMessage) []json.RawMessage {
	if b == nil {
		return nil
	}
	return []json.RawMessage{b}
}

// scanPage scans one scan answer: its tool result as a page, the rest (the
// scan's info) against the corpus.
func (l *leakScanner) scanPage(where string, page []byte) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(page, &m); err != nil {
		l.t.Fatalf("%s: not a JSON object: %v", where, err)
	}
	if r, ok := m["result"]; ok {
		l.page(where+" (result)", r)
		delete(m, "result")
	}
	b, _ := json.Marshal(m)
	l.global(where, b)
}

// echoLine reports a screen line that shows the agent's own input as it
// wrote it (its query's text, regex, values and trace id; a lookup's
// values): the human must read what the agent asked. Those lines hold
// nothing the agent did not write, so they are left out of the corpus
// scan (an agent's value can share a few characters with a canary).
func echoLine(l string) bool {
	for _, p := range []string{"text: ", "regex: ", "where[", "trace id: ", "  "} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// screen scans an approval screen against the corpus: its header, body and
// warnings, but for the lines that echo the agent's input and its note
// (the agent's reason: unmask and lookup screens mask it, a scan's shows
// it as written; the console escapes it). own are canaries the call
// carried, which the agent may see echoed anywhere on its screen.
func (l *leakScanner) screen(where string, a Approval, own []masktest.Canary) {
	a.Note = ""
	a.Body = slices.DeleteFunc(slices.Clone(a.Body), echoLine)
	b, _ := json.Marshal(a)
	before := len(l.hits)
	l.global(where+" (screen)", b)
	kept := l.hits[:before]
	for _, h := range l.hits[before:] {
		if !slices.ContainsFunc(own, func(c masktest.Canary) bool {
			return c.Value == h.Canary.Value || h.Canary.Kind == "person_name" && c.Kind == "person_name"
		}) {
			kept = append(kept, h)
		}
	}
	l.hits = kept
}

// consoleAnswer scans a console's answer passed back by the engine (a
// denial) against the corpus.
func (l *leakScanner) consoleAnswer(where string, err error) {
	l.global(where+" (console answer)", []byte(jsonString(err.Error())))
}

// suiteTokenRe finds the pseudonyms of an output.
var suiteTokenRe = regexp.MustCompile(`⟦([a-z_]+):[A-Z0-9]+⟧`)

// unmaskable returns the distinct pseudonyms of a record that unmask may
// reveal (not secrets, redactions nor field names).
func unmaskable(rec []byte) []string {
	var out []string
	for _, m := range suiteTokenRe.FindAllStringSubmatch(string(rec), -1) {
		if m[1] != mask.KeyKind && !slices.Contains(out, m[0]) {
			out = append(out, m[0])
		}
	}
	return out
}

// TestSuiteApprovalLeak: over the leak corpus (every kind in every encoding
// and position, every source), every suite call as an approved scan, run
// through its continuations on one approval; unmask of the records'
// pseudonyms, one at a time; lookup of the corpus values; and every
// refusal on the way (including the canaries written into the scan's
// query, the unmask and the lookup). Answers, refusals, the console's
// answers and the approval screens hold no canary; an unmask reveals only
// the span approved, exactly: that pseudonym's value, which is its
// record's, and no other value of the record.
func TestSuiteApprovalLeak(t *testing.T) {
	heavySuite(t)
	recs := leakCorpus(16)
	for _, mode := range []string{mask.StructuredRedactUnknown, mask.StructuredDetect} {
		t.Run(mode, func(t *testing.T) {
			s := newSuite(t, recs, suiteConfig{Structured: mode, Workers: 2, Cost: oneGranuleCost(),
				Engine:  func(o *Options) { o.Unmask = UnmaskApproved; o.ScanDeadline = o.Limits.Deadline },
				Budgets: func(b *Budgets) { b.LookupsPerHour, b.LookupsPerHourPerUID = 1<<20, 1<<20 }})
			l := newLeakScanner(t, recs)
			con := &screens{}
			ctx := con.ctx(1)
			var all []json.RawMessage // every record the scans returned
			for _, c := range suiteCalls() {
				r := s.runScan(ctx, c, 0)
				shown := con.take()
				for i, a := range shown {
					l.screen(fmt.Sprintf("scan %s screen %d", c.name, i), a, nil)
				}
				if r.refusal != nil || r.err != nil {
					t.Errorf("scan %s: refused: %v %v", c.name, r.refusal, r.err)
					continue
				}
				if len(shown) != 1 {
					t.Errorf("scan %s: %d approvals, want 1 for its whole plan", c.name, len(shown))
				}
				if c.method == MethodSearch && len(r.pages) < 2 {
					t.Errorf("scan %s: %d pages: not continued", c.name, len(r.pages))
				}
				for i, p := range r.pages {
					l.scanPage(fmt.Sprintf("scan %s page %d", c.name, i), p)
				}
				if c.name == "search all" {
					for _, res := range r.results {
						var sr SearchResult
						json.Unmarshal(res, &sr)
						all = append(all, sr.Records...)
					}
				}
			}
			total := 0
			for _, rs := range recs {
				total += len(rs)
			}
			if len(all) != total {
				t.Errorf("scan search all returned %d records, want %d", len(all), total)
			}
			unmaskLeak(t, s, l, con, recs, all)
			lookupLeak(t, s, l, con)
			scanLeakRefusals(t, mode, recs, l, con)
			l.report(mode)
			t.Logf("%s: %d pages, %d records, %d whole-corpus scans", mode, l.pages, l.nrecs, l.nglobs)
		})
	}
}

// unmaskLeak unmasks pseudonyms of the records, one per call: for each
// source, every record whose pseudonyms are not all of one kind up to a
// sample, each of its pseudonyms in turn; then the refusals.
func unmaskLeak(t *testing.T, s *suite, l *leakScanner, con *screens, recs map[string][]suiteRecord, all []json.RawMessage) {
	ctx := con.ctx(1)
	perSource := map[string]int{}
	unmasked := 0
	var otherRef string
	var otherTok string
	for _, rec := range all {
		var h struct {
			Source string `json:"source"`
			Ref    string `json:"ref"`
			TS     string `json:"ts"`
		}
		json.Unmarshal(rec, &h)
		toks := unmaskable(rec)
		if len(toks) == 0 {
			continue
		}
		if otherRef == "" {
			otherRef, otherTok = h.Ref, toks[0]
			continue
		}
		if perSource[h.Source] >= 40 {
			continue
		}
		perSource[h.Source]++
		ts, _ := time.Parse(time.RFC3339Nano, h.TS)
		own := l.bySec[h.Source][ts.Unix()]
		values := map[string]string{}
		for _, tok := range toks {
			where := fmt.Sprintf("unmask %s of %s@%s", tok, h.Source, h.TS)
			a := s.handle(ctx, MethodUnmask, UnmaskQuery{Ref: h.Ref, Pseudonyms: []string{tok}, Reason: "suite: who failed"})
			shown := con.take()
			if len(shown) != 1 && a.refusal == nil {
				t.Errorf("%s: %d approvals", where, len(shown))
			}
			for _, sc := range shown {
				l.screen(where, sc, nil)
				// The record, its approved spans marked » «: only those.
				body := sc.Body[len(sc.Body)-1]
				if n := strings.Count(body, "»"); n != strings.Count(body, "»"+tok+"«") || n == 0 {
					t.Errorf("%s: the screen marks other spans than %s: %.300q", where, tok, body)
				}
			}
			if a.err != nil {
				t.Fatalf("%s: %v", where, a.err)
			}
			if a.refusal != nil {
				// A value that held a secret span: never revealed.
				l.refusal(where, a.refusal, nil)
				if a.refusal.Code != EBadQuery || !strings.Contains(a.refusal.Message, "held a secret") {
					t.Errorf("%s: refused: %v", where, a.refusal)
				}
				continue
			}
			var res UnmaskResult
			json.Unmarshal(a.res, &res)
			if len(res.Values) != 1 || res.Values[0].Pseudonym != tok {
				t.Fatalf("%s: values %+v", where, res.Values)
			}
			v := res.Values[0].Value
			// The rest of the answer holds nothing.
			res.Values[0].Value = ""
			b, _ := json.Marshal(res)
			l.global(where+" (answer without the value)", b)
			if v == "" {
				t.Errorf("%s: an empty value", where)
			}
			values[tok] = v
			unmasked++
		}
		for tok, v := range values {
			// Exactly the span approved: a value that masks, on its
			// own, as a pseudonym of the approved kind is the approved
			// pseudonym's.
			if m := s.masker.Text(v); suiteTokenRe.FindString(m) == m {
				if kind, _ := tokenKind(m); strings.HasPrefix(tok, mask.Open+kind+":") && m != tok {
					t.Errorf("%s@%s: unmasking %s revealed the value of %s", h.Source, h.TS, tok, m)
				}
			}
			// The value is the record's own: one of its canaries, or
			// a value its corpus line holds. (A record whose line
			// carries a time of its own is found by its source only.)
			if !ownValue(v, own, recordLine(recs, h.Source, ts)) && !ownValue(v, l.bySrc[h.Source], "") {
				t.Errorf("%s@%s: %s revealed %q, not a value of its record", h.Source, h.TS, tok, v)
			}
		}
	}
	if unmasked < 100 || len(perSource) < len(suiteSources()) {
		t.Errorf("%d values unmasked over %d sources: the unmask path is not exercised", unmasked, len(perSource))
	}
	// Refusals: another record's pseudonym, a forged one, a secret, a
	// field name, a denial, unmask off.
	var rec0 []byte
	for _, r := range all {
		if len(unmaskable(r)) > 0 && !strings.Contains(string(r), otherTok) {
			rec0 = r
			break
		}
	}
	var h0 struct {
		Ref string `json:"ref"`
	}
	json.Unmarshal(rec0, &h0)
	for name, q := range map[string]UnmaskQuery{
		"another record's pseudonym": {Ref: h0.Ref, Pseudonyms: []string{otherTok}, Reason: "x"},
		"a forged pseudonym":         {Ref: h0.Ref, Pseudonyms: []string{"⟦email:AAAAAAAAAAAA⟧"}, Reason: "x"},
		"a secret":                   {Ref: h0.Ref, Pseudonyms: []string{"⟦secret⟧"}, Reason: "x"},
		"a field name":               {Ref: h0.Ref, Pseudonyms: []string{"⟦key:AAAAAAAAAAAA⟧"}, Reason: "x"},
		"a tampered ref":             {Ref: otherRef[:len(otherRef)-4] + "AAAA", Pseudonyms: []string{otherTok}, Reason: "x"},
	} {
		a := s.handle(ctx, MethodUnmask, q)
		for _, sc := range con.take() {
			l.screen("unmask "+name, sc, nil)
		}
		if a.refusal == nil {
			t.Errorf("unmask %s: not refused: %s %v", name, a.res, a.err)
			continue
		}
		l.refusal("unmask "+name, a.refusal, nil)
	}
	con.deny = true
	a := s.handle(ctx, MethodUnmask, UnmaskQuery{Ref: otherRef, Pseudonyms: []string{otherTok}, Reason: "x"})
	con.deny = false
	for _, sc := range con.take() {
		l.screen("unmask denied", sc, nil)
	}
	if !errors.Is(a.err, errDenied) || a.res != nil {
		t.Errorf("unmask denied: %+v", a)
	} else {
		l.consoleAnswer("unmask denied", a.err)
	}
	never := *s
	o := s.eng.o
	o.Unmask = UnmaskNever
	never.eng, _ = New(o)
	if a := never.handle(ctx, MethodUnmask, UnmaskQuery{Ref: otherRef, Pseudonyms: []string{otherTok}, Reason: "x"}); a.refusal == nil || a.refusal.Code != EUnmaskNever {
		t.Errorf("unmask never: %+v", a)
	} else {
		l.refusal("unmask never", a.refusal, nil)
	}
	if con.count() != 0 {
		t.Errorf("unmask never showed a screen")
	}
}

// ownValue reports whether v, an unmasked value, is its record's: a form
// of one of its canaries, or text its corpus line holds (raw or decoded).
func ownValue(v string, own []masktest.Canary, line string) bool {
	lv := strings.ToLower(v)
	for _, c := range own {
		for _, f := range masktest.Forms(c) {
			if strings.EqualFold(f, v) || strings.Contains(lv, strings.ToLower(f)) {
				return true
			}
		}
	}
	for _, view := range views(line) {
		if strings.Contains(view, lv) {
			return true
		}
	}
	return false
}

// recordLine is the line of the corpus record of src at ts (its second)
// as its source holds it, or "".
func recordLine(recs map[string][]suiteRecord, src string, ts time.Time) string {
	for _, r := range recs[src] {
		if r.TS.Unix() == ts.Unix() {
			switch src {
			case srcJournal, srcDocker:
				return r.payload(false)
			case srcLoki:
				return render("json", r)
			}
			return render(src, r)
		}
	}
	return ""
}

// lookupLeak looks up the corpus values of every detector kind (raw and in
// every encoding): an answer holds the pseudonyms only, never the value; a
// refusal names no value. With lookup = "approved", the screen shows the
// human the agent's values and nothing of the logs.
func lookupLeak(t *testing.T, s *suite, l *leakScanner, con *screens) {
	ctx := con.ctx(1)
	lk := s.masker
	kinds := lk.DetectorKinds()
	per := len(masktest.Kinds) * len(masktest.Encodings)
	lines := masktest.New(16).Lines(per)
	answered, refused := 0, 0
	for _, approved := range []bool{false, true} {
		e := s
		if approved {
			c := *s
			o := s.eng.o
			o.LookupApproved = true
			c.eng, _ = New(o)
			e = &c
		}
		for _, ln := range lines {
			for _, c := range ln.Canaries {
				kind := c.Kind
				if !slices.Contains(kinds, kind) {
					kind = kinds[(answered+refused)%len(kinds)]
				}
				for _, v := range []string{c.Value, masktest.Encode(c.Value, masktest.Encodings[ln.Encoding])} {
					where := fmt.Sprintf("lookup %s %q (approved %v)", kind, v, approved)
					a := e.handle(ctx, MethodLookup, LookupQuery{Kind: kind, Values: []string{v}, Reason: "the user gave it"})
					shown := con.take()
					if approved != (len(shown) == 1) && a.refusal == nil {
						t.Errorf("%s: %d screens", where, len(shown))
					}
					for _, sc := range shown {
						l.screen(where, sc, []masktest.Canary{c})
					}
					switch {
					case a.err != nil:
						t.Fatalf("%s: %v", where, a.err)
					case a.refusal != nil:
						refused++
						l.refusal(where, a.refusal, []masktest.Canary{c})
					default:
						answered++
						l.hits = append(l.hits, masktest.Scan(where, a.res, []masktest.Canary{c})...)
						l.global(where, a.res)
						var res LookupResult
						json.Unmarshal(a.res, &res)
						if len(res.Pseudonyms) != 1 || !strings.HasPrefix(res.Pseudonyms[0], mask.Open+kind+":") {
							t.Errorf("%s: %s", where, a.res)
						}
					}
				}
			}
		}
	}
	if answered < len(masktest.Kinds) || refused == 0 {
		t.Errorf("lookups: %d answered, %d refused: the paths are not exercised", answered, refused)
	}
}

// scanLeakRefusals writes canaries (every kind, in every encoding with
// LOCKLOG_SUITE_FULL=1) into a scan's query positions and its reason:
// refusals, answers and screens hold none of them but the agent's own on
// its screen.
func scanLeakRefusals(t *testing.T, mode string, recs map[string][]suiteRecord, l *leakScanner, con *screens) {
	ctx := con.ctx(1)
	per := len(masktest.Kinds) * len(masktest.Encodings)
	// The calls run on the corpus's first records of each source (every
	// kind and encoding is still in the data), each scan to its end.
	head := map[string][]suiteRecord{}
	for src, rs := range recs {
		head[src] = rs[:min(len(rs), 2*per)]
	}
	s := newSuite(t, head, suiteConfig{Structured: mode, Workers: 2,
		Engine: func(o *Options) { o.Unmask = UnmaskApproved }})
	lines := masktest.New(99).Lines(per)
	seen := map[string]bool{}
	refused := 0
	n := 0
	for _, ln := range lines {
		c, enc := ln.Canaries[0], masktest.Encodings[ln.Encoding]
		if !suiteFull() && seen[c.Kind] && seen[enc] {
			continue
		}
		seen[c.Kind], seen[enc] = true, true
		n++
		w := masktest.Encode(c.Value, enc)
		own := []masktest.Canary{c}
		calls := []agentCall{
			{"text", MethodSearch, suiteQuery(func(q *Query) { q.Text = w })},
			{"regex", MethodSearch, suiteQuery(func(q *Query) { q.Regex = regexp.QuoteMeta(w) })},
			{"value", MethodCount, CountQuery{Query: suiteQuery(func(q *Query) { q.Where = []Pred{{Field: "detail", Op: OpEq, Value: raw(w)}} })}},
			{"field", MethodPatterns, PatternsQuery{Query: suiteQuery(func(q *Query) { q.Where = []Pred{{Field: w, Op: OpExists}} })}},
			{"label", MethodSearch, suiteQuery(func(q *Query) { q.Where = []Pred{{Label: "app", Op: OpEq, Value: raw(w)}} })},
			{"trace id", MethodTrace, TraceQuery{From: suiteFrom, To: suiteTo, ID: w, Limit: 10}},
			{"cursor", MethodSearch, suiteQuery(func(q *Query) { q.Cursor = w })},
			{"raw", MethodSearch, json.RawMessage(`{"from":` + jsonString(w) + `}`)},
		}
		for _, call := range calls {
			where := fmt.Sprintf("scan %s with %s %q", call.name, c.Kind, w)
			r := s.runScan(ctx, call, 0)
			for _, sc := range con.take() {
				l.screen(where, sc, own)
			}
			if r.refusal != nil {
				refused++
				l.refusal(where, r.refusal, own)
				continue
			}
			if r.err != nil {
				t.Fatalf("%s: %v", where, r.err)
			}
			for j, p := range r.pages {
				l.hits = append(l.hits, masktest.Scan(fmt.Sprintf("%s page %d", where, j), p, own)...)
				l.scanPage(fmt.Sprintf("%s page %d", where, j), p)
			}
		}
		// The reason: masked on the screen.
		rs := s.runScanReason(ctx, agentCall{"reason", MethodCount, CountQuery{Query: suiteQuery(nil), ByPattern: true}}, 0,
			"the user "+w+" says it failed")
		for _, sc := range con.take() {
			// The scan's screen shows the reason as the agent wrote
			// it (unmask and lookup screens mask it).
			l.screen("scan reason "+c.Kind, sc, own)
		}
		if rs.refusal != nil {
			l.refusal("scan reason", rs.refusal, own)
		}
	}
	// A scan denied: the console's answer passed back.
	con.deny = true
	r := s.runScan(ctx, agentCall{"denied", MethodSearch, suiteQuery(func(q *Query) { q.Text = "upstream timed out" })}, 0)
	con.deny = false
	for _, sc := range con.take() {
		l.screen("scan denied", sc, nil)
	}
	if !errors.Is(r.err, errDenied) {
		t.Errorf("scan denied: %+v", r)
	} else {
		l.consoleAnswer("scan denied", r.err)
	}
	if refused < n*4 {
		t.Errorf("only %d scans refused: the refusal paths are not exercised", refused)
	}
}

func suiteFull() bool { return os.Getenv("LOCKLOG_SUITE_FULL") == "1" }

func mustJSON(t testing.TB, v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// normalizeScan renders scan answers for comparison: each tool result
// normalised as a page (normalizePages), the scan's info without its id
// and expiry (random, and the time of the approval).
func normalizeScan(t testing.TB, e *Engine, r scanRun) ([]string, map[string]int) {
	pages, ids := normalizePages(t, e, r.results)
	for i, info := range r.infos {
		pages[i] = fmt.Sprintf("done %v reattached %v: %s", info.Done, info.Reattached, pages[i])
	}
	return pages, ids
}

// TestSuiteApprovalOracle: approved scans of every oracle call, unmask and
// lookup on the oracle corpus give the same answers, modulo pseudonym ids,
// whichever values are planted (same lengths): the same pages, stopping
// points and plan positions, approvals and refusals.
func TestSuiteApprovalOracle(t *testing.T) {
	heavySuite(t)
	a, b := oraclePair(t, true)
	ep, err := pii.NewEpoch(suiteBase)
	if err != nil {
		t.Fatal(err)
	}
	cfg := suiteConfig{Structured: mask.StructuredDetect, Epoch: ep, Cost: oneGranuleCost(), Workers: 2,
		Engine:  func(o *Options) { o.Unmask = UnmaskApproved; o.ScanDeadline = o.Limits.Deadline },
		Budgets: func(b *Budgets) { b.LookupsPerHour, b.LookupsPerHourPerUID = 1<<20, 1<<20 }}
	sa := newSuite(t, oracleCorpus(a, 300, 9000, suiteSources()), cfg)
	sb := newSuite(t, oracleCorpus(b, 300, 9000, suiteSources()), cfg)
	ca, cb := &screens{}, &screens{}
	screenText := func(c *screens) string {
		var out []string
		for _, s := range c.take() {
			b, _ := json.Marshal(s)
			out = append(out, anyToken.ReplaceAllString(string(b), "⟦$1⟧"))
		}
		return strings.Join(out, "\n")
	}
	for _, c := range oracleCalls() {
		x, nx := normalizeScan(t, sa.eng, sa.runScan(ca.ctx(1), c, 0))
		y, ny := normalizeScan(t, sb.eng, sb.runScan(cb.ctx(1), c, 0))
		if d := firstDiff(x, y); d != "" {
			t.Errorf("scan %s: the planted values change the answer: %s", c.name, d)
		}
		if !maps.Equal(nx, ny) {
			t.Errorf("scan %s: distinct pseudonyms %v vs %v", c.name, nx, ny)
		}
		if len(x) < 3 && !strings.HasPrefix(c.name, "patterns") {
			t.Errorf("scan %s: %d pages: no stopping point compared", c.name, len(x))
		}
		if sx, sy := screenText(ca), screenText(cb); sx != sy {
			t.Errorf("scan %s: the screens differ:\n%s\n%s", c.name, sx, sy)
		}
	}
	// Unmask the planted value of the same record on both sides, and a
	// value of the record that is not planted; lookups of the planted
	// values and of values the logs do not hold.
	ua, ub := oracleUnmask(t, sa, ca, a), oracleUnmask(t, sb, cb, b)
	if d := firstDiff(ua, ub); d != "" {
		t.Errorf("unmask and lookup: the planted values change the answer: %s", d)
	}
}

// oracleUnmask runs unmasks and lookups on an oracle fixture and renders
// their answers with pseudonym ids dropped and the revealed values replaced
// by "planted" or "other" (the planted values differ by construction).
func oracleUnmask(t *testing.T, s *suite, con *screens, vals oracleValues) []string {
	ctx := con.ctx(1)
	var out []string
	add := func(name string, a approvalAnswer) {
		var b []byte
		switch {
		case a.refusal != nil:
			b, _ = json.Marshal(a.refusal)
		case a.err != nil:
			b = []byte(a.err.Error())
		default:
			b = a.res
		}
		txt := string(b)
		for _, v := range vals {
			txt = strings.ReplaceAll(txt, jsonString(v), `"planted"`)
		}
		txt = strings.ReplaceAll(anyToken.ReplaceAllString(txt, "⟦$1⟧"), s.masker.Epoch(), "EPOCH")
		var scr []string
		for _, sc := range con.take() {
			b, _ := json.Marshal(sc)
			scr = append(scr, anyToken.ReplaceAllString(string(b), "⟦$1⟧"))
		}
		out = append(out, name+": "+txt+" screens "+strings.Join(scr, " | "))
	}
	// The record of order 0 (planted with the first kind) in each source.
	for _, src := range suiteSources() {
		pages := s.mustRun(agentCall{"order 0", MethodSearch, suiteQuery(func(q *Query) {
			q.Sources = []string{src}
			q.Text = "(order 0)"
			q.Limit = 5
		})})
		var sr SearchResult
		json.Unmarshal(pages[0], &sr)
		if len(sr.Records) != 1 {
			t.Fatalf("%s: %d records of order 0", src, len(sr.Records))
		}
		var h struct {
			Ref string `json:"ref"`
		}
		json.Unmarshal(sr.Records[0], &h)
		for i, tok := range unmaskable(sr.Records[0]) {
			add(fmt.Sprintf("%s unmask %d", src, i), s.handle(ctx, MethodUnmask, UnmaskQuery{Ref: h.Ref, Pseudonyms: []string{tok}, Reason: "x"}))
		}
	}
	for _, k := range masktest.Kinds {
		if !slices.Contains(s.masker.DetectorKinds(), k) {
			continue
		}
		add("lookup "+k, s.handle(ctx, MethodLookup, LookupQuery{Kind: k, Values: []string{vals[k]}}))
	}
	return out
}

// TestSuiteApprovalInjection: control, bidi and zero-width characters and
// brackets in log content reach no approval screen, scan answer, unmask or
// lookup answer unescaped, and forge no placeholder.
func TestSuiteApprovalInjection(t *testing.T) {
	recs := injectionCorpus()
	// Records whose pseudonyms sit next to (and inside) injections, to
	// unmask.
	var extra []suiteRecord
	for i, inj := range injections {
		ts := suiteBase.Add(time.Hour + time.Duration(i)*time.Second)
		extra = append(extra, suiteRecord{TS: ts, Kind: "json",
			Payload: fmt.Sprintf(`{"ts":"%s","level":"error","msg":%s}`, tsMark, jsonString("render pdf for jane.doe@example.com"+inj+" from 203.0.113.9"+inj+"x failed"))})
	}
	// Invisible characters inside the values themselves.
	for i, v := range []string{"ja\u200bne.doe@example.com", "jane.d\u202eoe@example.com", "203.0\u2060.113.9", "jo\u00adhn@exa\ufeffmple.com"} {
		extra = append(extra, suiteRecord{TS: suiteBase.Add(2*time.Hour + time.Duration(i)*time.Second), Kind: "json",
			Payload: fmt.Sprintf(`{"ts":"%s","level":"error","msg":%s,"user":%s}`, tsMark, jsonString("render pdf for "+v+" failed"), jsonString(v))})
	}
	for src := range recs {
		recs[src] = append(slices.Clone(recs[src]), extra...)
	}
	for _, mode := range []string{mask.StructuredRedactUnknown, mask.StructuredDetect} {
		t.Run(mode, func(t *testing.T) {
			s := newSuite(t, recs, suiteConfig{Structured: mode, NoAgentMeta: true,
				Engine: func(o *Options) { o.Unmask = UnmaskApproved }})
			con := &screens{}
			ctx := con.ctx(1)
			// A screen's note is the agent's reason, as it wrote it:
			// the console escapes it (lockkit's console.Screen). The
			// rest carries what the engine read.
			checkScreens := func(where string) {
				for i, sc := range con.take() {
					sc.Note = ""
					b, _ := json.Marshal(sc)
					checkInjection(t, fmt.Sprintf("%s screen %d", where, i), b)
				}
			}
			var all []json.RawMessage
			for _, c := range suiteCalls() {
				r := s.runScan(ctx, c, 0)
				checkScreens("scan " + c.name)
				if r.refusal != nil || r.err != nil {
					t.Fatalf("scan %s: %v %v", c.name, r.refusal, r.err)
				}
				for i, p := range r.pages {
					checkInjection(t, fmt.Sprintf("scan %s page %d", c.name, i), p)
				}
				if c.name == "search all" {
					for _, res := range r.results {
						var sr SearchResult
						json.Unmarshal(res, &sr)
						all = append(all, sr.Records...)
					}
				}
			}
			unmasked := 0
			for _, rec := range all {
				var h struct {
					Ref string `json:"ref"`
				}
				json.Unmarshal(rec, &h)
				for _, tok := range unmaskable(rec) {
					a := s.handle(ctx, MethodUnmask, UnmaskQuery{Ref: h.Ref, Pseudonyms: []string{tok}, Reason: "who \x1b[31m⟦email:FORGED000001⟧ \u202e"})
					checkScreens("unmask " + tok)
					switch {
					case a.err != nil:
						t.Fatalf("unmask %s: %v", tok, a.err)
					case a.refusal != nil:
						b, _ := json.Marshal(a.refusal)
						checkInjection(t, "unmask refusal", b)
					default:
						unmasked++
						checkInjection(t, "unmask "+tok, a.res)
					}
				}
			}
			if unmasked == 0 {
				t.Fatal("nothing unmasked")
			}
			for _, inj := range injections {
				for _, v := range []string{inj, "jane.doe@example.com" + inj, "jane" + inj + "@example.com"} {
					a := s.handle(ctx, MethodLookup, LookupQuery{Kind: "email", Values: []string{v}, Reason: inj})
					var b []byte
					if a.refusal != nil {
						b, _ = json.Marshal(a.refusal)
					} else {
						b = a.res
					}
					checkInjection(t, fmt.Sprintf("lookup %q", v), b)
				}
				a := s.handle(ctx, MethodScan, ScanQuery{Tool: ScanSearch, Query: mustJSON(t, suiteQuery(func(q *Query) { q.Text = "failed" })), Reason: inj})
				checkScreens("scan reason")
				if a.refusal != nil {
					b, _ := json.Marshal(a.refusal)
					checkInjection(t, "scan reason refusal", b)
				}
			}
		})
	}
}
