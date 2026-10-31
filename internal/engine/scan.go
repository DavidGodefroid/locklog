package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// MethodScan is an approved scan (locklog_scan).
const MethodScan = "log.scan"

// MaxScans bounds the approved scans in progress on a console.
const MaxScans = 8

// MaxReason bounds the reason an agent gives for an approval.
const MaxReason = 300

// Scan states (lockkit plans' lifecycle: Begin once, Executing, then
// Executed when the plan is exhausted, or Expired at the TTL).
const (
	scanExecuting = "executing"
	scanExecuted  = "executed"
	scanExpired   = "expired"
)

// The tools an approved scan runs.
const (
	ScanSearch   = "search"
	ScanCount    = "count"
	ScanPatterns = "patterns"
	ScanTrace    = "trace"
)

// ScanQuery is an approved scan (log.scan): a search, count, patterns or
// trace call over the free budgets, approved once (class read) for its
// whole plan. Query is that tool's parameters; with its cursor it
// continues the approved plan, free and with no new approval.
type ScanQuery struct {
	Tool   string          `json:"tool"`
	Query  json.RawMessage `json:"query"`
	Reason string          `json:"reason,omitempty"`
}

// ScanInfo names the approved scan of a result: a random id (it carries
// nothing about the plan), when it expires and whether this call
// re-attached to a scan approved earlier.
type ScanInfo struct {
	ID         string    `json:"id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Reattached bool      `json:"reattached,omitempty"`
	// Done: the plan is exhausted and the scan ended.
	Done bool `json:"done"`
}

// ScanResult is the answer of a scan: the tool's own result (its cursor
// continues the scan) and the scan.
type ScanResult struct {
	Scan   ScanInfo `json:"scan"`
	Tool   string   `json:"tool"`
	Result any      `json:"result"`
}

// scanState is one approved scan. Its plan hash is keyed (HMAC under
// K_ref) and never leaves the console; the agent knows the scan by its id.
type scanState struct {
	id       string
	uid      int
	hash     string
	policyFP string
	tool     string
	// plan is the byte plan frozen at the approval, desc its order.
	plan    source.Byteplan
	desc    bool
	query   string // the query digest bound to the scan (cursors)
	expires time.Time
	state   string
	bytes   int64
	// cursor is the scan's one live position: the cursor its last call
	// returned ("" before the first answer). Only it continues the scan,
	// and a reissued scan resumes there.
	cursor string
	// busy: a call of the scan runs (one at a time).
	busy bool
}

// limit is what the scan may process in all: its frozen plan's bytes, or
// for a plan with remote slices (of unknown bytes) the scan budget.
func (s *scanState) limit(e *Engine) int64 {
	for _, c := range s.plan.Chunks {
		if e.remote(c.Source) {
			return e.o.ScanBytes
		}
	}
	return s.plan.Bytes()
}

type scanStore struct {
	mu sync.Mutex
	m  map[string]*scanState
}

// scanCall is the scan a call runs under: resolved from the cursor of a
// continuation, or admitted (approved, or re-attached) by the first call.
type scanCall struct {
	e     *Engine
	start time.Time // the request's arrival (the approval wait counts)
	tool  string
	note  string
	peer  Peer
	s     *scanState
	// reattached: the first call found the plan approved already.
	reattached bool
	lim        source.Limiter
	// claimed: this call holds the scan (scanState.busy).
	claimed bool
}

// errScanBusy refuses a second call of a scan while one runs.
var errScanBusy = &Error{Code: EStale, Span: "cursor", Message: "a call of this approved scan is in progress: wait for its answer and continue with its cursor"}

// claim takes the scan for this call: refused while another call runs, and
// for a continuation whose cursor is not the scan's live position.
func (sc *scanCall) claim(s *scanState, cursor string, check bool) *Error {
	st := &sc.e.scans
	st.mu.Lock()
	defer st.mu.Unlock()
	if s.busy {
		return errScanBusy
	}
	if check && subtle.ConstantTimeCompare([]byte(s.cursor), []byte(cursor)) != 1 {
		return &Error{Code: EStale, Span: "cursor", Message: "only the last cursor of an approved scan continues it (or run locklog_scan again without a cursor to resume it)"}
	}
	s.busy, sc.s, sc.claimed = true, s, true
	return nil
}

// release ends this call's hold on the scan, recording its live position
// when the call succeeded.
func (sc *scanCall) release(ok bool, cursor string) {
	if !sc.claimed {
		return
	}
	st := &sc.e.scans
	st.mu.Lock()
	defer st.mu.Unlock()
	sc.s.busy, sc.claimed = false, false
	if ok {
		sc.s.cursor = cursor
	}
}

// bytesLeft is what the scan may still process.
func (sc *scanCall) bytesLeft() int64 {
	st := &sc.e.scans
	st.mu.Lock()
	defer st.mu.Unlock()
	return sc.s.limit(sc.e) - sc.s.bytes
}

// errReattach asks Scan to resume a scan at its live position.
type errReattach struct{ s *scanState }

func (errReattach) Error() string { return "engine: resume the approved scan" }

// deadline is the deadline of a call of the scan: the scan deadline, and
// at most two thirds of what scanCallBudget leaves of the request (the
// hard deadline adds half the deadline). Under a second: no work.
func (sc *scanCall) deadline() time.Duration {
	left := scanCallBudget - time.Since(sc.start)
	d := min(sc.e.o.ScanDeadline, left*2/3)
	if d < time.Second {
		return 0
	}
	return d
}

// charge adds what a call of the scan processed to the scan (its own
// plan; never the rolling budgets).
func (sc *scanCall) charge(per map[string]int64) {
	if sc.s == nil {
		return
	}
	sc.e.scans.mu.Lock()
	defer sc.e.scans.mu.Unlock()
	for _, n := range per {
		sc.s.bytes += n
	}
}

// limiter is the scan's own request pacing (design R6-P2): its plan-based
// rate (ScanRequestsPerMinute, none by default beyond the source's
// in-flight cap), never the rolling per-minute budget of free calls.
func (sc *scanCall) limiter(src string) source.Limiter {
	if sc.lim == nil {
		if sc.e.o.ScanRequestsPerMinute <= 0 {
			sc.lim = noLimiter{}
		} else {
			// One pacing for the scan, shared by its calls.
			sc.e.scans.mu.Lock()
			l := sc.e.scanLedgers[sc.s.id]
			if l == nil {
				l = newLedger(Budgets{RemoteRequestsPerMinute: sc.e.o.ScanRequestsPerMinute}, time.Now)
				sc.e.scanLedgers[sc.s.id] = l
			}
			sc.e.scans.mu.Unlock()
			sc.lim = requestLimiter{l: l, src: src}
		}
	}
	return sc.lim
}

type noLimiter struct{}

func (noLimiter) Wait(context.Context) error { return nil }

// scanID is the id of the scan a call runs under ("" for a free call).
func scanID(ctx context.Context) string {
	if sc := scanFrom(ctx); sc != nil && sc.s != nil {
		return sc.s.id
	}
	return ""
}

// planHash is the keyed hash an approved scan is bound to: the tool, the
// query digest (itself keyed: the sources, the absolute range, the
// predicates and every other parameter), the scan's byte budget and the
// policy fingerprint. It is never returned to the agent.
func (e *Engine) planHash(tool, digest, fp string) string {
	return e.o.Sealer.Digest("locklog/scan/v1", []byte(tool), []byte(digest), []byte(strconv.FormatInt(e.o.ScanBytes, 10)), []byte(fp))
}

// boundDigest binds a query digest to a scan: cursors of a scan continue
// only that scan, never a free call, nor another scan.
func (e *Engine) boundDigest(digest, id string) string {
	return e.o.Sealer.Digest("locklog/scan-query/v1", []byte(digest), []byte(id))
}

// scanDigest is the digest a call's cursors carry: the query digest, or,
// for a continuation of an approved scan, that digest bound to the scan,
// once its plan hash is checked against the scan's (another query → stale).
func (e *Engine) scanDigest(ctx context.Context, tool, digest string) (string, *Error) {
	sc := scanFrom(ctx)
	if sc == nil || sc.s == nil {
		return digest, nil
	}
	if sc.s.tool != tool || subtle.ConstantTimeCompare([]byte(e.planHash(tool, digest, e.o.PolicyFP())), []byte(sc.s.hash)) != 1 {
		return "", errScanStale
	}
	return e.boundDigest(digest, sc.s.id), nil
}

var errScanStale = &Error{Code: EStale, Span: "cursor", Message: "the cursor belongs to another approved scan, or the plan changed: run locklog_scan again without the cursor"}

// admitPlan freezes the plan of a call's first page. A free call's plan is
// frozen as is (the rolling budgets admit it in run). A scan's first call
// re-attaches to the same plan approved earlier by the same peer, or asks
// the human to approve the plan (class read), then freezes it for the
// scan's whole life. It returns the frozen plan and the digest the call's
// cursors carry.
func (e *Engine) admitPlan(ctx context.Context, tool, digest string, plan source.Byteplan, desc bool, scope func() []string) (*frozen, string, error) {
	sc := scanFrom(ctx)
	if sc == nil {
		return e.freeze(digest, plan, desc), digest, nil
	}
	if sc.tool != tool {
		return nil, "", refuse(EBadQuery, "tool", "unknown tool")
	}
	fp := e.o.PolicyFP()
	hash := e.planHash(tool, digest, fp)
	if s := e.scans.reattach(sc.peer.UID, hash, e.o.Now()); s != nil {
		e.scans.mu.Lock()
		live := s.cursor
		e.scans.mu.Unlock()
		if live != "" {
			// Resume at the scan's live position, never from the start.
			return nil, "", errReattach{s}
		}
		// Approved, never answered (its first call failed): its plan
		// from the start, the bytes processed still counted.
		if err := sc.claim(s, "", false); err != nil {
			return nil, "", err
		}
		sc.reattached = true
		e.dropScanPlans(s.id)
		f, _ := e.freezeReplacing(s.query, s.plan, s.desc, "", s.id)
		return f, s.query, nil
	}
	if sc.peer.Approve == nil {
		return nil, "", &Error{Code: EApproval, Message: "no human console to approve a scan"}
	}
	if e.scans.live(e.o.Now()) >= MaxScans {
		return nil, "", &Error{Code: EOverBudget, Message: fmt.Sprintf("%d approved scans are in progress already: finish one, or wait for it to expire", MaxScans)}
	}
	if err := sc.peer.Approve(ctx, e.scanScreen(tool, plan, scope(), sc.note)); err != nil {
		return nil, "", err
	}
	// Time of check, time of use: the plan the human approved runs under
	// the policy it was approved under.
	if e.o.PolicyFP() != fp {
		return nil, "", &Error{Code: EPolicyChanged, Message: "the policy changed while the scan was being approved: ask again"}
	}
	var b [12]byte
	rand.Read(b[:])
	s := &scanState{id: hex.EncodeToString(b[:]), uid: sc.peer.UID, hash: hash, policyFP: fp, tool: tool, plan: plan, desc: desc,
		expires: e.o.Now().Add(e.o.ScanTTL), state: scanExecuting, busy: true}
	sc.claimed = true
	s.query = e.boundDigest(digest, s.id)
	e.scans.mu.Lock()
	e.scans.m[s.id] = s
	e.scans.mu.Unlock()
	sc.s = s
	f, _ := e.freezeReplacing(s.query, plan, desc, "", s.id)
	return f, s.query, nil
}

// scanScreen is the approval screen of a scan: what it reads (sources,
// absolute range, predicates as the agent wrote them, escaped by the
// console) and the plan's size.
func (e *Engine) scanScreen(tool string, plan source.Byteplan, scope []string, note string) Approval {
	body := []string{"tool: " + tool}
	body = append(body, scope...)
	size := fmt.Sprintf("plan: %d granules, %s", plan.Granules(), sizeText(plan.Bytes()))
	for _, c := range plan.Chunks {
		if e.remote(c.Source) {
			size += " (remote slices: bytes known once fetched)"
			break
		}
	}
	body = append(body, size, fmt.Sprintf("approved for its whole plan: continuations need no new approval, until it ends or %s from now", e.o.ScanTTL))
	return Approval{Class: "read", Header: "scan · read", Note: note, Body: body,
		Warnings: []string{"the agent receives the masked records of the whole plan"}}
}

func sizeText(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// reattach returns the executing scan of uid with plan hash hash.
func (st *scanStore) reattach(uid int, hash string, now time.Time) *scanState {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.m {
		st.expireLocked(s, now)
		if s.state == scanExecuting && s.uid == uid && subtle.ConstantTimeCompare([]byte(s.hash), []byte(hash)) == 1 {
			return s
		}
	}
	return nil
}

func (st *scanStore) expireLocked(s *scanState, now time.Time) {
	if s.state == scanExecuting && !now.Before(s.expires) {
		s.state = scanExpired
	}
}

// live counts the scans in progress.
func (st *scanStore) live(now time.Time) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for id, s := range st.m {
		st.expireLocked(s, now)
		if s.state == scanExecuting {
			n++
		} else {
			delete(st.m, id)
		}
	}
	return n
}

func (e *Engine) liveScans() int {
	n := e.scans.live(e.o.Now())
	e.dropEndedScanPlans()
	return n
}

// resolve returns the executing scan id for peer uid: refused when it ended,
// expired, belongs to another peer or to another policy.
func (st *scanStore) resolve(id string, uid int, fp string, now time.Time) (*scanState, *Error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.m[id]
	if s == nil || s.uid != uid {
		return nil, errScanStale
	}
	st.expireLocked(s, now)
	switch {
	case s.policyFP != fp:
		return nil, &Error{Code: EPolicyChanged, Span: "cursor", Message: "the policy changed since the scan was approved: ask again"}
	case s.state == scanExpired:
		return nil, &Error{Code: EStale, Span: "cursor", Message: "the approved scan expired: run locklog_scan again (a new approval)"}
	case s.state != scanExecuting:
		return nil, &Error{Code: EStale, Span: "cursor", Message: "the approved scan ended: run locklog_scan again (a new approval)"}
	}
	return s, nil
}

// finish ends a scan whose plan is exhausted.
func (e *Engine) finishScan(s *scanState) {
	e.scans.mu.Lock()
	if s.state == scanExecuting {
		s.state = scanExecuted
	}
	delete(e.scanLedgers, s.id)
	e.scans.mu.Unlock()
	e.dropScanPlans(s.id)
}

// dropScanPlans drops the frozen plans of scan id.
func (e *Engine) dropScanPlans(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, f := range e.plans {
		if f.scan == id {
			delete(e.plans, k)
		}
	}
}

// dropEndedScanPlans drops the frozen plans of scans no longer in progress.
func (e *Engine) dropEndedScanPlans() {
	e.scans.mu.Lock()
	live := map[string]bool{}
	for id, s := range e.scans.m {
		if s.state == scanExecuting {
			live[id] = true
		}
	}
	for id := range e.scanLedgers {
		if !live[id] {
			delete(e.scanLedgers, id)
		}
	}
	e.scans.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, f := range e.plans {
		if f.scan != "" && !live[f.scan] {
			delete(e.plans, k)
		}
	}
}

// Scan runs an approved scan (log.scan). The first call (no cursor in the
// query) plans the tool's call with the scan's budgets, re-attaches to the
// same plan approved earlier by the same peer within its TTL, or asks the
// human to approve it; every later call continues the approved plan with
// the cursor, free. The plan hash, its inputs and the policy fingerprint
// never reach the agent: it gets the scan's random id.
func (e *Engine) Scan(ctx context.Context, q ScanQuery) (ScanResult, error) {
	peer := peerFrom(ctx)
	if len(q.Reason) > MaxReason {
		return ScanResult{}, refuse(EBadQuery, "reason", "at most %d bytes", MaxReason)
	}
	sc := &scanCall{e: e, start: time.Now(), tool: q.Tool, note: q.Reason, peer: peer}
	decode := func(v any) *Error {
		if len(bytes.TrimSpace(q.Query)) == 0 {
			return refuse(EBadQuery, "query", "the tool's parameters are required")
		}
		d := json.NewDecoder(bytes.NewReader(q.Query))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			r := decodeRefusal(err)
			r.Span = "query"
			return r
		}
		return nil
	}
	var cursor string
	var run func(context.Context, string) (any, bool, string, error)
	switch q.Tool {
	case ScanSearch:
		var qq Query
		if r := decode(&qq); r != nil {
			return ScanResult{}, r
		}
		cursor = qq.Cursor
		run = func(ctx context.Context, cur string) (any, bool, string, error) {
			qq.Cursor = cur
			res, err := e.Search(ctx, qq)
			return res, res.Complete, res.Cursor, err
		}
	case ScanTrace:
		var qq TraceQuery
		if r := decode(&qq); r != nil {
			return ScanResult{}, r
		}
		cursor = qq.Cursor
		run = func(ctx context.Context, cur string) (any, bool, string, error) {
			qq.Cursor = cur
			res, err := e.Trace(ctx, qq)
			return res, res.Complete, res.Cursor, err
		}
	case ScanCount:
		var qq CountQuery
		if r := decode(&qq); r != nil {
			return ScanResult{}, r
		}
		cursor = qq.Cursor
		run = func(ctx context.Context, cur string) (any, bool, string, error) {
			qq.Cursor = cur
			res, err := e.Count(ctx, qq)
			return res, res.Complete, res.Cursor, err
		}
	case ScanPatterns:
		var qq PatternsQuery
		if r := decode(&qq); r != nil {
			return ScanResult{}, r
		}
		cursor = qq.Cursor
		run = func(ctx context.Context, cur string) (any, bool, string, error) {
			qq.Cursor = cur
			res, err := e.Patterns(ctx, qq)
			return res, res.Complete, res.Cursor, err
		}
	default:
		return ScanResult{}, refuse(EBadQuery, "tool", "want one of %s", strings.Join([]string{ScanSearch, ScanCount, ScanPatterns, ScanTrace}, ", "))
	}
	if cursor != "" {
		// A continuation: the cursor names the scan; it must be this
		// peer's, in progress, under the policy in force.
		st, err := e.openCursor(cursor)
		if err != nil {
			return ScanResult{}, err
		}
		if st.Scan == "" {
			return ScanResult{}, errScanStale
		}
		s, rerr := e.scans.resolve(st.Scan, peer.UID, e.o.PolicyFP(), e.o.Now())
		if rerr != nil {
			if rerr.Code != EPolicyChanged {
				e.dropEndedScanPlans()
			}
			return ScanResult{}, rerr
		}
		if err := sc.claim(s, cursor, true); err != nil {
			return ScanResult{}, err
		}
	}
	res, complete, next, err := run(withScan(ctx, sc), cursor)
	var ra errReattach
	if errors.As(err, &ra) {
		// A reissue of a scan in progress: its next part, from its live
		// position (the cursor its last call returned).
		sc.s, sc.reattached = nil, true
		s := ra.s
		e.scans.mu.Lock()
		cursor = s.cursor
		e.scans.mu.Unlock()
		if cerr := sc.claim(s, cursor, true); cerr != nil {
			return ScanResult{}, cerr
		}
		res, complete, next, err = run(withScan(ctx, sc), cursor)
	}
	defer func() { sc.release(err == nil, next) }()
	if err != nil {
		return ScanResult{}, err
	}
	if sc.s == nil {
		return ScanResult{}, &Error{Code: ESource, Message: "the scan was not admitted; try again"}
	}
	info := ScanInfo{ID: sc.s.id, ExpiresAt: sc.s.expires.UTC(), Reattached: sc.reattached}
	if complete {
		e.finishScan(sc.s)
		info.Done = true
	}
	return ScanResult{Scan: info, Tool: q.Tool, Result: res}, nil
}

// scopeLines describe a query for an approval screen: its sources, its
// absolute range and its predicates as the agent wrote them (the console
// escapes every line).
func scopeLines(q Query) []string {
	srcs := "every source"
	if len(q.Sources) > 0 {
		srcs = strings.Join(q.Sources, ", ")
	}
	out := []string{"sources: " + srcs,
		"range: " + q.From.UTC().Format(time.RFC3339) + " → " + q.To.UTC().Format(time.RFC3339) + " (" + q.To.Sub(q.From).String() + ")"}
	for i, p := range q.Where {
		name := p.Field
		if p.Label != "" {
			name = "label " + p.Label
		}
		out = append(out, fmt.Sprintf("where[%d]: %s %s %s", i, name, p.Op, string(p.Value)))
	}
	if q.Text != "" {
		out = append(out, "text: "+strconv.Quote(q.Text))
	}
	if q.Regex != "" {
		out = append(out, "regex: "+strconv.Quote(q.Regex))
	}
	if q.trace != nil {
		out = append(out, "trace id: "+strconv.Quote(q.trace.id))
	}
	return out
}
