package engine

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Methods of the approved and rate-limited value tools.
const (
	MethodUnmask = "log.unmask"
	MethodLookup = "log.lookup"
)

// Unmask modes (config: unmask).
const (
	UnmaskNever    = "never"
	UnmaskApproved = "approved"
)

// MaxUnmask bounds the pseudonyms of one unmask, MaxLookup the values of
// one lookup and MaxLookupValue the bytes of one looked-up value.
const (
	MaxUnmask      = 8
	MaxLookup      = 10
	MaxLookupValue = 256
)

// ClearMasker is what unmask needs of the masker: the clear value of each
// pseudonym of a record (mask.Masker.MaskClear).
type ClearMasker interface {
	MaskClear(source string, ev parse.Event) (mask.Record, map[string]string)
}

// Lookuper is what lookup needs of the masker (mask.Masker.Lookup).
type Lookuper interface {
	Lookup(kind, value string) (string, error)
	DetectorKinds() []string
}

// UnmaskQuery asks for the clear values of exact pseudonyms of one record
// (log.unmask), with the agent's reason for the human.
type UnmaskQuery struct {
	Ref        string   `json:"ref"`
	Pseudonyms []string `json:"pseudonyms"`
	Reason     string   `json:"reason"`
}

// UnmaskValue is one pseudonym's clear value.
type UnmaskValue struct {
	Pseudonym string `json:"pseudonym"`
	Value     string `json:"value"`
}

// UnmaskResult is the answer of an approved unmask: those spans' clear
// values, once.
type UnmaskResult struct {
	Epoch  string        `json:"epoch"`
	Values []UnmaskValue `json:"values"`
}

// AuditPseudonyms names what was revealed by pseudonym (never the value).
func (r UnmaskResult) AuditPseudonyms() []string {
	out := make([]string, 0, len(r.Values))
	for _, v := range r.Values {
		out = append(out, v.Pseudonym)
	}
	return out
}

// span is one occurrence of a pseudonym in the masked record (byte offsets
// in its masked rendering).
type span struct {
	token      string
	start, end int
}

// unmaskPlan is what an unmask approval binds: the record (its keyed
// digest), the epoch and the exact spans, and the plan hash over them.
type unmaskPlan struct {
	src    string
	ts     time.Time
	timed  bool
	shown  []byte
	spans  []span
	clear  map[string]string
	hash   string
	policy string
	// secret: a named value held a secret span. It is refused only after
	// the approval, never naming which: before it, the refusal would tell
	// the agent which pseudonym held a secret.
	secret bool
}

// errUnmaskNever refuses every unmask of a profile with unmask = "never".
var errUnmaskNever = &Error{Code: EUnmaskNever, Message: "unmask is off for this profile (unmask = \"never\", the production default): ask the human to read the record at the console, with clear results on (Ctrl-O)"}

// Unmask reveals the clear values of exact pseudonyms of one record to the
// agent, once, on a read-pii approval the human gives at the console
// (never auto-approved). The plan hash binds the ref, the record's keyed
// digest (HMAC under K_ref), the epoch and the exact (kind, ID, span
// offsets); the record is read again after the approval and anything that
// moved is refused (E_STALE). A secret span is never revealed, nor a value
// that held one.
func (e *Engine) Unmask(ctx context.Context, q UnmaskQuery) (UnmaskResult, error) {
	if e.o.Unmask != UnmaskApproved {
		return UnmaskResult{}, errUnmaskNever
	}
	if len(q.Pseudonyms) == 0 || len(q.Pseudonyms) > MaxUnmask {
		return UnmaskResult{}, refuse(EBadQuery, "pseudonyms", "want 1 to %d pseudonyms", MaxUnmask)
	}
	for i, p := range q.Pseudonyms {
		kind, ok := tokenKind(p)
		if !ok {
			return UnmaskResult{}, refuse(EBadQuery, fmt.Sprintf("pseudonyms[%d]", i), "want a pseudonym ⟦kind:ID⟧ as the record shows it")
		}
		if kind == "secret" || kind == "redacted" || kind == mask.KeyKind {
			return UnmaskResult{}, refuse(EBadQuery, fmt.Sprintf("pseudonyms[%d]", i), "a secret, a redaction or a field name is never unmasked")
		}
		if slices.Contains(q.Pseudonyms[:i], p) {
			return UnmaskResult{}, refuse(EBadQuery, fmt.Sprintf("pseudonyms[%d]", i), "a pseudonym given twice")
		}
	}
	if strings.TrimSpace(q.Reason) == "" || len(q.Reason) > MaxReason {
		return UnmaskResult{}, refuse(EBadQuery, "reason", "want a reason of 1 to %d bytes", MaxReason)
	}
	if _, ok := e.o.Masker.(ClearMasker); !ok {
		return UnmaskResult{}, errUnmaskNever
	}
	rr, digest, rerr := e.openRef(q.Ref)
	if rerr != nil {
		return UnmaskResult{}, rerr
	}
	peer := peerFrom(ctx)
	if peer.Approve == nil {
		return UnmaskResult{}, &Error{Code: EApproval, Message: "no human console to approve an unmask"}
	}
	plan, perr := e.planUnmask(ctx, q, rr, digest)
	if perr != nil {
		return UnmaskResult{}, perr
	}
	if err := peer.Approve(ctx, e.unmaskScreen(q, plan)); err != nil {
		return UnmaskResult{}, err
	}
	// Time of check, time of use: the record, the epoch, the policy and
	// the spans are those approved, or nothing is revealed.
	again, perr := e.planUnmask(ctx, q, rr, digest)
	if perr != nil {
		return UnmaskResult{}, perr
	}
	if subtle.ConstantTimeCompare([]byte(again.hash), []byte(plan.hash)) != 1 || again.policy != plan.policy {
		return UnmaskResult{}, &Error{Code: EStale, Span: "ref", Message: "the record or its pseudonyms changed since the unmask was approved: ask again"}
	}
	if again.secret {
		return UnmaskResult{}, refuse(EBadQuery, "pseudonyms", "a value named held a secret: nothing is unmasked")
	}
	res := UnmaskResult{Epoch: e.o.Masker.Epoch(), Values: []UnmaskValue{}}
	for _, p := range q.Pseudonyms {
		res.Values = append(res.Values, UnmaskValue{Pseudonym: p, Value: again.clear[p]})
	}
	return res, nil
}

// tokenKind returns the kind of a pseudonym placeholder ⟦kind:ID⟧.
func tokenKind(s string) (string, bool) {
	if !isToken(s) || !strings.HasPrefix(s, mask.Open) || !strings.HasSuffix(s, mask.Close) {
		return "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(s, mask.Open), mask.Close)
	kind, id, ok := strings.Cut(inner, ":")
	if !ok || kind == "" || id == "" || strings.ContainsAny(inner, mask.Open+mask.Close) {
		return "", false
	}
	return kind, true
}

// planUnmask reads the record again, checks it is the ref's (its keyed
// digest), masks it with its clear values and finds the exact spans.
func (e *Engine) planUnmask(ctx context.Context, q UnmaskQuery, rr source.RawRef, digest string) (unmaskPlan, *Error) {
	cctx, cancel := context.WithTimeout(ctx, e.o.Limits.Deadline)
	defer cancel()
	src := e.o.Sources[rr.Source]
	if e.remote(rr.Source) {
		cctx = source.WithLimiter(cctx, e.limiter(ctx, rr.Source))
	}
	raw, err := src.Reread(cctx, rr)
	if err != nil {
		return unmaskPlan{}, sourceError(err)
	}
	if subtle.ConstantTimeCompare([]byte(e.RecordDigest(raw.Event.Raw)), []byte(digest)) != 1 {
		return unmaskPlan{}, sourceError(source.ErrStale)
	}
	rec, clear := e.o.Masker.(ClearMasker).MaskClear(rr.Source, raw.Event)
	if rec.Failed() {
		return unmaskPlan{}, &Error{Code: ESource, Span: "ref", Message: "the record could not be masked: it is never unmasked"}
	}
	shown, merr := rec.MarshalJSON()
	if merr != nil {
		return unmaskPlan{}, &Error{Code: ESource, Message: "the record could not be rendered; try again"}
	}
	p := unmaskPlan{src: rr.Source, shown: shown, clear: clear, policy: e.o.PolicyFP()}
	p.ts, p.timed = rec.Time()
	for i, tok := range q.Pseudonyms {
		at := 0
		n := 0
		for {
			j := bytes.Index(shown[at:], []byte(tok))
			if j < 0 {
				break
			}
			p.spans = append(p.spans, span{token: tok, start: at + j, end: at + j + len(tok)})
			at += j + len(tok)
			n++
		}
		v, ok := clear[tok]
		switch {
		case n == 0 || !ok:
			return unmaskPlan{}, refuse(EStale, fmt.Sprintf("pseudonyms[%d]", i), "this pseudonym is not a value of this record: name the pseudonyms as the record shows them")
		case strings.Contains(v, mask.Open) || strings.Contains(e.o.Masker.Text(v), mask.Secret):
			// A value that held a secret span (redacted inside it), or
			// reads as a secret on its own: never revealed.
			p.secret = true
		}
	}
	var b strings.Builder
	for _, s := range p.spans {
		kind, _ := tokenKind(s.token)
		fmt.Fprintf(&b, "%s\x00%s\x00%d\x00%d\x00", kind, s.token, s.start, s.end)
	}
	p.hash = e.o.Sealer.Digest("locklog/unmask/v1", []byte(q.Ref), []byte(digest), []byte(e.o.Masker.Epoch()), []byte(b.String()))
	return p, nil
}

// unmaskScreen shows the human the masked record with exactly the spans
// to reveal marked, the reason (masked, escaped by the console) and what
// revealing them lets the agent do.
func (e *Engine) unmaskScreen(q UnmaskQuery, p unmaskPlan) Approval {
	marked := make([]byte, 0, len(p.shown)+4*len(p.spans))
	last := 0
	for _, s := range p.spans {
		marked = append(marked, p.shown[last:s.start]...)
		marked = append(marked, "»"...)
		marked = append(marked, p.shown[s.start:s.end]...)
		marked = append(marked, "«"...)
		last = s.end
	}
	marked = append(marked, p.shown[last:]...)
	when := "untimed"
	if p.timed {
		when = p.ts.UTC().Format(time.RFC3339Nano)
	}
	body := []string{"source: " + p.src, "record: " + when, "reveal: " + strings.Join(q.Pseudonyms, ", "),
		fmt.Sprintf("spans: %d in this record (marked » «)", len(p.spans)), string(marked)}
	return Approval{Class: "read-pii", Header: "unmask · read-pii", Note: e.o.Masker.Text(q.Reason), Body: body, NeverAuto: true,
		Clear: []string{clearView(p)},
		Warnings: []string{"the agent receives these clear values, once",
			"the agent can link this value to every record with this pseudonym (in this epoch)"}}
}

// LookupQuery asks for the pseudonyms of clear values of a detector kind
// (log.lookup): equality only.
type LookupQuery struct {
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
	Reason string   `json:"reason,omitempty"`
}

// LookupResult is the pseudonym of each value, in order (the values are
// not echoed).
type LookupResult struct {
	Epoch      string   `json:"epoch"`
	Kind       string   `json:"kind"`
	Pseudonyms []string `json:"pseudonyms"`
}

// AuditPseudonyms names the lookup's answer by pseudonym only.
func (r LookupResult) AuditPseudonyms() []string { return slices.Clone(r.Pseudonyms) }

// Lookup gives the pseudonyms of clear values of a detector kind, as the
// masker shows them in this epoch (the equality the agent then searches
// or counts by). It is free and rate-limited (distinct values per hour,
// per peer uid and per console), or a read-pii approval with lookup =
// "approved". Refused: a kind no value detector finds (field names,
// template tokens, rule kinds), a value that reads as a secret, and a
// value that is not wholly of the kind. Documented residual: membership
// probing (design §4.4 item 5).
func (e *Engine) Lookup(ctx context.Context, q LookupQuery) (LookupResult, error) {
	lk, ok := e.o.Masker.(Lookuper)
	if !ok {
		return LookupResult{}, refuse(EBadQuery, "kind", "this console resolves no lookup")
	}
	kinds := lk.DetectorKinds()
	if !slices.Contains(kinds, q.Kind) {
		return LookupResult{}, refuse(EBadQuery, "kind", "want a detector kind: %s", strings.Join(kinds, ", "))
	}
	if len(q.Values) == 0 || len(q.Values) > MaxLookup {
		return LookupResult{}, refuse(EBadQuery, "values", "want 1 to %d values", MaxLookup)
	}
	if len(q.Reason) > MaxReason {
		return LookupResult{}, refuse(EBadQuery, "reason", "at most %d bytes", MaxReason)
	}
	res := LookupResult{Epoch: e.o.Masker.Epoch(), Kind: q.Kind, Pseudonyms: []string{}}
	var digests []string
	for i, v := range q.Values {
		span := fmt.Sprintf("values[%d]", i)
		if v == "" || len(v) > MaxLookupValue {
			return LookupResult{}, refuse(EBadQuery, span, "want 1 to %d bytes", MaxLookupValue)
		}
		tok, err := lk.Lookup(q.Kind, v)
		switch {
		case err == nil:
		case errors.Is(err, mask.ErrLookupSecret):
			return LookupResult{}, refuse(EBadQuery, span, "a value that reads as a secret is never looked up")
		default:
			return LookupResult{}, refuse(EBadQuery, span, "not, whole, a value of kind %s", q.Kind)
		}
		res.Pseudonyms = append(res.Pseudonyms, tok)
		digests = append(digests, e.o.Sealer.Digest("locklog/lookup/v1", []byte(q.Kind), []byte(v)))
	}
	peer := peerFrom(ctx)
	if !e.ledger.takeLookups(peer.UID, digests) {
		return LookupResult{}, &Error{Code: EOverBudget, Message: "the lookup budget of distinct values per hour is used up (per peer and per console): wait for it to refill, or search by pseudonyms the results show"}
	}
	if e.o.LookupApproved {
		if peer.Approve == nil {
			return LookupResult{}, &Error{Code: EApproval, Message: "no human console to approve a lookup"}
		}
		body := []string{"kind: " + q.Kind, fmt.Sprintf("values: %d", len(q.Values))}
		for _, v := range q.Values {
			body = append(body, "  "+v)
		}
		if err := peer.Approve(ctx, Approval{Class: "read-pii", Header: "lookup · read-pii", Note: e.o.Masker.Text(q.Reason), Body: body, NeverAuto: true,
			Warnings: []string{"the agent learns the pseudonym of each value, and so every record holding it"}}); err != nil {
			return LookupResult{}, err
		}
	}
	return res, nil
}
