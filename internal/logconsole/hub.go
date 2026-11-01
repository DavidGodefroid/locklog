package logconsole

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// Hub mode (console --hub): the approved methods (log.scan, log.unmask,
// log.lookup with lookup = "approved") are decided on lockhub, never on
// the console's terminal. The first call makes a plan (plans.Store) bound
// to the peer uid, the agent's token, the policy fingerprint and the
// engine's keyed plan hash, pushes its masked screen to the hub (the clear
// screen sealed to the pinned devices only) and answers pending with the
// ticket id. The agent calls again with the ticket once it is decided: the
// engine plans the call again, and it runs once if the decision verifies
// and the keyed plan hash is the ticket's.

// hubTicketTTL is how long a ticket waits for its decision and its run;
// past it, its run asks again (a renewal).
const hubTicketTTL = 24 * time.Hour

// hubApproved are the methods a hub ticket can approve.
var hubApproved = []string{MethodScan, MethodUnmask, MethodLookup}

// HubRequest is an approval of the engine as the hub gets it.
type HubRequest struct {
	Risk   ticket.Risk
	Header string
	// Note is the agent's reason, masked.
	Note string
	// Body is the console's screen (masked by the engine), HubBody the
	// hub's when it differs (nil: Body).
	Body, HubBody []string
	Warnings      []string
	// Clear is the clear view of the screen's record (secrets redacted):
	// sealed to the pinned devices only, in the clear screen.
	Clear []string
	// PlanHash is the engine's keyed plan hash, Inputs its keyed input
	// digests (base64url HMAC-SHA256), Moving the inputs a renewal cannot
	// check without the record.
	PlanHash string
	Inputs   map[string]string
	Moving   []string
	// Production and NeverAuto flag the ticket.
	Production, NeverAuto bool
}

// hubBody is a plan of hub mode as the plan store keeps it: no value of
// the request, only what a renewal needs.
type hubBody struct {
	Method string `json:"method"`
	// Moving are the inputs a renewal names unchecked.
	Moving []string `json:"moving,omitempty"`
}

// HubCall is one call of an approved method in hub mode: a new request
// (no ticket) or the run of a ticket.
type HubCall struct {
	hub    *console.Hub
	env    console.Env
	now    func() time.Time
	id     int64
	method string
	ticket string
	caller plans.Caller
	// agent is the authenticated requester (peerName), never the
	// requester the params declare.
	agent string
	fp    string
	rec   *Record

	mu sync.Mutex
	// run is the plan begun for this call (Finish after the run).
	run *plans.Plan
	// submitted is the plan submitted by this call (withdrawn when the
	// call cannot be audited).
	submitted string
	used      bool
}

type hubCallKey struct{}

// WithHubCall attaches a hub call to ctx.
func WithHubCall(ctx context.Context, h *HubCall) context.Context {
	return context.WithValue(ctx, hubCallKey{}, h)
}

// HubCallFrom returns the call's hub call, nil standalone.
func HubCallFrom(ctx context.Context) *HubCall {
	h, _ := ctx.Value(hubCallKey{}).(*HubCall)
	return h
}

// envelope are the fields of an approved method's params that are the
// console's, not the engine's: the hub ticket to run and the requester
// (lea's agent and the hash of its token, mcpkit.RequesterFromEnv). Both
// are the agent's own claims: the token only binds the plan (compared at
// the run, as plans.Caller.Token); the agent name is never shown nor
// audited as an identity (peerName is).
type envelope struct {
	Ticket    string
	Requester ipc.Requester
}

// splitEnvelope takes the envelope out of params: the engine refuses any
// field it does not know.
func splitEnvelope(params json.RawMessage) (json.RawMessage, envelope, bool) {
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(params))
	if d.Decode(&m) != nil || m == nil {
		return params, envelope{}, true
	}
	var env envelope
	if raw, ok := m["ticket"]; ok {
		if json.Unmarshal(raw, &env.Ticket) != nil {
			return nil, envelope{}, false
		}
		delete(m, "ticket")
	}
	if raw, ok := m["requester"]; ok {
		if json.Unmarshal(raw, &env.Requester) != nil {
			return nil, envelope{}, false
		}
		delete(m, "requester")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, envelope{}, false
	}
	return out, env, true
}

// hubHash is a keyed digest (base64url HMAC-SHA256) in the ticket's hash
// form ("sha256:" and 64 hex). It stays keyed: only the label is sha256's.
func hubHash(d string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil || len(b) != 32 {
		return "", errors.New("not a keyed digest")
	}
	return "sha256:" + hex.EncodeToString(b), nil
}

// policyFP is the ticket form of a policy fingerprint.
func policyFP(p Policy) string { return "sha256:" + p.Fingerprint() }

// screenDetectors mask personal values on the hub's screen, beside the
// engine's masker (what the screen shows is masked already).
var screenDetectors = func() []pii.Detector {
	ds, err := pii.Detectors([]string{"email", "iban", "card"})
	if err != nil {
		panic(err)
	}
	return ds
}()

// Messages of hub mode to the agent: fixed texts.
const (
	msgNotSubmitted = "the request could not be submitted for approval; do not retry unless asked"
	msgRateLimited  = "too many requests are waiting for a decision; wait for them to be decided before asking again"
	msgDenied       = "denied by the human on lockhub; do not retry unless asked"
	msgNoSuchTicket = "no such ticket (unknown, used, or ended): ask again without the ticket"
	msgWrongAgent   = "the ticket was asked by another agent"
	msgNoDevice     = "the approval was not signed by a device this console pins: refused; ask the human"
	msgExpired      = "ticket expired, and could not be asked again: ask again without the ticket"
)

// Approve decides r on the hub: a new request is submitted (pending), the
// run of a ticket begins when its decision verifies and binds this plan.
// It returns nil once the run may proceed, or a *Declined with the
// agent's answer.
func (h *HubCall) Approve(ctx context.Context, r HubRequest) error {
	h.mu.Lock()
	used := h.used
	h.used = true
	h.mu.Unlock()
	if used {
		return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgNotSubmitted)}
	}
	hash, err := hubHash(r.PlanHash)
	if err != nil {
		return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgNotSubmitted)}
	}
	if h.ticket == "" {
		return h.submit(ctx, r, hash)
	}
	return h.begin(ctx, r, hash)
}

// submit stores the plan of r and pushes its ticket.
func (h *HubCall) submit(ctx context.Context, r HubRequest, hash string) error {
	inputs := make(map[string]string, len(r.Inputs))
	for k, v := range r.Inputs {
		d, err := hubHash(v)
		if err != nil {
			return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgNotSubmitted)}
		}
		inputs[k] = d
	}
	st := h.hub.Store
	// The same request of the same agent, pending already, lends its
	// ticket (hubclient.Submit would): no plan is left behind.
	planID := ""
	if p, ok := st.FindPending(h.caller, hash); ok {
		planID = p.ID
	} else {
		body, _ := json.Marshal(hubBody{Method: h.method, Moving: slices.Clone(r.Moving)})
		p, err := st.Create(plans.Binding{UID: h.caller.UID, Agent: h.agent, TokenHash: plans.HashToken(h.caller.Token),
			PolicyFP: h.fp, PlanHash: hash, Inputs: inputs}, body, hubTicketTTL)
		if err != nil {
			h.env.Println(console.Paint.Fail("hub: the plan could not be stored: " + h.env.Safe(err.Error())))
			return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgNotSubmitted)}
		}
		planID = p.ID
	}
	hb := r.HubBody
	if hb == nil {
		hb = r.Body
	}
	// The requester as the kernel names it (peerName), first on both
	// screens.
	who := "requested by " + h.agent + " (peer credentials)"
	lines := make([]render.Line, 0, len(hb)+1)
	lines = append(lines, render.Structure(who))
	for _, l := range hb {
		lines = append(lines, render.Structure(l))
	}
	red := r.Risk == ticket.RiskReadPII
	masked := render.MaskScreen(render.ScreenSource{Header: r.Header, Note: r.Note, Body: lines, Warnings: r.Warnings, Red: red},
		render.Masking{Detectors: screenDetectors})
	// The clear screen: the console's own, with the record in clear
	// (secrets redacted). Sealed to the pinned devices only, and kept in
	// the plan for a reveal to a pinned facade key.
	clearBody := append([]string{who}, r.Body...)
	if len(r.Clear) > 0 {
		clearBody = append(clearBody, "in clear (sealed to your device; the agent does not get it):")
		clearBody = append(clearBody, r.Clear...)
	}
	clear := &ticket.Screen{Header: r.Header, Note: r.Note, Body: clearBody, Warnings: slices.Clone(r.Warnings), Red: red}
	t := ticket.NewTicket(ticket.Source{Lock: product.P.Name}, r.Risk, hash, h.fp, h.now(), hubTicketTTL)
	t.Requester = ticket.Requester{Agent: h.agent}
	t.Flags = ticket.Flags{Production: r.Production, NeverAuto: r.NeverAuto}
	id, err := h.hub.Client.SubmitClear(ctx, st, planID, h.caller, t, masked, clear)
	if id == "" {
		if err == nil {
			err = errors.New("no ticket")
		}
		_ = st.End(planID, h.caller, plans.Withdrawn, "not submitted")
		h.env.Println(console.Paint.Fail(h.method + ": not submitted to the hub: " + h.env.Safe(err.Error())))
		if errors.Is(err, hubclient.ErrRateLimited) {
			return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgRateLimited)}
		}
		return &Declined{Resp: console.ErrResp(h.id, ipc.CodeInternal, msgNotSubmitted)}
	}
	h.mu.Lock()
	h.submitted = planID
	h.mu.Unlock()
	line := h.method + " · " + string(r.Risk) + ": pending on lockhub as ticket " + h.env.Safe(id)
	if err != nil {
		line += console.Paint.Dim(" (not delivered yet: " + h.env.Safe(err.Error()) + ")")
	}
	h.env.Println(line)
	h.rec.Ticket, h.rec.Approval = id, console.HubApproval
	return &Declined{Resp: console.PendingResp(h.id, product.P.Name, console.Pending{Ticket: id, Instance: h.hub.Instance})}
}

// localFacade reports a facade a read-pii decision may come from: the
// terminal, the deck or a phone (a device-signed decision).
func localFacade(f string) bool {
	return f == ticket.FacadeTTY || f == ticket.FacadeDeck || f == ticket.FacadeMobile
}

// begin runs the decided ticket of the call.
func (h *HubCall) begin(ctx context.Context, r HubRequest, hash string) error {
	st := h.hub.Store
	h.rec.Ticket, h.rec.Approval = h.ticket, console.HubApproval
	// The recheck is this call's own plan, made again by the engine under
	// the policy in force: another record, other spans, another plan or
	// another policy is stale.
	recheck := func(*plans.Plan) (string, string, error) { return h.fp, hash, nil }
	run, d, err := h.hub.Client.Begin(st, h.ticket, h.caller, recheck)
	if err != nil {
		if d != nil && (errors.Is(err, hubclient.ErrDenied) || errors.Is(err, ticket.ErrDevice)) {
			h.auditDecision(ctx, d, audit.EventDenied, string(d.Decision), "")
		}
		if errors.Is(err, ticket.ErrExpired) {
			return &Declined{Resp: h.renew(ctx)}
		}
		return &Declined{Resp: h.refusal(err)}
	}
	h.mu.Lock()
	h.run = run
	h.mu.Unlock()
	if r.Risk == ticket.RiskReadPII && !localFacade(d.Facade) {
		// Chat and any other remote facade never approve a read-pii: the
		// decision is consumed and refused here, in the lock.
		reason := "a read-pii decision from facade " + d.Facade + " is refused (tty, deck or mobile only)"
		h.auditDecision(ctx, d, audit.EventDenied, "refused", reason)
		h.env.Println(console.Paint.Warn("ticket " + h.env.Safe(h.ticket) + ": " + h.env.Safe(reason)))
		h.finish(ctx, false, "facade")
		return &Declined{Resp: refusalResp(h.id, &Refusal{
			Message: "a read-pii approval is taken on the console's terminal, the deck or a phone only; this decision came from another facade and is refused",
			Info:    refusal.Info{Code: "E_APPROVAL", Retry: refusal.RetryAskUser, Hint: "ask the human to approve it on the terminal, the deck or a phone, then ask again without the ticket"},
		}, h.env)}
	}
	h.auditDecision(ctx, d, audit.EventApproved, string(d.Decision), "")
	h.rec.Approver, h.rec.Facade, h.rec.HubSig = &ticket.Approver{ID: d.Approver.ID, Display: d.Approver.Display}, d.Facade, d.Sig
	return nil
}

// renew asks again for the expired ticket of the call (decision H1): the
// agent hears pending with the new ticket.
func (h *HubCall) renew(ctx context.Context) ipc.Response {
	n, err := h.hub.Client.Renew(ctx, h.hub.Store, h.ticket, h.caller)
	rec := Record{Base: audit.Base{Event: audit.EventRenew, Decision: "renewed", Approval: console.HubApproval, Ticket: h.ticket}, Method: h.method}
	rec.Profile = h.rec.Profile
	console.StampPeer(ctx, &rec.Base)
	switch {
	case n == "":
		if err == nil {
			err = errors.New("no renewal")
		}
		rec.Decision, rec.Reason, rec.Error = "refused", hubclient.AnswerCode(err), err.Error()
		h.env.Println(console.Paint.Warn("ticket " + h.env.Safe(h.ticket) + " expired and could not be asked again: " + h.env.Safe(err.Error())))
	case err != nil:
		rec.Reason, rec.Error = "renewed by ticket "+n+", not sent to the hub yet", err.Error()
		h.env.Println(console.Paint.Warn("ticket " + h.env.Safe(h.ticket) + " expired: asked again as ticket " + h.env.Safe(n) + ", not sent to the hub yet"))
	default:
		rec.Reason = "renewed by ticket " + n
		h.env.Println("ticket " + h.env.Safe(h.ticket) + " expired: asked again as ticket " + h.env.Safe(n))
	}
	h.env.Audit(rec)
	if n == "" {
		return console.ErrResp(h.id, ipc.CodeTimeout, msgExpired)
	}
	h.rec.Ticket = n
	return console.PendingResp(h.id, product.P.Name, console.Pending{Ticket: n, Instance: h.hub.Instance})
}

// refusal answers a run whose ticket cannot run: the outcome only, never
// the plan, its hash or the hub's text.
func (h *HubCall) refusal(err error) ipc.Response {
	switch {
	case errors.Is(err, hubclient.ErrPending):
		return console.PendingResp(h.id, product.P.Name, console.Pending{Ticket: h.ticket, Instance: h.hub.Instance})
	case errors.Is(err, hubclient.ErrDenied):
		return console.ErrResp(h.id, ipc.CodeDenied, msgDenied)
	case errors.Is(err, ticket.ErrDevice):
		return console.ErrResp(h.id, ipc.CodeDenied, msgNoDevice)
	case errors.Is(err, hubclient.ErrBadDecision):
		// The hub's answer did not verify and was dropped: the ticket
		// still waits for a decision.
		h.env.Println(console.Paint.Warn("ticket " + h.env.Safe(h.ticket) + ": " + h.env.Safe(err.Error())))
		return console.PendingResp(h.id, product.P.Name, console.Pending{Ticket: h.ticket, Instance: h.hub.Instance})
	case errors.Is(err, plans.ErrStale):
		return refusalResp(h.id, &Refusal{
			Message: "the request is not the one its ticket was asked for (another record, other pseudonyms or spans, another plan, or the policy changed): the ticket is spent",
			Info:    refusal.Info{Code: "E_STALE", Retry: refusal.RetryRewrite, Hint: "ask again without the ticket: a new ticket goes to the human"},
		}, h.env)
	}
	// The cause is told here only: the agent hears the outcome.
	h.env.Println(console.Paint.Warn("ticket " + h.env.Safe(h.ticket) + " (" + h.method + "): " + h.env.Safe(err.Error())))
	if errors.Is(err, plans.ErrWrongRequester) || errors.Is(err, plans.ErrWrongPeer) {
		return console.ErrResp(h.id, ipc.CodeWrongRequester, msgWrongAgent)
	}
	return console.ErrResp(h.id, ipc.CodeNoSuchPlan, msgNoSuchTicket)
}

// auditDecision records the hub's decision on the call's ticket: who
// answered, on which facade, and the hub's signature.
func (h *HubCall) auditDecision(ctx context.Context, d *ticket.Decision, event, decision, reason string) {
	rec := Record{Base: audit.Base{Event: event, Decision: decision, Approval: console.HubApproval, Ticket: h.ticket,
		Approver: &ticket.Approver{ID: d.Approver.ID, Display: d.Approver.Display}, Facade: d.Facade, HubSig: d.Sig}, Method: h.method}
	rec.Profile = h.rec.Profile
	rec.Reason = d.Reason
	if reason != "" {
		rec.Reason = reason
	}
	console.StampPeer(ctx, &rec.Base)
	h.env.Audit(rec)
}

// finish ends the plan begun by the call, once: the hub hears it was
// consumed.
func (h *HubCall) finish(ctx context.Context, ok bool, reason string) {
	h.mu.Lock()
	run := h.run
	h.run = nil
	h.mu.Unlock()
	if run == nil {
		return
	}
	if err := h.hub.Client.Finish(ctx, h.hub.Store, run.ID, h.caller, ok, reason); err != nil {
		h.env.Println("ticket " + h.env.Safe(h.ticket) + ": the hub was not told it was consumed: " + h.env.Safe(err.Error()))
	}
}

// withdraw takes back the ticket submitted by the call (it could not be
// audited).
func (h *HubCall) withdraw(ctx context.Context) {
	h.mu.Lock()
	id := h.submitted
	h.submitted = ""
	h.mu.Unlock()
	if id == "" {
		return
	}
	if err := h.hub.Client.Withdraw(ctx, h.hub.Store, id, h.caller, "the console could not record the request"); err != nil {
		h.env.Println(console.Paint.Fail("hub: a ticket could not be withdrawn: " + h.env.Safe(err.Error())))
	}
}

// OnHub is console.Options.OnHub: the console's hub, before any request,
// gets the recompute of a renewal, and locklog_status shows hub mode.
func (b *Backend) OnHub(h *console.Hub) {
	b.mu.Lock()
	b.hub = h
	b.mu.Unlock()
	h.Client.SetRecompute(b.recompute)
}

// recompute is the hub client's Recompute (decision H1): a renewal is
// re-checked against the policy in force (lockkit refuses one across a
// policy change). The record and the epoch cannot be checked without
// reading the record again, with no agent request: they are named
// unchecked and the plan hash stays the stored one; the run plans the
// call again and refuses a stale one.
func (b *Backend) recompute(p *plans.Plan) (string, string, map[string]string, error) {
	var body hubBody
	if err := json.Unmarshal(p.Body, &body); err != nil {
		return "", "", nil, err
	}
	b.mu.Lock()
	fp := b.fp
	b.mu.Unlock()
	if fp == "" {
		return "", "", nil, errors.New("no policy in force yet")
	}
	inputs := make(map[string]string, len(p.Binding.Inputs))
	for k, v := range p.Binding.Inputs {
		inputs[k] = v
	}
	for _, m := range body.Moving {
		if _, ok := inputs[m]; ok {
			inputs[m] = ticket.UncheckedInput
		}
	}
	return fp, p.Binding.PlanHash, inputs, nil
}

// HubStatus is the hub mode of the console in log.status: the instance
// only (never the hub's key, URL or a ticket's binding).
type HubStatus struct {
	Mode     string `json:"mode"`
	Instance string `json:"instance"`
}

// withHub adds the hub mode to the engine's status.
func withHub(st any, h *console.Hub) any {
	raw, err := json.Marshal(st)
	if err != nil {
		return st
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		m = map[string]json.RawMessage{}
	}
	hs, _ := json.Marshal(HubStatus{Mode: "hub", Instance: h.Instance})
	m["hub"] = hs
	return m
}

// newHubCall is the hub call of an approved method's request.
func (b *Backend) newHubCall(h *console.Hub, env console.Env, id int64, method string, e envelope, uid int, rec *Record) (*HubCall, error) {
	p, ok := env.Policy().(Policy)
	if !ok {
		return nil, fmt.Errorf("no locklog policy in force")
	}
	now := b.o.Now
	if now == nil {
		now = time.Now
	}
	return &HubCall{hub: h, env: env, now: now, id: id, method: method, ticket: e.Ticket, caller: plans.Caller{UID: uid, Token: e.Requester.Token},
		agent: peerName(uid), fp: policyFP(p), rec: rec}, nil
}

// peerName is who the hub shows as the requester: the kernel-verified
// peer uid (SO_PEERCRED), named where locklog knows the account (the
// image's agent), never a name the caller declared.
func peerName(uid int) string {
	if uid == product.AgentUID {
		return "agent (uid " + strconv.Itoa(uid) + ")"
	}
	return "uid " + strconv.Itoa(uid)
}
