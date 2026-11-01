//go:build unix

package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"

	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

// values is the clear values of an unmask answer.
func values(t *testing.T, a answer) map[string]string {
	t.Helper()
	var res struct {
		Values []struct{ Pseudonym, Value string } `json:"values"`
	}
	if err := json.Unmarshal(a.out.Data, &res); err != nil || len(res.Values) == 0 {
		t.Fatalf("not an unmask answer: %v %s", err, a.text)
	}
	out := map[string]string{}
	for _, v := range res.Values {
		out[v.Pseudonym] = v.Value
	}
	return out
}

// An unmask of exact spans goes to the hub as a ticket (no prompt on the
// console), its screen masked; approved on a TTY facade, the run with
// the ticket reveals exactly those spans, once.
func TestHubUnmaskApprovedOnTTYRunsOnce(t *testing.T) {
	r := newRig(t, rigOpts{})
	ref, toks := r.record()
	tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	if r.io.promptCount() != 0 {
		t.Fatalf("the console prompted in hub mode")
	}
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
	if err != nil {
		t.Fatal(err)
	}
	if signed.Risk != ticket.RiskReadPII || signed.Source.Lock != "locklog" || !signed.Flags.NeverAuto || signed.PII.SealedFor != nil {
		t.Fatalf("ticket %+v", signed)
	}
	screen := strings.Join(append([]string{signed.Screen.Header, signed.Screen.Note}, signed.Screen.Body...), "\n")
	if strings.Contains(screen, email1) || strings.Contains(screen, email2) || strings.Contains(screen, secret) ||
		!strings.Contains(screen, "»"+toks[0]+"«") || signed.Screen.Header != "unmask · read-pii" {
		t.Fatalf("hub screen:\n%s", screen)
	}
	// Before the decision: pending, the same ticket.
	if again := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk))); again != tk {
		t.Fatalf("ticket %s, then %s", tk, again)
	}
	r.hub.Decide(tk, ticket.Approved, "")
	a := r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk))
	if v := values(t, a); len(v) != 1 || v[toks[0]] != email1 {
		t.Fatalf("unmask = %v", v)
	}
	if !r.hub.Consumed(tk) {
		t.Error("the hub was not told the ticket was consumed")
	}
	// Once: the ticket is spent.
	if b := r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk)); !b.isErr || strings.Contains(b.text, email1) {
		t.Fatalf("second run: %s", b.text)
	}
	// Another agent's run of a ticket is refused.
	tk2 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	r.hub.Decide(tk2, ticket.Approved, "")
	other := r.mcp("tok-2")
	time.Sleep(200 * time.Millisecond)
	if b := r.callWith(other, mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk2)); !b.isErr || !strings.Contains(b.text, "another agent") {
		t.Fatalf("other agent: %s", b.text)
	}
	log := r.auditLog()
	for _, w := range []string{`"event":"approved"`, `"facade":"tty"`, `"hub_sig":"`, `"ticket":"` + tk + `"`, `"decision":"pending"`} {
		if !strings.Contains(log, w) {
			t.Errorf("audit lacks %s:\n%s", w, log)
		}
	}
	if strings.Contains(log, email1) || strings.Contains(log, secret) {
		t.Errorf("a clear value in the audit:\n%s", log)
	}
	r.checkAgentOutputs(true)
}

// A span swap: the ticket of one pseudonym does not run another's (stale,
// spent), and asking for it is a new ticket.
func TestHubUnmaskSpanSwapIsANewTicket(t *testing.T) {
	r := newRig(t, rigOpts{})
	ref, toks := r.record()
	tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	r.hub.Decide(tk, ticket.Approved, "")
	a := r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[1:], tk))
	if a.code() != "E_STALE" || strings.Contains(a.text, email2) || strings.Contains(a.text, email1) {
		t.Fatalf("swapped spans: %s", a.text)
	}
	if b := r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk)); !b.isErr || strings.Contains(b.text, email1) {
		t.Fatalf("a stale ticket ran: %s", b.text)
	}
	tk2 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[1:], "")))
	if tk2 == tk {
		t.Fatal("the swapped spans got the old ticket")
	}
	// The same request again lends its pending ticket.
	if tk3 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[1:], ""))); tk3 != tk2 {
		t.Fatalf("same request: %s then %s", tk2, tk3)
	}
	r.checkAgentOutputs(false)
}

// A read-pii decision from a chat facade is refused by the lock: nothing
// is revealed, the ticket is spent. A denial is a denial.
func TestHubChatFacadeReadPIIRefused(t *testing.T) {
	r := newRig(t, rigOpts{})
	ref, toks := r.record()
	tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	r.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Facade = "chat" })
	a := r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk))
	if a.code() != "E_APPROVAL" || strings.Contains(a.text, email1) {
		t.Fatalf("chat decision: %s", a.text)
	}
	if b := r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk)); !b.isErr || strings.Contains(b.text, email1) {
		t.Fatalf("ran after the refusal: %s", b.text)
	}
	if !strings.Contains(r.auditLog(), `"facade":"chat"`) || !strings.Contains(r.io.output(), "facade chat is refused") {
		t.Errorf("the refusal is not audited and told:\n%s\n%s", r.auditLog(), r.io.output())
	}
	tk2 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	r.hub.Decide(tk2, ticket.Denied, "not now")
	if b := r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk2)); !b.isErr || !strings.Contains(b.text, "denied") || strings.Contains(b.text, "not now") {
		t.Fatalf("denied: %s", b.text)
	}
	r.checkAgentOutputs(false)
}

// An approved lookup (lookup = "approved") is a read-pii ticket whose hub
// screen never shows the values; a chat decision is refused there too.
func TestHubLookupApproved(t *testing.T) {
	r := newRig(t, rigOpts{extra: `lookup = "approved"`})
	args := map[string]any{"kind": "email", "values": []string{email1}, "reason": "the user gave this address"}
	tk := r.mustPending(r.call(mcptools.ToolLookup, args))
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
	if err != nil {
		t.Fatal(err)
	}
	if body := strings.Join(signed.Screen.Body, "\n"); signed.Risk != ticket.RiskReadPII || strings.Contains(body, email1) || !strings.Contains(body, "value 1: ⟦email⟧") {
		t.Fatalf("lookup ticket %s: %s", signed.Risk, body)
	}
	r.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Facade = "slack" })
	run := map[string]any{"kind": "email", "values": []string{email1}, "reason": "the user gave this address", "ticket": tk}
	if a := r.decided(mcptools.ToolLookup, run); a.code() != "E_APPROVAL" {
		t.Fatalf("slack decision: %s", a.text)
	}
	tk2 := r.mustPending(r.call(mcptools.ToolLookup, args))
	r.hub.DecideWith(tk2, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Facade = ticket.FacadeDeck })
	run["ticket"] = tk2
	a := r.decided(mcptools.ToolLookup, run)
	var res struct {
		Pseudonyms []string `json:"pseudonyms"`
	}
	if json.Unmarshal(a.out.Data, &res) != nil || len(res.Pseudonyms) != 1 || !tokenRe.MatchString(res.Pseudonyms[0]) {
		t.Fatalf("lookup: %s", a.text)
	}
	r.checkAgentOutputs(false)
}

// An approved scan: one ticket (class read, any facade) covers its whole
// plan; its continuations need no new ticket.
func TestHubScanCoversContinuations(t *testing.T) {
	r := newRig(t, rigOpts{})
	query := map[string]any{"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z", "limit": 1,
		"where": []map[string]any{{"field": "level", "op": "=", "value": "error"}}}
	args := map[string]any{"tool": "search", "query": query, "reason": "the whole hour"}
	tk := r.mustPending(r.call(mcptools.ToolScan, args))
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
	if err != nil || signed.Risk != ticket.RiskRead || signed.Screen.Header != "scan · read" {
		t.Fatalf("scan ticket %+v %v", signed, err)
	}
	r.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Facade = "chat" })
	args["ticket"] = tk
	a := r.decided(mcptools.ToolScan, args)
	var res struct {
		Scan struct {
			ID   string `json:"id"`
			Done bool   `json:"done"`
		} `json:"scan"`
		Result struct {
			Records  []json.RawMessage `json:"records"`
			Cursor   string            `json:"cursor"`
			Complete bool              `json:"complete"`
		} `json:"result"`
	}
	if err := json.Unmarshal(a.out.Data, &res); err != nil || len(res.Result.Records) != 1 || res.Result.Cursor == "" || res.Result.Complete {
		t.Fatalf("first page: %v %s", err, a.text)
	}
	pushed := r.hub.Pushed()
	query["cursor"] = res.Result.Cursor
	cont := r.call(mcptools.ToolScan, map[string]any{"tool": "search", "query": query})
	var next struct {
		Scan struct {
			ID string `json:"id"`
		} `json:"scan"`
		Result struct {
			Records []json.RawMessage `json:"records"`
		} `json:"result"`
	}
	if err := json.Unmarshal(cont.out.Data, &next); err != nil || len(next.Result.Records) != 1 || next.Scan.ID != res.Scan.ID {
		t.Fatalf("continuation: %v %s", err, cont.text)
	}
	if r.hub.Pushed() != pushed {
		t.Fatalf("a continuation asked a new ticket (%d → %d)", pushed, r.hub.Pushed())
	}
	r.checkAgentOutputs(false)
}

// A ticket past its time is asked again: the agent hears pending with the
// new ticket, which runs once decided.
func TestHubExpiredTicketRenewed(t *testing.T) {
	r := newRig(t, rigOpts{})
	ref, toks := r.record()
	tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	r.clock.add(25 * time.Hour)
	n := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk)))
	if n == tk {
		t.Fatal("not renewed")
	}
	deadline := time.Now().Add(10 * time.Second)
	for r.hub.Ticket(n) == nil {
		if time.Now().After(deadline) {
			t.Fatal("the renewal never reached the hub")
		}
		time.Sleep(20 * time.Millisecond)
	}
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(n))
	if err != nil || signed.Renews == nil || signed.Renews.Of != tk {
		t.Fatalf("renewal %+v %v", signed, err)
	}
	// The record and the epoch cannot be checked without the record: the
	// renewal says so, never "unchanged".
	if signed.Renews.Unchanged() {
		t.Errorf("renewal presented as unchanged: %+v", signed.Renews)
	}
	// Decided on the console's clock (25 hours on).
	r.hub.DecideWith(n, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = r.clock.now().UTC().Truncate(time.Millisecond) })
	if v := values(t, r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], n))); v[toks[0]] != email1 {
		t.Fatalf("renewed run: %v", v)
	}
	if !strings.Contains(r.auditLog(), `"event":"renew"`) {
		t.Error("the renewal is not audited")
	}
	r.checkAgentOutputs(true)
}

// With pinned devices and --seal-clear, the clear screen (the record in
// clear, secrets redacted) goes sealed to the devices; read-pii approvals
// must be signed by one (the default with a devices file): a TTY approval
// alone is refused, the device's runs.
func TestHubClearScreenSealedSecretsRedacted(t *testing.T) {
	dev := devicetest.New("hub.example", "https://hub.example", "phone")
	devs, err := ticket.MarshalDevices([]ticket.Device{dev.Device()})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(file, devs, 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, rigOpts{hubOpts: func(h *console.HubOptions) {
		h.DevicesFile, h.SealClear, h.RequireDevice = file, true, string(ticket.RiskReadPII)
	}})
	ref, toks := r.record()
	tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
	if err != nil || len(signed.PII.SealedFor) != 1 {
		t.Fatalf("ticket %+v %v", signed, err)
	}
	if masked := strings.Join(signed.Screen.Body, "\n"); strings.Contains(masked, email1) {
		t.Fatalf("masked screen holds the clear value: %s", masked)
	}
	box := signed.PII.SealedFor[0]
	cl, err := ticket.OpenClearScreen(dev.Seal, signed.ID, box.Device, &box)
	if err != nil {
		t.Fatal(err)
	}
	clear := strings.Join(cl.Body, "\n")
	if !strings.Contains(clear, email1) || strings.Contains(clear, secret) || !strings.Contains(clear, "⟦secret⟧") {
		t.Fatalf("clear screen:\n%s", clear)
	}
	// A TTY approval without a device signature: refused.
	r.hub.Decide(tk, ticket.Approved, "")
	if a := r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk)); !a.isErr || strings.Contains(a.text, email1) {
		t.Fatalf("unsigned approval ran: %s", a.text)
	}
	tk2 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	raw := r.hub.Ticket(tk2)
	r.hub.DecideWith(tk2, ticket.Approved, "", nil, func(d *ticket.Decision) {
		d.HubKeyID = ticket.KeyID(r.hub.Pub)
		dev.Decide(d, raw)
	})
	if v := values(t, r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], tk2))); v[toks[0]] != email1 {
		t.Fatalf("device approval: %v", v)
	}
	r.checkAgentOutputs(true)
}

// The hub down: free reads work, approvals stay pending (the ticket goes
// out later); locklog_status shows hub mode and the instance, nothing of
// the hub's key.
func TestHubDownFreeReadsWork(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.hub.Close()
	ref, toks := r.record()
	r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	if c := r.call(mcptools.ToolCount, map[string]any{"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z", "by": []string{"level"}}); c.isErr {
		t.Fatalf("count with the hub down: %s", c.text)
	}
	st := r.call(mcptools.ToolStatus, map[string]any{})
	if !strings.Contains(st.text, `"hub":{"mode":"hub","instance":"logs"}`) {
		t.Fatalf("status: %s", st.text)
	}
	if strings.Contains(st.text, "127.0.0.1") || strings.Contains(st.text, "hub.pub") {
		t.Fatalf("status names the hub: %s", st.text)
	}
	r.checkAgentOutputs(false)
}

var (
	ulidRe  = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{26}`)
	epochRe = regexp.MustCompile(`"epoch":\s*"[^"]*"`)
)

// Every answer of a hub flow, refusals included, is byte-identical for two
// records that differ only in a masked value of the same kind and length,
// apart from refs, cursors, pseudonyms and tickets (#26's oracle case).
func TestHubAnswersNoOracle(t *testing.T) {
	run := func(mail string) []string {
		old := appLog
		appLog = strings.ReplaceAll(appLog, email1, mail)
		defer func() { appLog = old }()
		r := newRig(t, rigOpts{})
		ref, toks := r.record()
		tk := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
		r.hub.Decide(tk, ticket.Approved, "")
		r.decided(mcptools.ToolUnmask, unmaskArgs(ref, toks[1:], tk))
		r.mu.Lock()
		defer r.mu.Unlock()
		return slices.Clone(r.outputs)
	}
	a, b := run("anna.doe@example.com"), run("jane.dow@example.com")
	norm := func(s string) string {
		s = sealedRe.ReplaceAllString(strings.ReplaceAll(s, `\"`, `"`), "")
		s = tokenRe.ReplaceAllString(s, "⟦email⟧")
		s = ulidRe.ReplaceAllString(s, "TICKET")
		s = epochRe.ReplaceAllString(s, `"epoch":"E"`)
		return s
	}
	// The polls for the decision repeat the same pending answer: once.
	for _, o := range []*[]string{&a, &b} {
		var u []string
		for _, x := range *o {
			if x = norm(x); !slices.Contains(u, x) {
				u = append(u, x)
			}
		}
		*o = u
	}
	if len(a) != len(b) {
		t.Fatalf("%d answers, then %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("answer %d differs:\n%s\n%s", i, a[i], b[i])
		}
	}
}
