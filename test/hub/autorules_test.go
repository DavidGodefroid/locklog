//go:build unix

package hub

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

// autoCase is one approved method: its tool, its arguments, the profile
// keys it needs and its risk.
type autoCase struct {
	action, tool, extra string
	args                func(r *rig) map[string]any
	risk                ticket.Risk
	clear               bool
}

var autoCases = []autoCase{
	{"read", mcptools.ToolScan, "", func(*rig) map[string]any {
		return map[string]any{"tool": "search", "reason": "the whole hour", "query": map[string]any{
			"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z", "limit": 1,
			"where": []map[string]any{{"field": "level", "op": "=", "value": "error"}}}}
	}, ticket.RiskRead, false},
	{"unmask", mcptools.ToolUnmask, "", func(r *rig) map[string]any {
		ref, toks := r.record()
		return unmaskArgs(ref, toks[:1], "")
	}, ticket.RiskReadPII, true},
	{"lookup", mcptools.ToolLookup, `lookup = "approved"`, func(*rig) map[string]any {
		return map[string]any{"kind": "email", "values": []string{email1}, "reason": "the user gave this address"}
	}, ticket.RiskReadPII, false},
}

// auditRecords are the console's audit records that match.
func (r *rig) auditRecords(match func(map[string]any) bool) []map[string]any {
	r.t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(r.auditLog()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && match(m) {
			out = append(out, m)
		}
	}
	return out
}

// Every action × value of the profile's auto rules on hub tickets: deny
// is refused before any ticket (E_AUTO_DENY, nothing pushed); ask signs a
// version-2 ticket never_auto, whose auto approval the lock refuses and
// whose human approval runs; auto leaves it to lox run's auto rule, whose
// approval runs. The audit names the rule and what decided.
func TestHubAutoRulesEveryActionAndValue(t *testing.T) {
	for _, c := range autoCases {
		for _, v := range []string{"auto", "ask", "deny"} {
			t.Run(c.action+"-"+v, func(t *testing.T) {
				extra := c.extra + "\nauto = { " + c.action + ` = "` + v + `" }`
				r := newRig(t, rigOpts{extra: extra})
				args := c.args(r)
				rule := "auto." + c.action + " = " + v
				pushed := r.hub.Pushed()
				a := r.call(c.tool, args)
				if v == "deny" {
					if !a.isErr || a.code() != "E_AUTO_DENY" || a.out.Refusal.Retry != "ask_user" {
						t.Fatalf("denied: %s %+v", a.text, a.out.Refusal)
					}
					if r.hub.Pushed() != pushed {
						t.Fatal("a denied action was pushed to the hub")
					}
					recs := r.auditRecords(func(m map[string]any) bool { return m["auto_rule"] == rule })
					if len(recs) != 1 || recs[0]["decision"] != "refused" || recs[0]["code"] != "E_AUTO_DENY" {
						t.Fatalf("audit %v", recs)
					}
					r.checkAgentOutputs(false)
					return
				}
				tk := r.mustPending(a)
				signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
				if err != nil {
					t.Fatal(err)
				}
				if signed.V != ticket.VersionKinds || signed.Kind != ticket.KindRead || signed.Subject == nil ||
					signed.Subject.Profile != "staging" || signed.Risk != c.risk || signed.Flags.NeverAuto != (v != "auto") {
					t.Fatalf("ticket v%d kind %s subject %+v risk %s never_auto %t", signed.V, signed.Kind, signed.Subject, signed.Risk, signed.Flags.NeverAuto)
				}
				// lox run's auto rule approves it.
				id := "profile:read"
				r.hub.DecideWith(tk, ticket.Approved, "", nil, func(d *ticket.Decision) {
					d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleAuto, ID: id}
				})
				run := maps.Clone(args)
				run["ticket"] = tk
				b := r.decided(c.tool, run)
				byTicket := func(m map[string]any) bool { return m["ticket"] == tk }
				if v == "ask" {
					if !b.isErr || b.code() != "E_APPROVAL" || !strings.Contains(b.text, "waits for the human's decision") {
						t.Fatalf("an auto approval of an asked ticket ran: %s", b.text)
					}
					refused := r.auditRecords(func(m map[string]any) bool { return byTicket(m) && m["event"] == "refused" })
					if len(refused) != 1 || refused[0]["auto_rule"] != rule || refused[0]["decided_by"] != "auto:"+id {
						t.Fatalf("refused audit %v", refused)
					}
					// The human's approval runs it.
					r.hub.Decide(tk, ticket.Approved, "")
					if b = r.decided(c.tool, run); b.isErr {
						t.Fatalf("the human's approval did not run: %s", b.text)
					}
					id = ""
				} else if b.isErr {
					t.Fatalf("an auto approval of an auto ticket did not run: %s", b.text)
				}
				want := "human"
				if id != "" {
					want = "auto:" + id
				}
				ok := r.auditRecords(func(m map[string]any) bool { return byTicket(m) && m["decision"] == "ok" })
				approved := r.auditRecords(func(m map[string]any) bool { return byTicket(m) && m["event"] == "approved" })
				if len(ok) != 1 || ok[0]["auto_rule"] != rule || ok[0]["decided_by"] != want ||
					len(approved) != 1 || approved[0]["auto_rule"] != rule || approved[0]["decided_by"] != want {
					t.Fatalf("audit ok %v approved %v, want %s by %s", ok, approved, rule, want)
				}
				pending := r.auditRecords(func(m map[string]any) bool { return byTicket(m) && m["decision"] == "pending" })
				if len(pending) == 0 || pending[0]["auto_rule"] != rule {
					t.Fatalf("pending audit %v", pending)
				}
				r.checkAgentOutputs(c.clear)
			})
		}
	}
}

// A free lookup takes no ticket: its rule does not apply unless it
// denies, and then every lookup is refused.
func TestHubAutoRulesFreeLookup(t *testing.T) {
	args := map[string]any{"kind": "email", "values": []string{email1}, "reason": "the user gave this address"}
	r := newRig(t, rigOpts{extra: `auto = { lookup = "ask" }`})
	if a := r.call(mcptools.ToolLookup, args); a.isErr {
		t.Fatalf("free lookup: %s", a.text)
	}
	if recs := r.auditRecords(func(m map[string]any) bool { return m["method"] == "log.lookup" }); len(recs) != 1 || recs[0]["auto_rule"] != nil {
		t.Fatalf("free lookup audit %v", recs)
	}
	r = newRig(t, rigOpts{extra: `auto = { lookup = "deny" }`})
	if a := r.call(mcptools.ToolLookup, args); a.code() != "E_AUTO_DENY" {
		t.Fatalf("free lookup under deny: %s", a.text)
	}
	r.checkAgentOutputs(false)
}

// A tightening to deny applies at once: the run of a ticket asked before
// it is refused, its plan withdrawn, nothing runs. Loosening a rule back
// toward auto on production waits for :review and the typed name.
func TestHubAutoRulesTightenThenLoosen(t *testing.T) {
	r := newRig(t, rigOpts{extra: "production = true\nunmask = \"approved\"", reconnect: true})
	ctx := context.Background()
	ref, toks := r.record()
	args := unmaskArgs(ref, toks[:1], "")
	tk := r.mustPending(r.call(mcptools.ToolUnmask, args))
	r.hub.Decide(tk, ticket.Approved, "")

	b, err := os.ReadFile(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := string(b)
	write := func(rules string) {
		t.Helper()
		c := strings.Replace(base, "production = true", "production = true\nauto = { "+rules+" }", 1)
		if err := os.WriteFile(r.cfg, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
		r.srv.CheckPolicy()
	}
	write(`unmask = "deny"`)
	run := maps.Clone(args)
	run["ticket"] = tk
	if a := r.call(mcptools.ToolUnmask, run); a.code() != "E_AUTO_DENY" {
		t.Fatalf("run after the tightening: %s", a.text)
	}
	if _, ok := r.hub.Withdrawn(tk); !ok {
		t.Error("the denied ticket's plan was not withdrawn")
	}
	if ran := r.auditRecords(func(m map[string]any) bool { return m["ticket"] == tk && m["decision"] == "ok" }); len(ran) != 0 {
		t.Errorf("the denied ticket ran: %v", ran)
	}

	// Back to ask (a loosening from deny), then to auto: each waits for
	// :review, which takes the profile name on production.
	write(`unmask = "auto"`)
	if a := r.call(mcptools.ToolUnmask, args); a.code() != "E_AUTO_DENY" {
		t.Fatalf("a loosening applied before :review: %s", a.text)
	}
	r.io.answer("y")
	r.srv.Command(ctx, ":review")
	if p := r.io.lastPrompt(); !strings.Contains(p, `Type the profile name "staging"`) {
		t.Fatalf(":review prompt %q\n%s", p, r.io.output())
	}
	if !strings.Contains(r.io.output(), "auto.unmask") {
		t.Errorf("the review does not show the rule:\n%s", r.io.output())
	}
	if a := r.call(mcptools.ToolUnmask, args); a.code() != "E_AUTO_DENY" {
		t.Fatalf("a loosening applied with y on production: %s", a.text)
	}
	write(`unmask = "auto", lookup = "deny"`)
	r.io.answer("staging")
	r.srv.Command(ctx, ":review")
	if !strings.Contains(r.io.output(), "policy change applied") {
		t.Fatalf(":review with the name:\n%s", r.io.output())
	}
	// A new ref: the old one was made under the policy changed since.
	ref, toks = r.record()
	tk2 := r.mustPending(r.call(mcptools.ToolUnmask, unmaskArgs(ref, toks[:1], "")))
	signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk2))
	if err != nil || signed.Flags.NeverAuto || !signed.Flags.Production {
		t.Fatalf("ticket after the loosening %+v %v", signed.Flags, err)
	}
	st := r.call(mcptools.ToolStatus, map[string]any{})
	if !strings.Contains(st.text, `"auto":{"lookup":"deny","read":"ask","unmask":"auto"}`) {
		t.Errorf("status: %s", st.text)
	}
	r.checkAgentOutputs(false)
}
