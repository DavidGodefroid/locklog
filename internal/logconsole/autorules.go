package logconsole

import (
	"context"
	"fmt"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// The lock's side of the profile's auto rules (config/auto.go, #126).
// `lox run` decides in auto mode; the lock makes the rules hold whatever
// the decider does: deny is refused here, before any ticket; ask signs the
// ticket never-auto (ticket.Flags.NeverAuto), whose auto approval the lock
// refuses (ticket.ErrAuto); auto leaves the ticket to lox run's auto mode.
// The rule in force is that of the approved policy: loosening it is a
// policy loosening, reviewed at start or at :review, with the typed
// profile name on production.

// CodeAutoDeny: the profile's auto rules deny the action
// (auto.<action> = "deny"), even with a human's approval.
const CodeAutoDeny refusal.Code = "E_AUTO_DENY"

// autoAction is the auto action of an approved method.
func autoAction(method string) config.AutoAction {
	switch method {
	case MethodScan:
		return config.ActionRead
	case MethodUnmask:
		return config.ActionUnmask
	case MethodLookup:
		return config.ActionLookup
	}
	return "" // no action: Get denies it (fail closed)
}

// actionNoun names an action for the agent and the human.
func actionNoun(a config.AutoAction) string {
	switch a {
	case config.ActionRead:
		return "approved scan"
	case config.ActionUnmask:
		return "unmask"
	}
	return "lookup"
}

// autoRuleOf is the auto rule of method under the policy in force, set on
// rec (auto_rule) where it applies: a scan, an unmask, an approved
// lookup, and a denied lookup (a free lookup takes no ticket). A denied
// action is the refusal the agent gets.
func autoRuleOf(env console.Env, method string, rec *Record) *Refusal {
	p, _ := env.Policy().(Policy)
	pr := p.Policy.Profile
	rules := pr.AutoRules()
	act := autoAction(method)
	v := rules.Get(act)
	if method != MethodLookup || v == config.AutoDeny || pr.Lookup == config.LookupApproved {
		rec.AutoRule = rules.RuleText(act)
	}
	if v != config.AutoDeny {
		return nil
	}
	return &Refusal{
		Message: fmt.Sprintf("the auto rules of profile %s deny this %s (auto.%s = deny): no ticket is asked, and a human cannot approve it",
			pr.Name, actionNoun(act), act),
		Info: refusal.Info{Code: CodeAutoDeny, Retry: refusal.RetryAskUser,
			Hint: "do not look for another way to get it; only the human can change the profile's auto rules (auto in .locklog/config.toml): tell the user"},
	}
}

// withdrawTicket takes back the plan of ticket tk, the caller's, when it
// is still pending (best effort: a plan ended already has nothing to take
// back).
func withdrawTicket(ctx context.Context, env console.Env, h *console.Hub, tk string, caller plans.Caller) {
	p, err := h.Store.ByTicket(tk, caller)
	if err != nil || p.State != plans.Pending {
		return
	}
	if err := h.Client.Withdraw(ctx, h.Store, p.ID, caller, "the profile's auto rules deny it"); err != nil {
		env.Println(console.Paint.Fail("hub: a ticket could not be withdrawn: " + env.Safe(err.Error())))
	}
}

// decidedBy is what decided d, for the audit: "human", or "auto:<rule
// id>" for an auto rule of the decider; "" for a version-1 decision, which
// does not say.
func decidedBy(d *ticket.Decision) string {
	switch {
	case d == nil || d.Rule == nil:
		return ""
	case d.Rule.By == ticket.RuleAuto:
		return "auto:" + d.Rule.ID
	}
	return d.Rule.By
}
