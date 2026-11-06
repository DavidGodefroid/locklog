package logconsole

import (
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locklog/internal/config"
)

func TestAutoActionOfMethods(t *testing.T) {
	for m, want := range map[string]config.AutoAction{MethodScan: config.ActionRead, MethodUnmask: config.ActionUnmask, MethodLookup: config.ActionLookup} {
		if got := autoAction(m); got != want {
			t.Errorf("%s: %s, want %s", m, got, want)
		}
	}
	// A method without an action is denied (fail closed).
	if v := config.DefaultAutoRules.Get(autoAction(MethodSearch)); v != config.AutoDeny {
		t.Errorf("search: %s", v)
	}
	for _, m := range hubApproved {
		if autoAction(m) == "" {
			t.Errorf("approved method %s has no auto action", m)
		}
	}
}

func TestDecidedBy(t *testing.T) {
	for _, tt := range []struct {
		d    *ticket.Decision
		want string
	}{
		{nil, ""},
		{&ticket.Decision{}, ""},
		{&ticket.Decision{Rule: &ticket.Rule{By: ticket.RuleHuman}}, "human"},
		{&ticket.Decision{Rule: &ticket.Rule{By: ticket.RuleAuto, ID: "profile:read"}}, "auto:profile:read"},
	} {
		if got := decidedBy(tt.d); got != tt.want {
			t.Errorf("decidedBy(%+v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
