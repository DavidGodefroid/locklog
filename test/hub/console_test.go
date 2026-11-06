//go:build unix

package hub

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"

	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

// TestHubConsoleOwnDecisions: hub-attached, the console still decides its
// own widenings on its terminal, never on lockhub: a policy loosening at
// :review and :unmask ask there, and on a production profile they take
// the profile name typed exactly (y is not enough); the clear view
// (Ctrl-O) shows the records on the terminal only.
func TestHubConsoleOwnDecisions(t *testing.T) {
	r := newRig(t, rigOpts{extra: "production = true"})
	ctx := context.Background()
	pushed := r.hub.Pushed()

	// The clear view: the records the agent gets masked, in clear on this
	// terminal only.
	r.srv.Key(console.KeyCtrlO)
	a := r.call(mcptools.ToolSearch, map[string]any{"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z",
		"where": []map[string]any{{"field": "status", "op": "=", "value": 502}}})
	if a.isErr || strings.Contains(a.text, email1) {
		t.Fatalf("search: %s", a.text)
	}
	if out := r.io.output(); !strings.Contains(out, "records in clear (results on, Ctrl-O") || !strings.Contains(out, email1) {
		t.Fatalf("clear view:\n%s", out)
	}

	// :unmask: y is refused on production, the typed name allows it.
	r.io.answer("y")
	r.srv.Command(ctx, ":unmask")
	if p := r.io.lastPrompt(); !strings.Contains(p, `Allow unmasked output? Type the profile name "staging" to allow it`) {
		t.Fatalf(":unmask prompt %q", p)
	}
	if out := r.io.output(); !strings.Contains(out, "unmask: still off") {
		t.Fatalf(":unmask with y:\n%s", out)
	}
	r.io.answer("staging")
	r.srv.Command(ctx, ":unmask")
	if out := r.io.output(); !strings.Contains(out, "unmask: allowed") {
		t.Fatalf(":unmask with the name:\n%s", out)
	}

	// A loosening (a new source) read from the file waits for :review,
	// which takes the typed name on production.
	b, err := os.ReadFile(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)[strings.Index(string(b), "[profiles.staging.sources.app]"):]
	loose := string(b) + strings.Replace(src, "sources.app]", "sources.app2]", 1)
	if err := os.WriteFile(r.cfg, []byte(loose), 0o644); err != nil {
		t.Fatal(err)
	}
	r.srv.CheckPolicy()
	r.io.answer("y")
	r.srv.Command(ctx, ":review")
	if p := r.io.lastPrompt(); !strings.Contains(p, `Apply these changes? Type the profile name "staging" to apply them`) {
		t.Fatalf(":review prompt %q\n%s", p, r.io.output())
	}
	if out := r.io.output(); !strings.Contains(out, "policy change refused") {
		t.Fatalf(":review with y:\n%s", out)
	}
	// Refused, the same change is not asked again: another one is.
	loose += strings.Replace(src, "sources.app]", "sources.app3]", 1)
	if err := os.WriteFile(r.cfg, []byte(loose), 0o644); err != nil {
		t.Fatal(err)
	}
	r.srv.CheckPolicy()
	r.io.answer("staging")
	r.srv.Command(ctx, ":review")
	if out := r.io.output(); !strings.Contains(out, "policy change applied") {
		t.Fatalf(":review with the name:\n%s", out)
	}
	if r.hub.Pushed() != pushed {
		t.Fatalf("a console decision went to the hub (%d tickets)", r.hub.Pushed()-pushed)
	}
}
