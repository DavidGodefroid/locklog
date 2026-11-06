package mask

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CheckAgentRule checks without adding, and its canonical form names the
// field by its keyed digest only: never the clear name, nor the shown one.
func TestCheckAgentRuleCanonicalIsADigest(t *testing.T) {
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	rules := Rules{Agent: ag}
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &rules})
	maskedName := "jean.secretname@example.com"
	r := m.Mask("api", event(t, `{"order":"4812","`+maskedName+`":"Lyon"}`))
	var shownKey string
	for _, f := range r.Fields() {
		if strings.HasPrefix(f.Name(), Open+KeyKind) {
			shownKey = f.Name()
		}
	}
	lim := AgentLimits{PerHour: 10, Total: 50}
	rule, err := m.CheckAgentRule("api", shownKey, ModeRedact, t0, lim)
	if err != nil {
		t.Fatal(err)
	}
	if ag.Len() != 0 {
		t.Fatal("CheckAgentRule added the rule")
	}
	text := rule.String()
	for _, w := range []string{maskedName, "jean", "secretname", shownKey, "api"} {
		if strings.Contains(text, w) {
			t.Errorf("canonical form %q holds %q", text, w)
		}
	}
	back, err := ParseAgentRule(text)
	if err != nil || back != rule {
		t.Fatalf("ParseAgentRule(%q) = %v, %v", text, back, err)
	}
	for _, bad := range []string{"", "agent redact", "agent partial " + rule.Digest, "agent redact " + rule.Digest[:63], "agent redact " + strings.ToUpper(rule.Digest), "redact " + rule.Digest} {
		if _, err := ParseAgentRule(bad); err == nil {
			t.Errorf("ParseAgentRule(%q) accepted", bad)
		}
	}
	if err := ag.Add(rule, t0, lim); err != nil {
		t.Fatal(err)
	}
	if err := ag.Add(rule, t0, lim); !errors.Is(err, ErrRuleExists) {
		t.Errorf("a second Add = %v", err)
	}
	if _, err := m.CheckAgentRule("api", shownKey, ModeRedact, t0, lim); !errors.Is(err, ErrRuleExists) {
		t.Errorf("CheckAgentRule of an existing rule = %v", err)
	}
	if out := encode(t, m.Mask("api", event(t, `{"`+maskedName+`":"Lyon"}`))); strings.Contains(out, "Lyon") {
		t.Errorf("the added rule is not applied: %s", out)
	}
	// The caps are checked by CheckAgentRule too.
	m.Mask("api", event(t, `{"other":"x"}`))
	if _, err := m.CheckAgentRule("api", "other", ModeRedact, t0, AgentLimits{PerHour: 1, Total: 50}); !errors.Is(err, ErrRuleCap) {
		t.Errorf("hourly cap: %v", err)
	}
	if _, err := m.CheckAgentRule("api", "other", ModeRedact, t0, AgentLimits{PerHour: 10, Total: 1}); !errors.Is(err, ErrRuleCap) {
		t.Errorf("total cap: %v", err)
	}
}

// Stats counts the rules, those of the last hour and the last one's time.
func TestAgentRulesStats(t *testing.T) {
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	if st := ag.Stats(t0); st.Rules != 0 || st.LastHour != 0 || !st.Last.IsZero() {
		t.Fatalf("empty stats = %+v", st)
	}
	lim := AgentLimits{PerHour: 10, Total: 50}
	if err := ag.add("api", "a", ModeRedact, t0, lim); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(90 * time.Minute)
	if err := ag.add("api", "b", ModePseudonym, later, lim); err != nil {
		t.Fatal(err)
	}
	st := ag.Stats(later.Add(time.Minute))
	if st.Rules != 2 || st.LastHour != 1 || !st.Last.Equal(later) {
		t.Fatalf("stats = %+v", st)
	}
	list := ag.List()
	if len(list) != 2 || list[0].Mode != ModeRedact || !list[1].Added.Equal(later) {
		t.Fatalf("list = %+v", list)
	}
}
