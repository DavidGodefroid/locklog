package index_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
)

// TestAgentRuleMidGranuleRedactsIndex: an agent rule added while a granule
// is built, on an ancestor path of a trusted field ("http" when
// "http.status" is trusted), redacts that field in the records indexed
// after it, although the value was memoized as not sensitive (#84).
func TestAgentRuleMidGranuleRedactsIndex(t *testing.T) {
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ag, err := mask.OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := pii.NewEpoch(t0)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mask.New(mask.Options{Pseudonyms: ep, Rules: &mask.Rules{Agent: ag}, Trusted: []string{"http.status"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := parse.New(parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	line := `{"time":"2026-10-30T12:00:00Z","http":{"status":502}}`
	m.Mask("app", p.Line(line)) // shows "http" in clear, as a query answer would
	b := index.NewBuilder([]string{"http.status"}, func(f, v string) bool { return m.TrustedValue("app", f, v) != v }, m.RulesGeneration)
	b.Add(p.Line(line))
	if err := m.AgentAdd("app", "http", mask.ModeRedact, t0, mask.AgentLimits{PerHour: 10, Total: 10}); err != nil {
		t.Fatal(err)
	}
	b.Add(p.Line(line))
	g := b.Finish(0, 0, 1, true)
	if len(g.Minutes) != 1 {
		t.Fatalf("%+v", g)
	}
	var clear, redacted int64
	for _, c := range g.Minutes[0].Counts {
		switch c.Vals[0] {
		case "502":
			clear += c.N
		case index.Redacted:
			redacted += c.N
		}
	}
	if clear != 1 || redacted != 1 {
		t.Fatalf("clear %d redacted %d: %+v", clear, redacted, g.Minutes[0].Counts)
	}
}
