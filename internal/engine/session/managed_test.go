//go:build unix

package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mask"
)

const managedLog = `{"time":"2026-10-30T13:00:01Z","level":"error","user":{"email":"jdoe-77","id":"u-1"}}
`

// managedCfg is a profile of the source app-api.
func managedCfg(structured string) func(string) string {
	return func(logs string) string {
		return `version = 1
[profiles.staging]
structured = "` + structured + `"
[profiles.staging.sources.app-api]
kind = "file"
format = "json"
paths = ["` + logs + `/app.log"]
trusted = ["level", "user.id"]
`
	}
}

func writePII(t *testing.T, f *fixture, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, ".locklog", "pii.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func searchAll(t *testing.T, s *Session) string {
	t.Helper()
	res, ref := call(t, s, logconsole.MethodSearch, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"}`)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	out, _ := json.Marshal(res)
	return string(out)
}

// A managed [[locklog.bounds.pii_mask]] on user.email of the sources
// app-* masks the field under every profile, whatever its structured mode,
// even where an approved allow rule shows it; it is listed as managed.
// (The console refuses such an allow rule at load: here it is approved
// to show that the managed rule wins in the engine too.)
func TestManagedPIIMaskEveryProfile(t *testing.T) {
	rule, err := mask.BuildManagedRule(mask.RuleSpec{Sources: []string{"app-*"}, Field: "user.email"})
	if err != nil {
		t.Fatal(err)
	}
	for _, structured := range []string{config.StructuredDetect, config.StructuredRedactUnknown} {
		t.Run(structured, func(t *testing.T) {
			f := newFixture(t, managedCfg(structured), managedLog)
			writePII(t, f, "[[allow]]\nfield = \"user.email\"\n")
			o := f.options(nil)
			o.Policy.PIIAllow = []string{"allow field=user.email"}
			before := open(t, o)
			if got := searchAll(t, before); !strings.Contains(got, "jdoe-77") {
				t.Fatalf("without the managed rule, the allowed field is not clear: %s", got)
			}
			before.Close()
			o.Policy.PIIMask = []mask.Rule{rule}
			o.Policy = config.Canonical(o.Policy)
			o.FirstOpen = false
			s := open(t, o)
			if got := searchAll(t, s); strings.Contains(got, "jdoe-77") || !strings.Contains(got, `"id":"u-1"`) {
				t.Errorf("the managed rule did not mask user.email alone: %s", got)
			}
			if m, _ := s.PIIRules(); !slices.Contains(m, "redact field=user.email sources=app-* (managed)") {
				t.Errorf("rules in force = %q", m)
			}
		})
	}
	// Another source: the glob does not cover it.
	other, err := mask.BuildManagedRule(mask.RuleSpec{Sources: []string{"billing-*"}, Field: "user.email"})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, managedCfg(config.StructuredDetect), managedLog)
	writePII(t, f, "[[allow]]\nfield = \"user.email\"\n")
	o := f.options(nil)
	o.Policy.PIIAllow = []string{"allow field=user.email"}
	o.Policy.PIIMask = []mask.Rule{other}
	if got := searchAll(t, open(t, o)); !strings.Contains(got, "jdoe-77") {
		t.Errorf("a rule of sources billing-* masked app-api: %s", got)
	}
}

// A managed rule comes before the project's: a project pseudonym rule of
// the same field does not weaken it.
func TestManagedPIIMaskBeforeProject(t *testing.T) {
	rule, err := mask.BuildManagedRule(mask.RuleSpec{Field: "user.email"})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, managedCfg(config.StructuredDetect), managedLog)
	writePII(t, f, "[[mask]]\nfield = \"user.email\"\nmode = \"pseudonym\"\n")
	o := f.options(nil)
	o.Policy.PIIMask = []mask.Rule{rule}
	s := open(t, o)
	if m, _ := s.PIIRules(); len(m) < 2 || m[0] != "redact field=user.email (managed)" {
		t.Errorf("rules in force = %q", m)
	}
	if got := searchAll(t, s); strings.Contains(got, "jdoe-77") || !strings.Contains(got, mask.Redacted) {
		t.Errorf("search = %s", got)
	}
}
