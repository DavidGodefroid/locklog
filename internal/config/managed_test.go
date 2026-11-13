//go:build lockfamily_managed_test

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// managedOf parses a managed file's body (after its version line).
func managedOf(t *testing.T, body string) *Managed {
	t.Helper()
	f, err := managed.Parse([]byte("version = 1\norganisation = \"Acme\"\n" + body))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManaged(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// useManaged makes body the machine's managed file for the test.
func useManaged(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte("version = 1\norganisation = \"Acme\"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
}

const devFile = `[profiles.dev.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]
`

const devLoki = `[profiles.dev.sources.lk]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "bearer"
`

// violations are the lines of profile dev of body under the bounds.
func violations(t *testing.T, bounds, body string) []string {
	t.Helper()
	m := managedOf(t, "[locklog.bounds]\n"+bounds)
	p := mustParse(t, body)["dev"]
	m.Bounds.require(&p)
	lines, err := m.Bounds.Violations(m.Bounds.policyOf(p))
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

// One test per row of the bounds table: a profile beyond the bound is
// refused citing the managed key.
func TestManagedBoundsRows(t *testing.T) {
	for _, c := range []struct {
		name, bound, profile, want string
	}{
		{"production", "production = true", devFile, "blocked by company policy: locklog.bounds.production = true (profile dev: production = false)"},
		{"structured", `structured = "redact-unknown"`, devFile, "locklog.bounds.structured = redact-unknown (profile dev: structured = detect)"},
		{"text", `text = "template"`, devFile, "locklog.bounds.text = template (profile dev: text = detect)"},
		{"unmask", `unmask = "never"`, devFile, "blocked by company policy: locklog.bounds.unmask = never (profile dev: unmask = approved)"},
		{"lookup", `lookup = "approved"`, devFile, "locklog.bounds.lookup = approved (profile dev: lookup = free)"},
		{"strict", "strict = true", devFile, "locklog.bounds.strict = true (profile dev: strict = false)"},
		{"prefilter", "prefilter = false", "[profiles.dev]\nprefilter = true\n" + devFile, "locklog.bounds.prefilter = false (profile dev: prefilter = true)"},
		{"user_journals", "user_journals = false", "[profiles.dev]\nuser_journals = true\n" + devFile, "locklog.bounds.user_journals = false (profile dev: user_journals = true)"},
		{"pseudonym_rotation", `pseudonym_rotation = "session"`, devFile, "locklog.bounds.pseudonym_rotation = session (profile dev: pseudonym_rotation = 7d)"},
		{"pseudonym_rotation never", `pseudonym_rotation = "7d"`, "[profiles.dev]\npseudonym_rotation = \"never\"\n" + devFile, "locklog.bounds.pseudonym_rotation = 7d (profile dev: pseudonym_rotation = never)"},
		{"pseudonym_max_age", `pseudonym_max_age = "7d"`, devFile, "locklog.bounds.pseudonym_max_age = 7d (profile dev: pseudonym_max_age = 30d)"},
		{"auto.read", `auto = { read = "ask" }`, "[profiles.dev]\nauto = { read = \"auto\" }\n" + devFile, "locklog.bounds.auto.read = ask (profile dev: auto.read = auto)"},
		{"auto.unmask", `auto = { unmask = "deny" }`, devFile, "locklog.bounds.auto.unmask = deny (profile dev: auto.unmask = ask)"},
		{"auto.lookup", `auto = { lookup = "ask" }`, "[profiles.dev]\nauto = \"full-auto\"\n" + devFile, "locklog.bounds.auto.lookup = ask (profile dev: auto.lookup = auto)"},
		{"limits.local.range", `limits = { local = { range = "1d" } }`, devFile, "locklog.bounds.limits.local.range = 1d (profile dev: limits.local.range = 7d)"},
		{"limits.local.count_range", `limits = { local = { count_range = "7d" } }`, devFile, "locklog.bounds.limits.local.count_range = 7d (profile dev: limits.local.count_range = 30d)"},
		{"limits.local.max_bytes", `limits = { local = { max_bytes = "1MiB" } }`, devFile, "locklog.bounds.limits.local.max_bytes = 1MiB (profile dev: limits.local.max_bytes = 512MiB)"},
		{"limits.local.bytes_per_hour", `limits = { local = { bytes_per_hour = "1GiB" } }`, devFile, "locklog.bounds.limits.local.bytes_per_hour = 1GiB (profile dev: limits.local.bytes_per_hour = 40GiB)"},
		{"limits.remote.range", `limits = { remote = { range = "1h" } }`, devFile, "locklog.bounds.limits.remote.range = 1h0m0s (profile dev: limits.remote.range = 1d)"},
		{"limits.remote.count_range", `limits = { remote = { count_range = "1d" } }`, devFile, "locklog.bounds.limits.remote.count_range = 1d (profile dev: limits.remote.count_range = 30d)"},
		{"limits.remote.max_bytes", `limits = { remote = { max_bytes = "1MiB" } }`, devFile, "locklog.bounds.limits.remote.max_bytes = 1MiB (profile dev: limits.remote.max_bytes = 512MiB)"},
		{"limits.remote.bytes_per_hour", `limits = { remote = { bytes_per_hour = "1GiB" } }`, devFile, "locklog.bounds.limits.remote.bytes_per_hour = 1GiB (profile dev: limits.remote.bytes_per_hour = 20GiB)"},
		{"limits.remote.metric_queries_per_hour", `limits = { remote = { metric_queries_per_hour = 10 } }`, devFile, "locklog.bounds.limits.remote.metric_queries_per_hour = 10 (profile dev: limits.remote.metric_queries_per_hour = 120)"},
		{"limits.remote.requests_per_minute", `limits = { remote = { requests_per_minute = 60 } }`, devFile, "locklog.bounds.limits.remote.requests_per_minute = 60 (profile dev: limits.remote.requests_per_minute = 600)"},
		{"limits.max_records", `limits = { max_records = 10 }`, devFile, "locklog.bounds.limits.max_records = 10 (profile dev: limits.max_records = 200)"},
		{"limits.max_output", `limits = { max_output = "16KiB" }`, devFile, "locklog.bounds.limits.max_output = 16KiB (profile dev: limits.max_output = 64KiB)"},
		{"limits.lookups_per_hour", `limits = { lookups_per_hour = 5 }`, devFile, "locklog.bounds.limits.lookups_per_hour = 5 (profile dev: limits.lookups_per_hour = 50)"},
		{"limits.lookups_per_hour_per_uid", `limits = { lookups_per_hour_per_uid = 5 }`, devFile, "locklog.bounds.limits.lookups_per_hour_per_uid = 5 (profile dev: limits.lookups_per_hour_per_uid = 20)"},
		{"limits.pii_adds_per_hour", `limits = { pii_adds_per_hour = 2 }`, devFile, "locklog.bounds.limits.pii_adds_per_hour = 2 (profile dev: limits.pii_adds_per_hour = 10)"},
		{"limits.pii_rules_max", `limits = { pii_rules_max = 5 }`, devFile, "locklog.bounds.limits.pii_rules_max = 5 (profile dev: limits.pii_rules_max = 50)"},
		{"limits.max_calls", `limits = { max_calls = 2 }`, "[profiles.dev]\nlimits = { max_calls = 8 }\n" + devFile, "locklog.bounds.limits.max_calls = 2 (profile dev: limits.max_calls = 8)"},
		{"limits.idle_timeout", `limits = { idle_timeout = "10m" }`, devFile, "locklog.bounds.limits.idle_timeout = 10m0s (profile dev: limits.idle_timeout = 1h0m0s)"},
		{"limits.max_session", `limits = { max_session = "2h" }`, devFile, "locklog.bounds.limits.max_session = 2h0m0s (profile dev: limits.max_session = 12h0m0s)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			lines := violations(t, c.bound, c.profile)
			if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, c.want) }) {
				t.Errorf("lines %q, want one with %q", lines, c.want)
			}
		})
	}
}

// A profile stricter than or equal to every bound has no violation.
func TestManagedBoundsStricter(t *testing.T) {
	bounds := `production = true
structured = "redact-unknown"
text = "template"
unmask = "never"
lookup = "approved"
strict = true
prefilter = false
user_journals = false
pseudonym_rotation = "7d"
pseudonym_max_age = "30d"
auto = { read = "ask", unmask = "deny" }
limits = { max_records = 100, max_output = "64KiB", max_session = "8h", idle_timeout = "30m", local = { range = "1d" }, remote = { requests_per_minute = 240 } }
`
	profile := `[profiles.dev]
production = true
text = "template"
lookup = "approved"
strict = true
pseudonym_rotation = "session"
auto = { unmask = "deny" }
limits = { max_records = 50, max_session = "8h", idle_timeout = "30m", local = { range = "12h" } }
[profiles.dev.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]
`
	if lines := violations(t, bounds, profile); len(lines) > 0 {
		t.Errorf("a stricter profile: %q", lines)
	}
}

// Each allowlist bound refuses a value outside the list, naming the
// managed key, and accepts a value inside it.
func TestManagedAllowlists(t *testing.T) {
	loki := func(repl ...string) string {
		s := devLoki
		for i := 0; i+1 < len(repl); i += 2 {
			s = strings.Replace(s, repl[i], repl[i+1], 1)
		}
		return s
	}
	for _, c := range []struct {
		name, bound, bad, good, want string
		badNet, goodNet              string
		badRoots, goodRoots          []string
	}{
		{name: "kinds", bound: `kinds = ["file"]`, bad: devLoki, good: devFile, want: "locklog.bounds.kinds does not allow sources.lk.kind = loki (profile dev; allowed: file)"},
		{name: "hosts", bound: `hosts = ["*.example.com"]`, bad: loki("loki.example.com", "loki.other.org"), good: devLoki, want: "locklog.bounds.hosts does not allow sources.lk.url = loki.other.org"},
		{name: "paths", bound: `paths = ["/var/log/nginx"]`, bad: devFile, good: strings.Replace(devFile, "/var/log/app/app.log", "/var/log/nginx/access.log*", 1), want: "locklog.bounds.paths does not allow sources.app.paths = /var/log/app/app.log"},
		{name: "auth", bound: `auth = ["bearer"]`, bad: loki(`auth = "bearer"`, `auth = "basic"`+"\nuser = \"reader\""), good: devLoki, want: "locklog.bounds.auth does not allow sources.lk.auth = basic"},
		{name: "credentials", bound: `credentials = ["vault"]`, bad: devLoki, good: devLoki + "credentials = \"vault\"\nvault_path = \"secret/loki\"\n", want: "locklog.bounds.credentials does not allow sources.lk.credentials = ask"},
		{name: "tls", bound: `tls = "verify-full"`, bad: devLoki + "tls = \"verify-ca\"\n", good: devLoki, want: "locklog.bounds.tls does not allow sources.lk.tls = verify-ca"},
		{name: "network", bound: `network = ["logs"]`, bad: devFile, good: devFile, badNet: "other", goodNet: "logs", want: "locklog.bounds.network does not allow network = other"},
		{name: "network none", bound: `network = []`, bad: devFile, good: devFile, badNet: "logs", want: "locklog.bounds.network does not allow network = logs (profile dev; allowed: (none))"},
		{name: "extra_roots", bound: `extra_roots = ["/srv/logs"]`, bad: devFile, good: devFile, badRoots: []string{"/opt/app"}, goodRoots: []string{"/srv/logs/app"}, want: "locklog.bounds.extra_roots does not allow extra_roots = /opt/app"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := managedOf(t, "[locklog.bounds]\n"+c.bound)
			check := func(body, network string, roots []string) []string {
				pol, err := NewPolicy(mustParse(t, body)["dev"], network, roots)
				if err != nil {
					t.Fatal(err)
				}
				lines, err := m.Bounds.Violations(pol)
				if err != nil {
					t.Fatal(err)
				}
				return lines
			}
			if lines := check(c.bad, c.badNet, c.badRoots); !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, c.want) }) {
				t.Errorf("outside the list: %q, want %q", lines, c.want)
			}
			if lines := check(c.good, c.goodNet, c.goodRoots); len(lines) > 0 {
				t.Errorf("inside the list: %q", lines)
			}
		})
	}
}

// auto = { unmask = "ask" } refuses auto.unmask = "auto" and the
// full-auto preset, and accepts deny; a preset in a bound is refused.
func TestManagedAutoBound(t *testing.T) {
	for _, c := range []struct {
		auto string
		bad  bool
	}{{`auto = { unmask = "auto" }`, true}, {`auto = "full-auto"`, true}, {`auto = { unmask = "deny" }`, false}} {
		lines := violations(t, `auto = { unmask = "ask" }`, "[profiles.dev]\n"+c.auto+"\n"+devFile)
		got := slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "locklog.bounds.auto.unmask = ask") })
		if got != c.bad {
			t.Errorf("%s: lines %q, want a violation: %t", c.auto, lines, c.bad)
		}
	}
	f, err := managed.Parse([]byte("version = 1\n[locklog.bounds]\nauto = \"full-auto\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManaged(f); err == nil || !strings.Contains(err.Error(), "a preset is refused in a bound") {
		t.Errorf("a preset bound: %v", err)
	}
}

// [family] vault = { required = true } refuses a basic-auth loki source
// whose credentials are asked, and accepts it from Vault.
func TestManagedVaultRequired(t *testing.T) {
	m := managedOf(t, "[family]\nvault = { address = \"https://vault.example.com\", required = true }\n")
	basic := strings.Replace(devLoki, `auth = "bearer"`, "auth = \"basic\"\nuser = \"reader\"", 1)
	for _, c := range []struct {
		body string
		bad  bool
	}{{basic + "credentials = \"ask\"\n", true}, {basic + "credentials = \"vault\"\nvault_path = \"secret/loki\"\n", false}} {
		lines, err := m.Bounds.Violations(Canonical(Policy{Profile: mustParse(t, c.body)["dev"]}))
		if err != nil {
			t.Fatal(err)
		}
		got := slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, "family.vault.required does not allow sources.lk.credentials = ask")
		})
		if got != c.bad {
			t.Errorf("lines %q, want a violation: %t", lines, c.bad)
		}
	}
}

// detectors = ["iban"] keeps iban on a profile whose detectors omit it.
func TestManagedDetectorsRequired(t *testing.T) {
	useManaged(t, "[locklog.bounds]\ndetectors = [\"iban\"]\n")
	root := project(t, "version = 1\n[profiles.dev]\ndetectors = [\"email\"]\n"+devFile)
	for _, load := range []func() (map[string]Profile, error){
		func() (map[string]Profile, error) { ps, _, err := LoadFrom(root, ""); return ps, err },
		func() (map[string]Profile, error) { return LoadFile(filepath.Join(root, ".locklog", "config.toml")) },
	} {
		ps, err := load()
		if err != nil {
			t.Fatal(err)
		}
		if d := ps["dev"].Detectors; !slices.Equal(d, []string{"email", "iban"}) {
			t.Errorf("detectors %q", d)
		}
	}
}

// project writes a project's .locklog/config.toml and returns its root.
func project(t *testing.T, cfg string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

const sharedProfile = `[locklog.profiles.shared]
production = true
lookup = "approved"
[locklog.profiles.shared.sources.lk]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "bearer"
`

// A managed profile is served as written through both readers; a user
// or project profile of its name is refused, naming it.
func TestManagedProfiles(t *testing.T) {
	useManaged(t, sharedProfile)
	root := project(t, "version = 1\n"+devFile)
	cfg := filepath.Join(root, ".locklog", "config.toml")
	ps, _, err := LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	ps2, err := LoadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []map[string]Profile{ps, ps2} {
		p, ok := got["shared"]
		if !ok || !p.Managed || !p.Production || p.Lookup != LookupApproved || len(p.Sources) != 1 || p.Sources[0].Remote.URL != "https://loki.example.com" {
			t.Errorf("shared = %+v", p)
		}
		if _, ok := got["dev"]; !ok {
			t.Error("the project's profile is missing")
		}
	}

	redefined := project(t, "version = 1\n"+strings.ReplaceAll(devFile, "profiles.dev", "profiles.shared"))
	if _, err := LoadFile(filepath.Join(redefined, ".locklog", "config.toml")); err == nil || !strings.Contains(err.Error(), `profile "shared" is provided by the company's managed configuration`) {
		t.Errorf("a project profile of a managed name: %v", err)
	}
	user := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(user, []byte("version = 1\n"+strings.ReplaceAll(devFile, "profiles.dev", "profiles.shared")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFrom(root, user); err == nil || !strings.Contains(err.Error(), `profile "shared"`) || !strings.Contains(err.Error(), "user config") {
		t.Errorf("a user profile of a managed name: %v", err)
	}
}

// A managed profile beyond the bounds is a load error.
func TestManagedProfileBeyondBounds(t *testing.T) {
	beyond := strings.Replace(sharedProfile, "lookup = \"approved\"\n", "lookup = \"approved\"\nunmask = \"approved\"\n", 1)
	f, err := managed.Parse([]byte("version = 1\n[locklog.bounds]\nunmask = \"never\"\n" + beyond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManaged(f); err == nil || !strings.Contains(err.Error(), "beyond the managed bounds") || !strings.Contains(err.Error(), "locklog.bounds.unmask") {
		t.Errorf("a managed profile beyond the bounds: %v", err)
	}
}

// A managed default applies when the profile omits the key; a value of
// the config files within the bounds wins; a default beyond the bounds is
// a load error.
func TestManagedDefaults(t *testing.T) {
	useManaged(t, "[locklog.bounds]\nlimits = { max_records = 100 }\n[locklog.defaults]\nlookup = \"approved\"\nlimits = { max_records = 20, local = { range = \"1d\" } }\n")
	root := project(t, "version = 1\n[profiles.dev]\nlimits = { max_records = 50 }\n"+devFile+`[profiles.qa.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]
`)
	ps, _, err := LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if dev, qa := ps["dev"], ps["qa"]; dev.Limits.MaxRecords != 50 || qa.Limits.MaxRecords != 20 || dev.Lookup != LookupApproved || qa.Limits.Local.Range != Day || qa.Limits.Local.CountRange != 30*Day {
		t.Errorf("dev %+v, qa %+v", dev.Limits, qa.Limits)
	}

	f, err := managed.Parse([]byte("version = 1\n[locklog.bounds]\nlimits = { max_records = 100 }\n[locklog.defaults]\nlimits = { max_records = 500 }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManaged(f); err == nil || !strings.Contains(err.Error(), "the managed default is beyond the managed bounds") {
		t.Errorf("a default beyond the bounds: %v", err)
	}
	f, err = managed.Parse([]byte("version = 1\n[locklog.defaults.sources.x]\nkind = \"file\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManaged(f); err == nil || !strings.Contains(err.Error(), "a default holds no source") {
		t.Errorf("a default with sources: %v", err)
	}
}

// No managed file: the readers behave as before.
func TestNoManagedFile(t *testing.T) {
	managed.SetTestPath(filepath.Join(t.TempDir(), managed.FileName))
	t.Cleanup(func() { managed.SetTestPath("") })
	root := project(t, "version = 1\n"+devFile)
	ps, _, err := LoadFrom(root, "")
	if err != nil {
		t.Fatal(err)
	}
	want := mustParse(t, devFile)["dev"]
	if got := ps["dev"]; got.Name != want.Name || !slices.Equal(got.Detectors, want.Detectors) || got.Managed {
		t.Errorf("dev = %+v", got)
	}
}

// A managed mask rule overlapped by an allow rule is refused.
func TestManagedCheckAllow(t *testing.T) {
	m := managedOf(t, "[[locklog.bounds.pii_mask]]\nsources = [\"app-*\"]\nfield = \"user.email\"\n")
	for _, c := range []struct {
		allow string
		bad   bool
	}{
		{"[[allow]]\nfield = \"user.email\"\n", true},
		{"[[allow]]\nsources = [\"app-api\"]\nfield = \"user.*\"\n", true},
		{"[[allow]]\nsources = [\"billing\"]\nfield = \"user.email\"\n", false},
		{"[[allow]]\nfield = \"user.name\"\n", false},
	} {
		rules, err := mask.ParseProjectRules([]byte(c.allow))
		if err != nil {
			t.Fatal(err)
		}
		err = m.Bounds.CheckAllow(rules.Allow)
		if got := err != nil && strings.Contains(err.Error(), "locklog.bounds.pii_mask"); got != c.bad {
			t.Errorf("%q: %v, want refused: %t", c.allow, err, c.bad)
		}
	}
}
