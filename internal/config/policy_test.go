package config

import (
	"encoding/json"
	"strings"
	"testing"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

const basePolicy = `
[profiles.pp.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
format = "combined"
trusted = ["vhost"]
[profiles.pp.sources.sys]
kind = "journald"
units = ["nginx.service"]
[profiles.pp.sources.api]
kind = "docker"
containers = ["shop-api-1"]
[profiles.pp.sources.loki]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "bearer"
trusted_labels = ["app"]
`

func policyOf(t *testing.T, extra string, network string, roots ...string) Policy {
	t.Helper()
	return NewPolicy(mustParse(t, basePolicy+extra)["pp"], network, roots)
}

func TestDiffNoChange(t *testing.T) {
	a := policyOf(t, "", "net", "/srv/logs")
	b := policyOf(t, "", "net", "/srv/logs")
	if d := b.Diff(a); len(d) != 0 {
		t.Errorf("Diff of equal policies = %+v", d)
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("equal policies, different fingerprints")
	}
	if a.Fingerprint() == policyOf(t, "", "").Fingerprint() {
		t.Error("the launch environment is not fingerprinted")
	}
	if d := a.Diff(struct{ kconfig.Policy }{}); len(d) != 1 || !d[0].Loosens {
		t.Errorf("Diff against another type = %+v", d)
	}
}

func TestDiffLoosens(t *testing.T) {
	for _, tt := range []struct {
		name             string
		approved, cur    string
		aNet, cNet       string
		aRoots, cRoots   []string
		field            string
		loosens          bool
		replaceInApprove bool
	}{
		{name: "production off", approved: "[profiles.pp]\nproduction = true\n", cur: "[profiles.pp]\nstructured = \"redact-unknown\"\nunmask = \"never\"\n", field: "production", loosens: true},
		{name: "production on", cur: "[profiles.pp]\nproduction = true\n", field: "production", loosens: false},
		{name: "structured to detect", approved: "[profiles.pp]\nstructured = \"redact-unknown\"\n", field: "structured", loosens: true},
		{name: "structured to redact-unknown", cur: "[profiles.pp]\nstructured = \"redact-unknown\"\n", field: "structured", loosens: false},
		{name: "text to detect", approved: "[profiles.pp]\ntext = \"template\"\n", field: "text", loosens: true},
		{name: "detector removed", cur: "[profiles.pp]\ndetectors = [\"email\"]\n", field: "detectors", loosens: true},
		{name: "unmask approved", approved: "[profiles.pp]\nunmask = \"never\"\n", field: "unmask", loosens: true},
		{name: "unmask never", cur: "[profiles.pp]\nunmask = \"never\"\n", field: "unmask", loosens: false},
		{name: "lookup free", approved: "[profiles.pp]\nlookup = \"approved\"\n", field: "lookup", loosens: true},
		{name: "strict off", approved: "[profiles.pp]\nstrict = true\n", field: "strict", loosens: true},
		{name: "prefilter on", cur: "[profiles.pp]\nprefilter = true\n", field: "prefilter", loosens: true},
		{name: "user journals on", cur: "[profiles.pp]\nuser_journals = true\n", field: "user_journals", loosens: true},
		{name: "rotation longer", cur: "[profiles.pp]\npseudonym_rotation = \"14d\"\n", field: "pseudonym_rotation", loosens: true},
		{name: "rotation never", cur: "[profiles.pp]\npseudonym_rotation = \"never\"\n", field: "pseudonym_rotation", loosens: true},
		{name: "rotation session", cur: "[profiles.pp]\npseudonym_rotation = \"session\"\n", field: "pseudonym_rotation", loosens: false},
		{name: "max age longer", cur: "[profiles.pp]\npseudonym_max_age = \"60d\"\n", field: "pseudonym_max_age", loosens: true},
		{name: "range larger", cur: "[profiles.pp.limits.local]\nrange = \"30d\"\n", field: "limits.local.range", loosens: true},
		{name: "range smaller", cur: "[profiles.pp.limits.local]\nrange = \"1d\"\n", field: "limits.local.range", loosens: false},
		{name: "records larger", cur: "[profiles.pp.limits]\nmax_records = 500\n", field: "limits.max_records", loosens: true},
		{name: "session longer", cur: "[profiles.pp.limits]\nmax_session = \"1d\"\n", field: "limits.max_session", loosens: true},
		{name: "network added", cNet: "shop_default", field: "network", loosens: true},
		{name: "network changed", aNet: "a", cNet: "b", field: "network", loosens: true},
		{name: "network removed", aNet: "a", field: "network", loosens: false},
		{name: "extra root added", cRoots: []string{"/srv/logs"}, field: "extra_roots", loosens: true},
		{name: "extra root removed", aRoots: []string{"/srv/logs"}, field: "extra_roots", loosens: false},
		{name: "new source", cur: "[profiles.pp.sources.new]\nkind = \"journald\"\n", field: "sources", loosens: true},
		{name: "removed source", approved: "[profiles.pp.sources.new]\nkind = \"journald\"\n", field: "sources", loosens: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := policyOf(t, tt.approved, tt.aNet, tt.aRoots...)
			c := policyOf(t, tt.cur, tt.cNet, tt.cRoots...)
			assertChange(t, c.Diff(a), tt.field, tt.loosens)
		})
	}
}

func assertChange(t *testing.T, d []kconfig.Change, field string, loosens bool) {
	t.Helper()
	seen, anyLoosens := false, false
	for _, ch := range d {
		if ch.Field == field {
			seen = true
			anyLoosens = anyLoosens || ch.Loosens
		}
	}
	switch {
	case !seen:
		t.Errorf("no change on %s in %+v", field, d)
	case anyLoosens != loosens:
		t.Errorf("%s: loosens = %t, want %t (%+v)", field, anyLoosens, loosens, d)
	}
}

// edit applies old → new to the base sources and returns the policy.
func edited(t *testing.T, old, new string) Policy {
	t.Helper()
	if !strings.Contains(basePolicy, old) {
		t.Fatalf("base has no %q", old)
	}
	return NewPolicy(mustParse(t, strings.Replace(basePolicy, old, new, 1))["pp"], "", nil)
}

func TestDiffSources(t *testing.T) {
	base := policyOf(t, "", "")
	for _, tt := range []struct {
		name, old, new, field string
		loosens               bool
	}{
		{"path added", `paths = ["/var/log/nginx/access.log*"]`, `paths = ["/var/log/nginx/access.log*", "/var/log/nginx/error.log"]`, "sources.nginx.paths", true},
		{"path removed", `paths = ["/var/log/nginx/access.log*"]`, `paths = ["/var/log/nginx/access.log"]`, "sources.nginx.paths", true},
		{"format changed", `format = "combined"`, `format = "plain"`, "sources.nginx.format", true},
		{"trusted added", `trusted = ["vhost"]`, `trusted = ["vhost", "upstream"]`, "sources.nginx.trusted", true},
		{"trusted removed", `trusted = ["vhost"]`, `trusted = []`, "sources.nginx.trusted", false},
		{"recursive on", `trusted = ["vhost"]`, "trusted = [\"vhost\"]\nrecursive = true", "sources.nginx.recursive", true},
		{"unit added", `units = ["nginx.service"]`, `units = ["nginx.service", "ssh.service"]`, "sources.sys.units", true},
		{"every unit", `units = ["nginx.service"]`, ``, "sources.sys.units", true},
		{"allow added", `units = ["nginx.service"]`, "units = [\"nginx.service\"]\nallow = [\"REQ_ID\"]", "sources.sys.allow", true},
		{"container added", `containers = ["shop-api-1"]`, `containers = ["shop-api-1", "shop-db-1"]`, "sources.api.containers", true},
		{"container removed", `containers = ["shop-api-1"]`, `containers = ["shop-api-2"]`, "sources.api.containers", true},
		{"attrs added", `containers = ["shop-api-1"]`, "containers = [\"shop-api-1\"]\nattrs = [\"tag\"]", "sources.api.attrs", true},
		{"url changed", `url = "https://loki.example.com"`, `url = "https://loki2.example.com"`, "sources.loki.url", true},
		{"selector changed", `selector = { app = "api" }`, `selector = { app = "web" }`, "sources.loki.selector", true},
		{"auth changed", `auth = "bearer"`, "auth = \"basic\"\nuser = \"reader\"", "sources.loki.auth", true},
		{"label added", `trusted_labels = ["app"]`, `trusted_labels = ["app", "level"]`, "sources.loki.trusted_labels", true},
		{"tls weaker", `auth = "bearer"`, "auth = \"bearer\"\ntls = \"require\"", "sources.loki.tls", true},
		{"vault", `auth = "bearer"`, "auth = \"bearer\"\ncredentials = \"vault\"\nvault_path = \"a/b\"", "sources.loki.credentials", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertChange(t, edited(t, tt.old, tt.new).Diff(base), tt.field, tt.loosens)
		})
	}
	// Narrowing journald from every unit to one tightens.
	every := edited(t, `units = ["nginx.service"]`, ``)
	assertChange(t, base.Diff(every), "sources.sys.units", false)
}

func TestLooseningKeysAreDiffed(t *testing.T) {
	// Every key named for the agent's change requests is a field Diff
	// reports as loosening (allow: per source).
	want := map[string]string{
		"production": "production", "prefilter": "prefilter", "unmask": "unmask", "lookup": "lookup",
		"network": "network", "user_journals": "user_journals", "allow": "sources.sys.allow", "extra_roots": "extra_roots",
	}
	if len(want) != len(LooseningKeys) {
		t.Fatalf("LooseningKeys = %v", LooseningKeys)
	}
	for _, k := range LooseningKeys {
		if _, ok := want[k]; !ok {
			t.Errorf("untested loosening key %q", k)
		}
	}
	a := policyOf(t, "[profiles.pp]\nproduction = true\nunmask = \"never\"\nlookup = \"approved\"\n", "")
	// Each loosening alone (production off cannot stay with prefilter on
	// production, so production goes off first).
	c := NewPolicy(mustParse(t, strings.Replace(basePolicy, `units = ["nginx.service"]`, "units = [\"nginx.service\"]\nallow = [\"REQ_ID\"]", 1)+
		"[profiles.pp]\nprefilter = true\nuser_journals = true\nunmask = \"approved\"\nlookup = \"free\"\nstructured = \"redact-unknown\"\n")["pp"], "net", []string{"/srv/x"})
	d := c.Diff(a)
	for k, field := range want {
		found := false
		for _, ch := range d {
			if ch.Field == field && ch.Loosens {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no loosening change on %s", k, field)
		}
	}
}

func TestDescribe(t *testing.T) {
	lines := strings.Join(policyOf(t, "[profiles.pp]\nprefilter = true\n", "shop_default", "/srv/logs").Describe(), "\n")
	for _, part := range []string{
		"production: false", "detectors: ", "(secrets: always)", "pseudonyms: rotation 7d", "local budgets: range 7d",
		"remote budgets: range 1d", "prefilter: ON", "network: shop_default", "extra root: /srv/logs",
		"source api (docker", "containers: shop-api-1", "source loki (loki", "selector: {app=\"api\"}", "auth: bearer · tls: verify-full · credentials: ask",
		"trusted labels: app", "source nginx (file, format combined", "trusted: method, status, vhost", "units: nginx.service",
	} {
		if !strings.Contains(lines, part) {
			t.Errorf("Describe lacks %q:\n%s", part, lines)
		}
	}
}

func TestCanonicalJSONStable(t *testing.T) {
	a := policyOf(t, "", "", "/b", "/a", "/a")
	b, err := json.Marshal(Canonical(a))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := json.Marshal(Canonical(Canonical(a)))
	if string(b) != string(c) {
		t.Error("Canonical is not idempotent")
	}
	if !strings.Contains(string(b), `"extra_roots":["/a","/b"]`) {
		t.Errorf("extra roots not canonical: %s", b)
	}
}
