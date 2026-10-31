package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

const fileSrc = `
[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
format = "combined"
`

func parse(t *testing.T, body string) (map[string]Profile, error) {
	t.Helper()
	return ParseProfiles([]byte("version = 1\n"+body), "config.toml")
}

func mustParse(t *testing.T, body string) map[string]Profile {
	t.Helper()
	ps, err := parse(t, body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ps
}

func wantErr(t *testing.T, body, part string) {
	t.Helper()
	_, err := parse(t, body)
	if err == nil {
		t.Fatalf("no error, want one containing %q", part)
	}
	if !strings.Contains(err.Error(), part) {
		t.Fatalf("error %q, want it to contain %q", err, part)
	}
}

func TestVersion(t *testing.T) {
	for _, tt := range []struct {
		head, part string
	}{
		{"", "version is required"},
		{"version = 2\n", "written for a newer locklog"},
		{"version = 0\n", "unknown version 0"},
	} {
		_, err := ParseProfiles([]byte(tt.head+fileSrc), "config.toml")
		if err == nil || !strings.Contains(err.Error(), tt.part) {
			t.Errorf("%q: error %v, want %q", tt.head, err, tt.part)
		}
	}
}

func TestDefaults(t *testing.T) {
	p := mustParse(t, fileSrc)["staging"]
	if p.Production || p.Structured != StructuredDetect || p.Text != TextDetect || p.Unmask != UnmaskApproved || p.Lookup != LookupFree {
		t.Errorf("non-production defaults: %+v", p)
	}
	if p.PseudonymRotation != "7d" || p.PseudonymMaxAge != 30*Day || p.RotationEvery() != 7*Day {
		t.Errorf("pseudonyms: %q %s", p.PseudonymRotation, p.PseudonymMaxAge)
	}
	if !slices.Equal(p.Detectors, kconfig.SortedSet(DefaultDetectors())) || len(p.Detectors) < 8 {
		t.Errorf("detectors = %v", p.Detectors)
	}
	if p.Limits != DefaultLimits(false) {
		t.Errorf("limits = %+v", p.Limits)
	}
	l := p.Limits
	if l.Local.Range != 7*Day || l.Remote.Range != 24*time.Hour || l.Local.MaxBytes != 512*MiB || l.Remote.MaxBytes != 512*MiB ||
		l.Local.BytesPerHour != 40*GiB || l.Remote.BytesPerHour != 20*GiB || l.MaxRecords != 200 || l.MaxOutputBytes != 64*KiB ||
		l.LookupsPerHour != 50 || l.LookupsPerHourPerUID != 20 || l.PIIAddsPerHour != 10 || l.PIIRulesMax != 50 {
		t.Errorf("default budgets differ from the design and docs/performance.md: %+v", l)
	}
	if p.IdleTimeout != DefaultIdle || p.MaxSession != DefaultMaxSession {
		t.Errorf("session %s %s", p.IdleTimeout, p.MaxSession)
	}
	s, ok := p.Source("nginx")
	if !ok || s.Multiline != "none" || !slices.Equal(s.TrustedFields(), []string{"method", "status"}) {
		t.Errorf("source = %+v, trusted %v", s, s.TrustedFields())
	}
}

func TestBudgetDefaultsFromTheSpikes(t *testing.T) {
	for _, prod := range []bool{false, true} {
		l := DefaultLimits(prod)
		if l.Local.MaxBytes != 512*MiB || l.Remote.MaxBytes != 512*MiB {
			t.Errorf("production=%v: max_bytes local %d remote %d", prod, l.Local.MaxBytes, l.Remote.MaxBytes)
		}
		want := 600
		if prod {
			want = 240
		}
		if l.Remote.RequestsPerMinute != want {
			t.Errorf("production=%v: requests_per_minute %d, want %d", prod, l.Remote.RequestsPerMinute, want)
		}
	}
}

func TestProductionDefaults(t *testing.T) {
	p := mustParse(t, strings.ReplaceAll(fileSrc, "staging", "prod")+"[profiles.prod]\nproduction = true\n")["prod"]
	if !p.Production || p.Structured != StructuredRedactUnknown || p.Unmask != UnmaskNever {
		t.Errorf("production defaults: %+v", p)
	}
	l := p.Limits
	if l.Remote.BytesPerHour != 10*GiB || l.Remote.MetricQueriesPerHour != 60 || l.Remote.RequestsPerMinute != 240 || l.LookupsPerHour != 10 || l.LookupsPerHourPerUID != 10 {
		t.Errorf("production limits: %+v", l)
	}
}

func TestProductionRefusals(t *testing.T) {
	prod := strings.ReplaceAll(fileSrc, "staging", "prod") + "[profiles.prod]\nproduction = true\n"
	wantErr(t, prod+"prefilter = true\n", "prefilter = true is refused on a production profile")
	wantErr(t, prod+`pseudonym_rotation = "never"`+"\n", `"never" is refused on a production profile`)
	wantErr(t, strings.ReplaceAll(fileSrc, "staging", "y")+"[profiles.y]\nproduction = true\n", "production profile needs a name")
	// Non-production accepts both.
	mustParse(t, fileSrc+"[profiles.staging]\nprefilter = true\npseudonym_rotation = \"never\"\n")
}

func TestProfileValues(t *testing.T) {
	for _, tt := range []struct{ body, part string }{
		{`structured = "clear"`, "unknown structured mode"},
		{`text = "raw"`, "unknown text mode"},
		{`unmask = "always"`, "unknown unmask mode"},
		{`lookup = "open"`, "unknown lookup mode"},
		{`detectors = ["email", "dna"]`, "unknown detector"},
		{`detectors = ["email", "secret"]`, "secret detection is always on"},
		{`pseudonym_rotation = "5m"`, "pseudonym_rotation: want"},
		{`pseudonym_rotation = "500d"`, "pseudonym_rotation: want"},
		{`pseudonym_max_age = "3d"` + "\n" + `pseudonym_rotation = "7d"`, "is above pseudonym_max_age"},
		{`bogus = 1`, "unknown key"},
		{`password = "x"`, "looks like a secret"},
	} {
		wantErr(t, fileSrc+"[profiles.staging]\n"+tt.body+"\n", tt.part)
	}
	p := mustParse(t, fileSrc+"[profiles.staging]\ndetectors = []\npseudonym_rotation = \"session\"\n")["staging"]
	if len(p.Detectors) != 0 || p.PseudonymRotation != RotationSession || p.RotationEvery() != 0 {
		t.Errorf("explicit settings: %v %q", p.Detectors, p.PseudonymRotation)
	}
	wantErr(t, "[profiles.staging]\n", "no sources")
}

// The default set masks public IP addresses; person_name and phone_loose
// are opt-in, and a profile may name them.
func TestDetectorDefaultsAndOptIn(t *testing.T) {
	def := DefaultDetectors()
	if !slices.Contains(def, "ip") || slices.Contains(def, mask.SecretDetectorName) {
		t.Errorf("default detectors = %v", def)
	}
	for _, n := range OptInDetectors() {
		if slices.Contains(def, n) {
			t.Errorf("opt-in %s in the default set", n)
		}
	}
	p := mustParse(t, fileSrc+"[profiles.staging]\ndetectors = [\"email\", \"person_name\", \"phone_loose\", \"ip\"]\n")["staging"]
	if !slices.Equal(p.Detectors, []string{"email", "ip", "person_name", "phone_loose"}) {
		t.Errorf("detectors = %v", p.Detectors)
	}
}

func TestLimits(t *testing.T) {
	head := fileSrc + "[profiles.staging.limits]\n"
	p := mustParse(t, head+`max_records = 1000
max_output = "1MiB"
idle_timeout = "10m"
max_session = "1d"
[profiles.staging.limits.local]
range = "400d"
max_bytes = "64GiB"
bytes_per_hour = "100GiB"
[profiles.staging.limits.remote]
requests_per_minute = 30
`)["staging"]
	l := p.Limits
	if l.MaxRecords != 1000 || l.MaxOutputBytes != MiB || l.Local.Range != 400*Day || l.Local.MaxBytes != 64*GiB || l.Remote.RequestsPerMinute != 30 {
		t.Errorf("limits = %+v", l)
	}
	if p.IdleTimeout != 10*time.Minute || p.MaxSession != Day {
		t.Errorf("session %s %s", p.IdleTimeout, p.MaxSession)
	}
	// An explicit short max_session pulls the default idle timeout down.
	if p := mustParse(t, head+`max_session = "30m"`+"\n")["staging"]; p.IdleTimeout != 30*time.Minute {
		t.Errorf("idle = %s", p.IdleTimeout)
	}
	for _, tt := range []struct{ body, part string }{
		{"max_records = 1001", "above its ceiling 1000"},
		{`max_output = "2MiB"`, "above its ceiling 1MiB"},
		{"max_records = -1", "must be positive"},
		{"pii_rules_max = 501", "above its ceiling"},
		{"lookups_per_hour = 1001", "above its ceiling"},
		{"pii_adds_per_hour = 101", "above its ceiling"},
		{"lookups_per_hour = 10\nlookups_per_hour_per_uid = 20", "is above limits.lookups_per_hour"},
		{"[profiles.staging.limits.local]\nbytes_per_hour = \"2TiB\"", "above its ceiling 1TiB"},
		{"[profiles.staging.limits.remote]\nrequests_per_minute = 6001", "above its ceiling 6000"},
		{"[profiles.staging.limits.local]\nrange = \"401d\"", "above its ceiling 400d"},
		{"[profiles.staging.limits.local]\nmax_bytes = \"65GiB\"", "above its ceiling 64GiB"},
		{"[profiles.staging.limits.local]\nmax_bytes = \"4GB\"", "want a positive size"},
		{"[profiles.staging.limits.local]\nrange = \"-1h\"", "want a positive duration"},
		{"[profiles.staging.limits.local]\nmax_bytes = \"50GiB\"", "above limits.local.bytes_per_hour"},
		{"[profiles.staging.limits.local]\nrequests_per_minute = 5", "apply only to limits.remote"},
		{`idle_timeout = "2h"` + "\n" + `max_session = "1h"`, "is above limits.max_session"},
		{`max_session = "30s"`, "must be between"},
		{`max_session = "8d"`, "must be between"},
	} {
		wantErr(t, head+tt.body+"\n", tt.part)
	}
	// The per-uid lookup cap never exceeds the console's.
	if p := mustParse(t, head+"lookups_per_hour = 5\n")["staging"]; p.Limits.LookupsPerHourPerUID != 5 {
		t.Errorf("per uid = %d", p.Limits.LookupsPerHourPerUID)
	}
}

func TestLoadFrom(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	sub := filepath.Join(proj, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proj, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("version = 1\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	user := filepath.Join(dir, "user.toml")
	write(user, fileSrc+strings.ReplaceAll(fileSrc, "staging", "mine"))
	write(filepath.Join(proj, ".locklog", "config.toml"), strings.ReplaceAll(fileSrc, "nginx", "app"))
	ps, root, err := LoadFrom(sub, user)
	if err != nil {
		t.Fatal(err)
	}
	if root != proj {
		t.Errorf("root = %q", root)
	}
	if _, ok := ps["mine"]; !ok {
		t.Error("user profile missing")
	}
	// The project profile wins as a whole.
	if s := ps["staging"].Sources; len(s) != 1 || s[0].Name != "app" {
		t.Errorf("staging sources = %+v", s)
	}
	// A missing user file is no error; no project gives root "".
	ps, root, err = LoadFrom(dir, filepath.Join(dir, "none.toml"))
	if err != nil || root != "" || len(ps) != 0 {
		t.Errorf("LoadFrom(no config) = %v %q %v", ps, root, err)
	}
}

func TestUnits(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * Day, "24h": 24 * time.Hour, "90m": 90 * time.Minute} {
		if d, err := ParseDuration(in); err != nil || d != want {
			t.Errorf("ParseDuration(%q) = %s, %v", in, d, err)
		}
	}
	for _, in := range []string{"", "0d", "-1d", "1.5d", "0s", "x", "999999d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) accepted", in)
		}
	}
	if FormatDuration(7*Day) != "7d" || FormatDuration(90*time.Minute) != "1h30m0s" {
		t.Error("FormatDuration")
	}
	for in, want := range map[string]int64{"64KiB": 64 * KiB, "4GiB": 4 * GiB, "512B": 512, "1TiB": TiB} {
		if n, err := ParseSize(in); err != nil || n != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, n, err)
		}
		if FormatSize(want) != in {
			t.Errorf("FormatSize(%d) = %q", want, FormatSize(want))
		}
	}
	for _, in := range []string{"", "4GB", "0KiB", "-1MiB", "1.5GiB", "KiB", "99999999999TiB"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted", in)
		}
	}
}
