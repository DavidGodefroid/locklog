//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

func writeFacts(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "facts")
	if err := os.WriteFile(p, []byte(hostfacts.Header+"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// verbProject is a project directory of the test's (0755) and the
// launcher's facts: an app log and Claude Code installed.
func verbProject(t *testing.T) (root, facts string) {
	t.Helper()
	base := t.TempDir()
	os.Chmod(base, 0o700)
	root = filepath.Join(base, "p")
	if err := os.Mkdir(root, 0o755); err != nil || os.Chmod(root, 0o755) != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Setenv("LOCKLOG_HOST_HOME", "")
	facts = writeFacts(t, base, "euid 1000\ngroups dev docker\nsudo absent\ndocker unreachable\nagent claude\nlogs\n/var/log/app/app.log\n/var/log/app/app.log.1.gz\n")
	t.Chdir(root)
	return root, facts
}

func TestVerbsUsage(t *testing.T) {
	for _, args := range [][]string{
		{"setup"}, {"profile"}, {"profile", "rm"}, {"profile", "add", "extra"}, {"profile", "add", "--nope"},
		{"doctor", "x"}, {"doctor", "--nope"}, {"doctor", "--yes"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%q: exit %d (%s)", args, code, errb.String())
		}
	}
}

// profile add --non-interactive --json, as lox add calls it: one JSON
// line, the profile written; again, "exists" and nothing written.
func TestProfileAddNonInteractive(t *testing.T) {
	root, facts := verbProject(t)
	var out, errb bytes.Buffer
	code := run([]string{"profile", "add", "--non-interactive", "--json", "--profile", "app", "--facts", facts}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var p verbs.Profile
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	cfgPath := filepath.Join(root, ".locklog", "config.toml")
	if p != (verbs.Profile{Lock: "locklog", Profile: "app", Config: cfgPath}) {
		t.Errorf("profile %+v", p)
	}
	cfg, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(cfg), "[profiles.app]\nproduction = false\n") || !strings.Contains(string(cfg), `paths = ["/var/log/app/app.log*"]`) {
		t.Fatalf("config: %s %v", cfg, err)
	}
	if !strings.Contains(errb.String(), "created .locklog/config.toml") {
		t.Errorf("the human's text is not on stderr: %q", errb.String())
	}
	if _, err := os.Lstat(filepath.Join(root, ".mcp.json")); err == nil {
		t.Error("profile add wired an agent")
	}
	out.Reset()
	if code := run([]string{"profile", "add", "--non-interactive", "--json", "--profile", "app", "--production", "--facts", facts}, &out, &errb); code == 0 {
		t.Fatal("an existing profile was added again")
	}
	var e verbs.Error
	if err := json.Unmarshal(out.Bytes(), &e); err != nil || e.Code != verbs.CodeExists {
		t.Errorf("again: %q %v", out.String(), err)
	}
	if again, _ := os.ReadFile(cfgPath); !bytes.Equal(again, cfg) {
		t.Error("the refused profile add changed the config")
	}
	// A production profile appended.
	out.Reset()
	if code := run([]string{"profile", "add", "--non-interactive", "--json", "--profile", "prod", "--production", "--facts", facts}, &out, &errb); code != 0 {
		t.Fatalf("prod: %d %s", code, out.String())
	}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || !p.Production || p.Profile != "prod" {
		t.Errorf("prod: %+v %v", p, err)
	}
}

// No form of profile add takes a secret: a flag named like one, a value
// embedding a password, a credential source but ask or vault are refused
// (code secret), never quoted; the non-interactive form never asks, and
// the interactive one needs a terminal.
func TestProfileAddRefusesSecrets(t *testing.T) {
	root, facts := verbProject(t)
	const pw = "hunter2-Secret"
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"--password", pw}, verbs.CodeSecret},
		{[]string{"--loki-token", pw}, verbs.CodeSecret},
		{[]string{"--loki-selector", "user:" + pw + "@host"}, verbs.CodeSecret},
		{[]string{"--only", "/var/log/password=" + pw}, verbs.CodeSecret},
		{[]string{"--credentials", "keychain"}, verbs.CodeSecret},
		{[]string{"--credentials", pw}, verbs.CodeSecret},
		{[]string{"--loki-proxy", "loki"}, verbs.CodeUsage},
		{[]string{"--credentials", "vault", "--vault-path", "secret/data/loki"}, verbs.CodeUsage},
		{[]string{"--profile", "y", "--production"}, verbs.CodeUsage},
		{[]string{"--only", "relative/dir"}, verbs.CodeUsage},
		{[]string{pw}, verbs.CodeUsage},
	} {
		var out, errb bytes.Buffer
		args := append([]string{"profile", "add", "--non-interactive", "--json", "--facts", facts}, tc.args...)
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", tc.args, code)
		}
		var e verbs.Error
		if err := json.Unmarshal(out.Bytes(), &e); err != nil || e.Code != tc.code || e.Lock != "locklog" {
			t.Errorf("%v: %q (%v), want code %s", tc.args, out.String(), err, tc.code)
		}
		if strings.Contains(out.String()+errb.String(), pw) {
			t.Errorf("%v: the value is quoted: %s %s", tc.args, out.String(), errb.String())
		}
	}
	if _, err := os.Lstat(filepath.Join(root, ".locklog")); err == nil {
		t.Error("a refused profile add wrote .locklog/")
	}
	// Without --non-interactive and without a terminal: a usage error.
	var out, errb bytes.Buffer
	if code := run([]string{"profile", "add", "--facts", facts}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--non-interactive") {
		t.Errorf("no terminal: %d %s", code, errb.String())
	}
}

// doctor --json, as lox add calls it: one verbs.Doctor line; a host agent
// installed here but not wired warns with its fix; --fix --yes wires it.
// --fix without a terminal or --yes, and --yes without --fix, are usage
// errors in JSON.
func TestDoctorVerbs(t *testing.T) {
	root, facts := verbProject(t)
	var out, errb bytes.Buffer
	if code := run([]string{"doctor", "--json", "--facts", facts}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var d verbs.Doctor
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || !d.OK || len(d.Fixed) != 0 {
		t.Fatalf("doctor %q: %v", out.String(), err)
	}
	wiring := func(d verbs.Doctor) verbs.Check {
		for _, c := range d.Checks {
			if c.Check == "agent claude" {
				return c
			}
		}
		t.Fatalf("no agent check in %+v", d)
		return verbs.Check{}
	}
	if c := wiring(d); c.Status != verbs.StatusWarn || c.Fix != "locklog init claude" {
		t.Errorf("unwired claude: %+v", c)
	}
	for _, args := range [][]string{{"--fix"}, {"--yes"}} {
		out.Reset()
		if code := run(append([]string{"doctor", "--json", "--facts", facts}, args...), &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		var e verbs.Error
		if err := json.Unmarshal(out.Bytes(), &e); err != nil || e.Code != verbs.CodeUsage {
			t.Errorf("%v: %q", args, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"doctor", "--fix", "--yes", "--json", "--facts", facts}, &out, &errb); code != 0 {
		t.Fatalf("--fix: exit %d: %s", code, out.String())
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || len(d.Fixed) != 1 || !strings.Contains(d.Fixed[0], "claude") {
		t.Fatalf("--fix: %q %v", out.String(), err)
	}
	if c := wiring(d); c.Status != verbs.StatusOK {
		t.Errorf("wired claude: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(root, ".mcp.json")); err != nil {
		t.Error(err)
	}
	// Again: nothing left to fix.
	out.Reset()
	run([]string{"doctor", "--fix", "--yes", "--json", "--facts", facts}, &out, &errb)
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || len(d.Fixed) != 0 {
		t.Errorf("second --fix: %q", out.String())
	}
}

// doctor's findings: a non-production profile warns (exit 0), a
// production one fails (exit 1, and not ok in JSON).
func TestDoctorProduction(t *testing.T) {
	root, facts := verbProject(t)
	var out, errb bytes.Buffer
	if code := run([]string{"profile", "add", "--non-interactive", "--profile", "staging", "--facts", facts}, &out, &errb); code != 0 {
		t.Fatalf("profile add: %d %s", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"doctor", "--facts", facts}, &out, &errb); code != 0 || !strings.Contains(out.String(), "warn  group docker") {
		t.Errorf("doctor non-production: exit %d\n%s", code, out.String())
	}
	cfg, _ := os.ReadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(strings.Replace(string(cfg), "[profiles.staging]\nproduction = false", "[profiles.prod]\nproduction = true", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"doctor", "--facts", facts}, &out, &errb); code != 1 || !strings.Contains(out.String(), "RED   group docker") {
		t.Errorf("doctor production: exit %d\n%s", code, out.String())
	}
	out.Reset()
	var d verbs.Doctor
	if code := run([]string{"doctor", "--json", "--facts", facts}, &out, &errb); code != 1 || json.Unmarshal(out.Bytes(), &d) != nil || d.OK {
		t.Errorf("doctor production --json: exit %d\n%s", code, out.String())
	}
}

// doctor --facts - reads the launcher's facts on its input.
func TestDoctorFactsOnStdin(t *testing.T) {
	t.Chdir(t.TempDir())
	var out, errb bytes.Buffer
	in := strings.NewReader(hostfacts.Header + "\neuid 0\ngroups root\nsudo absent\ndocker absent\n")
	code := doctorCmd([]string{"--facts", "-"}, in, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "euid 0: the agent runs as root") {
		t.Errorf("exit %d\n%s%s", code, out.String(), errb.String())
	}
}
