//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

func TestSetupDoctorUsage(t *testing.T) {
	for _, args := range [][]string{
		{"setup", "extra"}, {"setup", "--production", "--no-production"}, {"setup", "--agent-uid", "0"},
		{"setup", "--agent-uid", "10051"}, {"setup", "--nope"}, {"doctor", "x"}, {"doctor", "--nope"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%q: exit %d (%s)", args, code, errb.String())
		}
	}
}

func writeFacts(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "facts")
	if err := os.WriteFile(p, []byte(hostfacts.Header+"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// setup from the launcher's facts, scripted; then doctor from facts: a
// non-production profile warns (exit 0), a production one fails (exit 1).
func TestSetupThenDoctor(t *testing.T) {
	base := t.TempDir()
	os.Chmod(base, 0o700)
	root := filepath.Join(base, "p")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(base, "home"))
	facts := writeFacts(t, base, "euid 1000\ngroups dev docker\nsudo absent\ndocker unreachable\nlogs\n/var/log/app/app.log\n/var/log/app/app.log.1.gz\n")
	t.Chdir(root)
	var out, errb bytes.Buffer
	if code := run([]string{"setup", "--facts", facts, "--yes", "--no-production", "--agent", "host", "--agents", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("setup: exit %d: %s", code, errb.String())
	}
	cfg, err := os.ReadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil || !strings.Contains(string(cfg), `paths = ["/var/log/app/app.log*"]`) {
		t.Fatalf("config: %s %v", cfg, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude", "settings.local.json")); err != nil {
		t.Error(err)
	}
	out.Reset()
	if code := run([]string{"doctor", "--facts", facts}, &out, &errb); code != 0 || !strings.Contains(out.String(), "warn  group docker") {
		t.Errorf("doctor non-production: exit %d\n%s", code, out.String())
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(strings.Replace(string(cfg), "[profiles.staging]\nproduction = false", "[profiles.prod]\nproduction = true", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"doctor", "--facts", facts}, &out, &errb); code != 1 || !strings.Contains(out.String(), "RED   group docker") {
		t.Errorf("doctor production: exit %d\n%s", code, out.String())
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
