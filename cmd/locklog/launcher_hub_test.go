//go:build unix

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Hub mode through the launcher: the hub flags go to the console only
// (never to locklog mounts), their files bound read-only under fixed
// names, and the console joins LOCKLOG_NETWORK, the network lockhub is on.
func TestLauncherConsoleHub(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	// No directory on a hub file's path may be writable by your group or
	// the others (the test's umask may leave the root group-writable).
	if err := os.Chmod(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	hubKey := filepath.Join(f.root, "hub.pub")
	devices := filepath.Join(f.project, "devices.json")
	for _, p := range []string{hubKey, devices} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"console", "--profile", "staging", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", hubKey,
		"--instance", "logs", "--devices-file=devices.json", "--seal-clear"}
	out, calls, err := f.run(t, f.project, []string{plan(f), "LOCKLOG_NETWORK=lockfamily"}, args...)
	if err != nil {
		t.Fatalf("console: %v\n%s", err, out)
	}
	for _, c := range calls {
		if slices.Contains(c, "mounts") && !slices.Equal(c[len(c)-4:], []string{"locklog", "mounts", "--profile", "staging"}) {
			t.Errorf("the mount plan got more than the profile: %q", c)
		}
	}
	run := lastRun(t, calls)
	// The console mounts private copies (a 0700 directory of yours), not
	// the files given: what it reads is what the launcher checked.
	name := run[slices.Index(run, "--name")+1]
	home, err := filepath.EvalSymlinks(filepath.Join(f.root, "home"))
	if err != nil {
		t.Fatal(err)
	}
	hubDir := filepath.Join(home, ".local", "state", "locklog", "hub", name)
	if st, err := os.Stat(hubDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("hub dir %s: %v %v", hubDir, st, err)
	}
	for _, p := range []string{hubKey, devices} {
		got, err := os.ReadFile(filepath.Join(hubDir, filepath.Base(p)))
		if err != nil || string(got) != filepath.Base(p)+"\n" {
			t.Errorf("copy of %s: %q %v", p, got, err)
		}
	}
	// A later change of the original does not reach the mounted copy.
	if err := os.WriteFile(hubKey, []byte("swapped\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(hubDir, "hub.pub")); string(got) != "hub.pub\n" {
		t.Errorf("the mounted copy follows the original: %q", got)
	}
	for _, seq := range [][]string{
		{"--network", "lockfamily"},
		{"--mount", "type=bind,src=" + filepath.Join(hubDir, "hub.pub") + ",dst=/run/locklog-hub/hub.pub,readonly"},
		{"--mount", "type=bind,src=" + filepath.Join(hubDir, "devices.json") + ",dst=/run/locklog-hub/devices.json,readonly"},
		{"locklog", "console", "--profile", "staging", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/locklog-hub/hub.pub",
			"--instance", "logs", "--devices-file=/run/locklog-hub/devices.json", "--seal-clear"},
	} {
		if !hasSeq(run, seq...) {
			t.Errorf("console run lacks %q:\n%q", seq, run)
		}
	}
	if !strings.Contains(out, "hub mode: requests are decided on lockhub (network lockfamily)") {
		t.Errorf("hub mode not told:\n%s", out)
	}

	// Without a network the console cannot reach the hub.
	if out, _, err := f.run(t, f.project, []string{plan(f)}, args...); err == nil || !strings.Contains(out, "LOCKLOG_NETWORK") {
		t.Errorf("no network: %v\n%s", err, out)
	}
	// A missing file, a link, a flag given twice: refused before docker run.
	link := filepath.Join(f.root, "link.pub")
	if err := os.Symlink(hubKey, link); err != nil {
		t.Fatal(err)
	}
	// A path with a space would be word-split into docker run's
	// arguments; a trust anchor others can write is refused.
	spaced := filepath.Join(f.root, "a b --privileged")
	if err := os.WriteFile(spaced, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(f.root, "shared.pub")
	if err := os.WriteFile(shared, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o666); err != nil {
		t.Fatal(err)
	}
	// A link on the file's path, or a directory above it others can
	// write: the file could be swapped between the check and the copy.
	realDir := filepath.Join(f.root, "keys")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "hub.pub"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(f.root, "keys-link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	openDir := filepath.Join(f.root, "open")
	if err := os.MkdirAll(filepath.Join(openDir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	inOpen := filepath.Join(openDir, "sub", "hub.pub")
	if err := os.WriteFile(inOpen, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The private copies' directory meets the same standard: under an
	// XDG_RUNTIME_DIR of yours that others can write, refused.
	openRun := filepath.Join(f.root, "run-open")
	if err := os.Mkdir(openRun, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openRun, 0o777); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, []string{plan(f), "LOCKLOG_NETWORK=lockfamily", "XDG_RUNTIME_DIR=" + openRun}, "console", "--hub", "http://lockhub:8443",
		"--hub-key-file", hubKey, "--instance", "logs")
	if err == nil || !strings.Contains(out, "is owned or writable by someone else") {
		t.Errorf("hub dir under an open XDG_RUNTIME_DIR: %v\n%s", err, out)
	}
	for _, c := range calls {
		if slices.Contains(c, "console") {
			t.Errorf("open XDG_RUNTIME_DIR: the console ran: %q", c)
		}
	}
	for name, bad := range map[string][]string{
		"linked parent": {"console", "--hub", "http://lockhub:8443", "--hub-key-file", filepath.Join(linkDir, "hub.pub"), "--instance", "logs"},
		"open parent":   {"console", "--hub", "http://lockhub:8443", "--hub-key-file", inOpen, "--instance", "logs"},
		"space":         {"console", "--hub", "http://lockhub:8443", "--hub-key-file", spaced, "--instance", "logs"},
		"space=":        {"console", "--hub", "http://lockhub:8443", "--devices-file=" + spaced, "--instance", "logs"},
		"writable":      {"console", "--hub", "http://lockhub:8443", "--facade-keys-file", shared, "--instance", "logs"},
		"single dash":   {"console", "-hub", "http://lockhub:8443", "-hub-key-file", hubKey, "--instance", "logs"},
		"missing":       {"console", "--hub", "http://lockhub:8443", "--hub-key-file", filepath.Join(f.root, "nope"), "--instance", "logs"},
		"link":          {"console", "--hub", "http://lockhub:8443", "--hub-key-file", link, "--instance", "logs"},
		"twice":         {"console", "--hub", "http://lockhub:8443", "--hub-key-file", hubKey, "--hub-key-file=" + hubKey, "--instance", "logs"},
		"no file":       {"console", "--hub", "http://lockhub:8443", "--instance", "logs", "--hub-key-file"},
	} {
		out, calls, err := f.run(t, f.project, []string{plan(f), "LOCKLOG_NETWORK=lockfamily"}, bad...)
		if err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		for _, c := range calls {
			if slices.Contains(c, "console") {
				t.Errorf("%s: the console ran: %q", name, c)
			}
		}
	}
}

// hub-key runs as the console account, with its home volume only and no
// network: the instance key lives there.
func TestLauncherHubKey(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.project, nil, "hub-key", "--instance", "logs")
	if err != nil {
		t.Fatalf("hub-key: %v\n%s", err, out)
	}
	run := lastRun(t, calls)
	confined(t, run)
	for _, seq := range [][]string{{"--user", "locklog"}, {"--network", "none"}, {"-v", "locklog-home:/home/locklog"}, {"locklog", "hub-key", "--instance", "logs"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("hub-key run lacks %q: %q", seq, run)
		}
	}
	if slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "locklog-run") || strings.Contains(a, f.project) }) {
		t.Errorf("hub-key mounts more than the home volume: %q", run)
	}
	// The home volume's owner is checked first.
	checked := false
	for _, c := range calls {
		if hasSeq(c, "-v", "locklog-home:/home/locklog") && slices.Contains(c, "stat") {
			checked = true
		}
	}
	if !checked {
		t.Error("the locklog-home owner was not checked")
	}
}
