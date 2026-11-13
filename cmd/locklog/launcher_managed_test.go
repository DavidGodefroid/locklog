//go:build unix

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// managedMounted reports whether run mounts a managed directory.
func managedMounted(f *launcherFixture, run []string) bool {
	return slices.ContainsFunc(run, func(a string) bool {
		return strings.Contains(a, "/etc/lockfamily") || strings.Contains(a, f.managed) || strings.Contains(a, f.managedMac)
	})
}

// withoutManaged is run without the managed directory's mount.
func withoutManaged(run []string, spec string) []string {
	var rest []string
	for i := 0; i < len(run); i++ {
		if run[i] == "-v" && i+1 < len(run) && run[i+1] == spec {
			i++
			continue
		}
		rest = append(rest, run[i])
	}
	return rest
}

// The machine's managed directory, when there is one, is mounted read-only
// on /etc/lockfamily in every container (as lox run mounts it in its
// locks), before the image; without one, nothing is.
func TestLauncherManagedMount(t *testing.T) {
	f := newLauncherFixture(t)
	f.fakeUname(t, "Linux")
	writeExec(t, filepath.Join(f.bin, "claude"), "#!/bin/sh\n")
	commands := [][]string{
		{"managed", "show"}, {"managed", "check", "--profile", "prod"}, {"profile", "add"}, {"profile", "rules"},
		{"profile", "list"}, {"init", "claude"}, {"doctor"}, {"doctor", "--fix", "--yes"}, {"mcp"}, {"status"},
		{"version"}, {"help"},
	}
	spec := f.managed + ":/etc/lockfamily:ro"
	// Without the directory, docker run's arguments are those of a launcher
	// without managed support.
	without := map[string][]string{}
	for _, args := range commands {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		if managedMounted(f, run) {
			t.Errorf("%v: no managed directory, but mounted: %q", args, run)
		}
		without[strings.Join(args, " ")] = run
	}
	if err := os.MkdirAll(f.managed, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range commands {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, "-v", spec) {
			t.Errorf("%v: managed directory not mounted read-only on /etc/lockfamily: %q", args, run)
		}
		// Before the image: an argument of docker, not of locklog.
		if img := imageArgs(run, "locklog"); img == nil || managedMounted(f, img) {
			t.Errorf("%v: mount after the image: %q", args, run)
		}
		// The mount is all that is added (the facts files' names change
		// from run to run: compare the length).
		if w, rest := without[strings.Join(args, " ")], withoutManaged(run, spec); len(rest) != len(w) {
			t.Errorf("%v: more than the mount added:\n%q\n%q", args, w, run)
		}
	}
}

// On macOS the managed directory is /Library/Application Support/lockfamily,
// mounted on /etc/lockfamily all the same; the Linux path is not looked at.
func TestLauncherManagedMountMacOS(t *testing.T) {
	f := newLauncherFixture(t)
	f.fakeUname(t, "Darwin")
	if err := os.MkdirAll(f.managedMac, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file at the Linux path would stop a Linux launcher.
	if err := os.MkdirAll(filepath.Dir(f.managed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.managed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"managed", "show"}, {"status"}, {"version"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if run := lastRun(t, calls); !hasSeq(run, "-v", f.managedMac+":/etc/lockfamily:ro") {
			t.Errorf("%v: macOS managed directory not mounted: %q", args, run)
		}
	}
}

// A managed path that is not a directory, or that a docker mount cannot
// carry, stops the launcher before docker runs.
func TestLauncherManagedRefused(t *testing.T) {
	f := newLauncherFixture(t)
	f.fakeUname(t, "Linux")
	if err := os.MkdirAll(filepath.Dir(f.managed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.managed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"managed", "show"}, {"mcp"}, {"doctor"}, {"version"}, {"profile", "rules"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if err == nil || !strings.Contains(out, f.managed+" is not a directory") || len(calls) != 0 {
			t.Errorf("a file, %v: %v, calls %q\n%s", args, err, calls, out)
		}
	}
	// The console is refused as before: it runs no container.
	out, calls, err := f.run(t, f.project, nil, "console")
	if exitCode(err) != 2 || !strings.Contains(out, "is run by `lox run` only") || len(calls) != 0 {
		t.Errorf("console with a managed file: %v, calls %q\n%s", err, calls, out)
	}
	// A link to a directory is mounted: what the image checks (root owns
	// it) is the directory it leads to.
	if err := os.Remove(f.managed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), f.managed); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err != nil || !hasSeq(lastRun(t, calls), "-v", f.managed+":/etc/lockfamily:ro") {
		t.Errorf("a link to a directory: %v, %q\n%s", err, calls, out)
	}
	// A dangling link: refused, not skipped.
	if err := os.Remove(f.managed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "nowhere"), f.managed); err != nil {
		t.Fatal(err)
	}
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err == nil || !strings.Contains(out, f.managed+" is not a directory") || len(calls) != 0 {
		t.Errorf("a dangling link: %v, calls %q\n%s", err, calls, out)
	}
	// A ":" in the path.
	b, err := os.ReadFile(f.script)
	if err != nil {
		t.Fatal(err)
	}
	colon := filepath.Join(f.root, "a:b")
	if err := os.MkdirAll(colon, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExec(t, f.script, strings.ReplaceAll(string(b), `managed_dir="`+f.managed+`"`, `managed_dir="`+colon+`"`))
	out, calls, err = f.run(t, f.project, nil, "managed", "show")
	if err == nil || !strings.Contains(out, colon+" holds a character a docker mount cannot carry") || len(calls) != 0 {
		t.Errorf("a \":\": %v, calls %q\n%s", err, calls, out)
	}
}
