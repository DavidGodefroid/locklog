//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Lock Family distribution: the release workflow asks the Homebrew tap
// (DavidGodefroid/homebrew-tap) to bump the locklog formula, as lockfile's
// release workflow does, and the install docs lead with Homebrew and lox.

const releaseWorkflow = "../../.github/workflows/release.yml"

// workflowJob is the text of one job of a workflow: from its "  name:" key
// line under jobs to the next job's.
func workflowJob(t *testing.T, path, job string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key := regexp.MustCompile(`^  [A-Za-z0-9_-]+:\s*$`)
	var out []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		if key.MatchString(line) {
			if in {
				break
			}
			in = line == "  "+job+":"
		}
		if in {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no job %q", path, job)
	}
	return strings.Join(out, "\n")
}

// runBlock is the "run: |" script of a job's only step, unindented.
func runBlock(t *testing.T, job string) string {
	t.Helper()
	lines := strings.Split(job, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "run: |" {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " ")) + 2
		var script []string
		for _, s := range lines[i+1:] {
			if strings.TrimSpace(s) != "" && len(s)-len(strings.TrimLeft(s, " ")) < indent {
				break
			}
			if len(s) >= indent {
				s = s[indent:]
			}
			script = append(script, s)
		}
		return strings.Join(script, "\n") + "\n"
	}
	t.Fatal("no run: | block")
	return ""
}

func TestReleaseTapJob(t *testing.T) {
	job := workflowJob(t, releaseWorkflow, "tap")
	needs := regexp.MustCompile(`(?m)^    needs: \[(.*)\]$`).FindStringSubmatch(job)
	if needs == nil {
		t.Fatalf("tap: no needs list:\n%s", job)
	}
	got := strings.Split(strings.ReplaceAll(needs[1], " ", ""), ",")
	// The tap verifies the published release: the archives and checksums
	// (goreleaser, a draft until publish) and the signed image manifests.
	for _, want := range []string{"goreleaser", "image-manifest", "publish"} {
		if !slices.Contains(got, want) {
			t.Errorf("tap needs %v, want %q in it", got, want)
		}
	}
	for _, want := range []string{
		"\n    permissions: {}\n",
		"TAP_DISPATCH_TOKEN: ${{ secrets.TAP_DISPATCH_TOKEN }}",
		"GH_TOKEN: ${{ secrets.TAP_DISPATCH_TOKEN }}",
		"if: ${{ env.TAP_DISPATCH_TOKEN != '' }}", // skipped without the secret
	} {
		if !strings.Contains(job, want) {
			t.Errorf("tap job lacks %q:\n%s", want, job)
		}
	}
	// The token is in this job only, which runs no action.
	if strings.Contains(job, "uses:") {
		t.Errorf("tap job runs an action:\n%s", job)
	}
	b, _ := os.ReadFile(releaseWorkflow)
	if n := strings.Count(string(b), "secrets.TAP_DISPATCH_TOKEN"); n != strings.Count(job, "secrets.TAP_DISPATCH_TOKEN") {
		t.Errorf("secrets.TAP_DISPATCH_TOKEN used outside the tap job (%d uses in all)", n)
	}
}

// The tap's bump workflow accepts a repository_dispatch of type "bump" with
// {"formula": one of its formulas, "version": "vX.Y.Z"}. The step's script,
// run with a fake gh, sends exactly that for the tag being released.
func TestReleaseTapDispatch(t *testing.T) {
	script := runBlock(t, workflowJob(t, releaseWorkflow, "tap"))
	dir := t.TempDir()
	log := filepath.Join(dir, "gh.args")
	fake := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >\"$GH_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-euc", script)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "GH_ARGS=" + log, "GITHUB_REF_NAME=v0.3.0", "GH_TOKEN=x"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tap step: %v\n%s", err, out)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	want := []string{
		"api", "repos/DavidGodefroid/homebrew-tap/dispatches",
		"-f", "event_type=bump",
		"-f", "client_payload[formula]=locklog",
		"-f", "client_payload[version]=v0.3.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("gh %q, want %q", got, want)
	}
}

// installDocs are the install sections a user reads: they lead with
// Homebrew and lox (lox run, never lox up), install.sh as the alternative.
var installDocs = []string{"../../README.md", "../../docs/setup.md", "../../site/install/index.html", "../../site/index.html"}

func TestInstallDocs(t *testing.T) {
	loxUp := regexp.MustCompile("`lox up`|<code>lox up</code>|^lox up\\b")
	for _, p := range installDocs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{
			"brew trust davidgodefroid/tap",
			"brew install davidgodefroid/tap/lockfamily",
			"brew install davidgodefroid/tap/locklog",
			"lox add locklog",
			"lox run",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
		if p != "../../site/index.html" && !strings.Contains(s, "locklog.dev/install.sh") {
			t.Errorf("%s lacks the install.sh alternative", p)
		}
		for _, line := range strings.Split(s, "\n") {
			if loxUp.MatchString(strings.TrimSpace(line)) {
				t.Errorf("%s names lox up (the console is started by lox run): %q", p, line)
			}
		}
		// Homebrew comes first: the brew lines before any install.sh line.
		if i, j := strings.Index(s, "brew install davidgodefroid/tap/"), strings.Index(s, "curl -fsSL https://locklog.dev/install.sh"); j >= 0 && j < i {
			t.Errorf("%s: install.sh comes before Homebrew", p)
		}
	}
}

// install.sh's last line points to the Lock Family's next step, lox add
// locklog then lox run, like lockfamily's install.sh.
func TestInstallShNextHint(t *testing.T) {
	b, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	last := lines[len(lines)-1]
	for _, want := range []string{"lox add locklog", "lox run"} {
		if !strings.Contains(last, want) {
			t.Errorf("install.sh's last line %q lacks %q", last, want)
		}
	}
	if strings.Contains(last, "lox up") {
		t.Errorf("install.sh's last line names lox up: %q", last)
	}
	// lockfamily's install.sh wording (#134).
	const want = `say "next step: lox add locklog in your project, then lox run in a terminal of its own, outside the agent: approvals live there"`
	if last != want {
		t.Errorf("install.sh's last line = %q, want %q", last, want)
	}
}
