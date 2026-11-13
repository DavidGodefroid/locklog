//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const managedE2E = `version = 1
organisation = "Acme"

[locklog.bounds]
unmask = "never"
`

// managedImage builds an image of e.image with the managed file written
// as root (0:0, mode, in /etc/lockfamily 0755), as a company's admin
// installs it, and returns its tag. The release image itself carries no
// test tag: the file sits where lockkit reads it.
func managedImage(t *testing.T, e *e2eEnv, mode string) string {
	t.Helper()
	dir := filepath.Join(e.base, "managed-"+mode)
	mkdir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "managed.toml"), []byte(managedE2E), 0o644); err != nil {
		t.Fatal(err)
	}
	dockerfile := "FROM " + e.image + "\nUSER root\nCOPY managed.toml /etc/lockfamily/managed.toml\n" +
		"RUN chown -R 0:0 /etc/lockfamily && chmod 0755 /etc/lockfamily && chmod " + mode + " /etc/lockfamily/managed.toml\nUSER agent\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	tag := "locklog-e2e-managed-" + mode + "-" + hex.EncodeToString(b)
	docker(t, "build", "-q", "-t", tag, dir)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// managedConfig writes profiles ok (within the bounds) and bad (unmask
// = "approved", beyond them) over the test's logs.
func managedConfig(t *testing.T, e *e2eEnv) {
	t.Helper()
	var b strings.Builder
	b.WriteString("version = 1\n")
	for _, p := range []struct{ name, unmask string }{{"ok", "never"}, {"bad", "approved"}} {
		fmt.Fprintf(&b, "[profiles.%s]\nunmask = %q\n[profiles.%s.sources.app]\nkind = \"file\"\npaths = [%q]\nformat = \"logfmt\"\n",
			p.name, p.unmask, p.name, e.logs+"/app.log*")
	}
	mkdir(t, filepath.Join(e.proj, ".locklog"))
	cfgPath := filepath.Join(e.proj, ".locklog", "config.toml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0o644); err != nil {
		t.Fatal(err)
	}
}

// managedCheck runs `locklog managed check` in image over the project:
// its output and exit code.
func managedCheck(t *testing.T, e *e2eEnv, image string, args ...string) (string, int) {
	t.Helper()
	ll := filepath.Join(e.proj, ".locklog")
	cmd := exec.Command("docker", append([]string{"run", "--rm", "--network", "none", "--log-driver", "none", "--read-only",
		"--mount", "type=bind,src=" + ll + ",dst=" + ll + ",readonly", "-w", e.proj, image, "managed", "check"}, args...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// The company's managed file in the release image, written as root: the
// console prints "Managed by Acme (sha256:…)" and starts a profile within
// the bounds; `locklog managed check` exits 3 on a profile beyond them,
// citing the key. A managed file writable by others is a refusal to start.
func TestManagedFile(t *testing.T) {
	e, _, _, _ := newEnv(t, "managed")
	managedConfig(t, e)
	e.image = managedImage(t, e, "0644")

	out, code := managedCheck(t, e, e.image)
	if code != 3 || !strings.Contains(out, "blocked by company policy: locklog.bounds.unmask = never (profile bad: unmask = approved)") {
		t.Errorf("managed check: exit %d\n%s", code, out)
	}
	if out, code := managedCheck(t, e, e.image, "--profile", "ok"); code != 0 || !strings.Contains(out, "ok: 1 profile within the company policy (ok)") {
		t.Errorf("managed check --profile ok: exit %d\n%s", code, out)
	}

	_, screen, exited := launchLoxRun(t, e, true, "ok", "", [2]string{"Apply these changes? [y/N]", "y"})
	waitFor(t, screen, "Managed by Acme (sha256:", 2*time.Minute, exited)
	waitFor(t, screen, "Listening on ", 2*time.Minute, exited)
}

func TestManagedFileWritableRefused(t *testing.T) {
	e, _, _, _ := newEnv(t, "managed-0666")
	managedConfig(t, e)
	e.image = managedImage(t, e, "0666")

	out, code := managedCheck(t, e, e.image)
	if code != 3 || !strings.Contains(out, "must be writable by root only") {
		t.Errorf("managed check with a 0666 file: exit %d\n%s", code, out)
	}
	_, screen, exited := launchLoxRun(t, e, true, "ok", "")
	waitFor(t, screen, "must be writable by root only", 2*time.Minute, exited)
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		t.Fatalf("the console did not refuse to start:\n%s", plain(screen.String()))
	}
	if strings.Contains(plain(screen.String()), "Listening on ") {
		t.Errorf("the console listened with a managed file writable by others:\n%s", plain(screen.String()))
	}
}
