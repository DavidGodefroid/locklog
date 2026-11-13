//go:build unix && lockfamily_managed_test

package logconsole

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locklog/internal/product"
)

func useManaged(t *testing.T, body string) *managed.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte("version = 1\norganisation = \"Acme\"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	f, err := managed.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The backend's ManagedBounds is what the console checks: a policy
// beyond a bound, or outside an allowlist, is refused citing the managed
// key; one within them passes.
func TestManagedBoundsBackend(t *testing.T) {
	f := useManaged(t, "[locklog.bounds]\nunmask = \"never\"\nkinds = [\"file\", \"journald\"]\n")
	root := project(t, `version = 1
[profiles.staging]
unmask = "never"
[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
[profiles.dev]
unmask = "approved"
[profiles.dev.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
[profiles.remote]
unmask = "never"
`+strings.ReplaceAll(lokiCfg, "profiles.staging", "profiles.remote"))
	for _, c := range []struct{ profile, want string }{
		{"staging", ""},
		{"dev", "blocked by company policy: locklog.bounds.unmask = never (profile dev: unmask = approved)"},
		{"remote", "blocked by company policy: locklog.bounds.kinds does not allow sources.loki.kind = loki (profile remote; allowed: file, journald)"},
	} {
		be := New(Options{Profile: c.profile, Root: root, Network: "n"})
		pol, err := be.LoadPolicy()
		if err != nil {
			t.Fatalf("%s: %v", c.profile, err)
		}
		err = console.CheckManaged(product.P, be, pol, f)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.profile, err)
			}
			continue
		}
		if !errors.Is(err, console.ErrManaged) || !slices.Contains(console.ManagedLines(err), c.want) {
			t.Errorf("%s: %v (lines %q), want %q", c.profile, err, console.ManagedLines(err), c.want)
		}
	}
}

// The managed mask rules are in the policy, shown as managed in the PII
// view; a project allow rule on one is refused at load.
func TestManagedPIIPolicy(t *testing.T) {
	useManaged(t, "[[locklog.bounds.pii_mask]]\nsources = [\"app-*\"]\nfield = \"user.email\"\n")
	root := project(t, localCfg)
	be := New(Options{Profile: "staging", Root: root})
	pol, err := be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := be.PIIRules(pol); !slices.Equal(m, []string{"redact field=user.email sources=app-* (managed)"}) {
		t.Errorf("PII view = %q", m)
	}
	if lines := strings.Join(pol.(Policy).Describe(), "\n"); !strings.Contains(lines, "pii mask (managed): redact field=user.email sources=app-*") {
		t.Errorf("describe = %s", lines)
	}
	// Removing the managed rule (the file changed) loosens the policy.
	without := pol.(Policy)
	without.PIIMask = nil
	if !console.Loosens(without.Diff(pol)) {
		t.Error("removing a managed mask rule does not loosen")
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "pii.toml"), []byte("[[allow]]\nsources = [\"app-api\"]\nfield = \"user.email\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := be.LoadPolicy(); err == nil || !strings.Contains(err.Error(), "locklog.bounds.pii_mask") {
		t.Errorf("an allow rule on a managed mask: %v", err)
	}
}
