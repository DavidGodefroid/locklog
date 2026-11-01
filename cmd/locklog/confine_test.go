package main

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/source/docker"
)

func TestConfineRules(t *testing.T) {
	sys := []string{"/etc/passwd", "/etc/group", "/etc/locklog", "/etc/localtime", "/usr/share/zoneinfo", "/etc/ssl", "/proc", "/sys/class/net"}
	// Files and the journal.
	r := confineRules(confineInput{
		Roots:   logconsole.Roots{Dirs: []string{"/var/log/nginx", "/srv/logs"}, Journal: []string{"/var/log/journal"}},
		Project: "/home/dev/shop", StateDir: "/home/locklog/.local/state/locklog",
	})
	want := append([]string{"/srv/logs", "/var/log/journal", "/var/log/nginx", "/home/dev/shop/.locklog"}, sys...)
	if !slices.Equal(r.ReadOnly, want) {
		t.Errorf("read-only = %q\nwant %q", r.ReadOnly, want)
	}
	if !slices.Equal(r.ReadWrite, []string{"/run/locklog", "/home/locklog", "/tmp"}) || r.Exec != nil {
		t.Errorf("read-write = %q, exec = %q", r.ReadWrite, r.Exec)
	}
	// Docker: the containers root and the map directory; the vault CLI
	// when a source reads its credentials from Vault.
	r = confineRules(confineInput{Roots: logconsole.Roots{Docker: "/var/lib/docker/containers"}, Docker: true, Project: "/p", Vault: "/usr/local/bin/vault"})
	want = append([]string{"/var/lib/docker/containers", "/run/locklog-map", "/p/.locklog"}, sys...)
	if !slices.Equal(r.ReadOnly, want) || !slices.Equal(r.Exec, []string{"/usr/local/bin/vault"}) || !slices.Contains(r.ReadWrite, "/dev/null") {
		t.Errorf("docker rules = %+v", r)
	}
	// A project under /tmp is readable through /tmp (Landlock refuses a
	// read-only rule beneath a read-write one); a state directory outside
	// the home volume is writable.
	r = confineRules(confineInput{Project: "/tmp/shop", StateDir: "/var/lib/locklog-state"})
	if slices.Contains(r.ReadOnly, "/tmp/shop/.locklog") || !slices.Contains(r.ReadWrite, "/var/lib/locklog-state") {
		t.Errorf("rules = %+v", r)
	}
}

func TestVaultCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the console runs on Linux")
	}
	found := func(string) (string, error) { return "/usr/local/bin/vault", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	local := config.Profile{Sources: []config.Source{{Name: "f", Kind: config.KindFile}}}
	vault := config.Profile{Sources: []config.Source{{Name: "l", Kind: config.KindLoki, Remote: &config.Remote{}}}}
	vault.Sources[0].Remote.Credentials = "vault"
	if vaultCLI(local, found) != "" || vaultCLI(vault, missing) != "" || vaultCLI(vault, found) != "/usr/local/bin/vault" {
		t.Error("vaultCLI")
	}
}

func TestOpenerConfinesOnce(t *testing.T) {
	var applied []landlock.Rules
	op := &opener{inContainer: true, openat2: func() bool { return true }, lookPath: func(string) (string, error) { return "", errors.New("no") },
		restrict: func(r landlock.Rules) (landlock.Status, error) {
			applied = append(applied, r)
			return landlock.Status{State: landlock.Enforced, ABI: 6}, nil
		}}
	o := logconsole.OpenOptions{Roots: logconsole.Roots{Dirs: []string{"/var/log/app"}}, Project: "/p", StateDir: "/home/locklog/.local/state/locklog"}
	st, err := op.confine(o)
	if err != nil || st.State != landlock.Enforced || len(applied) != 1 || !slices.Contains(applied[0].ReadOnly, "/var/log/app") {
		t.Fatalf("confine: %+v %v %+v", st, err, applied)
	}
	// A reconnection: not applied again.
	if _, err := op.confine(o); err != nil || len(applied) != 1 {
		t.Errorf("second confine: %v, %d rulesets", err, len(applied))
	}
	// A later policy naming a root the ruleset does not grant.
	o.Roots.Dirs = append(o.Roots.Dirs, "/var/log/other")
	if _, err := op.confine(o); err == nil || !strings.Contains(err.Error(), "restart the console") {
		t.Errorf("new root after the confinement: %v", err)
	}
	// A ruleset that cannot be applied refuses to open.
	bad := &opener{inContainer: true, lookPath: op.lookPath, restrict: func(landlock.Rules) (landlock.Status, error) {
		return landlock.Status{}, errors.New("landlock: create ruleset: EINVAL")
	}}
	if _, err := bad.confine(o); err == nil || !strings.Contains(err.Error(), "could not confine itself") {
		t.Errorf("failed ruleset: %v", err)
	}
	// Outside the image nothing is applied.
	out := &opener{restrict: func(landlock.Rules) (landlock.Status, error) {
		t.Fatal("restricted outside the image")
		return landlock.Status{}, nil
	}}
	if st, err := out.confine(o); err != nil || st.State != landlock.Unsupported || !strings.Contains(st.String(), "outside its image") {
		t.Errorf("outside: %+v %v", st, err)
	}
}

func TestOpenerRefusesUnsupportedKindFirst(t *testing.T) {
	op := &opener{inContainer: true, restrict: func(landlock.Rules) (landlock.Status, error) {
		t.Fatal("confined before refusing the profile")
		return landlock.Status{}, nil
	}}
	pol := config.Policy{Profile: config.Profile{Name: "p", Sources: []config.Source{{Name: "l", Kind: "splunk"}}}}
	if _, err := op.Open(context.Background(), logconsole.OpenOptions{Policy: pol}); err == nil || !strings.Contains(err.Error(), "does not read yet") {
		t.Errorf("Open: %v", err)
	}
}

// A failed first open (a missing key the human then fixes) leaves the
// next open first: a per-session pseudonym rotation still rotates.
func TestOpenerFirstOpenSurvivesAFailedOpen(t *testing.T) {
	var firsts []bool
	fail := true
	op := &opener{openat2: func() bool { return false },
		openSession: func(_ context.Context, o session.Options) (logconsole.Engine, error) {
			firsts = append(firsts, o.FirstOpen)
			if fail {
				return nil, errors.New("ref.key: missing")
			}
			return nil, nil
		}}
	pol := config.Policy{Profile: config.Profile{Name: "p"}}
	if _, err := op.Open(context.Background(), logconsole.OpenOptions{Policy: pol}); err == nil {
		t.Fatal("the failing open succeeded")
	}
	fail = false
	for range 2 {
		if _, err := op.Open(context.Background(), logconsole.OpenOptions{Policy: pol}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(firsts, []bool{true, true, false}) {
		t.Errorf("FirstOpen per open: %v, want [true true false]", firsts)
	}

	// An open that fails after the epochs opened (and rotated) has used
	// up the first open: the retry does not rotate again.
	firsts = nil
	op = &opener{openat2: func() bool { return false },
		openSession: func(_ context.Context, o session.Options) (logconsole.Engine, error) {
			firsts = append(firsts, o.FirstOpen)
			o.EpochsOpened()
			return nil, errors.New("index: permission denied")
		}}
	for range 2 {
		if _, err := op.Open(context.Background(), logconsole.OpenOptions{Policy: pol}); err == nil {
			t.Fatal("the failing open succeeded")
		}
	}
	if !slices.Equal(firsts, []bool{true, false}) {
		t.Errorf("FirstOpen after a late failure: %v, want [true false]", firsts)
	}
}

// A reviewed policy that reads credentials from Vault, on a console
// confined without the vault CLI's exec rule, is refused with a restart
// message.
func TestOpenerConfinedWithoutVaultRefusesVault(t *testing.T) {
	vaultAt := ""
	op := &opener{inContainer: true, lookPath: func(string) (string, error) {
		if vaultAt == "" {
			return "", errors.New("no")
		}
		return vaultAt, nil
	}, restrict: func(landlock.Rules) (landlock.Status, error) {
		return landlock.Status{State: landlock.Enforced, ABI: 6}, nil
	}}
	src := func(cred string) logconsole.OpenOptions {
		return logconsole.OpenOptions{Policy: config.Policy{Profile: config.Profile{Name: "p", Sources: []config.Source{{Name: "r", Kind: config.KindLoki, Remote: &config.Remote{Base: kconfig.Base{Credentials: cred}}}}}}}
	}
	if _, err := op.confine(src("")); err != nil {
		t.Fatal(err)
	}
	// Absolute on every build OS (vaultCLI grants absolute paths only).
	vaultAt = filepath.Join(t.TempDir(), "vault")
	if _, err := op.confine(src(kconfig.CredentialsVault)); err == nil || !strings.Contains(err.Error(), "restart the console") {
		t.Errorf("vault after a ruleset without it: %v", err)
	}
	// Confined with the vault rule: a later Vault policy is accepted.
	op = &opener{inContainer: true, lookPath: op.lookPath, restrict: op.restrict}
	if _, err := op.confine(src(kconfig.CredentialsVault)); err != nil {
		t.Fatal(err)
	}
	if _, err := op.confine(src(kconfig.CredentialsVault)); err != nil {
		t.Errorf("vault after a ruleset with it: %v", err)
	}
}

// A reviewed policy that adds a docker source to a console confined
// without one is refused with a restart message: the map directory is
// not in the ruleset.
func TestOpenerConfinedWithoutDockerRefusesDocker(t *testing.T) {
	op := &opener{inContainer: true, lookPath: func(string) (string, error) { return "", errors.New("no") },
		restrict: func(landlock.Rules) (landlock.Status, error) {
			return landlock.Status{State: landlock.Enforced, ABI: 6}, nil
		}}
	files := logconsole.OpenOptions{Policy: config.Policy{Profile: config.Profile{Name: "p", Sources: []config.Source{{Name: "f", Kind: config.KindFile}}}}}
	if _, err := op.confine(files); err != nil {
		t.Fatal(err)
	}
	dock := logconsole.OpenOptions{Policy: config.Policy{Profile: config.Profile{Name: "p", Sources: []config.Source{{Name: "d", Kind: config.KindDocker}}}}}
	if _, err := op.confine(dock); err == nil || !strings.Contains(err.Error(), "restart the console") || !strings.Contains(err.Error(), docker.DefaultMapDir) {
		t.Errorf("docker after a ruleset without it: %v", err)
	}
}
