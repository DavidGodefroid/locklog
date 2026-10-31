package main

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
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
	pol := config.Policy{Profile: config.Profile{Name: "p", Sources: []config.Source{{Name: "l", Kind: config.KindLoki}}}}
	if _, err := op.Open(context.Background(), logconsole.OpenOptions{Policy: pol}); err == nil || !strings.Contains(err.Error(), "does not read yet") {
		t.Errorf("Open: %v", err)
	}
}
