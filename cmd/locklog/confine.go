package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/secrets"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/source/docker"
)

// The console's writable directories in its image: the socket volume, the
// home volume (keys, index, approved policy, audit) and /tmp.
var consoleReadWrite = []string{"/run/locklog", "/home/locklog", "/tmp"}

// consoleSystemRead are the system paths the console still reads once
// confined: the accounts and groups of the peer check (os/user reads them
// on every connection), the separated setup's file, the zone info, the CA
// bundle (remote sources), /proc (the peer's process name and status,
// /proc/self/mountinfo for the docker source's own container, the
// hostname) and /sys/class/net (the no-network check).
var consoleSystemRead = []string{
	"/etc/passwd", "/etc/group", "/etc/locklog", "/etc/localtime", "/usr/share/zoneinfo", "/etc/ssl",
	"/proc", "/sys/class/net",
}

// confineInput is what the console's ruleset is computed from.
type confineInput struct {
	// Roots are the checked mount roots of the policy's sources.
	Roots logconsole.Roots
	// Docker is set with a docker source (its map directory is read).
	Docker bool
	// Project is the project root: its .locklog is read again (:review).
	Project string
	// StateDir is the console's state directory: writable.
	StateDir string
	// Vault is the vault CLI the console runs ("" for none).
	Vault string
}

// confineRules are the console's Landlock rules: read-only beneath the
// checked log roots, the containers root and its map, the project's
// .locklog and the system paths it still reads; writes only to its
// volumes and /tmp; exec only of the vault CLI, when a source reads its
// credentials from Vault.
func confineRules(in confineInput) landlock.Rules {
	r := landlock.Rules{ReadWrite: slices.Clone(consoleReadWrite)}
	r.ReadOnly = append(r.ReadOnly, in.Roots.All()...)
	if in.Docker {
		r.ReadOnly = append(r.ReadOnly, docker.DefaultMapDir)
	}
	if in.Project != "" {
		r.ReadOnly = append(r.ReadOnly, filepath.Join(in.Project, ".locklog"))
	}
	r.ReadOnly = append(r.ReadOnly, consoleSystemRead...)
	if in.StateDir != "" && !slices.ContainsFunc(r.ReadWrite, func(w string) bool { return beneath(in.StateDir, w) }) {
		r.ReadWrite = append(r.ReadWrite, in.StateDir)
	}
	// A path already beneath a writable one (a project under /tmp) is
	// readable through it, and Landlock would refuse the overlap.
	r.ReadOnly = slices.DeleteFunc(r.ReadOnly, func(p string) bool {
		return slices.ContainsFunc(r.ReadWrite, func(w string) bool { return beneath(p, w) })
	})
	if in.Vault != "" {
		r.Exec = []string{in.Vault}
		// os/exec opens /dev/null for the child's unset streams.
		r.ReadWrite = append(r.ReadWrite, "/dev/null")
	}
	return r
}

func beneath(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// vaultCLI is the vault CLI to allow: only when a source of p reads its
// credentials from Vault and the image has the CLI (the -vault image).
func vaultCLI(p config.Profile, lookPath func(string) (string, error)) string {
	if !slices.ContainsFunc(p.Sources, func(s config.Source) bool {
		return s.Remote != nil && s.Remote.Credentials == kconfig.CredentialsVault
	}) {
		return ""
	}
	// A relative result (a PATH entry like ".") is not granted.
	if exe, err := lookPath(secrets.VaultCommand); err == nil && filepath.IsAbs(exe) {
		return exe
	}
	return ""
}

// opener is the console's engine opener: in its image, the first open
// confines the console (Landlock) before any source is opened; every
// open builds the engine of the approved policy.
type opener struct {
	inContainer bool
	restrict    func(landlock.Rules) (landlock.Status, error)
	openat2     func() bool
	lookPath    func(string) (string, error)

	mu       sync.Mutex
	confined bool
	status   landlock.Status
	allowed  []string // the read-only roots of the ruleset
	opens    int
}

func newOpener(inContainer bool) *opener {
	return &opener{inContainer: inContainer, restrict: landlock.Restrict, openat2: docker.Openat2, lookPath: exec.LookPath}
}

// notConfined is the status outside the image.
var notConfined = landlock.Status{State: landlock.Unsupported, Detail: "not applied: the console runs outside its image"}

// confine applies the ruleset once per process: Landlock cannot be undone,
// and a later policy (a reconnection, a reviewed change) may only read
// roots of the first ruleset.
func (op *opener) confine(o logconsole.OpenOptions) (landlock.Status, error) {
	if !op.inContainer {
		return notConfined, nil
	}
	roots := o.Roots.All()
	if op.confined {
		for _, r := range roots {
			if !slices.Contains(op.allowed, r) {
				return landlock.Status{}, fmt.Errorf("%s is not readable by this console (it was confined at start, before this policy named it): restart the console", r)
			}
		}
		return op.status, nil
	}
	pr := o.Policy.Profile
	docker := slices.ContainsFunc(pr.Sources, func(s config.Source) bool { return s.Kind == config.KindDocker })
	rules := confineRules(confineInput{Roots: o.Roots, Docker: docker, Project: o.Project, StateDir: o.StateDir, Vault: vaultCLI(pr, op.lookPath)})
	st, err := op.restrict(rules)
	if err != nil {
		return landlock.Status{}, fmt.Errorf("the console could not confine itself (Landlock): %w", err)
	}
	op.confined, op.status, op.allowed = true, st, roots
	return st, nil
}

// Open implements logconsole.Opener.
func (op *opener) Open(ctx context.Context, o logconsole.OpenOptions) (logconsole.Engine, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	// A kind this build does not read is refused before anything else.
	if err := session.CheckKinds(o.Policy.Profile); err != nil {
		return nil, err
	}
	st, err := op.confine(o)
	if err != nil {
		return nil, err
	}
	op.opens++
	s, err := session.Open(ctx, session.Options{OpenOptions: o, FirstOpen: op.opens == 1,
		Confinement: session.Confinement{Landlock: st, Openat2: op.openat2()}})
	if err != nil {
		return nil, err
	}
	return s, nil
}
