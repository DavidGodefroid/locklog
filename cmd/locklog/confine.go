package main

import (
	"context"
	"fmt"
	"os/exec"
	"path"
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
// bundle (remote sources), the files of Go's resolver (without cgo it reads
// them at every lookup: remote sources and the hub are dialled by name),
// /proc (the peer's process name and status, /proc/self/mountinfo for the
// docker source's own container, the hostname) and /sys/class/net (the
// no-network check).
var consoleSystemRead = []string{
	"/etc/passwd", "/etc/group", "/etc/locklog", "/etc/localtime", "/usr/share/zoneinfo", "/etc/ssl",
	"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
	"/proc", "/sys/class/net",
}

// consoleTerminal is the controlling terminal: a secret's prompt before
// the console's reader starts (a remote source's password asked again
// after the first connection failed) opens it and turns the echo off. The
// console holds the same terminal as its standard streams already.
var consoleTerminal = []string{"/dev/tty"}

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
// credentials from Vault; the controlling terminal. A log root at, beneath
// or above a writable directory (an extra root under /tmp or the home
// volume) is refused: the ruleset would let the console write there, or
// a source read the console's own files.
func confineRules(in confineInput) (landlock.Rules, error) {
	r := landlock.Rules{ReadWrite: slices.Clone(consoleReadWrite), Terminal: slices.Clone(consoleTerminal)}
	if in.StateDir != "" && !slices.ContainsFunc(r.ReadWrite, func(w string) bool { return beneath(in.StateDir, w) }) {
		r.ReadWrite = append(r.ReadWrite, in.StateDir)
	}
	logs := in.Roots.All()
	if in.Docker {
		logs = append(logs, docker.DefaultMapDir)
	}
	for _, p := range logs {
		for _, w := range r.ReadWrite {
			if beneath(p, w) || beneath(w, p) {
				return landlock.Rules{}, fmt.Errorf("the log root %s overlaps the console's writable %s: refused (bind the logs elsewhere than the console's volumes and /tmp)", p, w)
			}
		}
	}
	r.ReadOnly = logs
	if in.Project != "" {
		// Linux paths (Landlock is Linux-only), whatever the build's OS.
		r.ReadOnly = append(r.ReadOnly, path.Join(in.Project, ".locklog"))
	}
	r.ReadOnly = append(r.ReadOnly, consoleSystemRead...)
	// A project's .locklog already beneath a writable directory (a project
	// under /tmp) is readable through it, and Landlock would refuse the
	// overlap.
	r.ReadOnly = slices.DeleteFunc(r.ReadOnly, func(p string) bool {
		return slices.ContainsFunc(r.ReadWrite, func(w string) bool { return beneath(p, w) })
	})
	if in.Vault != "" {
		r.Exec = []string{in.Vault}
		// os/exec opens /dev/null for the child's unset streams.
		r.ReadWrite = append(r.ReadWrite, "/dev/null")
	}
	return r, nil
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
	// openSession opens the engine (session.Open; a test's stub).
	openSession func(context.Context, session.Options) (logconsole.Engine, error)

	mu       sync.Mutex
	confined bool
	status   landlock.Status
	allowed  []string // the read-only roots of the ruleset
	docker   bool     // the ruleset reads the docker map directory
	vault    bool     // the ruleset executes the vault CLI
	// opened is set by the first successful open: a failed first open
	// (a missing key the human then fixes) leaves the next one first, so
	// that a per-session pseudonym rotation still rotates.
	opened bool
}

func newOpener(inContainer bool) *opener {
	return &opener{inContainer: inContainer, restrict: landlock.Restrict, openat2: docker.Openat2, lookPath: exec.LookPath}
}

// dockerMapDir is the docker source's map directory in the image.
const dockerMapDir = docker.DefaultMapDir

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
	pr := o.Policy.Profile
	docker := slices.ContainsFunc(pr.Sources, func(s config.Source) bool { return s.Kind == config.KindDocker })
	if op.confined {
		if docker && !op.docker {
			return landlock.Status{}, fmt.Errorf("%s is not readable by this console (it was confined at start, before this policy named a docker source): restart the console", dockerMapDir)
		}
		if vaultCLI(pr, op.lookPath) != "" && !op.vault {
			return landlock.Status{}, fmt.Errorf("the vault CLI is not executable by this console (it was confined at start, before this policy read credentials from Vault): restart the console")
		}
		for _, r := range roots {
			if !slices.Contains(op.allowed, r) {
				return landlock.Status{}, fmt.Errorf("%s is not readable by this console (it was confined at start, before this policy named it): restart the console", r)
			}
		}
		return op.status, nil
	}
	vault := vaultCLI(pr, op.lookPath)
	rules, err := confineRules(confineInput{Roots: o.Roots, Docker: docker, Project: o.Project, StateDir: o.StateDir, Vault: vault})
	if err != nil {
		return landlock.Status{}, err
	}
	st, err := op.restrict(rules)
	if err != nil {
		return landlock.Status{}, fmt.Errorf("the console could not confine itself (Landlock): %w", err)
	}
	op.confined, op.status, op.allowed, op.docker, op.vault = true, st, roots, docker, vault != ""
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
	open := op.openSession
	if open == nil {
		open = openSession
	}
	s, err := open(ctx, session.Options{OpenOptions: o, FirstOpen: !op.opened,
		// An open that fails after the epochs rotated has used up the
		// first open: a retry does not rotate again.
		EpochsOpened: func() { op.opened = true },
		Confinement:  session.Confinement{Landlock: st, Openat2: op.openat2()}})
	if err != nil {
		return nil, err
	}
	op.opened = true
	return s, nil
}

// openSession is session.Open as a logconsole.Engine.
func openSession(ctx context.Context, o session.Options) (logconsole.Engine, error) {
	s, err := session.Open(ctx, o)
	if err != nil {
		return nil, err
	}
	return s, nil
}
