package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/ticket"
	"golang.org/x/term"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// openEngine returns the opener of the log engine of a policy: in the
// image, its first open confines the console (Landlock) before any source
// is opened.
func openEngine(inContainer bool) logconsole.Opener { return newOpener(inContainer).Open }

const consoleUsage = "usage: locklog console [--profile P] [--allowed-uids UID,...] [--hub URL --hub-key-file FILE --instance NAME [--hub-plain-http] [--devices-file FILE [--require-device CLASSES] [--seal-clear]] [--facade-keys-file FILE]]"

// hubDefaults completes the hub flags: with pinned devices and no
// --require-device, a read-pii approval (an unmask, an approved lookup)
// must be signed by one of them.
func hubDefaults(h console.HubOptions) console.HubOptions {
	if h.DevicesFile != "" && h.RequireDevice == "" {
		h.RequireDevice = string(ticket.RiskReadPII)
	}
	return h
}

// consoleCmd is `locklog console`: the console of one profile, in the
// human's terminal, in the launcher's container.
func consoleCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile to serve")
	var allowed onceFlag
	fs.Var(&allowed, "allowed-uids", "uids that may connect besides locklog-clients' members (an agent in a container of its own)")
	var hub console.HubOptions
	hub.Register(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(stderr, consoleUsage)
		return 2
	}
	uids, err := parseAllowedUIDs(allowed.v)
	if err != nil {
		fmt.Fprintf(stderr, "locklog console: %v\n%s\n", err, consoleUsage)
		return 2
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(stderr, "locklog console: must run in a terminal: it shows the policy and the approvals to the human")
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locklog console:", err)
		return 1
	}
	o := logconsole.FromEnv(logconsole.Options{}, os.Getenv)
	o.InContainer = logconsole.InImage(os.Getuid(), os.Stat)
	o.Open = openEngine(o.InContainer)
	// The engine's state (keys, index, PII rules) beside lockkit's own
	// (approved policies, audit), in the home volume in the image.
	stateBase, err := kit.StateBase()
	if err != nil {
		fmt.Fprintln(stderr, "locklog console:", err)
		return 1
	}
	o.StateDir = filepath.Join(stateBase, product.P.Name)
	var root string
	if o.InContainer {
		// The launcher starts the console in the project it checked: the
		// project is this directory, never an ancestor a walk would find,
		// and it is checked before anything in it is read.
		root = cwd
		o.Root = root
		if err := logconsole.CheckMounts(o); err != nil {
			fmt.Fprintln(stderr, "locklog console:", err)
			return 1
		}
	} else {
		var ok bool
		if root, ok = kconfig.FindProjectRoot(product.P, cwd); !ok {
			fmt.Fprintln(stderr, "locklog console: no .locklog/ here or above: run locklog setup first")
			return 1
		}
		o.Root = root
	}
	ps, err := config.LoadFile(kconfig.ProjectConfigPath(product.P, root))
	if err != nil {
		fmt.Fprintln(stderr, "locklog console:", err)
		return 1
	}
	p, err := selectProfile(ps, *profile)
	if err != nil {
		fmt.Fprintln(stderr, "locklog console:", err)
		return 1
	}
	t := console.NewTerminal(os.Stdin, stdout)
	if err := t.Interactive(); err != nil {
		fmt.Fprintln(stderr, "locklog console: warning:", err, "(the mode keys and the status line are off)")
	}
	defer t.Restore()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	kp := product.P
	kp.Version = strings.TrimPrefix(version, "v")
	o.Profile = p.Name
	be := logconsole.New(o)
	hub = hubDefaults(hub)
	var onHub func(*console.Hub)
	if hub.Enabled() {
		onHub = be.OnHub
	}
	var iso *console.IsolationEnv
	if len(uids) > 0 {
		// Set by whoever starts the console (the human, the launcher, lock
		// up), never by a client.
		env := allowUIDs(console.RealIsolationEnv(kp, os.Stdin), uids)
		iso = &env
		t.Println("allowed uids besides locklog-clients (--allowed-uids): " + joinUIDs(uids))
	}
	err = console.Run(ctx, kp, be, console.Options{
		Profile: p.Name, ProjectRoot: root, IO: t, TTY: os.Stdin, Isolation: iso, StateDir: stateBase,
		Sanitizer: logconsole.Sanitizer(), Hub: hub, OnHub: onHub,
	})
	if err != nil {
		fmt.Fprintln(stderr, "locklog console:", err)
		if errors.Is(err, console.ErrConfig) {
			return 2
		}
		return 1
	}
	return 0
}
