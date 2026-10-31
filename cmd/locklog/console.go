package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"golang.org/x/term"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// openEngine opens the log engine of a policy; nil until the engine is
// part of this build (the console then refuses to connect).
var openEngine logconsole.Opener

const consoleUsage = "usage: locklog console [--profile P] [--allowed-uids UID,...]"

// consoleCmd is `locklog console`: the console of one profile, in the
// human's terminal, in the launcher's container.
func consoleCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "profile to serve")
	var allowed onceFlag
	fs.Var(&allowed, "allowed-uids", "uids that may connect besides locklog-clients' members (an agent in a container of its own)")
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
	root, ok := kconfig.FindProjectRoot(product.P, cwd)
	if !ok {
		fmt.Fprintln(stderr, "locklog console: no .locklog/ here or above: run locklog setup first")
		return 1
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
	be := logconsole.New(logconsole.FromEnv(logconsole.Options{Profile: p.Name, Root: root, Open: openEngine}, os.Getenv))
	var iso *console.IsolationEnv
	if len(uids) > 0 {
		// Set by whoever starts the console (the human, the launcher, lock
		// up), never by a client.
		env := allowUIDs(console.RealIsolationEnv(kp, os.Stdin), uids)
		iso = &env
		t.Println("allowed uids besides locklog-clients (--allowed-uids): " + joinUIDs(uids))
	}
	err = console.Run(ctx, kp, be, console.Options{
		Profile: p.Name, ProjectRoot: root, IO: t, TTY: os.Stdin, Isolation: iso,
		Sanitizer: logconsole.Sanitizer(),
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
