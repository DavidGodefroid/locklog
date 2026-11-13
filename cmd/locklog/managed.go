package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/product"
)

const (
	managedShowUsage  = "usage: locklog managed show"
	managedCheckUsage = "usage: locklog managed check [--profile NAME] [--project DIR]"
	// noManaged is what managed show, managed check and doctor print when
	// the machine has no managed file.
	noManaged = "no managed configuration"
	// exitManaged is the exit code of a managed file refused or of a
	// profile beyond its bounds: lox and the launcher read it.
	exitManaged = 3
)

// managedCmd is `locklog managed show|check`: the company's managed file
// (lockkit managed) as locklog reads it. lox runs `managed check` before
// it starts the lock (lockhub#179), the launcher too (#146): its output
// and exit codes are a contract.
func managedCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return managedShowCmd(args[1:], stdout, stderr)
		case "check":
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintln(stderr, "locklog managed check:", err)
				return 1
			}
			return managedCheckCmd(args[1:], cwd, os.Getenv, stdout, stderr)
		}
	}
	// The subcommand is not quoted: it may be a token pasted in the
	// wrong place.
	fmt.Fprintln(stderr, "locklog managed: unknown subcommand; want show or check")
	fmt.Fprintln(stderr, managedShowUsage)
	fmt.Fprintln(stderr, managedCheckUsage)
	return 2
}

// managedShowCmd prints the managed file: its path, organisation,
// fingerprint and signature, then locklog's bounds, defaults, managed PII
// rules and profile names. No file: noManaged, exit 0. A file refused:
// the error, exit 3.
func managedShowCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "locklog managed show: unexpected arguments")
		fmt.Fprintln(stderr, managedShowUsage)
		return 2
	}
	m, err := config.LoadManaged()
	if err != nil {
		fmt.Fprintln(stderr, "locklog managed show:", err)
		return exitManaged
	}
	if m == nil {
		fmt.Fprintln(stdout, noManaged)
		return 0
	}
	f := m.File
	fmt.Fprintln(stdout, f.Describe())
	fmt.Fprintln(stdout, "path: "+f.Path)
	org := f.Organisation
	if org == "" {
		org = "none"
	}
	fmt.Fprintln(stdout, "organisation: "+org)
	fmt.Fprintln(stdout, "fingerprint: sha256:"+f.Fingerprint)
	signed := "no"
	if f.Signed {
		signed = "yes"
	}
	fmt.Fprintln(stdout, "signed: "+signed)
	var bounds, rules []string
	for _, l := range m.BoundsOf().Describe() {
		if strings.HasPrefix(l, config.ManagedTool+".bounds.pii_mask = ") {
			rules = append(rules, strings.TrimPrefix(l, config.ManagedTool+".bounds.pii_mask = "))
			continue
		}
		bounds = append(bounds, l)
	}
	section(stdout, "bounds", bounds)
	section(stdout, "defaults", m.DescribeDefaults())
	section(stdout, "pii rules (locklog.bounds.pii_mask)", rules)
	names := f.Profiles(config.ManagedTool)
	if len(names) == 0 {
		names = []string{"none"}
	}
	fmt.Fprintln(stdout, "profiles: "+strings.Join(names, ", "))
	return 0
}

// section prints a titled list of lines, "none" when empty.
func section(w io.Writer, title string, lines []string) {
	if len(lines) == 0 {
		fmt.Fprintln(w, title+": none")
		return
	}
	fmt.Fprintln(w, title+":")
	for _, l := range lines {
		fmt.Fprintln(w, "  "+l)
	}
}

// managedCheckCmd checks the profiles of the project's config against
// the managed bounds, as the console does at start, with the launch
// environment of getenv (LOCKLOG_NETWORK, LOCKLOG_EXTRA_ROOTS): no
// connection, no log, no credential, no hub, no terminal. One "blocked by
// company policy: …" line per violation and exit 3 on any, else one ok
// line and exit 0. A config the managed file refuses (a redefined managed
// profile, an allow rule on a managed mask) is exit 3 too.
func managedCheckCmd(args []string, cwd string, getenv func(string) string, stdout, stderr io.Writer) int {
	usage := func(msg string) int {
		fmt.Fprintln(stderr, "locklog managed check: "+msg)
		fmt.Fprintln(stderr, managedCheckUsage)
		return 2
	}
	fs := flag.NewFlagSet("managed check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String(verbs.FlagProfile, "", "check one profile")
	project := fs.String(verbs.FlagProject, "", "the project directory (default: the project of this directory)")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, managedCheckUsage)
			return 0
		}
		return usage(err.Error())
	}
	if fs.NArg() != 0 {
		return usage("unexpected arguments")
	}
	dir := cwd
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return usage("--project: not a usable path")
		}
		dir = abs
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "locklog managed check:", err)
		return exitManaged
	}
	m, err := config.LoadManaged()
	if err != nil {
		return fail(err)
	}
	if m == nil {
		fmt.Fprintln(stdout, noManaged)
		return 0
	}
	// The console's reader: the project's config file with the managed
	// profiles and defaults (no project: the managed profiles alone).
	root, ok := kconfig.FindProjectRoot(product.P, dir)
	ps := m.Profiles
	if ok {
		if ps, err = config.LoadFileWith(kconfig.ProjectConfigPath(product.P, root), m); err != nil {
			return fail(err)
		}
	}
	names := slices.Sorted(maps.Keys(ps))
	if *name != "" {
		if _, ok := ps[*name]; !ok {
			return usage("no such profile in the project's config or the managed file")
		}
		names = []string{*name}
	}
	env := logconsole.FromEnv(logconsole.Options{}, getenv)
	blocked := false
	for _, n := range names {
		pol, err := logconsole.ProfilePolicy(ps[n], root, env.Network, env.ExtraRoots, m)
		if err != nil {
			return fail(err)
		}
		lines, err := m.BoundsOf().Violations(pol)
		if err != nil {
			return fail(err)
		}
		for _, l := range lines {
			fmt.Fprintln(stdout, l)
			blocked = true
		}
	}
	if blocked {
		return exitManaged
	}
	word := "profiles"
	if len(names) == 1 {
		word = "profile"
	}
	fmt.Fprintf(stdout, "ok: %d %s within the company policy (%s)\n", len(names), word, strings.Join(names, ", "))
	return 0
}
