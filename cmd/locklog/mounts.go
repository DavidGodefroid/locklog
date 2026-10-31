package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/mountplan"
)

// profileFlag parses an optional --profile NAME (or --profile=NAME) and
// refuses anything else.
func profileFlag(args []string) (string, error) {
	name := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--profile" && i+1 < len(args):
			name = args[i+1]
			i++
		case strings.HasPrefix(a, "--profile="):
			name = strings.TrimPrefix(a, "--profile=")
		default:
			return "", fmt.Errorf("unexpected argument %q", a)
		}
	}
	return name, nil
}

// selectProfile returns the named profile, or the only one when name is "".
func selectProfile(ps map[string]config.Profile, name string) (config.Profile, error) {
	if name != "" {
		p, ok := ps[name]
		if !ok {
			return config.Profile{}, fmt.Errorf("no profile %q", name)
		}
		return p, nil
	}
	names := make([]string, 0, len(ps))
	for n := range ps {
		names = append(names, n)
	}
	sort.Strings(names)
	switch len(names) {
	case 0:
		return config.Profile{}, fmt.Errorf("no profile: run locklog setup first")
	case 1:
		return ps[names[0]], nil
	}
	return config.Profile{}, fmt.Errorf("several profiles (%s): name one with --profile", strings.Join(names, ", "))
}

// mounts prints the mount plan of a profile, one line per mount
// (internal/mountplan), for the launcher.
func mounts(args []string, stdout, stderr io.Writer) int {
	name, err := profileFlag(args)
	if err != nil {
		fmt.Fprintf(stderr, "locklog mounts: %v\nusage: locklog mounts [--profile NAME]\n", err)
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "locklog mounts: %v\n", err)
		return 1
	}
	ps, _, err := config.Load(cwd)
	if err != nil {
		fmt.Fprintf(stderr, "locklog mounts: %v\n", err)
		return 1
	}
	p, err := selectProfile(ps, name)
	if err != nil {
		fmt.Fprintf(stderr, "locklog mounts: %v\n", err)
		return 1
	}
	lines, err := mountplan.Lines(p)
	if err != nil {
		fmt.Fprintf(stderr, "locklog mounts: profile %s: %v\n", p.Name, err)
		return 1
	}
	// The profile name and whether it is production head the plan.
	fmt.Fprintf(stdout, "profile %s %t\n", p.Name, p.Production)
	for _, l := range lines {
		fmt.Fprintln(stdout, l.String())
	}
	// A remote source mounts nothing; the launcher needs LOCKLOG_NETWORK
	// to reach it.
	if slices.ContainsFunc(p.Sources, func(s config.Source) bool { return s.Remote != nil }) {
		fmt.Fprintln(stdout, mountplan.RemoteLine)
	}
	return 0
}
