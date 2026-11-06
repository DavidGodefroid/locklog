package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidGodefroid/lockkit/verbs"
	"golang.org/x/term"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
	"github.com/DavidGodefroid/locklog/internal/product"
	"github.com/DavidGodefroid/locklog/internal/setup"
)

const profileAddUsage = `usage: locklog profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production]
                           [--only DIR,...] [--loki-proxy SERVICE [--loki-selector label=value]
                           [--credentials ask|vault [--vault-path P]]]`

// loadFacts reads the launcher's facts file, or gathers the facts here.
func loadFacts(path string, stdin io.Reader, getenv func(string) string) (hostfacts.Facts, error) {
	if path == "" {
		roots := []string{"/var/log"}
		roots = append(roots, strings.Fields(getenv("LOCKLOG_EXTRA_ROOTS"))...)
		return hostfacts.Gather(hostfacts.Env{LogRoots: roots}), nil
	}
	if path == "-" {
		return hostfacts.Parse(stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return hostfacts.Facts{}, err
	}
	defer f.Close()
	return hostfacts.Parse(f)
}

// profileCmd is `locklog profile add`, the launcher verb of lockkit's
// GUIDE.md §14: a profile of the project's .locklog/config.toml from the
// logs this host has. It never takes, asks for or writes a secret: the
// console asks for a remote source's at its start, or reads it from Vault.
func profileCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	asJSON := verbs.WantsJSON(args)
	fail := func(code string, exit int, err error) int {
		msg := strings.TrimPrefix(err.Error(), "profile add: ")
		if asJSON {
			if werr := verbs.WriteJSON(stdout, verbs.Error{Lock: product.P.Name, Code: code, Error: msg}); werr != nil {
				return 1
			}
			return exit
		}
		fmt.Fprintln(stderr, "locklog profile add:", msg)
		if code == verbs.CodeUsage || code == verbs.CodeSecret {
			fmt.Fprintln(stderr, profileAddUsage)
		}
		return exit
	}
	if len(args) == 0 || args[0] != "add" {
		return fail(verbs.CodeUsage, 2, errors.New("the only subcommand is add"))
	}
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	nonInteractive := fs.Bool(verbs.FlagNonInteractive, false, "never ask: a missing value is a usage error")
	fs.Bool(verbs.FlagJSON, false, "one line of JSON on stdout")
	projectDir := fs.String(verbs.FlagProject, "", "the project directory (default: this one)")
	profile := fs.String(verbs.FlagProfile, "", "the profile's name (default: prod or staging)")
	prod := fs.Bool(verbs.FlagProduction, false, "a production profile")
	credentials := fs.String(verbs.FlagCredentials, "", "the proxied Loki's: ask (the console asks at start) or vault")
	vaultPath := fs.String(verbs.FlagVaultPath, "", "with --credentials vault: the Vault path")
	only := fs.String("only", "", "detect only the log files under these directories (comma-separated; no journal, no container)")
	lokiProxy := fs.String("loki-proxy", "", "the Compose Loki service to put behind an authenticating proxy (interactive only)")
	lokiSel := fs.String("loki-selector", "", "the proxied Loki source's label=value")
	facts := fs.String("facts", "", "the host's facts (written by the launcher)")
	proxyDir := fs.String("proxy-dir", "", "where the proxies' files go, outside the project (set by the launcher)")
	if err := verbs.Parse(product.P, fs, args[1:]); err != nil {
		return fail(verbs.ErrorCode(err, verbs.CodeUsage), 2, err)
	}
	cred, err := verbs.Credentials(*credentials, *vaultPath)
	if err != nil {
		return fail(verbs.ErrorCode(err, verbs.CodeUsage), 2, err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	interactive := !*nonInteractive
	if interactive && !isTerminal(stdin) {
		return fail(verbs.CodeUsage, 2, fmt.Errorf("no terminal to ask on: give the values as flags with --%s", verbs.FlagNonInteractive))
	}
	if *lokiProxy != "" && !interactive {
		return fail(verbs.CodeUsage, 2, fmt.Errorf("--loki-proxy shows its token on your terminal once: not with --%s", verbs.FlagNonInteractive))
	}
	if *lokiProxy == "" && (set[verbs.FlagCredentials] || set[verbs.FlagVaultPath] || set["loki-selector"]) && !interactive {
		return fail(verbs.CodeUsage, 2, errors.New("--credentials, --vault-path and --loki-selector are for the proxied Loki (--loki-proxy)"))
	}
	o := setup.Options{Profile: *profile, Production: *prod, ProductionSet: set[verbs.FlagProduction] || *nonInteractive, Ask: interactive,
		LokiProxy: *lokiProxy, LokiSelector: *lokiSel, ProxyBase: *proxyDir, Credentials: cred, VaultPath: *vaultPath, In: stdin, Out: stdout}
	if asJSON {
		// stdout carries the JSON line only.
		o.Out = stderr
	}
	if *only != "" {
		for _, d := range strings.Split(*only, ",") {
			if !filepath.IsAbs(d) {
				return fail(verbs.CodeUsage, 2, errors.New("--only: want absolute directories"))
			}
			o.Only = append(o.Only, d)
		}
	}
	root := *projectDir
	if root == "" {
		if root, err = os.Getwd(); err != nil {
			return fail(verbs.CodeFailed, 1, err)
		}
	}
	if root, err = filepath.Abs(root); err != nil {
		return fail(verbs.CodeUsage, 2, errors.New("--project: not a directory"))
	}
	o.Root = filepath.Clean(root)
	// The host's home through the launcher (in the image, HOME is not it).
	if o.Home = os.Getenv("LOCKLOG_HOST_HOME"); o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	if o.Facts, err = loadFacts(*facts, nil, os.Getenv); err != nil {
		return fail(verbs.CodeFailed, 1, err)
	}
	if o.ProxyBase == "" {
		if d, err := os.UserConfigDir(); err == nil {
			o.ProxyBase = filepath.Join(d, "locklog", "proxy")
		}
	}
	// The proxy's token goes to the human's terminal only.
	if interactive && isTerminal(stdin) && term.IsTerminal(int(os.Stderr.Fd())) {
		if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
			defer tty.Close()
			o.TTY = tty
		}
	}
	res, err := setup.AddProfile(o)
	switch {
	case errors.Is(err, setup.ErrExists):
		return fail(verbs.CodeExists, 1, fmt.Errorf("profile %s (or one of its side profiles) is already in the project's config: nothing written", res.Profile))
	case errors.Is(err, setup.ErrUsage):
		return fail(verbs.CodeUsage, 2, errors.New(strings.TrimPrefix(err.Error(), setup.ErrUsage.Error()+": ")))
	case err != nil:
		return fail(verbs.CodeFailed, 1, err)
	}
	if asJSON {
		if err := verbs.WriteJSON(stdout, verbs.Profile{Lock: product.P.Name, Profile: res.Profile, Config: res.Config,
			Production: res.Production, Credentials: res.Credentials}); err != nil {
			return 1
		}
	}
	return 0
}

// isTerminal reports whether r is a terminal.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
