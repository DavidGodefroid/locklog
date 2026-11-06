package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/authproxy"
	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// ErrExists refuses a profile already in the project's config: nothing
// is written (lockkit's verbs code "exists").
var ErrExists = errors.New("the profile is already in the project's config")

// ErrNoSource refuses a profile with no log file or journal found: nothing
// is written.
var ErrNoSource = errors.New("no log file or journal found here (under /var/log and LOCKLOG_EXTRA_ROOTS, or the --only directories): nothing written; name the directories with --only, or write the profile's sources by hand (docs/usage.md)")

// ErrUsage is an option the run cannot take (verbs code "usage").
var ErrUsage = errors.New("usage")

// Options of one `locklog profile add` run.
type Options struct {
	// Root is the project directory (absolute): .locklog/ is created in it.
	Root string
	// Home is the user's home directory, never a project ("" unknown).
	Home string
	// Facts are the host's.
	Facts hostfacts.Facts
	// Production is --production; ProductionSet says it was given.
	Production, ProductionSet bool
	// Ask asks, on In, what the options did not give (the interactive
	// form): whether the profile is production, and the proxy of a
	// detected Compose Loki. Without it nothing is asked.
	Ask bool
	// Only limits detection to the log files under these directories: no
	// journal, no container (scripted runs that know their logs).
	Only []string
	// Profile is the main profile's name ("" : prod or staging).
	Profile string
	// LokiProxy is the Compose Loki service (or container) to put behind
	// the authenticating proxy (interactive only: its token is shown on
	// TTY); "" asks when one is detected (with Ask).
	LokiProxy string
	// LokiSelector is the Loki source's "label=value" matcher.
	LokiSelector string
	// ProxyBase is the directory, outside the project, that holds the
	// proxies' directories (created 0700).
	ProxyBase string
	// Credentials is the proxied Loki source's: "ask" (the console asks at
	// start) or "vault" (with VaultPath; the console asks the Vault token
	// at start).
	Credentials, VaultPath string
	// In holds the answers; Out is what the run prints (a human's text).
	// TTY is the human's terminal, the only place the proxy's token is
	// shown (nil: no terminal, and no proxy is generated).
	In  io.Reader
	Out io.Writer
	TTY io.Writer
}

var (
	selectorRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}=[A-Za-z0-9_.:/@-]{1,256}$`)
	serviceRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?$`)
)

// Result is what a run did.
type Result struct {
	Profile    string
	Production bool
	// Config is the config file written (created, or the profiles
	// appended to it).
	Config string
	// Created: the config file did not exist before.
	Created bool
	// Profiles are the profiles written: Profile, and its side profiles
	// (Profile-docker for the containers, Profile-loki for a proxied
	// Loki).
	Profiles []string
	// Credentials is the proxied Loki's ("ask" or "vault"); empty when no
	// profile written has a secret.
	Credentials string
	// Proxy is the generated proxy (its Token is shown on TTY only).
	Proxy *authproxy.Result
}

// AddProfile is `locklog profile add`: the profile (and its side
// profiles) from the host's logs, written to the trusted .locklog/ of the
// project: the file is created, or the profiles appended to it. A profile
// already there is never rewritten (ErrExists, nothing written). It never
// takes, asks for or writes a secret: a remote source's is asked by the
// console at start, or read from Vault.
func AddProfile(o Options) (Result, error) {
	var res Result
	in := bufio.NewReader(o.In)
	if o.In == nil {
		in = bufio.NewReader(strings.NewReader(""))
	}
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) != o.Root {
		return res, errors.New("profile add: the project root must be an absolute, clean path")
	}
	if o.Home != "" && sameDir(o.Root, o.Home) {
		return res, errors.New("profile add: run it in a project directory, not in your home directory (a ~/.locklog/ would choose the logs of every directory below it)")
	}
	if err := checkRoot(o.Root); err != nil {
		return res, err
	}
	llDir := filepath.Join(o.Root, product.P.ProjectDir())
	cfgPath := kconfig.ProjectConfigPath(product.P, o.Root)
	res.Config = cfgPath
	existing, err := checkLocklogDir(llDir, cfgPath)
	if err != nil {
		return res, err
	}
	var have map[string]config.Profile
	var old []byte
	if existing {
		if old, err = os.ReadFile(cfgPath); err != nil {
			return res, fmt.Errorf("profile add: %w", err)
		}
		if have, err = config.ParseProfiles(old, cfgPath); err != nil {
			return res, fmt.Errorf("profile add: the project's config does not load: %w", err)
		}
	}

	// The production question: unanswered is yes.
	switch {
	case o.ProductionSet:
		res.Production = o.Production
	case o.Ask:
		res.Production = ask(in, out, "Is this a production profile (real people's data in the logs)? [Y/n] ", true)
	}
	res.Profile = o.Profile
	if res.Profile == "" {
		res.Profile = "staging"
		if res.Production {
			res.Profile = "prod"
		}
	}
	if err := kconfig.CheckProfileName(res.Profile, res.Production); err != nil {
		return res, fmt.Errorf("%w: --profile: %w", ErrUsage, err)
	}
	if _, ok := have[res.Profile]; ok {
		return res, ErrExists
	}

	facts := o.Facts
	if len(o.Only) > 0 {
		facts = OnlyUnder(facts, o.Only)
	}
	det := Detect(facts)
	if len(det.Files) == 0 && !det.Journald {
		// The profile would have no source: nothing is written, and the
		// caller (lox add) is told so rather than handed a profile that
		// is not in the file.
		return res, ErrNoSource
	}
	plan := Plan{Profile: res.Profile, Production: res.Production, Detected: det}

	// The Compose Loki's proxy.
	target := o.LokiProxy
	if target == "" && o.Ask && len(det.Lokis) > 0 {
		l := det.Lokis[0]
		if ask(in, out, fmt.Sprintf("Loki %s runs in Compose project %s: generate an authenticating proxy for it? [y/N] ", l.Service, l.Project), false) {
			target = l.Service
		}
	}
	for _, n := range plan.Names(target != "") {
		if _, ok := have[n]; ok {
			return res, ErrExists
		}
	}
	if target != "" {
		lp, r, err := proxy(o, det, target, res.Profile)
		if err != nil {
			return res, err
		}
		plan.LokiProxy = lp
		res.Proxy = &r
		res.Credentials = lp.Credentials
		fmt.Fprintf(o.TTY, "\nThe Loki read token (shown once, here only; it is written nowhere):\n\n  %s\n\n", r.Token)
		if lp.Credentials == kconfig.CredentialsVault {
			fmt.Fprintf(o.TTY, "Store it in Vault before the console starts: vault kv put %s password=<the token>\n", o.VaultPath)
		} else {
			fmt.Fprintln(o.TTY, "The console asks for it when it starts (credentials = \"ask\"): keep it where you keep secrets.")
		}
	}
	res.Profiles = plan.Names(plan.LokiProxy != nil)

	if existing {
		frag, err := RenderProfiles(plan)
		if err != nil {
			return res, err
		}
		data := append(append(old, '\n'), frag...)
		if _, err := config.ParseProfiles(data, cfgPath); err != nil {
			return res, fmt.Errorf("profile add: the config with the new profile would not load: %w", err)
		}
		if err := replaceConfig(llDir, cfgPath, data); err != nil {
			return res, err
		}
		fmt.Fprintf(out, "added to %s: %s\n", rel(o.Root, cfgPath), summary(plan))
	} else {
		data, err := Render(plan)
		if err != nil {
			return res, err
		}
		if err := writeConfig(llDir, cfgPath, data); err != nil {
			return res, err
		}
		res.Created = true
		fmt.Fprintf(out, "created %s: %s\n", rel(o.Root, cfgPath), summary(plan))
	}
	if r := res.Proxy; r != nil {
		fmt.Fprintf(out, "created the Loki proxy in %s (0700, outside the project): Caddyfile (a bcrypt hash of the token only), server.crt, server.key, ca.crt; the CA's private key was discarded\n", filepath.Dir(r.Caddyfile))
		fmt.Fprintf(out, "add this service to the Compose project of %s:\n\n%s\n", target, r.Compose)
		if plan.LokiProxy.Network != "" {
			fmt.Fprintf(out, "the console reaches it on the Compose network %s, which no agent joins (lox run: the lock's network)\n", plan.LokiProxy.Network)
		}
		if plan.LokiProxy.Selector == "" {
			fmt.Fprintf(out, "its source in %s is commented out until it names the streams to serve (selector = { app = \"api\" })\n", rel(o.Root, cfgPath))
		}
	}
	fmt.Fprintf(out, "\nnext: lox add locklog <name> serving profile %s, then lox run (it shows the profile before any log is read)\n", res.Profile)
	return res, nil
}

// proxy generates the authenticating proxy of a Compose Loki (target: its
// service or container name) and returns the source of the profile.
func proxy(o Options, det Detected, target, profile string) (*LokiSource, authproxy.Result, error) {
	var l *Loki
	for i := range det.Lokis {
		if det.Lokis[i].Service == target || det.Lokis[i].Container == target {
			l = &det.Lokis[i]
		}
	}
	if l == nil {
		return nil, authproxy.Result{}, errors.New("profile add: --loki-proxy: no running Compose Loki of that name")
	}
	if o.TTY == nil {
		return nil, authproxy.Result{}, fmt.Errorf("%w: --loki-proxy needs a terminal: its token is shown once, to you, and written nowhere", ErrUsage)
	}
	if o.LokiSelector != "" && !selectorRe.MatchString(o.LokiSelector) {
		return nil, authproxy.Result{}, fmt.Errorf("%w: --loki-selector: want label=value", ErrUsage)
	}
	if !serviceRe.MatchString(l.Service) {
		return nil, authproxy.Result{}, fmt.Errorf("profile add: the Compose service name %q cannot name the proxy", l.Service)
	}
	if o.ProxyBase == "" || !filepath.IsAbs(o.ProxyBase) {
		return nil, authproxy.Result{}, errors.New("profile add: no directory for the proxy's files outside the project")
	}
	if err := os.MkdirAll(o.ProxyBase, 0o700); err != nil {
		return nil, authproxy.Result{}, fmt.Errorf("profile add: %w", err)
	}
	host := "locklog-" + strings.ReplaceAll(strings.ReplaceAll(l.Service, "_", "-"), ".", "-") + "-proxy"
	if len(host) > 63 {
		host = strings.TrimRight(host[:63], "-")
	}
	dir := filepath.Join(o.ProxyBase, l.Project+"-"+l.Service)
	r, err := authproxy.Generate(authproxy.Options{
		Dir: dir, Project: o.Root, Host: host, Upstream: l.Service + ":3100",
	})
	if err != nil {
		return nil, r, fmt.Errorf("profile add: %w", err)
	}
	// The CA certificate (public) is copied beside the config: the console
	// reads it in its container, where only .locklog/ of the project is
	// mounted. The token, the hash and the server key stay outside.
	ca, err := os.ReadFile(r.CACert)
	if err != nil {
		return nil, r, fmt.Errorf("profile add: %w", err)
	}
	llDir := filepath.Join(o.Root, product.P.ProjectDir())
	if err := os.MkdirAll(llDir, 0o755); err != nil {
		return nil, r, fmt.Errorf("profile add: %w", err)
	}
	caPath := filepath.Join(llDir, host+"-ca.crt")
	if err := writeExcl(caPath, ca, 0o644); err != nil {
		return nil, r, err
	}
	creds := o.Credentials
	if creds == "" {
		creds = kconfig.CredentialsAsk
	}
	network := ""
	if len(l.Networks) > 0 {
		network = l.Networks[0]
	}
	return &LokiSource{URL: r.URL, User: "locklog", CACert: caPath, Credentials: creds, VaultPath: o.VaultPath,
		Selector: o.LokiSelector, Network: network}, r, nil
}

// checkRoot refuses a project directory someone else could write: they
// could replace the .locklog/ profile add creates.
func checkRoot(root string) error {
	st, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("profile add: %s is not a directory", root)
	}
	if root == "/" {
		return errors.New("profile add: run it from a project directory, not from /")
	}
	if st.Mode().Perm()&0o022 != 0 || st.Mode()&fs.ModeSticky != 0 || !ownedByMe(st) {
		return fmt.Errorf("profile add: %s is writable by someone else than you, or not yours: run locklog profile add in a project directory of your own", root)
	}
	return nil
}

// checkLocklogDir accepts a missing .locklog/, or one of yours that no one
// else can write; it reports whether its config.toml exists.
func checkLocklogDir(dir, cfg string) (bool, error) {
	st, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("profile add: %w", err)
	}
	if !st.IsDir() || st.Mode().Perm()&0o022 != 0 || !ownedByMe(st) {
		return false, fmt.Errorf("profile add: %s is a link, not a directory, not yours, or writable by others: remove it and run locklog profile add again", dir)
	}
	cst, err := os.Lstat(cfg)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("profile add: %w", err)
	}
	if !cst.Mode().IsRegular() || cst.Mode().Perm()&0o022 != 0 || !ownedByMe(cst) {
		return false, fmt.Errorf("profile add: %s is a link, not a file, not yours, or writable by others", cfg)
	}
	return true, nil
}

// writeConfig creates .locklog/ (0755) and its config.toml (0644), never
// over an existing file.
func writeConfig(dir, cfg string, data []byte) error {
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("profile add: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	return writeExcl(cfg, data, 0o644)
}

// replaceConfig replaces the config (a trusted file of yours) with data:
// a new file beside it, renamed over it, 0644 as writeConfig makes it.
func replaceConfig(dir, cfg string, data []byte) error {
	f, err := os.CreateTemp(dir, ".config.toml.*")
	if err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o644)
	}
	if err == nil {
		err = os.Rename(tmp, cfg)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("profile add: %w", err)
	}
	return nil
}

// writeExcl creates path with data, never over an existing file or link.
func writeExcl(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(path, mode)
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("profile add: %w", err)
	}
	return nil
}

func rel(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

// summary is the one-line account of a plan.
func summary(p Plan) string {
	d := p.Detected
	kind := "non-production"
	if p.Production {
		kind = "production"
	}
	parts := []string{fmt.Sprintf("profile %s (%s)", p.Profile, kind)}
	parts = append(parts, fmt.Sprintf("%d log file families", len(d.Files)))
	if d.Journald {
		parts = append(parts, "the journal")
	}
	if len(d.Containers) > 0 {
		parts = append(parts, fmt.Sprintf("%d containers in %s", len(d.Containers), DockerProfile(p.Profile)))
	}
	if p.LokiProxy != nil {
		parts = append(parts, "the proxied Loki in "+LokiProfile(p.Profile))
	}
	return strings.Join(parts, ", ")
}

// ask asks a yes/no question; an empty or missing answer is def.
func ask(in *bufio.Reader, out io.Writer, q string, def bool) bool {
	fmt.Fprint(out, q)
	line, err := in.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	if err != nil && a == "" {
		fmt.Fprintln(out)
	}
	switch a {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

// OnlyUnder keeps the log files of f under dirs, and no journal or
// container.
func OnlyUnder(f hostfacts.Facts, dirs []string) hostfacts.Facts {
	var logs []string
	for _, p := range f.Logs {
		for _, d := range dirs {
			d = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(d)), "/")
			if strings.HasPrefix(p, d+"/") {
				logs = append(logs, p)
				break
			}
		}
	}
	f.Logs, f.Journals, f.Containers = logs, nil, nil
	return f
}

// sameDir reports whether a and b name the same directory, by their real
// paths when they resolve.
func sameDir(a, b string) bool {
	if r, err := filepath.EvalSymlinks(a); err == nil {
		a = r
	}
	if r, err := filepath.EvalSymlinks(b); err == nil {
		b = r
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
