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

	"github.com/DavidGodefroid/locklog/internal/agentassets"
	"github.com/DavidGodefroid/locklog/internal/authproxy"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// Agent placements.
const (
	AgentHost      = "host"
	AgentContainer = "container"
	AgentLea       = "lea"
)

// Options of one setup run.
type Options struct {
	// Root is the project directory (absolute): .locklog/ is created in it.
	Root string
	// Home is the user's home directory, never a project ("" unknown).
	Home string
	// Facts are the host's.
	Facts hostfacts.Facts
	// Production is the answer when set; nil asks (an unanswered question
	// is yes).
	Production *bool
	// Yes takes the default answer of every other question.
	Yes bool
	// Agent is the placement ("" asks; unanswered: container for a
	// production profile, host otherwise).
	Agent string
	// Agents overrides the detected agents (host placement).
	Agents []string
	// Only limits detection to the log files under these directories: no
	// journal, no container (scripted runs that know their logs).
	Only []string
	// Profile is the main profile's name ("" : prod or staging).
	Profile string
	// LokiProxy is the Compose Loki service (or container) to put behind
	// the authenticating proxy; "" asks when one is detected (and Yes
	// skips it).
	LokiProxy string
	// LokiSelector is the Loki source's "label=value" matcher.
	LokiSelector string
	// ProxyBase is the directory, outside the project, that holds the
	// proxies' directories (created 0700).
	ProxyBase string
	// VaultPath stores the proxy's token in Vault (credentials = "vault");
	// empty: the console asks for it.
	VaultPath string
	// Recipe is the own-container recipe's image and agent uid.
	Recipe RecipeOptions
	// In holds the answers; Out is what setup prints. TTY is the human's
	// terminal, the only place the proxy's token is shown (nil: no
	// terminal, and no proxy is generated).
	In  io.Reader
	Out io.Writer
	TTY io.Writer
}

var (
	selectorRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}=[A-Za-z0-9_.:/@-]{1,256}$`)
	serviceRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]{0,61}[a-z0-9])?$`)
)

// Result is what a setup run did, for its tests.
type Result struct {
	Profile    string
	Production bool
	Agent      string
	// ConfigWritten is false when a config was already there (kept).
	ConfigWritten bool
	// Proxy is the generated proxy (its Token is shown on TTY only).
	Proxy *authproxy.Result
}

// Run is `locklog setup`.
func Run(o Options) (Result, error) {
	var res Result
	in := bufio.NewReader(o.In)
	if o.In == nil {
		in = bufio.NewReader(strings.NewReader(""))
	}
	out := o.Out
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) != o.Root {
		return res, errors.New("setup: the project root must be an absolute, clean path")
	}
	if o.Home != "" && sameDir(o.Root, o.Home) {
		return res, errors.New("setup: run it in a project directory, not in your home directory (a ~/.locklog/ would choose the logs of every directory below it)")
	}
	if err := checkRoot(o.Root); err != nil {
		return res, err
	}
	llDir := filepath.Join(o.Root, product.P.ProjectDir())
	cfgPath := kconfig.ProjectConfigPath(product.P, o.Root)
	existing, err := checkLocklogDir(llDir, cfgPath)
	if err != nil {
		return res, err
	}

	// The production question: unanswered is yes.
	if o.Production != nil {
		res.Production = *o.Production
	} else if o.Yes {
		res.Production = true
	} else {
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
		return res, fmt.Errorf("setup: %w", err)
	}

	res.Agent = o.Agent
	if res.Agent == "" {
		def := AgentHost
		if res.Production {
			// A host agent is refused on production: the trial placement.
			def = AgentContainer
		}
		res.Agent = def
		if !o.Yes {
			res.Agent = choose(in, out, fmt.Sprintf("Where does the agent run: host, container (an image of its own) or lea? [%s] ", def), def,
				[]string{AgentHost, AgentContainer, AgentLea})
		}
	}
	switch res.Agent {
	case AgentHost, AgentContainer, AgentLea:
	default:
		return res, fmt.Errorf("setup: unknown agent placement %q (want host, container or lea)", res.Agent)
	}

	facts := o.Facts
	if len(o.Only) > 0 {
		facts = OnlyUnder(facts, o.Only)
	}
	det := Detect(facts)
	plan := Plan{Profile: res.Profile, Production: res.Production, Detected: det}

	// The Compose Loki's proxy.
	target := o.LokiProxy
	if target == "" && !o.Yes && !existing && len(det.Lokis) > 0 {
		l := det.Lokis[0]
		if ask(in, out, fmt.Sprintf("Loki %s runs in Compose project %s: generate an authenticating proxy for it? [y/N] ", l.Service, l.Project), false) {
			target = l.Service
		}
	}
	if target != "" {
		if existing {
			return res, errors.New("setup: .locklog/config.toml exists: add the proxy's source to it by hand, or move it away and run setup again")
		}
		lp, r, err := proxy(o, det, target, res.Profile)
		if err != nil {
			return res, err
		}
		plan.LokiProxy = lp
		res.Proxy = &r
		fmt.Fprintf(o.TTY, "\nThe Loki read token (shown once, here only; it is written nowhere):\n\n  %s\n\n", r.Token)
		if o.VaultPath != "" {
			fmt.Fprintf(o.TTY, "Store it in Vault before the console starts: vault kv put %s password=<the token>\n", o.VaultPath)
		} else {
			fmt.Fprintln(o.TTY, "The console asks for it when it starts (credentials = \"ask\"): keep it where you keep secrets.")
		}
	}

	if existing {
		fmt.Fprintf(out, "kept %s (yours): setup writes it only once; edit it, and the console reviews every loosening\n", rel(o.Root, cfgPath))
	} else {
		data, err := Render(plan)
		if err != nil {
			return res, err
		}
		if err := writeConfig(llDir, cfgPath, data); err != nil {
			return res, err
		}
		res.ConfigWritten = true
		fmt.Fprintf(out, "created %s: %s\n", rel(o.Root, cfgPath), summary(plan))
	}
	if r := res.Proxy; r != nil {
		fmt.Fprintf(out, "created the Loki proxy in %s (0700, outside the project): Caddyfile (a bcrypt hash of the token only), server.crt, server.key, ca.crt; the CA's private key was discarded\n", filepath.Dir(r.Caddyfile))
		fmt.Fprintf(out, "add this service to the Compose project of %s:\n\n%s\n", target, r.Compose)
		net := plan.LokiProxy.Network
		if net == "" {
			net = "<the Compose network>"
		}
		fmt.Fprintf(out, "the console reaches it on the Compose network, which no agent joins: LOCKLOG_NETWORK=%s locklog console --profile %s\n", net, LokiProfile(res.Profile))
		if plan.LokiProxy.Selector == "" {
			fmt.Fprintf(out, "its source in %s is commented out until it names the streams to serve (selector = { app = \"api\" })\n", rel(o.Root, cfgPath))
		}
	}

	switch res.Agent {
	case AgentHost:
		agents := o.Agents
		if agents == nil {
			agents = o.Facts.Agents
		}
		if len(agents) == 0 {
			fmt.Fprintln(out, "no agent found on this host (claude, codex, cursor, gemini): wire one with locklog init <agent>")
		}
		for _, a := range agents {
			r, err := agentassets.InitProject(o.Root, a)
			if err != nil {
				return res, fmt.Errorf("setup: wiring %s: %w", a, err)
			}
			fmt.Fprintf(out, "\n%s (project scope):\n", a)
			agentassets.Report(out, r)
		}
		if res.Production {
			fmt.Fprintln(out, "\nwarning: a host agent is refused on a production profile (E_PRODUCTION_HOST_AGENT): run it in a container of its own (locklog setup --agent container) or with lea")
		}
	case AgentContainer:
		fmt.Fprintln(out)
		ro := o.Recipe
		ro.Profile = res.Profile
		ContainerRecipe(out, ro)
	case AgentLea:
		fmt.Fprintln(out)
		LeaRecipe(out)
	}
	fmt.Fprintf(out, "\nnext: locklog console --profile %s (it shows the profile before any log is read)\n", res.Profile)
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
		return nil, authproxy.Result{}, fmt.Errorf("setup: no running Compose Loki named %q", target)
	}
	if o.TTY == nil {
		return nil, authproxy.Result{}, errors.New("setup: the Loki proxy needs a terminal: its token is shown once, to you, and written nowhere")
	}
	if o.LokiSelector != "" && !selectorRe.MatchString(o.LokiSelector) {
		return nil, authproxy.Result{}, errors.New("setup: --loki-selector: want label=value")
	}
	if !serviceRe.MatchString(l.Service) {
		return nil, authproxy.Result{}, fmt.Errorf("setup: the Compose service name %q cannot name the proxy", l.Service)
	}
	if o.ProxyBase == "" || !filepath.IsAbs(o.ProxyBase) {
		return nil, authproxy.Result{}, errors.New("setup: no directory for the proxy's files outside the project")
	}
	if err := os.MkdirAll(o.ProxyBase, 0o700); err != nil {
		return nil, authproxy.Result{}, fmt.Errorf("setup: %w", err)
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
		return nil, r, fmt.Errorf("setup: %w", err)
	}
	// The CA certificate (public) is copied beside the config: the console
	// reads it in its container, where only .locklog/ of the project is
	// mounted. The token, the hash and the server key stay outside.
	ca, err := os.ReadFile(r.CACert)
	if err != nil {
		return nil, r, fmt.Errorf("setup: %w", err)
	}
	llDir := filepath.Join(o.Root, product.P.ProjectDir())
	if err := os.MkdirAll(llDir, 0o755); err != nil {
		return nil, r, fmt.Errorf("setup: %w", err)
	}
	caPath := filepath.Join(llDir, host+"-ca.crt")
	if err := writeExcl(caPath, ca, 0o644); err != nil {
		return nil, r, err
	}
	creds := kconfig.CredentialsAsk
	if o.VaultPath != "" {
		creds = kconfig.CredentialsVault
	}
	network := ""
	if len(l.Networks) > 0 {
		network = l.Networks[0]
	}
	return &LokiSource{URL: r.URL, User: "locklog", CACert: caPath, Credentials: creds, VaultPath: o.VaultPath,
		Selector: o.LokiSelector, Network: network}, r, nil
}

// checkRoot refuses a project directory someone else could write: they
// could replace the .locklog/ setup creates.
func checkRoot(root string) error {
	st, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("setup: %s is not a directory", root)
	}
	if root == "/" {
		return errors.New("setup: run it from a project directory, not from /")
	}
	if st.Mode().Perm()&0o022 != 0 || st.Mode()&fs.ModeSticky != 0 || !ownedByMe(st) {
		return fmt.Errorf("setup: %s is writable by someone else than you, or not yours: run setup in a project directory of your own", root)
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
		return false, fmt.Errorf("setup: %w", err)
	}
	if !st.IsDir() || st.Mode().Perm()&0o022 != 0 || !ownedByMe(st) {
		return false, fmt.Errorf("setup: %s is a link, not a directory, not yours, or writable by others: remove it and run setup again", dir)
	}
	cst, err := os.Lstat(cfg)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("setup: %w", err)
	}
	if !cst.Mode().IsRegular() || cst.Mode().Perm()&0o022 != 0 || !ownedByMe(cst) {
		return false, fmt.Errorf("setup: %s is a link, not a file, not yours, or writable by others", cfg)
	}
	return true, nil
}

// writeConfig creates .locklog/ (0755) and its config.toml (0644), never
// over an existing file.
func writeConfig(dir, cfg string, data []byte) error {
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("setup: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	return writeExcl(cfg, data, 0o644)
}

// writeExcl creates path with data, never over an existing file or link.
func writeExcl(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
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
		return fmt.Errorf("setup: %w", err)
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

// choose asks for one of opts; an empty, missing or unknown answer is def.
func choose(in *bufio.Reader, out io.Writer, q, def string, opts []string) string {
	fmt.Fprint(out, q)
	line, err := in.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	if err != nil && a == "" {
		fmt.Fprintln(out)
	}
	for _, o := range opts {
		if a == o || (a != "" && strings.HasPrefix(o, a)) {
			return o
		}
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
