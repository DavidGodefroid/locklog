package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
	"github.com/DavidGodefroid/locklog/internal/product"
	"github.com/DavidGodefroid/locklog/internal/setup"
)

const setupUsage = `usage: locklog setup [--yes] [--production|--no-production] [--agent host|container|lea]
                     [--agents claude,codex,...] [--profile P] [--only DIR,...]
                     [--loki-proxy SERVICE [--loki-selector label=value] [--vault-path P]]
                     [--image REF] [--agent-uid UID]`

// releaseRegistry is where the release images are published.
const releaseRegistry = "ghcr.io/davidgodefroid/locklog"

// loadFacts reads the launcher's facts file, or gathers the facts here.
func loadFacts(path string, getenv func(string) string) (hostfacts.Facts, error) {
	if path == "" {
		roots := []string{"/var/log"}
		roots = append(roots, strings.Fields(getenv("LOCKLOG_EXTRA_ROOTS"))...)
		return hostfacts.Gather(hostfacts.Env{LogRoots: roots}), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return hostfacts.Facts{}, err
	}
	defer f.Close()
	return hostfacts.Parse(f)
}

// setupCmd is `locklog setup`: the trusted .locklog/ and its config.toml
// from the host's logs, the production question, and the agent's
// placement (its project wiring, or the own-container recipe).
func setupCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "take the default answers (production: yes)")
	prod := fs.Bool("production", false, "a production profile")
	noProd := fs.Bool("no-production", false, "a non-production profile")
	agent := fs.String("agent", "", "host, container or lea")
	agents := fs.String("agents", "", "the agents to wire (host): default the detected ones")
	profile := fs.String("profile", "", "the main profile's name")
	only := fs.String("only", "", "detect only the log files under these directories (comma-separated; no journal, no container)")
	facts := fs.String("facts", "", "the host's facts (written by the launcher)")
	lokiProxy := fs.String("loki-proxy", "", "the Compose Loki service to put behind an authenticating proxy")
	lokiSel := fs.String("loki-selector", "", "the Loki source's label=value")
	proxyDir := fs.String("proxy-dir", "", "where the proxies' files go, outside the project")
	vaultPath := fs.String("vault-path", "", "keep the proxy's token in Vault at this path")
	image := fs.String("image", "", "the locklog image the own-container recipe copies from")
	agentUID := fs.Int("agent-uid", 0, "the agent user's uid in its own image")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || (*prod && *noProd) {
		fmt.Fprintln(stderr, setupUsage)
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["agent-uid"] && (*agentUID <= 0 || *agentUID == product.ConsoleUID || *agentUID == 65534) {
		fmt.Fprintln(stderr, "locklog setup: --agent-uid: not root, the console account or nobody")
		return 2
	}
	o := setup.Options{Yes: *yes, Agent: *agent, Profile: *profile, LokiProxy: *lokiProxy, LokiSelector: *lokiSel,
		ProxyBase: *proxyDir, VaultPath: *vaultPath, In: stdin, Out: stdout}
	switch {
	case *prod:
		t := true
		o.Production = &t
	case *noProd:
		f := false
		o.Production = &f
	}
	if *only != "" {
		for _, d := range strings.Split(*only, ",") {
			if !filepath.IsAbs(d) {
				fmt.Fprintln(stderr, "locklog setup: --only: want absolute directories")
				return 2
			}
			o.Only = append(o.Only, d)
		}
	}
	if *agents != "" {
		o.Agents = strings.Split(*agents, ",")
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locklog setup:", err)
		return 1
	}
	o.Root = filepath.Clean(cwd)
	if o.Facts, err = loadFacts(*facts, os.Getenv); err != nil {
		fmt.Fprintln(stderr, "locklog setup:", err)
		return 1
	}
	if o.ProxyBase == "" {
		if d, err := os.UserConfigDir(); err == nil {
			o.ProxyBase = filepath.Join(d, "locklog", "proxy")
		}
	}
	o.Recipe = setup.RecipeOptions{Image: *image, AgentUID: *agentUID}
	if o.Recipe.Image == "" {
		o.Recipe.Image = os.Getenv("LOCKLOG_IMAGE_REF")
	}
	if o.Recipe.Image == "" {
		o.Recipe.Image = releaseRegistry + ":" + strings.TrimPrefix(version, "v")
	}
	// The proxy's token goes to the human's terminal only.
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
			defer tty.Close()
			o.TTY = tty
		}
	}
	if _, err := setup.Run(o); err != nil {
		fmt.Fprintln(stderr, "locklog", err)
		return 1
	}
	return 0
}
