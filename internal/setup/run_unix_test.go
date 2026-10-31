//go:build unix

package setup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/agentassets"
	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

func hostFacts() hostfacts.Facts {
	return hostfacts.Facts{
		Logs:     []string{"/var/log/syslog", "/var/log/syslog.1.gz"},
		Journals: []string{"/var/log/journal"},
		Agents:   []string{"claude"},
		Containers: []hostfacts.Container{
			{Name: "shop-loki-1", Image: "grafana/loki:3.5.7", Service: "loki", Project: "shop", Networks: []string{"shop_default"}},
		},
	}
}

// project is a fresh project directory (0755, the test's) with HOME
// pointed at an empty directory: nothing may be written there.
func project(t *testing.T) (root, home string) {
	t.Helper()
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	os.Chmod(base, 0o700) // t.TempDir follows the umask
	root, home = filepath.Join(base, "project"), filepath.Join(base, "home")
	for _, d := range []string{root, home} {
		if err := os.Mkdir(d, 0o755); err != nil || os.Chmod(d, 0o755) != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return root, home
}

func boolp(b bool) *bool { return &b }

// --yes --no-production --agent host: a non-production profile, the trusted
// .locklog/ and its config, and the Claude Code wiring at project scope
// (the allow list in .claude/settings.local.json, nothing at user scope).
func TestRunHostScripted(t *testing.T) {
	root, home := project(t)
	var out bytes.Buffer
	res, err := Run(Options{Root: root, Facts: hostFacts(), Production: boolp(false), Yes: true, Agent: AgentHost, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Production || res.Profile != "staging" || res.Agent != AgentHost || !res.ConfigWritten || res.Proxy != nil {
		t.Errorf("result = %+v", res)
	}
	st, err := os.Lstat(filepath.Join(root, ".locklog"))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
		t.Fatalf(".locklog: %v %v", st, err)
	}
	cst, err := os.Lstat(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil || cst.Mode().Perm() != 0o644 {
		t.Fatalf("config.toml: %v %v", cst, err)
	}
	ps, err := config.LoadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil || ps["staging"].Production || len(ps["staging"].Sources) != 2 || len(ps["staging-docker"].Sources) != 1 {
		t.Errorf("config = %+v, %v", ps, err)
	}
	var s struct {
		Permissions struct{ Allow []string } `json:"permissions"`
	}
	b, err := os.ReadFile(filepath.Join(root, ".claude", "settings.local.json"))
	if err != nil || json.Unmarshal(b, &s) != nil || strings.Join(s.Permissions.Allow, ",") != strings.Join(agentassets.ClaudeAllow(), ",") {
		t.Errorf("settings.local.json = %s (%v)", b, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".claude", "settings.json")); err == nil {
		t.Error("the shared settings.json was written")
	}
	if es, _ := os.ReadDir(home); len(es) != 0 {
		t.Errorf("setup wrote at user scope: %v", es)
	}
	for _, want := range []string{"created .locklog/config.toml: profile staging (non-production), 1 log file families, the journal, 1 containers in staging-docker\n",
		"claude (project scope):\ncreated .mcp.json\n", "added to permissions.allow in .claude/settings.local.json: mcp__locklog__locklog_search\n",
		"next: locklog console --profile staging"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "warning: a host agent is refused") {
		t.Error("non-production warned about the host agent")
	}

	// A second run keeps the config (the human's now).
	out.Reset()
	res, err = Run(Options{Root: root, Facts: hostFacts(), Production: boolp(false), Yes: true, Agent: AgentHost, Out: &out})
	if err != nil || res.ConfigWritten || !strings.Contains(out.String(), "kept .locklog/config.toml (yours)") {
		t.Errorf("re-run: %+v %v\n%s", res, err, out.String())
	}
}

// Unanswered questions: production is yes, the profile is prod, and the
// agent goes to a container of its own (a host agent is refused there).
func TestRunDefaults(t *testing.T) {
	for _, in := range []string{"", "\n\n\n", "maybe\nwhat\n"} {
		root, _ := project(t)
		var out bytes.Buffer
		res, err := Run(Options{Root: root, Facts: hostFacts(), In: strings.NewReader(in), Out: &out, Recipe: RecipeOptions{Image: digestRef}})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Production || res.Profile != "prod" || res.Agent != AgentContainer || res.Proxy != nil {
			t.Errorf("in %q: result = %+v", in, res)
		}
		for _, q := range []string{"Is this a production profile (real people's data in the logs)? [Y/n] ", "[container] ", "generate an authenticating proxy for it? [y/N] ", "COPY --from=" + digestRef} {
			if !strings.Contains(out.String(), q) {
				t.Errorf("in %q: output lacks %q", in, q)
			}
		}
		if _, err := os.Lstat(filepath.Join(root, ".mcp.json")); err == nil {
			t.Error("the container placement wired the host agent")
		}
	}
	// --yes: production too.
	root, _ := project(t)
	res, err := Run(Options{Root: root, Facts: hostFacts(), Yes: true, Out: &bytes.Buffer{}})
	if err != nil || !res.Production || res.Agent != AgentContainer {
		t.Errorf("--yes: %+v %v", res, err)
	}
}

func TestRunAnswers(t *testing.T) {
	root, _ := project(t)
	var out bytes.Buffer
	res, err := Run(Options{Root: root, Facts: hostFacts(), Agents: []string{}, In: strings.NewReader("n\nh\nn\n"), Out: &out})
	if err != nil || res.Production || res.Profile != "staging" || res.Agent != AgentHost {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(out.String(), "no agent found on this host") {
		t.Errorf("output:\n%s", out.String())
	}
	// A production profile with a host agent warns.
	root, _ = project(t)
	out.Reset()
	if _, err := Run(Options{Root: root, Facts: hostFacts(), Production: boolp(true), Yes: true, Agent: AgentHost, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "E_PRODUCTION_HOST_AGENT") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestRunRefuses(t *testing.T) {
	root, _ := project(t)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{Root: root, Yes: true, Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "writable by someone else") {
		t.Errorf("world-writable root: %v", err)
	}
	root, _ = project(t)
	if err := os.Mkdir(filepath.Join(root, ".locklog"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, ".locklog"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{Root: root, Yes: true, Out: &bytes.Buffer{}}); err == nil {
		t.Error("a writable .locklog/ was accepted")
	}
	root, _ = project(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(root, ".locklog")); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{Root: root, Yes: true, Out: &bytes.Buffer{}}); err == nil {
		t.Error("a symlinked .locklog/ was accepted")
	}
	root, _ = project(t)
	if _, err := Run(Options{Root: root, Yes: true, Profile: "y", Production: boolp(true), Out: &bytes.Buffer{}}); err == nil {
		t.Error("production profile named y accepted")
	}
	root, _ = project(t)
	if _, err := Run(Options{Root: root, Yes: true, Agent: "vm", Out: &bytes.Buffer{}}); err == nil {
		t.Error("unknown placement accepted")
	}
	// The proxy needs a terminal for its token.
	root, home := project(t)
	if _, err := Run(Options{Root: root, Facts: hostFacts(), Yes: true, LokiProxy: "loki", ProxyBase: filepath.Join(home, "proxy"), Out: &bytes.Buffer{}}); err == nil ||
		!strings.Contains(err.Error(), "needs a terminal") {
		t.Errorf("proxy without a terminal: %v", err)
	}
}

// R6-S1: the Compose Loki's proxy. Caddy gets a bcrypt hash only, the
// token goes to the terminal only, the CA key is never on disk, the files
// are outside the project in a 0700 directory: nothing secret is under
// the project, and nothing secret reaches setup's output.
func TestRunLokiProxyLeak(t *testing.T) {
	// authproxy checks every ancestor of the proxy's directory, from /: the
	// sticky /tmp of t.TempDir would be refused. The first of the checkout
	// and the home directory whose ancestors pass is used instead.
	tmp, err := os.MkdirTemp(safeBase(t), ".locklog-leak-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
		t.Fatal(err)
	}
	root, home := filepath.Join(tmp, "project"), filepath.Join(tmp, "home")
	for _, d := range []string{root, home} {
		if err := os.Mkdir(d, 0o755); err != nil || os.Chmod(d, 0o755) != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	base := filepath.Join(home, ".config", "locklog", "proxy")
	var out, tty bytes.Buffer
	res, err := Run(Options{Root: root, Facts: hostFacts(), Production: boolp(true), Yes: true, Agent: AgentContainer,
		LokiProxy: "loki", LokiSelector: "app=shop", ProxyBase: base, Out: &out, TTY: &tty, Recipe: RecipeOptions{Image: digestRef}})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Proxy
	if r == nil || len(r.Token) < 40 {
		t.Fatalf("proxy = %+v", r)
	}
	if !strings.Contains(tty.String(), r.Token) || strings.Contains(out.String(), r.Token) {
		t.Errorf("the token must go to the terminal only:\nout %s\ntty %s", out.String(), tty.String())
	}
	dir := filepath.Dir(r.Caddyfile)
	st, err := os.Lstat(dir)
	if err != nil || st.Mode().Perm() != 0o700 || strings.HasPrefix(dir, root+"/") {
		t.Fatalf("proxy dir %s: %v %v", dir, st, err)
	}
	caddy, _ := os.ReadFile(r.Caddyfile)
	serverKey, _ := os.ReadFile(r.ServerKey)
	if strings.Contains(string(caddy), r.Token) || !strings.Contains(string(caddy), "$2a$") {
		t.Error("the Caddyfile holds the token, or no bcrypt hash")
	}
	hash := ""
	for _, f := range strings.Fields(string(caddy)) {
		if strings.HasPrefix(f, "$2a$") {
			hash = f
		}
	}
	// No CA key on disk: the files are these four, and the only private
	// key is the server's, which is not the CA's.
	names := map[string]bool{}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		names[e.Name()] = true
	}
	if len(names) != 4 || !names["Caddyfile"] || !names["server.crt"] || !names["server.key"] || !names["ca.crt"] {
		t.Errorf("proxy files = %v", names)
	}
	caPEM, _ := os.ReadFile(r.CACert)
	cb, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(serverKey)
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ca.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("the server key is the CA's key")
	}

	// Walk the project: no token, hash, key, or private-key block anywhere.
	secrets := map[string][]byte{"token": []byte(r.Token), "hash": []byte(hash), "server key": serverKey,
		"key bytes": kb.Bytes, "private key block": []byte("PRIVATE KEY")}
	n := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for what, s := range secrets {
			if len(s) > 0 && bytes.Contains(b, s) {
				t.Errorf("%s holds the %s", p, what)
			}
		}
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("walk: %d files, %v", n, err)
	}
	for what, s := range secrets {
		if bytes.Contains(out.Bytes(), s) {
			t.Errorf("setup's output holds the %s", what)
		}
	}

	// The config points at the CA certificate copied beside it (the console
	// reads only .locklog/ of the project), with the console asking.
	ps, err := config.LoadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := ps["prod-loki"].Source("loki")
	if !ok || s.Remote.Credentials != "ask" || s.Remote.URL != r.URL || !strings.HasPrefix(s.Remote.TLSCA, root+"/.locklog/") {
		t.Fatalf("loki source = %+v", s)
	}
	if got, _ := os.ReadFile(s.Remote.TLSCA); !bytes.Equal(got, caPEM) {
		t.Error("tls_ca is not the CA certificate")
	}
	if !strings.Contains(out.String(), "LOCKLOG_NETWORK=shop_default") || !strings.Contains(out.String(), "image: caddy") {
		t.Errorf("output:\n%s", out.String())
	}
	// A second proxy for the same service is refused (the directory is
	// not empty), before anything is written.
	if _, err := Run(Options{Root: root, Facts: hostFacts(), Yes: true, LokiProxy: "loki", ProxyBase: base, Out: &bytes.Buffer{}, TTY: &bytes.Buffer{}}); err == nil {
		t.Error("a second proxy run over an existing config was accepted")
	}
}

// Your home directory is never a project, even of yours.
func TestRunRefusesHome(t *testing.T) {
	root, _ := project(t)
	if _, err := Run(Options{Root: root, Home: root, Yes: true, Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("home as the project: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".locklog")); err == nil {
		t.Error(".locklog/ was created in the home directory")
	}
	sub := filepath.Join(root, "proj")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{Root: sub, Home: root, Yes: true, Out: &bytes.Buffer{}}); err != nil {
		t.Errorf("a project under home: %v", err)
	}
}

// safeBase is a directory whose every ancestor authproxy accepts: a real
// directory, owned by root or this user, writable by no one else.
func safeBase(t *testing.T) string {
	t.Helper()
	var cands []string
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, wd)
	}
	if h, err := os.UserHomeDir(); err == nil {
		cands = append(cands, h)
	}
	for _, c := range cands {
		r, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		ok := true
		for p := r; ok; p = filepath.Dir(p) {
			st, err := os.Lstat(p)
			if err != nil {
				ok = false
				break
			}
			s, isUnix := st.Sys().(*syscall.Stat_t)
			ok = st.IsDir() && isUnix && (s.Uid == 0 || int(s.Uid) == os.Geteuid()) && st.Mode().Perm()&0o022 == 0
			if p == "/" {
				break
			}
		}
		if ok {
			return r
		}
	}
	t.Skipf("no directory among %v whose ancestors are all yours or root's and writable by no one else", cands)
	return ""
}
