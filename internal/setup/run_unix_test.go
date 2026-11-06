//go:build unix

package setup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

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

// --non-interactive: a non-production profile, the trusted .locklog/ and
// its config; nothing wired, nothing at user scope. A second run of the
// same profile is refused (exists) and writes nothing; another profile is
// appended.
func TestAddProfileScripted(t *testing.T) {
	root, home := project(t)
	var out bytes.Buffer
	res, err := AddProfile(Options{Root: root, Facts: hostFacts(), ProductionSet: true, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Production || res.Profile != "staging" || !res.Created || res.Proxy != nil || res.Credentials != "" ||
		strings.Join(res.Profiles, ",") != "staging,staging-docker" || res.Config != filepath.Join(root, ".locklog", "config.toml") {
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
	if _, err := os.Lstat(filepath.Join(root, ".mcp.json")); err == nil {
		t.Error("profile add wired an agent")
	}
	if es, _ := os.ReadDir(home); len(es) != 0 {
		t.Errorf("profile add wrote at user scope: %v", es)
	}
	for _, want := range []string{"created .locklog/config.toml: profile staging (non-production), 1 log file families, the journal, 1 containers in staging-docker\n",
		"next: lox add locklog <name> serving profile staging, then lox run"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	before, _ := os.ReadFile(filepath.Join(root, ".locklog", "config.toml"))

	// The same profile again: exists, nothing written.
	if _, err := AddProfile(Options{Root: root, Facts: hostFacts(), ProductionSet: true, Out: &bytes.Buffer{}}); !errors.Is(err, ErrExists) {
		t.Errorf("re-run: %v", err)
	}
	// A profile whose side profile exists: exists too.
	if _, err := AddProfile(Options{Root: root, Profile: "staging-docker", Facts: hostfacts.Facts{Logs: []string{"/var/log/app.log"}}, ProductionSet: true, Out: &bytes.Buffer{}}); !errors.Is(err, ErrExists) {
		t.Errorf("side profile: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(root, ".locklog", "config.toml")); !bytes.Equal(before, after) {
		t.Error("a refused run changed the config")
	}

	// Another profile is appended; the first is untouched.
	out.Reset()
	res, err = AddProfile(Options{Root: root, Profile: "prod", Production: true, ProductionSet: true, Only: []string{"/var/log"}, Facts: hostFacts(), Out: &out})
	if err != nil || res.Created || !res.Production || strings.Join(res.Profiles, ",") != "prod" {
		t.Fatalf("append: %+v %v", res, err)
	}
	after, _ := os.ReadFile(filepath.Join(root, ".locklog", "config.toml"))
	if !bytes.HasPrefix(after, before) || !strings.Contains(out.String(), "added to .locklog/config.toml: profile prod (production)") {
		t.Errorf("append changed the existing profiles, or says so wrong:\n%s\n%s", after, out.String())
	}
	ps, err = config.LoadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil || !ps["prod"].Production || len(ps["prod"].Sources) != 1 || len(ps["staging"].Sources) != 2 {
		t.Errorf("appended config = %+v, %v", ps, err)
	}
	if cst, err := os.Lstat(filepath.Join(root, ".locklog", "config.toml")); err != nil || cst.Mode().Perm() != 0o644 {
		t.Errorf("config.toml after the append: %v %v", cst, err)
	}
}

// Asked (the interactive form): unanswered, production is yes and the
// profile is prod; a Compose Loki's proxy is offered, and no is the
// default. Not asked: non-production unless --production.
func TestAddProfileAsks(t *testing.T) {
	for _, in := range []string{"", "\n\n\n", "maybe\nwhat\n"} {
		root, _ := project(t)
		var out bytes.Buffer
		res, err := AddProfile(Options{Root: root, Facts: hostFacts(), Ask: true, In: strings.NewReader(in), Out: &out})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Production || res.Profile != "prod" || res.Proxy != nil {
			t.Errorf("in %q: result = %+v", in, res)
		}
		for _, q := range []string{"Is this a production profile (real people's data in the logs)? [Y/n] ", "generate an authenticating proxy for it? [y/N] "} {
			if !strings.Contains(out.String(), q) {
				t.Errorf("in %q: output lacks %q", in, q)
			}
		}
	}
	root, _ := project(t)
	var out bytes.Buffer
	res, err := AddProfile(Options{Root: root, Facts: hostFacts(), Ask: true, In: strings.NewReader("n\nn\n"), Out: &out})
	if err != nil || res.Production || res.Profile != "staging" {
		t.Fatalf("answers: %+v %v", res, err)
	}
	// --production given: not asked.
	root, _ = project(t)
	out.Reset()
	res, err = AddProfile(Options{Root: root, Facts: hostFacts(), Production: true, ProductionSet: true, Out: &out})
	if err != nil || !res.Production || strings.Contains(out.String(), "production profile (") {
		t.Errorf("--production: %+v %v\n%s", res, err, out.String())
	}
}

func TestAddProfileRefuses(t *testing.T) {
	root, _ := project(t)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(Options{Root: root, Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "writable by someone else") {
		t.Errorf("world-writable root: %v", err)
	}
	root, _ = project(t)
	if err := os.Mkdir(filepath.Join(root, ".locklog"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, ".locklog"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(Options{Root: root, Out: &bytes.Buffer{}}); err == nil {
		t.Error("a writable .locklog/ was accepted")
	}
	root, _ = project(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(root, ".locklog")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(Options{Root: root, Out: &bytes.Buffer{}}); err == nil {
		t.Error("a symlinked .locklog/ was accepted")
	}
	root, _ = project(t)
	if _, err := AddProfile(Options{Root: root, Profile: "y", Production: true, ProductionSet: true, Out: &bytes.Buffer{}}); !errors.Is(err, ErrUsage) {
		t.Errorf("production profile named y: %v", err)
	}
	// No log file or journal found: refused, nothing written.
	root, _ = project(t)
	if _, err := AddProfile(Options{Root: root, Facts: hostfacts.Facts{Containers: hostFacts().Containers}, Out: &bytes.Buffer{}}); !errors.Is(err, ErrNoSource) {
		t.Errorf("no source: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".locklog")); err == nil {
		t.Error("a profile with no source wrote .locklog/")
	}
	// A config that does not load is not appended to.
	root, _ = project(t)
	if err := os.Mkdir(filepath.Join(root, ".locklog"), 0o755); err != nil || os.Chmod(filepath.Join(root, ".locklog"), 0o755) != nil {
		t.Fatal(err)
	}
	bad := []byte("version = 1\n[profiles.x]\nnope = 1\n")
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(Options{Root: root, Facts: hostFacts(), Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Errorf("broken config: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, ".locklog", "config.toml")); !bytes.Equal(got, bad) {
		t.Error("the broken config was rewritten")
	}
	// The proxy needs a terminal for its token.
	root, home := project(t)
	if _, err := AddProfile(Options{Root: root, Facts: hostFacts(), LokiProxy: "loki", ProxyBase: filepath.Join(home, "proxy"), Out: &bytes.Buffer{}}); !errors.Is(err, ErrUsage) ||
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
	// and the home directory whose ancestors pass is used instead; a run
	// killed before its cleanup leaves the directory, which .gitignore
	// keeps out of commits.
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
	res, err := AddProfile(Options{Root: root, Facts: hostFacts(), Production: true, ProductionSet: true,
		LokiProxy: "loki", LokiSelector: "app=shop", ProxyBase: base, Out: &out, TTY: &tty})
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
	if res.Credentials != "ask" || !strings.Contains(out.String(), "Compose network shop_default") || !strings.Contains(out.String(), "image: caddy") {
		t.Errorf("output:\n%s", out.String())
	}
	// A second proxy for the same service is refused (the directory is
	// not empty), before anything is written.
	if _, err := AddProfile(Options{Root: root, Profile: "other", Facts: hostFacts(), LokiProxy: "loki", ProxyBase: base, Out: &bytes.Buffer{}, TTY: &bytes.Buffer{}}); err == nil {
		t.Error("a second proxy for the same service was accepted")
	}
}

// Your home directory is never a project, even of yours.
func TestRunRefusesHome(t *testing.T) {
	root, _ := project(t)
	if _, err := AddProfile(Options{Root: root, Home: root, Out: &bytes.Buffer{}}); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("home as the project: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".locklog")); err == nil {
		t.Error(".locklog/ was created in the home directory")
	}
	sub := filepath.Join(root, "proj")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := AddProfile(Options{Root: sub, Home: root, Facts: hostFacts(), Out: &bytes.Buffer{}}); err != nil {
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
	// In CI the leak test must run: a runner where it cannot is a failure,
	// not a skip.
	if os.Getenv("CI") != "" {
		t.Fatalf("no directory among %v whose ancestors are all yours or root's and writable by no one else (CI is set: the leak test must run)", cands)
	}
	t.Skipf("no directory among %v whose ancestors are all yours or root's and writable by no one else", cands)
	return ""
}
