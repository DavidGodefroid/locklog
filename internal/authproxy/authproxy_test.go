//go:build unix

package authproxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func setup(t *testing.T) (Options, string) {
	t.Helper()
	base := t.TempDir()
	os.Chmod(base, 0o700) // t.TempDir follows the umask
	// t.TempDir is under /tmp (sticky, world-writable): its own ancestors
	// are not checked; base (0700, ours) and below are.
	prev := TrustedRoot
	TrustedRoot = base
	t.Cleanup(func() { TrustedRoot = prev })
	project := filepath.Join(base, "project")
	os.MkdirAll(filepath.Join(project, ".locklog"), 0o755)
	return Options{Dir: filepath.Join(base, "state", "loki-proxy"), Project: project, Host: "loki-proxy", Upstream: "loki:3100"}, base
}

// TestTokenNeverOnDisk is the leak-harness case of the round-6 amendment:
// the clear token is in no file anywhere (project or proxy directory, in
// clear, base64 or hex), the proxy holds a bcrypt hash that verifies it,
// and the CA's private key was discarded.
func TestTokenNeverOnDisk(t *testing.T) {
	o, base := setup(t)
	os.MkdirAll(filepath.Dir(o.Dir), 0o700)
	r, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Token) < 40 {
		t.Fatalf("token %d chars", len(r.Token))
	}
	keys := 0
	filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(r.Token)) || bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(r.Token))) {
			t.Errorf("token found in %s", p)
		}
		if strings.HasPrefix(p, o.Project) {
			t.Errorf("file written in the project: %s", p)
		}
		keys += bytes.Count(b, []byte("-----BEGIN")) - bytes.Count(b, []byte("-----BEGIN CERTIFICATE"))
		return nil
	})
	if keys != 1 {
		t.Fatalf("%d private keys on disk, want only the server's", keys)
	}
	if strings.Contains(r.Compose, r.Token) || strings.Contains(r.URL, r.Token) {
		t.Fatal("token in a snippet")
	}
	caddy, _ := os.ReadFile(r.Caddyfile)
	hash := regexp.MustCompile(`\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}`).Find(caddy)
	if hash == nil || bcrypt.CompareHashAndPassword(hash, []byte(r.Token)) != nil {
		t.Fatal("the Caddyfile hash does not verify the token")
	}
	// Modes: directory 0700, secrets 0600.
	fi, _ := os.Stat(o.Dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	for _, p := range []string{r.Caddyfile, r.ServerKey, r.ServerCert} {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", p, fi.Mode().Perm())
		}
	}
	// The server certificate verifies against the CA for the host only,
	// and the CA cannot sign for another name.
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(r.CACert)
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA certificate")
	}
	certPEM, _ := os.ReadFile(r.ServerCert)
	blk, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "loki-proxy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other"}); err == nil {
		t.Fatal("verifies for another name")
	}
	cb, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(cb.Bytes)
	if !ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 || !ca.MaxPathLenZero {
		t.Fatal("the CA is not name-constrained")
	}
	// Nor for any IP address.
	var ex []string
	for _, n := range ca.ExcludedIPRanges {
		ex = append(ex, n.String())
	}
	if strings.Join(ex, ",") != "0.0.0.0/0,::/0" {
		t.Fatalf("excluded IP ranges %v", ex)
	}
	// The snippet pins the image and quotes the paths.
	if !strings.Contains(r.Compose, "image: caddy:2.10.2\n") || !strings.Contains(r.Compose, `- "`+r.Caddyfile+`:/etc/caddy/Caddyfile:ro"`) ||
		!strings.Contains(r.Compose, `- "`+o.Dir+`:/etc/locklog-proxy:ro"`) {
		t.Fatalf("compose snippet:\n%s", r.Compose)
	}
}

func TestRefusesSymlinksIntoTheProject(t *testing.T) {
	for name, mk := range map[string]func(o Options, base string) Options{
		// Dir itself a symlink into the project.
		"dir symlink": func(o Options, base string) Options {
			o.Dir = filepath.Join(base, "dirlink")
			os.Symlink(filepath.Join(o.Project, ".locklog"), o.Dir)
			return o
		},
		// Dir's parent a symlink into the project.
		"parent symlink": func(o Options, base string) Options {
			os.Symlink(filepath.Join(o.Project, ".locklog"), filepath.Join(base, "parentlink"))
			o.Dir = filepath.Join(base, "parentlink", "proxy")
			return o
		},
		// The project given through a symlink, Dir inside its target.
		"project symlink": func(o Options, base string) Options {
			real := o.Project
			o.Project = filepath.Join(base, "projlink")
			os.Symlink(real, o.Project)
			o.Dir = filepath.Join(real, "proxy")
			return o
		},
		// Dir a symlink, even to an empty directory outside the project.
		"dir symlink outside": func(o Options, base string) Options {
			os.MkdirAll(filepath.Join(base, "outside"), 0o700)
			o.Dir = filepath.Join(base, "outlink")
			os.Symlink(filepath.Join(base, "outside"), o.Dir)
			return o
		},
	} {
		o, base := setup(t)
		project := o.Project
		if _, err := Generate(mk(o, base)); err == nil {
			t.Errorf("%s accepted", name)
		}
		filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && d.Type()&fs.ModeSymlink == 0 {
				t.Errorf("%s: %s written", name, strings.TrimPrefix(p, project))
			}
			return nil
		})
	}
	// A plain directory outside the project, existing and empty: fine.
	o, base := setup(t)
	o.Dir = filepath.Join(base, "outside")
	os.MkdirAll(o.Dir, 0o755)
	if _, err := Generate(o); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(o.Dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestRefusesUnsafeAncestors(t *testing.T) {
	// A group-writable ancestor: someone else could swap what is below.
	o, base := setup(t)
	shared := filepath.Join(base, "shared")
	os.MkdirAll(shared, 0o700)
	os.Chmod(shared, 0o770)
	o.Dir = filepath.Join(shared, "proxy")
	if _, err := Generate(o); err == nil || !strings.Contains(err.Error(), "writable by no one else") {
		t.Fatalf("group-writable ancestor: %v", err)
	}
	// A symlinked ancestor, even to a safe directory outside the project.
	o, base = setup(t)
	os.MkdirAll(filepath.Join(base, "real"), 0o700)
	os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link"))
	o.Dir = filepath.Join(base, "link", "proxy")
	if _, err := Generate(o); err == nil {
		t.Fatal("symlinked ancestor accepted")
	}
	if ents, _ := os.ReadDir(filepath.Join(base, "real")); len(ents) != 0 {
		t.Fatal("written through the symlink")
	}
}

func TestSafeAncestorPredicate(t *testing.T) {
	euid := 1000
	for _, tt := range []struct {
		mode, uid uint32
		ok        bool
	}{
		{syscall.S_IFDIR | 0o755, 0, true},
		{syscall.S_IFDIR | 0o700, 1000, true},
		{syscall.S_IFDIR | 0o755, 1001, false}, // another user's
		{syscall.S_IFDIR | 0o775, 1000, false}, // group-writable
		{syscall.S_IFDIR | 0o757, 0, false},    // other-writable
		{syscall.S_IFDIR | 0o1777, 0, false},   // sticky /tmp
		{syscall.S_IFLNK | 0o777, 1000, false}, // a symlink
		{syscall.S_IFREG | 0o644, 1000, false}, // not a directory
	} {
		if got := safeAncestor(tt.mode, tt.uid, euid); got != tt.ok {
			t.Errorf("mode %o uid %d: %t", tt.mode, tt.uid, got)
		}
	}
}

func TestSwapCaught(t *testing.T) {
	// The directory is swapped between its open and the writes: the files
	// go to the directory opened (never the swapped-in path), are removed,
	// and Generate fails.
	o, _ := setup(t)
	os.MkdirAll(filepath.Dir(o.Dir), 0o700)
	moved := o.Dir + ".moved"
	prev := afterOpen
	afterOpen = func() {
		os.Rename(o.Dir, moved)
		os.Mkdir(o.Dir, 0o777)
	}
	t.Cleanup(func() { afterOpen = prev })
	if _, err := Generate(o); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("swap not caught: %v", err)
	}
	for _, d := range []string{o.Dir, moved} {
		if ents, _ := os.ReadDir(d); len(ents) != 0 {
			t.Fatalf("%s holds %d files", d, len(ents))
		}
	}
}

func TestProjectCheckResolvesBothSides(t *testing.T) {
	// As on macOS (/var -> /private/var): the project given by its real
	// path, Dir through a symlinked ancestor that the ancestor walk does
	// not see (above its root). The containment check must still refuse.
	_, base := setup(t)
	real := filepath.Join(base, "real")
	os.MkdirAll(filepath.Join(real, "project"), 0o700)
	alias := filepath.Join(base, "alias")
	os.Symlink(real, alias)
	TrustedRoot = filepath.Join(alias, "project")
	o := Options{Project: filepath.Join(real, "project"), Dir: filepath.Join(alias, "project", "proxy"), Host: "loki-proxy", Upstream: "loki:3100"}
	if _, err := Generate(o); err == nil {
		t.Fatal("a Dir inside the project through a symlink accepted")
	}
	// And the other way round: the project through the alias.
	o = Options{Project: filepath.Join(alias, "project"), Dir: filepath.Join(real, "project", "proxy2"), Host: "loki-proxy", Upstream: "loki:3100"}
	TrustedRoot = filepath.Join(real, "project")
	if _, err := Generate(o); err == nil {
		t.Fatal("a Dir inside the project given through a symlink accepted")
	}
	if ents, _ := os.ReadDir(filepath.Join(real, "project")); len(ents) != 0 {
		t.Fatalf("%d entries written in the project", len(ents))
	}
}

func TestFailureRemovesTheDirectoryItCreated(t *testing.T) {
	for _, existing := range []bool{false, true} {
		o, _ := setup(t)
		os.MkdirAll(filepath.Dir(o.Dir), 0o700)
		if existing {
			os.Mkdir(o.Dir, 0o700)
		}
		// A write that fails once the directory is open.
		prev := afterOpen
		afterOpen = func() { os.Chmod(o.Dir, 0o500) }
		_, err := Generate(o)
		afterOpen = prev
		os.Chmod(o.Dir, 0o700)
		if err == nil {
			t.Fatal("generated in a read-only directory")
		}
		_, serr := os.Lstat(o.Dir)
		switch {
		case !existing && !errors.Is(serr, fs.ErrNotExist):
			t.Fatalf("the directory this call created is left: %v", serr)
		case existing && serr != nil:
			t.Fatalf("the user's directory removed: %v", serr)
		}
		if existing {
			if ents, _ := os.ReadDir(o.Dir); len(ents) != 0 {
				t.Fatalf("%d files left", len(ents))
			}
		}
	}
}

func TestDirLockedBeforeTheEmptinessCheck(t *testing.T) {
	// An existing Dir open to its group: made 0700 before it is checked
	// empty (and left so when it is refused for not being empty).
	o, _ := setup(t)
	os.MkdirAll(o.Dir, 0o700)
	os.Chmod(o.Dir, 0o770)
	os.WriteFile(filepath.Join(o.Dir, "planted"), nil, 0o600)
	if _, err := Generate(o); err == nil {
		t.Fatal("a non-empty directory accepted")
	}
	if fi, _ := os.Stat(o.Dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v after the check", fi.Mode().Perm())
	}
}

// TestRefusesComposeSpecialCharsInDir: the Dir goes into the generated
// Compose snippet's volume strings, where ':' splits and '$' interpolates.
func TestRefusesComposeSpecialCharsInDir(t *testing.T) {
	for _, bad := range []string{"loki$proxy", "loki${HOME}", "loki$$x", "a:b", `a"b`, `a\b`, "a\nb"} {
		o, _ := setup(t)
		o.Dir = filepath.Join(filepath.Dir(o.Dir), bad)
		os.MkdirAll(filepath.Dir(o.Dir), 0o700)
		if _, err := Generate(o); err == nil {
			t.Errorf("Dir %q accepted", bad)
		}
		if _, err := os.Lstat(o.Dir); err == nil {
			t.Errorf("Dir %q created", bad)
		}
	}
}
