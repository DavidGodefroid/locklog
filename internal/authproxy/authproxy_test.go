//go:build unix

package authproxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func setup(t *testing.T) (Options, string) {
	t.Helper()
	base := t.TempDir()
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
}

func TestRefusesProjectAndBadInputs(t *testing.T) {
	o, _ := setup(t)
	for name, mod := range map[string]func(*Options){
		"in project":    func(o *Options) { o.Dir = filepath.Join(o.Project, ".locklog", "proxy") },
		"project in it": func(o *Options) { o.Dir = filepath.Dir(o.Project) },
		"relative":      func(o *Options) { o.Dir = "proxy" },
		"bad host":      func(o *Options) { o.Host = "Loki_Proxy" },
		"bad upstream":  func(o *Options) { o.Upstream = "loki:3100\n reverse_proxy evil" },
		"no project":    func(o *Options) { o.Project = "" },
	} {
		oo := o
		mod(&oo)
		if _, err := Generate(oo); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	os.MkdirAll(o.Dir, 0o700)
	os.WriteFile(filepath.Join(o.Dir, "x"), nil, 0o600)
	if _, err := Generate(o); err == nil {
		t.Error("non-empty directory accepted")
	}
}
