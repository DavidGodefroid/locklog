// Package authproxy generates an authenticating TLS proxy (Caddy) for a
// Loki that runs without auth in the user's Compose stack, so that a
// production profile can read it (design §2.5).
//
// What it writes keeps the backend read token away from agents
// (precondition P3, round-6 amendment):
//
//   - the proxy gets only a bcrypt hash of the token, never the token;
//   - the clear token is returned to the caller, which shows it on the
//     console's terminal only (the console then asks for it, or reads it
//     from Vault); it is never written to a file;
//   - the internal CA's private key is discarded once the server
//     certificate is signed: only the CA certificate is written, for the
//     profile's tls_ca;
//   - files go to a directory outside the project, created 0700.
package authproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Options describe the proxy.
type Options struct {
	// Dir is where the files go: absolute, outside Project (resolved),
	// created 0700. Every ancestor must be a real directory (no symlink)
	// owned by root or the user and writable by no one else; Dir must not
	// exist yet, or be an empty real directory of the user's. The files are
	// created relative to Dir's descriptor (see writeFiles).
	Dir string
	// Project is the project root (agents may read it): Dir must not be
	// inside it.
	Project string
	// Host is the proxy's service name in the Compose network (the
	// certificate's name and the profile's url host).
	Host string
	// Port is the proxy's listening port.
	Port int
	// Upstream is the Loki service address in the network ("loki:3100").
	Upstream string
	// User is the basic-auth user name.
	User string
	// Validity of the certificates (default 2 years).
	Validity time.Duration
}

// Result is what Generate produced. Token is the clear read token: show it on
// the console's terminal only.
type Result struct {
	Token string
	// Files written (absolute paths).
	Caddyfile, ServerCert, ServerKey, CACert string
	// URL is the profile's url; Compose is the service snippet to add to
	// the user's compose file (it holds no secret).
	URL     string
	Compose string
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var upstreamRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}:[0-9]{1,5}$`)
var userRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// inside reports whether path is dir or below it.
func inside(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Generate writes the proxy's files and returns the token and snippets.
func Generate(o Options) (Result, error) {
	if o.User == "" {
		o.User = "locklog"
	}
	if o.Port == 0 {
		o.Port = 3101
	}
	if o.Validity == 0 {
		o.Validity = 2 * 365 * 24 * time.Hour
	}
	switch {
	case !filepath.IsAbs(o.Dir) || filepath.Clean(o.Dir) != o.Dir:
		return Result{}, errors.New("authproxy: the directory must be an absolute, clean path")
	case o.Project == "" || !filepath.IsAbs(o.Project):
		return Result{}, errors.New("authproxy: the project root is required")
	case inside(o.Dir, o.Project) || inside(o.Project, o.Dir):
		return Result{}, errors.New("authproxy: the directory must be outside the project (agents can read the project)")
	case !hostRe.MatchString(o.Host):
		return Result{}, errors.New("authproxy: invalid host name")
	case !upstreamRe.MatchString(o.Upstream):
		return Result{}, errors.New("authproxy: invalid upstream (want service:port)")
	case !userRe.MatchString(o.User):
		return Result{}, errors.New("authproxy: invalid user name")
	case o.Port < 1 || o.Port > 65535:
		return Result{}, errors.New("authproxy: invalid port")
	case strings.ContainsAny(o.Dir, ":\"\\") || strings.ContainsFunc(o.Dir, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		// The Compose short volume syntax splits on ':'.
		return Result{}, errors.New("authproxy: the directory path must not hold ':', quotes, backslashes or control characters")
	}
	// The project through its real path: a Dir inside its target is
	// inside it. Dir's own ancestors may hold no symlink (writeFiles).
	project, err := filepath.EvalSymlinks(o.Project)
	if err != nil {
		return Result{}, fmt.Errorf("authproxy: the project root: %w", err)
	}
	if inside(o.Dir, project) || inside(project, o.Dir) {
		return Result{}, errors.New("authproxy: the directory must be outside the project (agents can read the project)")
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Result{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(token), 12)
	if err != nil {
		return Result{}, err
	}

	caCert, serverCert, serverKey, err := certificates(o.Host, o.Validity)
	if err != nil {
		return Result{}, err
	}
	r := Result{
		Token:      token,
		Caddyfile:  filepath.Join(o.Dir, "Caddyfile"),
		ServerCert: filepath.Join(o.Dir, "server.crt"),
		ServerKey:  filepath.Join(o.Dir, "server.key"),
		CACert:     filepath.Join(o.Dir, "ca.crt"),
		URL:        fmt.Sprintf("https://%s:%d", o.Host, o.Port),
	}
	caddy := fmt.Sprintf(`# Generated by locklog setup: an authenticating TLS proxy in front of Loki.
# It holds only a bcrypt hash of the read token; the token itself is shown
# once on the locklog console's terminal.
{
	admin off
	auto_https off
}

https://%s:%d {
	tls /etc/locklog-proxy/server.crt /etc/locklog-proxy/server.key
	basic_auth {
		%s %s
	}
	reverse_proxy %s
}
`, o.Host, o.Port, o.User, hash, o.Upstream)
	if err := writeFiles(o.Dir, []file{
		{"Caddyfile", []byte(caddy), 0o600},
		{"server.crt", serverCert, 0o600},
		{"server.key", serverKey, 0o600},
		{"ca.crt", caCert, 0o644},
	}); err != nil {
		return Result{}, err
	}
	r.Compose = fmt.Sprintf(`  %s:
    image: caddy:2.10.2
    volumes:
      - "%s:/etc/caddy/Caddyfile:ro"
      - "%s:/etc/locklog-proxy:ro"
    # No published port: only the locklog console's network reaches it.
`, o.Host, r.Caddyfile, o.Dir)
	return r, nil
}

// file is one file Generate writes in Dir.
type file struct {
	name string
	data []byte
	mode os.FileMode
}

// certificates makes an internal CA, signs a server certificate for host
// with it, and discards the CA's private key (it never leaves this
// function).
func certificates(host string, validity time.Duration) (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		return n
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "locklog internal CA for " + host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		// The CA can only sign for the proxy's name, and for no IP
		// address.
		PermittedDNSDomains:         []string{host},
		PermittedDNSDomainsCritical: true,
		ExcludedIPRanges:            []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	// caKey goes out of scope here, never written: nothing can sign
	// another certificate for this CA.
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
