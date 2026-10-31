package egress

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/config"
)

func TestAllowlist(t *testing.T) {
	for _, tt := range []struct {
		method, path string
		ok           bool
	}{
		{"GET", "/loki/api/v1/query_range", true},
		{"GET", "/loki/api/v1/label/app/values", true},
		{"GET", "/loki/api/v1/index/stats", true},
		{"GET", "/ready", true},
		{"POST", "/loki/api/v1/query_range", false},
		{"DELETE", "/loki/api/v1/delete", false},
		{"GET", "/loki/api/v1/push", false},
		{"GET", "/loki/api/v1/label//values", false},
		{"GET", "/loki/api/v1/label/../values", false},
		{"GET", "/loki/api/v1/label/./values", false},
		{"GET", "/loki/api/v1/label/a/b/values", false},
		{"GET", "/loki/api/v1/query_range/", false},
		{"GET", "loki/api/v1/labels", false},
		{"GET", "//loki/api/v1/labels", false},
		{"GET", "/config", false},
		{"GET", "/loki/api/v1/tail", false},
	} {
		if got := LokiRoutes.Allows(tt.method, tt.path); got != tt.ok {
			t.Errorf("Allows(%s %s) = %t, want %t", tt.method, tt.path, got, tt.ok)
		}
	}
	for _, bad := range []Route{{"PUT", "/x"}, {"GET", "x"}, {"GET", "/a//b"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewAllowlist(%v) did not panic", bad)
				}
			}()
			NewAllowlist(bad)
		}()
	}
}

type seen struct {
	auth, org, tags, path, query string
	n                            atomic.Int32
}

func lokiServer(t *testing.T, s *seen, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.n.Add(1)
		s.auth, s.org, s.tags, s.path, s.query = r.Header.Get("Authorization"), r.Header.Get("X-Scope-OrgID"), r.Header.Get("X-Query-Tags"), r.URL.Path, r.URL.RawQuery
		if handler != nil {
			handler(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":["app"]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func roots(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

func remote(u, auth, tlsMode string) *config.Remote {
	return &config.Remote{URL: u, Auth: auth, Base: kconfig.Base{TLS: tlsMode}}
}

func TestGetSendsCredentialsAndTags(t *testing.T) {
	var s seen
	srv := lokiServer(t, &s, nil)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	r := remote(srv.URL+"/prefix", config.AuthBearer, kconfig.TLSVerifyFull)
	r.OrgID = "tenant-1"
	c, err := New(r, LokiRoutes, Credentials{Secret: "s3cret"}, Options{RootCAs: roots(srv)})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(context.Background(), "/loki/api/v1/labels", url.Values{"start": {"1"}})
	if err != nil {
		t.Fatalf("Get (proxy env ignored): %v", err)
	}
	if resp.Status != 200 || s.auth != "Bearer s3cret" || s.org != "tenant-1" || s.tags != "source=locklog" ||
		s.path != "/prefix/loki/api/v1/labels" || s.query != "start=1" {
		t.Errorf("request: %+v %+v", resp, &s)
	}
	b := remote(srv.URL, config.AuthBasic, kconfig.TLSVerifyFull)
	c, _ = New(b, LokiRoutes, Credentials{User: "reader", Secret: "pw"}, Options{RootCAs: roots(srv)})
	if _, err := c.Get(context.Background(), "/ready", nil); err != nil || !strings.HasPrefix(s.auth, "Basic ") {
		t.Errorf("basic: %v %q", err, s.auth)
	}
}

func TestGetWithHeaders(t *testing.T) {
	var s seen
	srv := lokiServer(t, &s, nil)
	c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "s3cret"}, Options{RootCAs: roots(srv)})
	q := url.Values{"query": {`{app="api"}`}}
	if _, err := c.GetWith(context.Background(), "/loki/api/v1/labels", q, LokiHeaders); err != nil || s.auth != "Bearer s3cret" || s.query != q.Encode() {
		t.Fatalf("GetWith: %v %+v", err, &s)
	}
	n := s.n.Load()
	for _, h := range []string{"Authorization", "cookie", "X-Scope-OrgID", "Host", "User-Agent", "x-query-tags"} {
		if _, err := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "s3cret"}, Options{RootCAs: roots(srv), Headers: map[string]string{h: "x"}}); err == nil {
			t.Errorf("fixed header %s accepted", h)
		}
		if _, err := c.GetWith(context.Background(), "/loki/api/v1/labels", nil, map[string]string{h: "x"}); err == nil {
			t.Errorf("header %s sent", h)
		}
	}
	if s.n.Load() != n {
		t.Error("a refused request reached the server")
	}
}

func TestNotAllowedSendsNothing(t *testing.T) {
	var s seen
	srv := lokiServer(t, &s, nil)
	c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "x"}, Options{RootCAs: roots(srv)})
	for _, p := range []string{"/loki/api/v1/push", "/loki/api/v1/label/../values", "/../../etc"} {
		if _, err := c.Get(context.Background(), p, nil); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Get(%s) = %v", p, err)
		}
	}
	if s.n.Load() != 0 {
		t.Errorf("%d requests reached the server", s.n.Load())
	}
	// An escaped name stays one segment.
	if _, err := c.Get(context.Background(), "/loki/api/v1/label/"+url.PathEscape("a/../../x")+"/values", nil); err != nil {
		t.Fatal(err)
	}
	if s.path != "/loki/api/v1/label/a%2F..%2F..%2Fx/values" && s.path != "/loki/api/v1/label/a/../../x/values" {
		t.Errorf("path = %q", s.path)
	}
}

func TestRedirectsAndErrors(t *testing.T) {
	var s seen
	srv := lokiServer(t, &s, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			http.Redirect(w, r, "https://elsewhere.example/ready", http.StatusFound)
		case "/loki/api/v1/labels":
			w.WriteHeader(500)
			_, _ = w.Write([]byte("secret-body-detail"))
		default:
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		}
	})
	c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "x"}, Options{RootCAs: roots(srv), MaxResponseBytes: 1024})
	if _, err := c.Get(context.Background(), "/ready", nil); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Errorf("redirect: %v", err)
	}
	_, err := c.Get(context.Background(), "/loki/api/v1/labels", nil)
	if err == nil || strings.Contains(err.Error(), "secret-body-detail") || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("500: %v", err)
	}
	if _, err := c.Get(context.Background(), "/loki/api/v1/series", url.Values{"match[]": {`{app="secret-selector"}`}}); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("cap: %v", err)
	}
}

func TestDialerPinned(t *testing.T) {
	c, err := New(remote("https://127.0.0.1:9", config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.http.Transport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "127.0.0.2:9"); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("dial elsewhere: %v", err)
	}
	if tr.Proxy != nil {
		t.Error("a proxy function is set")
	}
	md, _ := New(remote("https://169.254.169.254", config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{}, Options{})
	if _, err := md.Get(context.Background(), "/ready", nil); err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("metadata address: %v", err)
	}
}

func TestTLSModes(t *testing.T) {
	var s seen
	srv := lokiServer(t, &s, nil)
	// httptest's certificate names 127.0.0.1 and example.com, not localhost.
	local := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, url, mode, ca string
		pool                bool
		ok                  bool
	}{
		{"verify-full, right name", srv.URL, kconfig.TLSVerifyFull, "", true, true},
		{"verify-full, tls_ca", srv.URL, kconfig.TLSVerifyFull, ca, false, true},
		{"verify-full, wrong name", local, kconfig.TLSVerifyFull, "", true, false},
		{"verify-full, unknown CA", srv.URL, kconfig.TLSVerifyFull, "", false, false},
		{"verify-ca, wrong name", local, kconfig.TLSVerifyCA, ca, false, true},
		{"verify-ca, unknown CA", local, kconfig.TLSVerifyCA, "", false, false},
		{"require with tls_ca verifies the chain", local, kconfig.TLSRequire, ca, false, true},
		{"require without tls_ca", local, kconfig.TLSRequire, "", false, true},
	} {
		r := remote(tt.url, config.AuthBearer, tt.mode)
		r.TLSCA = tt.ca
		opt := Options{}
		if tt.pool {
			opt.RootCAs = roots(srv)
		}
		c, err := New(r, LokiRoutes, Credentials{Secret: "x"}, opt)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		_, err = c.Get(context.Background(), "/ready", nil)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err %v, want ok=%t", tt.name, err, tt.ok)
		}
	}
	r := remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull)
	r.TLSCA = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(r, LokiRoutes, Credentials{}, Options{}); err == nil {
		t.Error("missing tls_ca accepted")
	}
}

func TestProbe(t *testing.T) {
	type result int
	const (
		open result = iota
		closed
		unknown // an error: the production check fails closed
	)
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
		want    result
	}{
		{"open Loki", nil, open},
		{"open Loki, empty data", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"success"}`)) }, open},
		{"auth required", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		}, closed},
		{"an org id alone opens it", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Scope-OrgID") == "" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":["app"]}`))
		}, open},
		{"login page", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>sign in</html>")) }, closed},
		{"redirect to login", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login", http.StatusFound) }, closed},
		{"redirect to itself", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
		}, unknown},
		{"forbidden", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }, closed},
		{"not found", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }, unknown},
		{"rate limited", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }, unknown},
		{"starting", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, unknown},
		{"bad request", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }, unknown},
	} {
		var s seen
		srv := lokiServer(t, &s, tt.handler)
		c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "token"}, Options{RootCAs: roots(srv)})
		got, err := c.Probe(context.Background(), LokiProbePath, LokiData)
		res := closed
		switch {
		case err != nil:
			res = unknown
		case got:
			res = open
		}
		if res != tt.want {
			t.Errorf("%s: open %t err %v, want %d", tt.name, got, err, tt.want)
		}
		if s.auth != "" {
			t.Errorf("%s: the probe sent credentials (%q)", tt.name, s.auth)
		}
		err = CheckUnauthenticated(context.Background(), c, true)
		if (err == nil) != (tt.want == closed) {
			t.Errorf("%s: CheckUnauthenticated = %v", tt.name, err)
		}
		n := s.n.Load()
		if err := CheckUnauthenticated(context.Background(), c, false); err != nil || s.n.Load() != n {
			t.Errorf("%s: non-production probed", tt.name)
		}
	}
	// The configured org id is the tenant the second probe sends.
	var s seen
	srv := lokiServer(t, &s, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	r := remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull)
	r.OrgID = "t1"
	c, _ := New(r, LokiRoutes, Credentials{Secret: "token"}, Options{RootCAs: roots(srv)})
	if open, err := c.Probe(context.Background(), LokiProbePath, LokiData); open || err != nil || s.org != "t1" || s.auth != "" {
		t.Errorf("org id probe: %t %v %q %q", open, err, s.org, s.auth)
	}
	// An unreachable backend fails the production check (closed).
	c, _ = New(remote("https://127.0.0.1:1", config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{}, Options{})
	if err := CheckUnauthenticated(context.Background(), c, true); err == nil {
		t.Error("unreachable backend passed the check")
	}
}

func TestLokiData(t *testing.T) {
	for body, want := range map[string]bool{
		`{"status":"success","data":["a"]}`:      true,
		`{ "status" : "success", "data" : [ ] }`: true,
		`{"data":["a"],"status":"success"}`:      true,
		`{"status":"error","error":"auth"}`:      false,
		`{"status":"success","data":null}`:       true,
		`<html>{"status":"success"}</html>`:      false,
		``:                                       false,
	} {
		if got := LokiData([]byte(body)); got != want {
			t.Errorf("LokiData(%q) = %t", body, got)
		}
	}
}

func TestExtraInterfaces(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"lo", "eth0"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ExtraInterfaces(dir)
	if err != nil || len(got) != 1 || got[0] != "eth0" {
		t.Errorf("ExtraInterfaces = %v %v", got, err)
	}
}

// TestMTLS: the client presents its certificate; the probe never does, and
// a backend that demands one reads as closed.
func TestMTLS(t *testing.T) {
	ca := testCA(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":["app"]}`))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.pool}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, "client")
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	r := remote(srv.URL, config.AuthMTLS, kconfig.TLSVerifyFull)
	r.TLSCert, r.TLSKey = certFile, keyFile
	c, err := New(r, LokiRoutes, Credentials{}, Options{RootCAs: roots(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/ready", nil); err != nil {
		t.Fatalf("mTLS client: %v", err)
	}
	// A pooled connection with the certificate exists now; the probe has
	// its own.
	if err := CheckUnauthenticated(context.Background(), c, true); err != nil {
		t.Errorf("mTLS-only backend: %v", err)
	}
	r.TLSKey = certFile
	if _, err := New(r, LokiRoutes, Credentials{}, Options{}); err == nil {
		t.Error("a bad key pair accepted")
	}
}

type testCAKit struct {
	pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testCA(t *testing.T) testCAKit {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCAKit{pool: pool, cert: cert, key: key}
}

func (ca testCAKit) issue(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestHostHeaderAndGzipCap(t *testing.T) {
	var host string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(strings.Repeat("a", 4096)))
		_ = gz.Close()
	}))
	t.Cleanup(srv.Close)
	c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{Secret: "x"}, Options{RootCAs: roots(srv), MaxResponseBytes: 1024})
	if _, err := c.Get(context.Background(), "/ready", nil); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("gzip cap: %v", err)
	}
	if want := strings.TrimPrefix(srv.URL, "https://"); host != want {
		t.Errorf("Host = %q, want %q", host, want)
	}
}

func TestMetadataAddr(t *testing.T) {
	for ip, want := range map[string]bool{"169.254.169.254": true, "fe80::1": true, "fd00:ec2::254": true, "100.100.100.200": true,
		"0.0.0.0": true, "::": true, "10.0.0.1": false, "127.0.0.1": false, "8.8.8.8": false} {
		if got := metadataAddr(net.ParseIP(ip)); got != want {
			t.Errorf("metadataAddr(%s) = %t", ip, got)
		}
	}
}
