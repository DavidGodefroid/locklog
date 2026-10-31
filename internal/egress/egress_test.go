package egress

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
		open    bool
	}{
		{"open Loki", nil, true},
		{"auth required", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		}, false},
		{"login page", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>sign in</html>")) }, false},
		{"redirect to login", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login", http.StatusFound) }, false},
		{"forbidden", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }, false},
	} {
		var s seen
		srv := lokiServer(t, &s, tt.handler)
		r := remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull)
		r.OrgID = "t1"
		c, _ := New(r, LokiRoutes, Credentials{Secret: "token"}, Options{RootCAs: roots(srv)})
		open, err := c.Probe(context.Background(), LokiProbePath, LokiData)
		if err != nil || open != tt.open {
			t.Errorf("%s: open %t err %v", tt.name, open, err)
		}
		if s.auth != "" || s.org != "" {
			t.Errorf("%s: the probe sent credentials (%q, %q)", tt.name, s.auth, s.org)
		}
		err = CheckUnauthenticated(context.Background(), c, true)
		if (err != nil) != tt.open {
			t.Errorf("%s: CheckUnauthenticated = %v", tt.name, err)
		}
		n := s.n.Load()
		if err := CheckUnauthenticated(context.Background(), c, false); err != nil || s.n.Load() != n {
			t.Errorf("%s: non-production probed", tt.name)
		}
	}
	// An unreachable backend fails the production check (closed).
	c, _ := New(remote("https://127.0.0.1:1", config.AuthBearer, kconfig.TLSVerifyFull), LokiRoutes, Credentials{}, Options{})
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
