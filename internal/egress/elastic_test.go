package egress

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/config"
)

func TestElasticRoutes(t *testing.T) {
	a, err := ElasticRoutes([]string{"logs-b", "logs-a*", "logs-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		method, path string
		ok           bool
	}{
		{"POST", "/logs-a*,logs-b/_search", true},
		{"POST", "/logs-a*,logs-b/_count", true},
		{"GET", "/logs-a*,logs-b/_field_caps", true},
		{"GET", "/logs-a*,logs-b/_mapping", true},
		{"GET", "/", true},
		{"GET", "/_security/user/_has_privileges", false},
		{"GET", "/_security/user/_privileges", true},
		{"GET", "/_resolve/index/logs-a*,logs-b", true},
		{"GET", "/_resolve/index/logs-a*", false},
		{"GET", "/_resolve/index/*", false},
		{"GET", "/_resolve/index/logs-a*,logs-b/x", false},
		{"POST", "/_resolve/index/logs-a*,logs-b", false},
		{"GET", "/_plugins/_security/api/account", false},
		{"PUT", "/logs-a*,logs-b/_mapping", false},
		{"POST", "/logs-a*,logs-b/_field_caps", false},
		{"GET", "/_plugins/_security/authinfo", true},
		{"GET", "/logs-a*,logs-b/_search", false},
		{"POST", "/logs-b/_search", false},
		{"POST", "/other/_search", false},
		{"POST", "/_all/_search", false},
		{"POST", "/*/_search", false},
		{"POST", "/logs-a*,logs-b/_delete_by_query", false},
		{"POST", "/logs-a*,logs-b/_update_by_query", false},
		{"POST", "/logs-a*,logs-b/_doc", false},
		{"POST", "/logs-a*,logs-b/_bulk", false},
		{"POST", "/_search", false},
		{"POST", "/_security/user/_has_privileges", false},
		{"GET", "/_security/user", false},
		{"GET", "/_cat/indices", false},
		{"GET", "/logs-a*,logs-b/_search/", false},
	} {
		if got := a.Allows(tt.method, tt.path); got != tt.ok {
			t.Errorf("Allows(%s %s) = %t, want %t", tt.method, tt.path, got, tt.ok)
		}
	}
	for _, bad := range [][]string{nil, {""}, {"_all"}, {".kibana"}, {"Logs"}, {"a,b"}, {"a/b"}, {"*"}, {"a*b"}, {"a**"}, {"r:logs"}, {"a b"}, {"-a"}, {"a..b"}} {
		if _, err := ElasticRoutes(bad); err == nil {
			t.Errorf("indices %q accepted", bad)
		}
	}
}

func TestSendPostsJSONWithCredentials(t *testing.T) {
	var s seen
	var ctype, method string
	var body []byte
	srv := lokiServer(t, &s, func(w http.ResponseWriter, r *http.Request) {
		ctype, method = r.Header.Get("Content-Type"), r.Method
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"count":3}`))
	})
	a, _ := ElasticRoutes([]string{"logs-*"})
	c, err := New(remote(srv.URL+"/es", config.AuthBearer, kconfig.TLSVerifyFull), a, Credentials{Secret: "tok"}, Options{RootCAs: roots(srv)})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Send(context.Background(), "POST", "/logs-*/_count", url.Values{"expand_wildcards": {"open"}}, []byte(`{"query":{}}`))
	if err != nil || string(resp.Body) != `{"count":3}` {
		t.Fatalf("%v %s", err, resp.Body)
	}
	if method != "POST" || ctype != "application/json" || string(body) != `{"query":{}}` || s.auth != "Bearer tok" ||
		(s.path != "/es/logs-*/_count" && s.path != "/es/logs-%2A/_count") || s.query != "expand_wildcards=open" {
		t.Fatalf("%s %s %s %q %s %s", method, ctype, body, s.auth, s.path, s.query)
	}
	// A GET without a body (the indices resolved).
	if _, err := c.Send(context.Background(), "GET", "/_resolve/index/logs-*", nil, nil); err != nil || method != "GET" || len(body) != 0 || ctype != "" {
		t.Fatalf("%v %s %s %s", err, method, body, ctype)
	}
	n := s.n.Load()
	if _, err := c.Send(context.Background(), "POST", "/logs-*/_delete_by_query", nil, []byte(`{}`)); !errors.Is(err, ErrNotAllowed) || s.n.Load() != n {
		t.Fatalf("%v", err)
	}
}

func TestElasticProbe(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler http.HandlerFunc
		ok      bool // passes the production check
	}{
		{"open", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"logs-a":{"mappings":{"properties":{}}}}`))
		}, false},
		{"open, nothing matched", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }, false},
		{"security on", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"type":"security_exception"},"status":401}`))
		}, true},
		{"login page", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>login</html>`)) }, true},
		{"not found", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }, false},
	} {
		var s seen
		srv := lokiServer(t, &s, tt.handler)
		a, _ := ElasticRoutes([]string{"logs-*"})
		c, _ := New(remote(srv.URL, config.AuthBearer, kconfig.TLSVerifyFull), a, Credentials{Secret: "tok"}, Options{RootCAs: roots(srv)})
		err := CheckElasticUnauthenticated(context.Background(), c, true, []string{"logs-*"})
		if (err == nil) != tt.ok {
			t.Errorf("%s: %v", tt.name, err)
		}
		if s.auth != "" {
			t.Errorf("%s: the probe sent credentials", tt.name)
		}
		if s.path != "/logs-*/_mapping" && s.path != "/logs-%2A/_mapping" {
			t.Errorf("%s: probed %s", tt.name, s.path)
		}
	}
	for body, want := range map[string]bool{
		`{"a":{"mappings":{}}}`:            true,
		`{}`:                               true,
		`{"error":{"reason":"x"}}`:         false,
		`{"a":{"mappings":{}},"status":1}`: false,
		`[]`:                               false,
		`null`:                             false,
	} {
		if got := ElasticData([]byte(body)); got != want {
			t.Errorf("ElasticData(%s) = %t", body, got)
		}
	}
}

func TestSendAuthModes(t *testing.T) {
	for _, tt := range []struct {
		auth  string
		creds Credentials
		want  string
	}{
		{config.AuthAPIKey, Credentials{Secret: "aWQ6a2V5"}, "ApiKey aWQ6a2V5"},
		{config.AuthBearer, Credentials{Secret: "tok"}, "Bearer tok"},
		{config.AuthBasic, Credentials{User: "reader", Secret: "pw"}, "Basic cmVhZGVyOnB3"},
		{config.AuthNone, Credentials{}, ""},
	} {
		var s seen
		srv := lokiServer(t, &s, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
		a, _ := ElasticRoutes([]string{"logs-*"})
		c, err := New(remote(srv.URL, tt.auth, kconfig.TLSVerifyFull), a, tt.creds, Options{RootCAs: roots(srv)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Send(context.Background(), "GET", "/", nil, nil); err != nil {
			t.Fatal(err)
		}
		if s.auth != tt.want {
			t.Errorf("%s: Authorization %q, want %q", tt.auth, s.auth, tt.want)
		}
		// The probe never sends them.
		_, _ = c.Probe(context.Background(), "/logs-*/_mapping", ElasticData)
		if s.auth != "" {
			t.Errorf("%s: the probe sent %q", tt.auth, s.auth)
		}
	}
}
