//go:build unix

package session

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/source/elastic/elastictest"
	"github.com/DavidGodefroid/locklog/internal/source/loki/lokitest"
)

// The secret the fakes accept: it must never reach an error, a note or an
// answer.
const remoteSecret = "s3cr3t-Reader-Token-9f2"

// lokiEntries: four entries in the hour after t0, two levels, an e-mail
// in every line and in untrusted metadata.
func lokiEntries() []lokitest.Entry {
	var out []lokitest.Entry
	for i := 0; i < 4; i++ {
		lv := []string{"info", "error"}[i%2]
		out = append(out, lokitest.Entry{TS: t0.Add(time.Duration(i+1) * time.Minute).UnixNano(),
			Labels: map[string]string{"app": "api", "level": lv, "pod": fmt.Sprintf("pod-%d", i)},
			Meta:   map[string]string{"trace_id": fmt.Sprintf("t%d", i), "user_email": "jane.doe@example.com"},
			Line:   fmt.Sprintf(`{"msg":"payment %d failed for jane.doe@example.com","status":%d}`, i, 200+302*(i%2))})
	}
	return out
}

func esDocs() []elastictest.Doc {
	var out []elastictest.Doc
	for i := 0; i < 4; i++ {
		lv := []string{"info", "error"}[i%2]
		out = append(out, elastictest.Doc{Index: []string{"logs-a", "logs-b"}[i%2], ID: fmt.Sprintf("d%d", i), TS: t0.Add(time.Duration(i+1) * time.Minute),
			Fields: map[string]any{"app": "api", "level": lv, "user_email": "jane.doe@example.com",
				"message": fmt.Sprintf(`{"msg":"payment %d failed for jane.doe@example.com","status":%d}`, i, 200+302*(i%2))}})
	}
	return out
}

func lokiCfg(url string, production bool, tlsCA string) func(string) string {
	return func(string) string {
		c := fmt.Sprintf(`version = 1
[profiles.staging]
production = %t
structured = "redact-unknown"
[profiles.staging.sources.loki]
kind = "loki"
format = "json"
url = %q
selector = { app = "api" }
trusted_labels = ["level"]
trusted_metadata = ["trace_id"]
auth = "basic"
user = "reader"
`, production, url)
		if tlsCA != "" {
			c += fmt.Sprintf("tls_ca = %q\n", tlsCA)
		}
		return c
	}
}

func esCfg(kind, url string, production bool, tlsCA string) func(string) string {
	return func(string) string {
		c := fmt.Sprintf(`version = 1
[profiles.staging]
production = %t
structured = "redact-unknown"
[profiles.staging.sources.es]
kind = %q
format = "json"
url = %q
indices = ["logs-*"]
trusted_fields = ["app", "level"]
auth = "basic"
user = "reader"
`, production, kind, url)
		if tlsCA != "" {
			c += fmt.Sprintf("tls_ca = %q\n", tlsCA)
		}
		return c
	}
}

// remoteOptions are the fixture's options with the console's secret.
func remoteOptions(f *fixture) Options {
	return f.options(func(o *Options) {
		o.Credentials = egress.Credentials{User: "reader", Secret: remoteSecret}
		o.Roots = logconsole.Roots{}
		o.Egress = egress.Options{Timeout: 10 * time.Second}
	})
}

// tlsCA writes the server's certificate as a CA file: verify-full then
// holds for its 127.0.0.1 address.
func tlsCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.crt")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const hour = `"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"`

// checkMasked runs a search and two counts (one scanned, one answered by
// the server's counts) and checks every answer masked.
func checkMasked(t *testing.T, s *Session, src string) {
	t.Helper()
	res, ref := call(t, s, logconsole.MethodSearch, `{`+hour+`}`)
	if ref != nil {
		t.Fatalf("search refused: %+v", ref)
	}
	out, _ := json.Marshal(res)
	got := string(out)
	if strings.Contains(got, "jane") || strings.Contains(got, "example.com") || strings.Contains(got, remoteSecret) {
		t.Fatalf("unmasked search: %s", got)
	}
	if !strings.Contains(got, "⟦email:") || !strings.Contains(got, `"level":"error"`) || !strings.Contains(got, "payment") {
		t.Errorf("search = %s", got)
	}
	if strings.Contains(got, "pod-") || strings.Contains(got, "user_email") {
		t.Errorf("an untrusted label or field reached the search: %s", got)
	}
	var sr struct {
		Records []json.RawMessage `json:"records"`
	}
	if json.Unmarshal(out, &sr) != nil || len(sr.Records) != 4 {
		t.Errorf("search: %d records, want 4: %s", len(sr.Records), got)
	}

	// Scanned: a text predicate, grouped by a trusted label.
	res, ref = call(t, s, logconsole.MethodCount, `{`+hour+`,"text":"failed","by_labels":["level"]}`)
	if ref != nil {
		t.Fatalf("scanned count refused: %+v", ref)
	}
	cr := res.(engine.CountResult)
	if n := total(cr); n != 4 {
		t.Errorf("scanned count = %d, want 4: %+v", n, cr)
	}
	out, _ = json.Marshal(res)
	if strings.Contains(string(out), "jane") {
		t.Fatalf("unmasked count: %s", out)
	}
	// By the masked message's pattern: the address as its pseudonym.
	res, ref = call(t, s, logconsole.MethodCount, `{`+hour+`,"by_pattern":true}`)
	if ref != nil {
		t.Fatalf("pattern count refused: %+v", ref)
	}
	out, _ = json.Marshal(res)
	if strings.Contains(string(out), "jane") || strings.Contains(string(out), "example.com") || total(res.(engine.CountResult)) != 4 {
		t.Fatalf("pattern count: %s", out)
	}
	// Trusted-only: answered by the server's counts.
	res, ref = call(t, s, logconsole.MethodCount, `{`+hour+`,"where":[{"label":"level","op":"=","value":"error"}],"by_labels":["level"]}`)
	if ref != nil {
		t.Fatalf("trusted count refused: %+v", ref)
	}
	cr = res.(engine.CountResult)
	if n := total(cr); n != 2 || len(cr.Groups) != 1 || cr.Groups[0].Key[0] == nil || *cr.Groups[0].Key[0] != "error" {
		t.Errorf("trusted count = %d: %+v", n, cr)
	}
	// log.sources: the trusted names, no untrusted one.
	srcs, _ := call(t, s, logconsole.MethodSources, `{}`)
	raw, _ := json.Marshal(srcs)
	if !strings.Contains(string(raw), `"name":"`+src+`"`) || strings.Contains(string(raw), "jane") || strings.Contains(string(raw), "pod-") {
		t.Errorf("sources = %s", raw)
	}
}

func total(cr engine.CountResult) int64 {
	var n int64
	for _, g := range cr.Groups {
		n += g.N
	}
	return n
}

func TestRemoteLokiMasked(t *testing.T) {
	fake := &lokitest.Server{Entries: lokiEntries(), User: "reader", Password: remoteSecret}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	f := newFixture(t, lokiCfg(srv.URL, false, ""), "")
	s := open(t, remoteOptions(f))
	st := s.Status(context.Background()).(Status)
	if len(st.Sources) != 1 || st.Sources[0] != (SourceStatus{Name: "loki", Kind: "loki"}) || len(st.Notes) != 0 {
		t.Errorf("status = %+v", st)
	}
	checkMasked(t, s, "loki")
	// The trusted-only count went to Loki as a metric query.
	metric := false
	for _, p := range fake.Requests() {
		metric = metric || p == "/loki/api/v1/query" || p == "/loki/api/v1/query_range"
	}
	if !metric {
		t.Errorf("requests %v", fake.Requests())
	}
}

func TestRemoteElasticMasked(t *testing.T) {
	for _, kind := range []string{"elastic", "opensearch"} {
		t.Run(kind, func(t *testing.T) {
			fake := &elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret, OpenSearch: kind == "opensearch"}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			f := newFixture(t, esCfg(kind, srv.URL, false, ""), "")
			s := open(t, remoteOptions(f))
			st := s.Status(context.Background()).(Status)
			if len(st.Sources) != 1 || st.Sources[0].Kind != kind || len(st.Notes) != 0 {
				t.Errorf("status = %+v", st)
			}
			checkMasked(t, s, "es")
			// Checked at connection: the trusted-only count was answered
			// with an aggregation, not a scan.
			reqs := strings.Join(fake.Requests(), " ")
			if !strings.Contains(reqs, "GET /logs-*/_field_caps") || !strings.Contains(reqs, "POST /logs-*/_search") {
				t.Errorf("requests: %s", reqs)
			}
		})
	}
}

// Off production a failed elastic Check leaves the source open, failing
// closed, with a note that holds no detail.
func TestRemoteElasticCheckFailsOpenOffProduction(t *testing.T) {
	// The time field is not a date: Check refuses it.
	fake := &elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret,
		Types: map[string]string{"@timestamp": "keyword", "message": "text", "app": "keyword", "level": "keyword", "user_email": "keyword"}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	f := newFixture(t, esCfg("elastic", srv.URL, false, ""), "")
	s := open(t, remoteOptions(f))
	st := s.Status(context.Background()).(Status)
	if len(st.Notes) != 1 || !strings.Contains(st.Notes[0], "source es: the backend check") || strings.Contains(st.Notes[0], "keyword") {
		t.Fatalf("notes = %q", st.Notes)
	}
	// Still readable, masked; the trusted-only count is scanned (no
	// aggregation before a Check succeeds).
	res, ref := call(t, s, logconsole.MethodCount, `{`+hour+`,"where":[{"label":"level","op":"=","value":"error"}]}`)
	if ref != nil {
		t.Fatalf("count refused: %+v", ref)
	}
	if n := total(res.(engine.CountResult)); n != 2 {
		t.Errorf("count = %d", n)
	}
}

func TestRemoteProductionRefused(t *testing.T) {
	cases := []struct {
		name string
		srv  func() *httptest.Server
		cfg  func(url, ca string) func(string) string
		want string
	}{
		{"loki open endpoint", func() *httptest.Server {
			return httptest.NewTLSServer(&lokitest.Server{Entries: lokiEntries(), Open: true})
		}, func(url, ca string) func(string) string { return lokiCfg(url, true, ca) }, "answers a data read without credentials"},
		{"elastic open endpoint", func() *httptest.Server {
			return httptest.NewTLSServer(&elastictest.Server{Docs: esDocs(), Open: true})
		}, func(url, ca string) func(string) string { return esCfg("elastic", url, true, ca) }, "answers a data read without credentials"},
		{"opensearch open endpoint", func() *httptest.Server {
			return httptest.NewTLSServer(&elastictest.Server{Docs: esDocs(), Open: true, OpenSearch: true})
		}, func(url, ca string) func(string) string { return esCfg("opensearch", url, true, ca) }, "answers a data read without credentials"},
		{"elastic write-capable key", func() *httptest.Server {
			return httptest.NewTLSServer(&elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret, Grants: elastictest.WriteGrants})
		}, func(url, ca string) func(string) string { return esCfg("elastic", url, true, ca) }, "write or manage privileges"},
		{"opensearch unvouched role", func() *httptest.Server {
			return httptest.NewTLSServer(&elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret, OpenSearch: true, Roles: []string{"custom_writer"}})
		}, func(url, ca string) func(string) string { return esCfg("opensearch", url, true, ca) }, "write or manage privileges"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := c.srv()
			defer srv.Close()
			f := newFixture(t, c.cfg(srv.URL, tlsCA(t, srv)), "")
			_, err := Open(context.Background(), remoteOptions(f))
			if err == nil {
				t.Fatal("a production profile opened")
			}
			msg := err.Error()
			if !strings.Contains(msg, "the connection checks refuse this profile") || !strings.Contains(msg, c.want) {
				t.Errorf("error = %v", err)
			}
			if strings.Contains(msg, remoteSecret) || strings.Contains(msg, "jane") || strings.Contains(msg, "{") {
				t.Errorf("the error carries a secret or a body: %v", err)
			}
		})
	}
}

// A production profile over TLS, behind authentication, with a read-only
// key: accepted, and masked.
func TestRemoteProductionAccepted(t *testing.T) {
	lk := httptest.NewTLSServer(&lokitest.Server{Entries: lokiEntries(), User: "reader", Password: remoteSecret})
	defer lk.Close()
	f := newFixture(t, lokiCfg(lk.URL, true, tlsCA(t, lk)), "")
	s := open(t, remoteOptions(f))
	checkMasked(t, s, "loki")

	es := httptest.NewTLSServer(&elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret})
	defer es.Close()
	f = newFixture(t, esCfg("elastic", es.URL, true, tlsCA(t, es)), "")
	s = open(t, remoteOptions(f))
	checkMasked(t, s, "es")
}

// A wrong secret is refused, without the secret in the error.
func TestRemoteWrongSecret(t *testing.T) {
	es := httptest.NewServer(&elastictest.Server{Docs: esDocs(), User: "reader", Password: "another"})
	defer es.Close()
	f := newFixture(t, esCfg("elastic", es.URL, false, ""), "")
	s := open(t, remoteOptions(f))
	// Off production the source opens; its check failed (status 401).
	if st := s.Status(context.Background()).(Status); len(st.Notes) != 1 {
		t.Errorf("notes = %q", st.Notes)
	}
	_, ref := call(t, s, logconsole.MethodSearch, `{`+hour+`}`)
	if ref == nil || strings.Contains(ref.Message, remoteSecret) {
		t.Errorf("search with a wrong secret: %+v", ref)
	}
}

// A trusted-only count on a remote source that answers counts is bounded
// by limits.remote.count_range, not the local one; a scanned one by the
// remote range.
func TestRemoteCountRange(t *testing.T) {
	fake := &lokitest.Server{Entries: lokiEntries(), User: "reader", Password: remoteSecret}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := func(l string) string {
		return lokiCfg(srv.URL, false, "")(l) + `[profiles.staging.limits.local]
count_range = "30d"
[profiles.staging.limits.remote]
range = "1h"
count_range = "2h"
`
	}
	f := newFixture(t, cfg, "")
	s := open(t, remoteOptions(f))
	trusted := `"where":[{"label":"level","op":"=","value":"error"}]`
	if _, ref := call(t, s, logconsole.MethodCount, `{"from":"2026-10-30T12:00:00Z","to":"2026-10-30T14:00:00Z",`+trusted+`}`); ref != nil {
		t.Errorf("within the remote count range: %+v", ref)
	}
	if _, ref := call(t, s, logconsole.MethodCount, `{"from":"2026-10-30T11:00:00Z","to":"2026-10-30T14:00:00Z",`+trusted+`}`); ref == nil || ref.Info.Code != "E_OVER_BUDGET" {
		t.Errorf("past the remote count range: %+v", ref)
	}
	if _, ref := call(t, s, logconsole.MethodCount, `{"from":"2026-10-30T12:00:00Z","to":"2026-10-30T14:00:00Z","text":"failed"}`); ref == nil || ref.Info.Code != "E_OVER_BUDGET" {
		t.Errorf("a scanned count past the remote range: %+v", ref)
	}
}

// remoteBudget is the remote class of :status's rolling budgets.
func remoteBudget(t *testing.T, s *Session) engine.ClassBudget {
	t.Helper()
	b := s.Status(context.Background()).(Status).Budgets.Remote
	if b == nil || b.RequestsLeft == nil || b.MetricLeft == nil {
		t.Fatalf("no remote budget: %+v", b)
	}
	return *b
}

// One remote request takes exactly one token of the per-minute request
// budget (the engine's, Engine.Paced and the query path: no double
// pacing), log.sources included; a server-side count's requests are each
// one metric query too.
func TestRemoteRequestsPaced(t *testing.T) {
	lk := &lokitest.Server{Entries: lokiEntries(), User: "reader", Password: remoteSecret}
	ls := httptest.NewServer(lk)
	defer ls.Close()
	es := &elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret}
	ess := httptest.NewServer(es)
	defer ess.Close()
	for _, c := range []struct {
		name string
		cfg  func(string) string
		reqs func() int
	}{
		{"loki", lokiCfg(ls.URL, false, ""), func() int { return len(lk.Requests()) }},
		{"elastic", esCfg("elastic", ess.URL, false, ""), func() int { return len(es.Requests()) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.cfg, "")
			s := open(t, remoteOptions(f))
			for _, m := range []struct {
				method, params string
				metric         bool
			}{
				{logconsole.MethodSources, `{}`, false},
				{logconsole.MethodSearch, `{` + hour + `}`, false},
				{logconsole.MethodCount, `{` + hour + `,"where":[{"label":"level","op":"=","value":"error"}]}`, true},
			} {
				before, b := c.reqs(), remoteBudget(t, s)
				if _, ref := call(t, s, m.method, m.params); ref != nil {
					t.Fatalf("%s refused: %+v", m.method, ref)
				}
				a := remoteBudget(t, s)
				reqs, took := c.reqs()-before, *b.RequestsLeft-*a.RequestsLeft
				if reqs == 0 || took != reqs {
					t.Errorf("%s: %d requests, %d tokens", m.method, reqs, took)
				}
				if metric := *b.MetricLeft - *a.MetricLeft; m.metric && metric != reqs || !m.metric && metric != 0 {
					t.Errorf("%s: %d requests, %d metric queries", m.method, reqs, metric)
				}
			}
		})
	}
}

// A spent hourly budget refuses the call: server-side metric queries
// (limits.remote.metric_queries_per_hour) and bytes fetched
// (limits.remote.bytes_per_hour), for Loki and Elasticsearch.
func TestRemoteHourlyBudgets(t *testing.T) {
	lk := httptest.NewServer(&lokitest.Server{Entries: lokiEntries(), User: "reader", Password: remoteSecret})
	defer lk.Close()
	es := httptest.NewServer(&elastictest.Server{Docs: esDocs(), User: "reader", Password: remoteSecret})
	defer es.Close()
	for _, c := range []struct {
		name string
		cfg  func(string) string
	}{
		{"loki", lokiCfg(lk.URL, false, "")},
		{"elastic", esCfg("elastic", es.URL, false, "")},
	} {
		t.Run(c.name+"/metric", func(t *testing.T) {
			f := newFixture(t, func(l string) string {
				return c.cfg(l) + "[profiles.staging.limits.remote]\nmetric_queries_per_hour = 1\n"
			}, "")
			s := open(t, remoteOptions(f))
			var ref *logconsole.Refusal
			for i := 0; i < 3 && ref == nil; i++ {
				// A new window each time: no cached answer.
				_, ref = call(t, s, logconsole.MethodCount, fmt.Sprintf(`{"from":"2026-10-30T13:0%d:00Z","to":"2026-10-30T14:00:00Z","where":[{"label":"level","op":"=","value":"error"}]}`, i))
			}
			if ref == nil || ref.Info.Code != "E_OVER_BUDGET" || !strings.Contains(ref.Message, "metric queries per hour") {
				t.Errorf("past the metric budget: %+v", ref)
			}
			if left := *remoteBudget(t, s).MetricLeft; left != 0 {
				t.Errorf("metric left %d", left)
			}
		})
		t.Run(c.name+"/bytes", func(t *testing.T) {
			f := newFixture(t, func(l string) string {
				return c.cfg(l) + "[profiles.staging.limits.remote]\nmax_bytes = \"1KiB\"\nbytes_per_hour = \"1KiB\"\n"
			}, "")
			s := open(t, remoteOptions(f))
			var ref *logconsole.Refusal
			n := 0
			for i := 0; i < 10 && ref == nil; i++ {
				n++
				_, ref = call(t, s, logconsole.MethodSearch, fmt.Sprintf(`{"from":"2026-10-30T13:0%d:00Z","to":"2026-10-30T14:00:00Z"}`, i))
			}
			// The first call is served; a later one finds the hour spent.
			if n < 2 || ref == nil || ref.Info.Code != "E_OVER_BUDGET" || !strings.Contains(ref.Message, "bytes processed per hour") {
				t.Errorf("past the byte budget: %+v", ref)
			}
		})
	}
}
