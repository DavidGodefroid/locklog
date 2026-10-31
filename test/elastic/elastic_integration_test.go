//go:build integration

// Package elastic_test runs the Elasticsearch source against a real
// Elasticsearch 8 and a real OpenSearch 2, both with security on: the test
// creates read-only and write-capable roles and users (and Elasticsearch
// API keys for them), and checks that a production profile accepts only
// the read-only ones. CI starts both from pulled images; locally, under the
// heavy lease:
//
//	LOCKLOG_ES_URL=http://127.0.0.1:9200 LOCKLOG_ES_ADMIN=elastic:<password> \
//	LOCKLOG_OPENSEARCH_URL=http://127.0.0.1:9201 LOCKLOG_OPENSEARCH_ADMIN=admin:<password> \
//	go test -tags integration ./test/elastic
package elastic_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/elastic"
)

func env(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Skip(k + " not set")
	}
	return strings.TrimSuffix(v, "/")
}

// admin sends a request with the admin's credentials (setup only: the
// source itself can only read).
func admin(t *testing.T, base, user, pw, method, path, ctype string, body []byte) []byte {
	t.Helper()
	b, status := adminStatus(t, base, user, pw, method, path, ctype, body)
	if status/100 != 2 {
		t.Fatalf("%s %s: %d %s", method, path, status, b)
	}
	return b
}

// adminStatus is admin returning the status instead of failing on it.
func adminStatus(t *testing.T, base, user, pw, method, path, ctype string, body []byte) ([]byte, int) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	if user != "" {
		req.SetBasicAuth(user, pw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode
}

const mapping = `{"mappings":{"properties":{"@timestamp":{"type":"date"},"message":{"type":"text"},
"app":{"type":"keyword"},"level":{"type":"keyword"},"pod":{"type":"keyword"},"user_email":{"type":"keyword"},
"event":{"properties":{"id":{"type":"keyword"}}}}}}`

// load creates index and writes n documents 100 ms apart, every tenth
// sharing its millisecond with the one before.
func load(t *testing.T, base, user, pw, idx string, start time.Time, n int) {
	t.Helper()
	admin(t, base, user, pw, "PUT", "/"+idx, "application/json", []byte(mapping))
	var b bytes.Buffer
	levels := []string{"info", "info", "warn", "error"}
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * 100 * time.Millisecond)
		if i%10 == 1 {
			ts = start.Add(time.Duration(i-1) * 100 * time.Millisecond)
		}
		doc := map[string]any{"@timestamp": ts.UTC().Format(time.RFC3339Nano), "app": []string{"api", "worker"}[i%2], "level": levels[i%4],
			"pod": "p" + strconv.Itoa(i%3), "user_email": fmt.Sprintf("u%d@example.com", i%7), "event": map[string]any{"id": fmt.Sprintf("e%06d", i)},
			"message": fmt.Sprintf(`{"msg":"request %d","status":%d}`, i, 200+100*(i%4))}
		line, _ := json.Marshal(doc)
		b.WriteString(`{"index":{}}` + "\n")
		b.Write(line)
		b.WriteByte('\n')
	}
	out := admin(t, base, user, pw, "POST", "/"+idx+"/_bulk?refresh=true", "application/x-ndjson", b.Bytes())
	var r struct {
		Errors bool `json:"errors"`
	}
	if json.Unmarshal(out, &r) != nil || r.Errors {
		t.Fatalf("bulk: %.500s", out)
	}
}

func newSource(t *testing.T, kind, base string, auth string, creds egress.Credentials, indices []string, tie string) (*elastic.Source, *egress.Client) {
	t.Helper()
	routes, err := egress.ElasticRoutes(indices)
	if err != nil {
		t.Fatal(err)
	}
	r := &config.Remote{URL: base, Auth: auth}
	r.User = creds.User
	cl, err := egress.New(r, routes, creds, egress.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	s, err := elastic.New(elastic.Options{Name: "es", Kind: kind, Client: cl, Parser: p, Indices: indices,
		TrustedFields: []string{"app", "level"}, TieBreaker: tie, Size: 500})
	if err != nil {
		t.Fatal(err)
	}
	return s, cl
}

func scan(t *testing.T, s *elastic.Source, r source.Range, sel source.Selector) []source.RawRecord {
	t.Helper()
	plan, err := s.Plan(context.Background(), r, sel)
	if err != nil {
		t.Fatal(err)
	}
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		it, err := s.Scan(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		for {
			rec, err := it.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, rec)
		}
		it.Close()
	}
	return out
}

// exercise runs the reads every flavour must answer the same way.
func exercise(t *testing.T, s *elastic.Source, start time.Time, n int) {
	t.Helper()
	ctx := context.Background()
	r := source.Range{From: start, To: start.Add(10 * time.Minute)}
	recs := scan(t, s, r, source.Selector{})
	if len(recs) != n {
		t.Fatalf("%d records, want %d", len(recs), n)
	}
	seen := map[string]bool{}
	for i, rec := range recs {
		if seen[rec.Event.Raw] {
			t.Fatalf("duplicate %q", rec.Event.Raw)
		}
		seen[rec.Event.Raw] = true
		if i > 0 && rec.Event.Time.Before(recs[i-1].Event.Time) {
			t.Fatal("out of order")
		}
		for _, a := range rec.Event.Attrs {
			if a.Key != "app" && a.Key != "level" {
				t.Fatalf("attr %q returned (untrusted field)", a.Key)
			}
		}
		if strings.Contains(rec.Event.Raw, "@example.com") {
			t.Fatal("an untrusted field reached a record")
		}
	}
	// Server-side selection on trusted fields: levels repeat every 4
	// documents, apps every 2: error documents are api's... never (i%4==3
	// is odd: worker).
	sel := source.Selector{Terms: []source.Term{{Field: "level", Label: true, Op: "=", Values: []string{"error"}}, {Field: "app", Label: true, Op: "in", Values: []string{"worker"}}}}
	if got := scan(t, s, r, sel); len(got) != n/4 {
		t.Fatalf("selected %d records, want %d", len(got), n/4)
	}
	notSel := source.Selector{Terms: []source.Term{{Field: "level", Label: true, Op: "!=", Values: []string{"info"}}}}
	if got := scan(t, s, r, notSel); len(got) != n/2 {
		t.Fatalf("negated selection: %d records, want %d", len(got), n/2)
	}
	// Counts on the server equal the scan.
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"level"}, Bucket: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	byLevel := map[string]int64{}
	for _, row := range res.Rows {
		total += row.N
		byLevel[row.Vals[0]] += row.N
	}
	if total != int64(n) || byLevel["error"] != int64(n/4) {
		t.Fatalf("histogram total %d (%v), want %d", total, byLevel, n)
	}
	one, err := s.IndexCounts(ctx, source.CountQuery{Range: r})
	if err != nil || len(one.Rows) != 1 || one.Rows[0].N != int64(n) {
		t.Fatalf("_count: %v %+v", err, one.Rows)
	}
	by, err := s.IndexCounts(ctx, source.CountQuery{Range: r, ByLabels: []string{"app", "level"}})
	if err != nil {
		t.Fatal(err)
	}
	total = 0
	for _, row := range by.Rows {
		total += row.N
	}
	if total != int64(n) || len(by.Rows) != 4 {
		t.Fatalf("terms: %d in %d rows", total, len(by.Rows))
	}
	// Reread, a tied document included.
	for _, i := range []int{100, 101} {
		got, err := s.Reread(ctx, recs[i].Ref)
		if err != nil || got.Event.Raw != recs[i].Event.Raw {
			t.Fatalf("reread %d: %v", i, err)
		}
	}
	around, err := s.Around(ctx, recs[200].Ref, 2, 2)
	if err != nil || len(around) != 5 || around[2].Event.Raw != recs[200].Event.Raw {
		t.Fatalf("around: %v %d", err, len(around))
	}
	sch, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]source.FieldInfo{}
	for _, f := range sch.Fields {
		fields[f.Name] = f
	}
	if !fields["level"].Trusted || len(fields["level"].Values) != 3 || fields["pod"].Trusted || fields["pod"].Values != nil {
		t.Fatalf("describe: %+v", sch.Fields)
	}
}

// checkProduction fails unless a production Check of s accepts (ok) or
// refuses it with write grants listed.
func checkProduction(t *testing.T, what string, s *elastic.Source, ok bool) {
	t.Helper()
	info, err := s.Check(context.Background(), true)
	switch {
	case ok && (err != nil || !info.Verified || len(info.Write) != 0):
		t.Fatalf("%s refused on production: %+v %v", what, info, err)
	case !ok && err == nil:
		t.Fatalf("%s passed the production check: %+v", what, info)
	case !ok && len(info.Write) == 0:
		t.Fatalf("%s refused without write grants listed: %+v %v", what, info, err)
	}
}

func TestElasticsearch(t *testing.T) {
	base := env(t, "LOCKLOG_ES_URL")
	adm := env(t, "LOCKLOG_ES_ADMIN")
	au, ap, _ := strings.Cut(adm, ":")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	idx := "locklog-it-" + run
	pattern := idx[:len(idx)-2] + "*"
	start := time.Now().Add(-30 * time.Minute).Truncate(5 * time.Minute)
	const n = 2400
	load(t, base, au, ap, idx, start, n)
	pw := "Tz4#mQ9!vXr2Lp8$wK"
	user := func(name, role string) egress.Credentials {
		admin(t, base, au, ap, "PUT", "/_security/role/"+name, "application/json", []byte(role))
		admin(t, base, au, ap, "PUT", "/_security/user/"+name, "application/json", []byte(`{"password":"`+pw+`","roles":["`+name+`"]}`))
		return egress.Credentials{User: name, Secret: pw}
	}
	// An API key granted to a user: it holds the user's privileges.
	apiKey := func(u egress.Credentials) egress.Credentials {
		b := admin(t, base, au, ap, "POST", "/_security/api_key/grant", "application/json",
			[]byte(`{"grant_type":"password","username":"`+u.User+`","password":"`+u.Secret+`","api_key":{"name":"locklog-it-`+run+`"}}`))
		var k struct {
			ID      string `json:"id"`
			Key     string `json:"api_key"`
			Encoded string `json:"encoded"`
		}
		if json.Unmarshal(b, &k) != nil || k.Encoded == "" {
			t.Fatalf("grant: %s", b)
		}
		return egress.Credentials{Secret: k.Encoded}
	}
	reader := user("locklog_reader_"+run, `{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read","view_index_metadata"]}]}`)
	writer := user("locklog_writer_"+run, `{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read","view_index_metadata","write"]}]}`)

	for _, tie := range []string{"", "event.id"} {
		s, cl := newSource(t, elastic.KindElastic, base, config.AuthBasic, reader, []string{idx}, tie)
		checkProduction(t, "the read-only user", s, true)
		info, _ := s.Check(context.Background(), true)
		if info.Flavour != elastic.FlavourElasticsearch {
			t.Fatalf("flavour %+v", info)
		}
		if err := egress.CheckElasticUnauthenticated(context.Background(), cl, true, []string{idx}); err != nil {
			t.Fatalf("security on, yet: %v", err)
		}
		exercise(t, s, start, n)
	}
	// The read-only user's API key: accepted, and it reads.
	s, _ := newSource(t, elastic.KindElastic, base, config.AuthAPIKey, apiKey(reader), []string{pattern}, "")
	checkProduction(t, "the read-only API key", s, true)
	exercise(t, s, start, n)
	// The write-capable user and its API key: refused on production,
	// allowed elsewhere.
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, writer, []string{pattern}, "")
	checkProduction(t, "the write-capable user", s, false)
	if _, err := s.Check(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthAPIKey, apiKey(writer), []string{idx}, "")
	checkProduction(t, "the write-capable API key", s, false)
	// The superuser is refused on production.
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, egress.Credentials{User: au, Secret: ap}, []string{idx}, "")
	checkProduction(t, "the superuser", s, false)
	// Roles that read the index yet hold one more privilege reaching it:
	// a write on the concrete index the read-only pattern matches, a
	// write through another pattern covering it, a manage on the index,
	// a cluster privilege no denylist would name, run_as.
	for i, extra := range []string{
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]},{"names":["` + idx + `"],"privileges":["create_doc"]}]}`,
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]},{"names":["locklog-*"],"privileges":["delete"]}]}`,
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read","manage"]}]}`,
		`{"cluster":["monitor","manage_ingest_pipelines"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]}]}`,
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]}],"run_as":["elastic"]}`,
	} {
		u := user(fmt.Sprintf("locklog_extra_%d_%s", i, run), extra)
		s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, u, []string{pattern}, "")
		checkProduction(t, fmt.Sprintf("role %d", i), s, false)
	}
	// A write grant on indices the source does not read is refused too:
	// the check fails closed, on any pattern.
	u := user("locklog_unrelated_"+run, `{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read","view_index_metadata"]},{"names":["unrelated-`+run+`-*"],"privileges":["write"]}]}`)
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, u, []string{idx}, "")
	checkProduction(t, "a write on unrelated indices", s, false)
	// Write grants on an alias and on a data stream name.
	for i, extra := range []string{
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]},{"names":["locklog-alias-` + run + `"],"privileges":["index"]}]}`,
		`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read"]},{"names":["logs-locklog-` + run + `"],"privileges":["create_doc"]}]}`,
	} {
		u := user(fmt.Sprintf("locklog_alias_%d_%s", i, run), extra)
		s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, u, []string{idx}, "")
		checkProduction(t, fmt.Sprintf("alias/data stream grant %d", i), s, false)
	}
	// An OpenSearch source refuses an Elasticsearch backend.
	s, _ = newSource(t, elastic.KindOpenSearch, base, config.AuthBasic, reader, []string{idx}, "")
	if _, err := s.Check(context.Background(), false); err == nil {
		t.Fatal("kind opensearch accepted an Elasticsearch backend")
	}
	// A key that cannot read the index is refused everywhere.
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, reader, []string{"other-" + run}, "")
	if _, err := s.Check(context.Background(), false); err == nil {
		t.Fatal("a key without read passed")
	}
}

func TestOpenSearch(t *testing.T) {
	base := env(t, "LOCKLOG_OPENSEARCH_URL")
	adm := env(t, "LOCKLOG_OPENSEARCH_ADMIN")
	au, ap, _ := strings.Cut(adm, ":")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	idx := "locklog-it-" + run
	start := time.Now().Add(-30 * time.Minute).Truncate(5 * time.Minute)
	const n = 2400
	load(t, base, au, ap, idx, start, n)
	// The demo configuration maps every user to own_index (all on an index
	// named after the user): not a read-only role, so it is unmapped.
	if b, st := adminStatus(t, base, au, ap, "DELETE", "/_plugins/_security/api/rolesmapping/own_index", "application/json", nil); st/100 != 2 && st != 404 {
		t.Fatalf("unmap own_index: %d %s", st, b)
	}
	pw := "Tz4#mQ9!vXr2Lp8$wK"
	user := func(name, role string) egress.Credentials {
		admin(t, base, au, ap, "PUT", "/_plugins/_security/api/roles/"+name, "application/json", []byte(role))
		admin(t, base, au, ap, "PUT", "/_plugins/_security/api/internalusers/"+name, "application/json", []byte(`{"password":"`+pw+`"}`))
		admin(t, base, au, ap, "PUT", "/_plugins/_security/api/rolesmapping/"+name, "application/json", []byte(`{"users":["`+name+`"]}`))
		return egress.Credentials{User: name, Secret: pw}
	}
	readRole := `{"cluster_permissions":["cluster_composite_ops_ro","cluster_monitor"],"index_permissions":[{"index_patterns":["locklog-it-*"],"allowed_actions":["read","indices:admin/mappings/get"]}]}`
	reader := user("locklog_reader_"+run, readRole)
	writer := user("locklog_writer_"+run, `{"cluster_permissions":["cluster_composite_ops_ro","cluster_monitor"],"index_permissions":[{"index_patterns":["locklog-it-*"],"allowed_actions":["read","write"]}]}`)

	for _, tie := range []string{"", "event.id"} {
		s, cl := newSource(t, elastic.KindOpenSearch, base, config.AuthBasic, reader, []string{idx}, tie)
		// A custom role is not known read-only: refused until vouched for.
		checkProduction(t, "an unvouched custom role", s, false)
		if err := egress.CheckElasticUnauthenticated(context.Background(), cl, true, []string{idx}); err != nil {
			t.Fatalf("security on, yet: %v", err)
		}
		exercise(t, s, start, n)
	}
	vouched := func(creds egress.Credentials, roles ...string) *elastic.Source {
		routes, _ := egress.ElasticRoutes([]string{idx})
		r := &config.Remote{URL: base, Auth: config.AuthBasic}
		r.User = creds.User
		cl, err := egress.New(r, routes, creds, egress.Options{})
		if err != nil {
			t.Fatal(err)
		}
		p, _ := parse.New(parse.Options{})
		s, err := elastic.New(elastic.Options{Name: "os", Kind: elastic.KindOpenSearch, Client: cl, Parser: p, Indices: []string{idx},
			TrustedFields: []string{"app", "level"}, ReadOnlyRoles: roles})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := vouched(reader, "locklog_reader_"+run)
	checkProduction(t, "the vouched read-only role", s, true)
	if info, _ := s.Check(context.Background(), true); info.Flavour != elastic.FlavourOpenSearch {
		t.Fatalf("flavour %+v", info)
	}
	// The write-capable role, the admin: refused on production.
	checkProduction(t, "the write-capable role", vouched(writer, "locklog_reader_"+run), false)
	checkProduction(t, "the admin", vouched(egress.Credentials{User: au, Secret: ap}), false)
	if _, err := vouched(writer).Check(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// An Elasticsearch source refuses an OpenSearch backend.
	s, _ = newSource(t, elastic.KindElastic, base, config.AuthBasic, reader, []string{idx}, "")
	if _, err := s.Check(context.Background(), false); err == nil {
		t.Fatal("kind elastic accepted an OpenSearch backend")
	}
}
