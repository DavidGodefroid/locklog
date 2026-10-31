//go:build integration && unix

package elastic_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
)

// loadEmails writes n documents 100 ms apart into idx, each message
// naming an e-mail address.
func loadEmails(t *testing.T, base, user, pw, idx string, start time.Time, n int) {
	t.Helper()
	admin(t, base, user, pw, "PUT", "/"+idx, "application/json", []byte(mapping))
	var b bytes.Buffer
	levels := []string{"info", "info", "warn", "error"}
	for i := 0; i < n; i++ {
		doc := map[string]any{"@timestamp": start.Add(time.Duration(i) * 100 * time.Millisecond).UTC().Format(time.RFC3339Nano),
			"app": []string{"api", "worker"}[i%2], "level": levels[i%4], "pod": "p" + strconv.Itoa(i%3), "user_email": fmt.Sprintf("u%d@example.com", i%7),
			"message": fmt.Sprintf(`{"msg":"payment %d failed for u%d@example.com","status":%d}`, i, i%7, 200+100*(i%4))}
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

// openSession opens the console's engine of a one-source profile over
// the backend, with the reader's secret, as the console does once it has
// asked for it: config, then policy, then session.
func openSession(t *testing.T, kind, base, idx string, creds egress.Credentials) *session.Session {
	t.Helper()
	project, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`version = 1
[profiles.staging]
structured = "redact-unknown"
[profiles.staging.sources.search]
kind = %q
format = "json"
url = %q
indices = [%q]
trusted_fields = ["app", "level"]
auth = "basic"
user = %q
`, kind, base, idx, creds.User)
	ps, err := config.ParseProfiles([]byte(cfg), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := config.NewPolicy(ps["staging"], "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Open(context.Background(), session.Options{
		OpenOptions: logconsole.OpenOptions{Policy: pol, Credentials: creds, StateDir: state, Project: project},
		FirstOpen:   true,
		Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if st := s.Status(context.Background()).(session.Status); len(st.Notes) != 0 {
		t.Fatalf("the backend check failed: %q", st.Notes)
	}
	return s
}

func handle(t *testing.T, s *session.Session, method, params string) any {
	t.Helper()
	res, ref, err := s.Handle(context.Background(), method, json.RawMessage(params), logconsole.Caller{})
	if err != nil || ref != nil {
		t.Fatalf("%s %s: %v %+v", method, params, err, ref)
	}
	return res
}

func countTotal(res any) int64 {
	var n int64
	for _, g := range res.(engine.CountResult).Groups {
		n += g.N
	}
	return n
}

// sessionCounts checks masked counts and a masked search through the
// session.
func sessionCounts(t *testing.T, s *session.Session, start time.Time, n int) {
	t.Helper()
	window := fmt.Sprintf(`"from":%q,"to":%q`, start.UTC().Format(time.RFC3339Nano), start.Add(10*time.Minute).UTC().Format(time.RFC3339Nano))
	res := handle(t, s, logconsole.MethodCount, `{`+window+`,"text":"failed","by_labels":["level"]}`)
	out, _ := json.Marshal(res)
	if countTotal(res) != int64(n) || strings.Contains(string(out), "example.com") {
		t.Fatalf("scanned count: %s", out)
	}
	res = handle(t, s, logconsole.MethodCount, `{`+window+`,"where":[{"label":"level","op":"=","value":"error"}],"by_labels":["level"]}`)
	out, _ = json.Marshal(res)
	if countTotal(res) != int64(n/4) || !strings.Contains(string(out), `"error"`) {
		t.Fatalf("trusted count: %s", out)
	}
	res = handle(t, s, logconsole.MethodCount, `{`+window+`,"by_pattern":true}`)
	out, _ = json.Marshal(res)
	if countTotal(res) != int64(n) || strings.Contains(string(out), "example.com") {
		t.Fatalf("pattern count: %s", out)
	}
	res = handle(t, s, logconsole.MethodSearch, `{`+window+`,"limit":20}`)
	out, _ = json.Marshal(res)
	if strings.Contains(string(out), "example.com") || !strings.Contains(string(out), "⟦email:") || strings.Contains(string(out), "user_email") {
		t.Fatalf("search: %s", out)
	}
}

func TestSessionOpenSearch(t *testing.T) {
	base := env(t, "LOCKLOG_OPENSEARCH_URL")
	au, ap, _ := strings.Cut(env(t, "LOCKLOG_OPENSEARCH_ADMIN"), ":")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	idx := "locklog-it-s" + run
	start := time.Now().Add(-30 * time.Minute).Truncate(5 * time.Minute)
	const n = 800
	loadEmails(t, base, au, ap, idx, start, n)
	if b, st := adminStatus(t, base, au, ap, "DELETE", "/_plugins/_security/api/rolesmapping/own_index", "application/json", nil); st/100 != 2 && st != 404 {
		t.Fatalf("unmap own_index: %d %s", st, b)
	}
	name, pw := "locklog_sreader_"+run, "Tz4#mQ9!vXr2Lp8$wK"
	admin(t, base, au, ap, "PUT", "/_plugins/_security/api/roles/"+name, "application/json",
		[]byte(`{"cluster_permissions":["cluster_composite_ops_ro","cluster_monitor"],"index_permissions":[{"index_patterns":["locklog-it-*"],"allowed_actions":["read","indices:admin/mappings/get","indices:monitor/settings/get"]}]}`))
	admin(t, base, au, ap, "PUT", "/_plugins/_security/api/internalusers/"+name, "application/json", []byte(`{"password":"`+pw+`"}`))
	admin(t, base, au, ap, "PUT", "/_plugins/_security/api/rolesmapping/"+name, "application/json", []byte(`{"users":["`+name+`"]}`))
	s := openSession(t, config.KindOpenSearch, base, idx, egress.Credentials{User: name, Secret: pw})
	sessionCounts(t, s, start, n)
}

func TestSessionElasticsearch(t *testing.T) {
	base := env(t, "LOCKLOG_ES_URL")
	au, ap, _ := strings.Cut(env(t, "LOCKLOG_ES_ADMIN"), ":")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	idx := "locklog-it-s" + run
	start := time.Now().Add(-30 * time.Minute).Truncate(5 * time.Minute)
	const n = 800
	loadEmails(t, base, au, ap, idx, start, n)
	name, pw := "locklog_sreader_"+run, "Tz4#mQ9!vXr2Lp8$wK"
	admin(t, base, au, ap, "PUT", "/_security/role/"+name, "application/json",
		[]byte(`{"cluster":["monitor"],"indices":[{"names":["locklog-it-*"],"privileges":["read","view_index_metadata"]}]}`))
	admin(t, base, au, ap, "PUT", "/_security/user/"+name, "application/json", []byte(`{"password":"`+pw+`","roles":["`+name+`"]}`))
	s := openSession(t, config.KindElastic, base, idx, egress.Credentials{User: name, Secret: pw})
	sessionCounts(t, s, start, n)
}
