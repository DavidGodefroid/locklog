//go:build integration && unix

package loki_test

import (
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
	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
)

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

// The console's engine over the CI Loki: config, then policy, then
// session, then masked counts and a masked search.
func TestSessionLoki(t *testing.T) {
	base := lokiURL(t)
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	start := time.Now().Add(-20 * time.Minute).Truncate(5 * time.Minute)
	const n = 400
	push(t, base, run, start, n)

	project, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`version = 1
[profiles.staging]
structured = "redact-unknown"
[profiles.staging.sources.loki]
kind = "loki"
format = "json"
url = %q
selector = { run = %q }
trusted_labels = ["app", "level"]
trusted_metadata = ["trace_id"]
auth = "none"
`, base, run)
	ps, err := config.ParseProfiles([]byte(cfg), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := config.NewPolicy(ps["staging"], "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Open(context.Background(), session.Options{
		OpenOptions: logconsole.OpenOptions{Policy: pol, StateDir: state, Project: project},
		FirstOpen:   true,
		Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	window := fmt.Sprintf(`"from":%q,"to":%q`, start.UTC().Format(time.RFC3339Nano), start.Add(10*time.Minute).UTC().Format(time.RFC3339Nano))
	// Ingestion: wait until every entry reads back.
	var res any
	for i := 0; i < 60; i++ {
		if res = handle(t, s, logconsole.MethodCount, `{`+window+`,"text":"request","by_labels":["level"]}`); countTotal(res) >= n {
			break
		}
		time.Sleep(time.Second)
	}
	out, _ := json.Marshal(res)
	if countTotal(res) != n || strings.Contains(string(out), "example.com") {
		t.Fatalf("scanned count: %s", out)
	}
	// Trusted-only: Loki's metric counts.
	res = handle(t, s, logconsole.MethodCount, `{`+window+`,"where":[{"label":"level","op":"=","value":"error"}],"by_labels":["level"]}`)
	out, _ = json.Marshal(res)
	if countTotal(res) != n/4 || !strings.Contains(string(out), `"error"`) {
		t.Fatalf("trusted count: %s", out)
	}
	res = handle(t, s, logconsole.MethodCount, `{`+window+`,"by_pattern":true}`)
	out, _ = json.Marshal(res)
	if countTotal(res) != n || strings.Contains(string(out), "example.com") {
		t.Fatalf("pattern count: %s", out)
	}
	res = handle(t, s, logconsole.MethodSearch, `{`+window+`,"limit":20}`)
	out, _ = json.Marshal(res)
	if strings.Contains(string(out), "example.com") || !strings.Contains(string(out), "⟦email:") || strings.Contains(string(out), "user_email") || strings.Contains(string(out), `"pod"`) {
		t.Fatalf("search: %s", out)
	}
}
