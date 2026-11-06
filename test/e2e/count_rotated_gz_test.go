//go:build e2e

// Package e2e runs locklog as a user does: the image, the console started
// hub-attached as lox run starts it (approved at its terminal), and the
// launcher's mcp, driven by an MCP client. It needs Docker and the image
// built as `locklog`: it runs in CI (job "e2e (docker)"), never on a
// developer machine. Run with:
//
//	LOCKLOG_E2E_DIR=<empty directory of yours> go test -tags e2e ./test/e2e
package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The personal values written in the logs: none may reach the agent.
var (
	emails = []string{"jane.doorstep@example.org", "marcel.quintavalle@example.net", "e2e-user-7@example.com"}
	names  = []string{"Jane Doorstep", "Marcel Quintavalle", "Oriane Pelletback"}
)

// The rotated files, oldest first, and their line counts.
var files = []struct {
	name  string
	lines int
	gz    bool
}{
	{"app.log.3.gz", 20, true},
	{"app.log.2.gz", 30, true},
	{"app.log.1", 40, false},
	{"app.log", 50, false},
}

const step = 10 * time.Second // between two records

// buffer is an io.Writer safe for concurrent use.
type buffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// ansi matches the terminal escapes of the console's output.
var ansi = regexp.MustCompile(`\x1b(\[[0-9;?]*[ -/]*[@-~]|[78]|\][^\a]*\a)`)

func plain(s string) string { return strings.ReplaceAll(ansi.ReplaceAllString(s, ""), "\r", "") }

// waitFor waits until the plain text of b holds want.
func waitFor(t *testing.T, b *buffer, want string, timeout time.Duration, exited <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(plain(b.String()), want) {
			return
		}
		select {
		case <-exited:
			if strings.Contains(plain(b.String()), want) {
				return
			}
			t.Fatalf("the console ended before printing %q", want)
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("the console did not print %q within %s", want, timeout)
}

// writeLogs writes the rotated logs in dir, one record every step from
// start, and returns the number of records.
func writeLogs(t *testing.T, dir string, start time.Time) int {
	t.Helper()
	i := 0
	for _, f := range files {
		var b bytes.Buffer
		for n := 0; n < f.lines; n++ {
			email, name := emails[i%len(emails)], names[i%len(names)]
			fmt.Fprintf(&b, "time=%s level=%s order=%d email=%s customer_name=%q msg=%q\n",
				start.Add(time.Duration(i)*step).Format(time.RFC3339), []string{"info", "warn", "error"}[i%3], i, email, name,
				fmt.Sprintf("order %d shipped to %s", i, email))
			i++
		}
		data := b.Bytes()
		if f.gz {
			var z bytes.Buffer
			w := gzip.NewWriter(&z)
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			data = z.Bytes()
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, f.name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return i
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Whatever the umask: the console and the agent accounts read them.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// out is the structured output of a locklog tool.
type out struct {
	Data    json.RawMessage `json:"data"`
	Refusal json.RawMessage `json:"refusal"`
}

// result is the data of a locklog_count or a locklog_search.
type result struct {
	Groups []struct {
		N json.Number `json:"n"`
	} `json:"groups"`
	Records  []json.RawMessage `json:"records"`
	Complete bool              `json:"complete"`
	Cursor   string            `json:"cursor"`
}

// decode decodes the data of a locklog_count or a locklog_search.
func decode(t *testing.T, tool string, o out) result {
	t.Helper()
	var r result
	if err := json.Unmarshal(o.Data, &r); err != nil {
		t.Fatalf("%s: data: %v: %s", tool, err, o.Data)
	}
	return r
}

// text is the text content of a tool result.
func text(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// call calls a tool and decodes its structured output; a tool error or a
// refusal fails the test.
func call(t *testing.T, ctx context.Context, cs *mcp.ClientSession, tool string, args map[string]any) (out, string) {
	t.Helper()
	r, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	txt := text(r)
	if r.IsError {
		t.Fatalf("%s: tool error: %s", tool, txt)
	}
	var o out
	j, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(j, &o); err != nil {
		t.Fatalf("%s: structured output: %v: %s", tool, err, j)
	}
	if len(o.Refusal) > 0 && string(o.Refusal) != "null" {
		t.Fatalf("%s: refused: %s", tool, o.Refusal)
	}
	return o, txt
}

// count sums the groups of a locklog_count over every page, and returns
// the number of calls it took.
func count(t *testing.T, ctx context.Context, cs *mcp.ClientSession, args map[string]any) (total int64, groups, calls int) {
	t.Helper()
	for {
		raw, txt := call(t, ctx, cs, "locklog_count", args)
		o := decode(t, "locklog_count", raw)
		calls++
		for _, g := range o.Groups {
			n, err := g.N.Int64()
			if err != nil {
				t.Fatalf("locklog_count: group count %q: %v", g.N, err)
			}
			total += n
			groups++
		}
		if o.Complete {
			return total, groups, calls
		}
		if o.Cursor == "" || calls >= 50 {
			t.Fatalf("locklog_count: incomplete with no cursor to continue (after %d calls): %s", calls, txt)
		}
		next := map[string]any{}
		for k, v := range args {
			next[k] = v
		}
		next["cursor"] = o.Cursor
		args = next
	}
}

func TestCountRotatedGz(t *testing.T) {
	e, want, from, to := newEnv(t, "count")
	t.Logf("%d records in %d files, %s to %s", want, len(files), from, to)

	cfg := strings.Join([]string{
		"version = 1",
		"[profiles.e2e]",
		"production = false",
		"[profiles.e2e.sources.app]",
		`kind = "file"`,
		fmt.Sprintf("paths = [%q]", e.logs+"/app.log*"),
		`format = "logfmt"`,
		"",
	}, "\n")
	mkdir(t, filepath.Join(e.proj, ".locklog"))
	cfgPath := filepath.Join(e.proj, ".locklog", "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0o644); err != nil {
		t.Fatal(err)
	}

	// The console, as lox run starts it, hub-attached; first start: the
	// policy review, approved as a human does at its terminal.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	lr := startLoxRun(t, e, "e2e", "", [2]string{"Apply these changes? [y/N]", "y"})

	// The agent: the launcher's mcp over stdin and stdout, on lox run's
	// socket volume.
	cs := e.connect(t, ctx, []string{"locklog", "mcp"})

	tl, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var tools []string
	for _, tool := range tl.Tools {
		tools = append(tools, tool.Name)
	}
	for _, need := range []string{"locklog_status", "locklog_count", "locklog_search"} {
		if !strings.Contains(" "+strings.Join(tools, " ")+" ", " "+need+" ") {
			t.Fatalf("tools/list: no %s in %v", need, tools)
		}
	}

	_, st := call(t, ctx, cs, "locklog_status", nil)
	if !strings.Contains(st, "profile e2e: console running") {
		t.Fatalf("locklog_status: the console is not running:\n%s", st)
	}

	total, _, countCalls := count(t, ctx, cs, map[string]any{"from": from, "to": to})
	t.Logf("locklog_count: %d records (%d calls)", total, countCalls)
	if total != int64(want) {
		t.Errorf("locklog_count over %s..%s = %d, want %d (the lines of app.log, app.log.1 and the .gz files)", from, to, total, want)
	}
	bucketed, groups, calls := count(t, ctx, cs, map[string]any{"from": from, "to": to, "bucket": "5m"})
	countCalls += calls
	t.Logf("locklog_count bucket 5m: %d buckets summing to %d (%d calls)", groups, bucketed, calls)
	if groups < 2 {
		t.Errorf("locklog_count bucket 5m: %d buckets, want several over %s..%s", groups, from, to)
	}
	if bucketed != int64(want) {
		t.Errorf("locklog_count bucket 5m sums to %d, want %d", bucketed, want)
	}

	sraw, stext := call(t, ctx, cs, "locklog_search", map[string]any{"from": from, "to": to, "limit": 50})
	so := decode(t, "locklog_search", sraw)
	t.Logf("locklog_search: %d records", len(so.Records))
	if len(so.Records) == 0 {
		t.Errorf("locklog_search: no records:\n%s", stext)
	}
	if !strings.Contains(stext, "⟦email:") {
		t.Errorf("locklog_search: no ⟦email: pseudonym in the result:\n%s", stext)
	}
	j, _ := json.Marshal(sraw)
	for _, clear := range append(append([]string{}, emails...), names...) {
		for _, where := range []string{stext, string(j)} {
			if strings.Contains(strings.ToLower(where), strings.ToLower(clear)) {
				t.Errorf("locklog_search: the clear value %q reached the agent", clear)
			}
		}
		// Each part of a name too (Doorstep, Quintavalle...).
		for _, part := range strings.Fields(clear) {
			if len(part) > 4 && !strings.Contains(part, "@") && strings.Contains(stext, part) {
				t.Errorf("locklog_search: %q (of a clear name) reached the agent", part)
			}
		}
	}
	if t.Failed() {
		t.Logf("locklog_search result:\n%s", stext)
	}

	// The console's audit: one log.call record per call that reached it.
	auditOut := lr.auditLog(t, e.image)
	methods := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(auditOut)), "\n") {
		var rec struct {
			Event    string `json:"event"`
			Method   string `json:"method"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		if rec.Event == "log.call" {
			methods[rec.Method]++
		}
	}
	t.Logf("audit: log.call records by method: %v", methods)
	if methods["log.count"] != countCalls {
		t.Errorf("audit: %d log.count records, want %d (one per call)", methods["log.count"], countCalls)
	}
	if methods["log.search"] != 1 {
		t.Errorf("audit: %d log.search records, want 1", methods["log.search"])
	}
	for _, clear := range append(append([]string{}, emails...), names...) {
		if strings.Contains(string(auditOut), clear) {
			t.Errorf("audit: the clear value %q is in the audit log", clear)
		}
	}
	if t.Failed() {
		t.Logf("audit log:\n%s", auditOut)
	}
}
