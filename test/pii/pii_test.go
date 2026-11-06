//go:build unix

// Package pii runs the PII rules end to end in one process, as an agent
// meets them: the MCP tools, the console server (lockkit) with the
// logconsole backend and a real engine session over a log file. The
// tests need Unix (the engine's file source).
package pii

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mcptools"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// maskedName is a key holding a personal value: the records show it as
// ⟦key:ID⟧, and it must never be written anywhere.
const maskedName = "jane.doe@example.com"

const appLog = `{"time":"2026-10-30T13:00:01Z","level":"error","status":502,"msg":"payment failed","city":"Lyon","` + maskedName + `":"vip"}
`

const cfg = `version = 1
[profiles.staging]
structured = "MODE"
[profiles.staging.sources.app]
kind = "file"
format = "json"
paths = ["LOGS/app.log"]
trusted = ["level", "status"]
`

type termIO struct {
	mu     sync.Mutex
	out    []string
	answer string
}

func (f *termIO) Println(s string) { f.mu.Lock(); defer f.mu.Unlock(); f.out = append(f.out, s) }
func (f *termIO) Ask(context.Context, string, time.Duration) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.answer, f.answer != ""
}
func (f *termIO) AskSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("no secret")
}
func (f *termIO) output() string { f.mu.Lock(); defer f.mu.Unlock(); return strings.Join(f.out, "\n") }

type rig struct {
	t     *testing.T
	root  string
	state string
	srv   *console.Server
	io    *termIO
	cs    *mcp.ClientSession
	opens atomic.Int32
}

// srvConn calls the server in process, as the agent's peer.
type srvConn struct {
	r *rig
	n atomic.Int64
}

func (c *srvConn) Call(ctx context.Context, method string, params, result any) error {
	var raw json.RawMessage
	if params != nil {
		var err error
		if raw, err = json.Marshal(params); err != nil {
			return err
		}
	}
	ctx = console.WithPeer(ctx, ipc.Cred{UID: 1000, PID: 4242})
	resp := c.r.srv.Handle(ctx, ipc.Request{JSONRPC: "2.0", ID: c.n.Add(1), Method: method, Params: raw})
	if resp.Error != nil {
		return resp.Error
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}
func (c *srvConn) Close() error { return nil }

func newRig(t *testing.T, mode string) *rig {
	t.Helper()
	r := &rig{t: t, root: t.TempDir(), state: t.TempDir(), io: &termIO{}}
	logs, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.WriteFile(filepath.Join(logs, "app.log"), []byte(appLog), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(r.root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, ".locklog", "config.toml"), []byte(strings.NewReplacer("LOGS", logs, "MODE", mode).Replace(cfg)), 0o644); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC) }
	open := func(ctx context.Context, oo logconsole.OpenOptions) (logconsole.Engine, error) {
		first := r.opens.Add(1) == 1
		return session.Open(ctx, session.Options{OpenOptions: oo, FirstOpen: first, Now: now,
			Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
	}
	be := logconsole.New(logconsole.Options{Profile: "staging", Root: r.root, StateDir: filepath.Join(r.state, product.P.Name),
		ExtraRoots: []string{logs}, Open: open})
	pol, err := be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := be.Connect(context.Background(), console.Credentials{Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(product.P, r.state)
	if err != nil {
		t.Fatal(err)
	}
	r.srv, err = console.NewServer(console.ServerConfig{Product: product.P, Backend: be, Policy: pol, Session: sess, Audit: log, IO: r.io,
		Approver: console.NewTypedApprover(r.io), Sanitizer: logconsole.Sanitizer(), Now: now, Quantum: -1,
		ReconnectPolicy: func(ctx context.Context, p console.Policy) (console.Session, error) {
			return be.Connect(ctx, console.Credentials{Policy: p})
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.srv.Close)

	conn := &srvConn{r: r}
	tools := mcptools.New(mcptools.Options{Profiles: func() ([]string, error) { return []string{"staging"}, nil },
		Dial: func(string) (mcptools.Conn, error) { return conn, nil }, Version: "test"})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := tools.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.cs, err = mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.cs.Close(); ss.Close() })
	return r
}

// call returns the tool's text and whether it is an error.
func (r *rig) call(tool string, args map[string]any) (string, bool) {
	r.t.Helper()
	res, err := r.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		r.t.Fatalf("%s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func (r *rig) search() string {
	r.t.Helper()
	text, isErr := r.call(mcptools.ToolSearch, map[string]any{"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z"})
	if isErr {
		r.t.Fatalf("search: %s", text)
	}
	return text
}

func (r *rig) auditLog() string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.state, product.P.Name, "audit.log"))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

var keyRe = regexp.MustCompile(`⟦key:[A-Z0-9]+⟧`)

// locklog_pii_add on a key shown masked: the field is masked from the
// next call on, locklog_status counts the rule, and no name the agent was
// shown masked reaches the audit, the console's terminal, the agent's
// answers or .locklog.
func TestPIIAddThenStatus(t *testing.T) {
	r := newRig(t, "detect")
	out := r.search()
	key := keyRe.FindString(out)
	if key == "" || !strings.Contains(out, "vip") || !strings.Contains(out, "payment failed") {
		t.Fatalf("no masked key, or values masked, in %s", out)
	}
	if text, isErr := r.call(mcptools.ToolPIIAdd, map[string]any{"pattern": "app:" + key}); isErr {
		t.Fatalf("pii_add: %s", text)
	}
	if text, isErr := r.call(mcptools.ToolPIIAdd, map[string]any{"pattern": "app:" + maskedName}); !isErr || !strings.Contains(text, "E_PII_IN_QUERY") || strings.Contains(text, maskedName) {
		t.Errorf("pii_add of a clear masked name: %s", text)
	}
	if text, isErr := r.call(mcptools.ToolPIIAdd, map[string]any{"pattern": "msg"}); isErr {
		t.Fatalf("pii_add msg: %s", text)
	}
	if out := r.search(); strings.Contains(out, "payment failed") || strings.Contains(out, "vip") || !strings.Contains(out, key) {
		t.Errorf("the rules are not applied: %s", out)
	}
	st, _ := r.call(mcptools.ToolStatus, nil)
	if !regexp.MustCompile(`"rules":\s*2`).MatchString(st) || !regexp.MustCompile(`"adds_last_hour":\s*2`).MatchString(st) || !strings.Contains(st, `"last_add"`) {
		t.Errorf("status: %s", st)
	}
	list, _ := r.call(mcptools.ToolPIIList, nil)
	if strings.Count(list, "agent redact") != 2 || regexp.MustCompile(`[0-9a-f]{64}`).MatchString(list) {
		t.Errorf("pii_list: %s", list)
	}
	log := r.auditLog()
	for _, w := range []string{maskedName, "jane", strings.TrimSuffix(strings.TrimPrefix(key, "⟦key:"), "⟧")} {
		if strings.Contains(log, w) {
			t.Errorf("the audit holds %q:\n%s", w, log)
		}
		if strings.Contains(r.io.output(), w) {
			t.Errorf("the console's terminal shows %q:\n%s", w, r.io.output())
		}
	}
	if n := strings.Count(log, `"method":"pii.add"`); n != 3 {
		t.Errorf("%d pii.add records, want 3 (2 added, 1 refused):\n%s", n, log)
	}
	if _, err := os.Stat(filepath.Join(r.root, ".locklog", "pii.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pii.toml written: %v", err)
	}
}

// An allow rule added to .locklog/pii.toml waits for :review; once the
// human approves it, it takes effect at the agent's next call, with no
// reconnection.
func TestReviewedAllowRuleApplies(t *testing.T) {
	r := newRig(t, "redact-unknown")
	if out := r.search(); strings.Contains(out, "Lyon") {
		t.Fatalf("city in clear before any allow rule: %s", out)
	}
	if err := os.WriteFile(filepath.Join(r.root, ".locklog", "pii.toml"), []byte("[[allow]]\nfield = \"city\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.srv.CheckPolicy()
	if !r.srv.PolicyPending() {
		t.Fatalf("an added allow rule is not a loosening:\n%s", r.io.output())
	}
	if out := r.search(); strings.Contains(out, "Lyon") {
		t.Fatalf("an unapproved allow rule applies: %s", out)
	}
	r.io.mu.Lock()
	r.io.answer = "y"
	r.io.mu.Unlock()
	r.srv.Command(context.Background(), ":review")
	if !strings.Contains(r.io.output(), "pii.allow") || !strings.Contains(r.io.output(), "policy change applied") {
		t.Fatalf("review:\n%s", r.io.output())
	}
	if out := r.search(); !strings.Contains(out, "Lyon") {
		t.Errorf("the approved allow rule is not applied: %s", out)
	}
	// Removing it only tightens: applied at once.
	if err := os.WriteFile(filepath.Join(r.root, ".locklog", "pii.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r.srv.CheckPolicy()
	if r.srv.PolicyPending() {
		t.Fatal("removing an allow rule waits for review")
	}
	if out := r.search(); strings.Contains(out, "Lyon") {
		t.Errorf("a removed allow rule still applies: %s", out)
	}
}
