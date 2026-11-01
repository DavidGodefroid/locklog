//go:build unix

package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/plans"

	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mcptools"
	"github.com/DavidGodefroid/locklog/internal/product"
)

const instance = "logs"

// The personal values and the secret in the log: none may reach the agent
// or the hub's masked screen.
const (
	email1 = "jane.doe@example.com"
	email2 = "bob.marley@example.org"
	secret = "AKIAIOSFODNN7EXAMPLE"
)

var appLog = `{"time":"2026-10-30T13:00:01Z","level":"error","status":502,"msg":"payment failed for ` + email1 + ` cc ` + email2 + ` key ` + secret + `"}
{"time":"2026-10-30T13:00:02Z","level":"error","status":503,"msg":"retry failed for ` + email1 + `"}
{"time":"2026-10-30T13:00:03Z","level":"info","status":200,"msg":"ok"}
`

const cfg = `version = 1
[profiles.staging]
structured = "redact-unknown"
EXTRA
[profiles.staging.sources.app]
kind = "file"
format = "json"
paths = ["LOGS/app.log"]
trusted = ["level", "status"]
`

// clock is the console's clock, which a test moves (ticket expiry).
type clock struct {
	mu sync.Mutex
	d  time.Duration
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.d) }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.d += d
	c.mu.Unlock()
}

type fakeIO struct {
	mu      sync.Mutex
	out     []string
	prompts int
}

func (f *fakeIO) Println(s string) { f.mu.Lock(); defer f.mu.Unlock(); f.out = append(f.out, s) }
func (f *fakeIO) Ask(context.Context, string, time.Duration) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts++
	return "", false
}
func (f *fakeIO) AskSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("no secret")
}
func (f *fakeIO) output() string   { f.mu.Lock(); defer f.mu.Unlock(); return strings.Join(f.out, "\n") }
func (f *fakeIO) promptCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.prompts }

type rigOpts struct {
	extra   string // profile keys
	hubOpts func(*console.HubOptions)
}

type rig struct {
	t     *testing.T
	srv   *console.Server
	hub   *hubtest.Hub
	h     *console.Hub
	pub   ed25519.PublicKey
	io    *fakeIO
	clock *clock
	state string
	cs    *mcp.ClientSession
	// outputs are every text and structured output the agent got.
	mu      sync.Mutex
	outputs []string
	token   string
}

// srvConn is a console connection that calls the server in process, as
// the agent's peer.
type srvConn struct {
	r   *rig
	uid int
	n   atomic.Int64
}

func (c *srvConn) Call(ctx context.Context, method string, params, result any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if params == nil {
		raw = nil
	}
	ctx = console.WithPeer(ctx, ipc.Cred{UID: c.uid, PID: 4242})
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

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	r := &rig{t: t, io: &fakeIO{}, clock: &clock{}, state: t.TempDir(), token: "tok-1"}
	root := t.TempDir()
	logs, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.WriteFile(filepath.Join(logs, "app.log"), []byte(appLog), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := strings.ReplaceAll(strings.ReplaceAll(cfg, "LOGS", logs), "EXTRA", o.extra)
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
	sessNow := func() time.Time { return time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC) }
	first := true
	open := func(ctx context.Context, oo logconsole.OpenOptions) (logconsole.Engine, error) {
		s, err := session.Open(ctx, session.Options{OpenOptions: oo, FirstOpen: first, Now: sessNow,
			Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
		first = false
		return s, err
	}
	be := logconsole.New(logconsole.Options{Profile: "staging", Root: root, StateDir: filepath.Join(r.state, product.P.Name),
		ExtraRoots: []string{logs}, Open: open, Now: r.clock.now})
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

	// The hub: the instance key in the console's home, the hub's key
	// pinned in a file.
	home := t.TempDir()
	key, err := hubclient.InstanceKey(home, instance)
	if err != nil {
		t.Fatal(err)
	}
	r.pub = key.Public().(ed25519.PublicKey)
	r.hub = hubtest.New(t, instance, r.pub)
	hubKey := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(hubKey, []byte(base64.StdEncoding.EncodeToString(r.hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ho := console.HubOptions{URL: r.hub.URL(), KeyFile: hubKey, Instance: instance, Home: home}
	if o.hubOpts != nil {
		o.hubOpts(&ho)
	}
	r.h, err = console.OpenHub(product.P, ho, r.state, r.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	// As console.Run: OnHub before any request, the watch, the requests.
	be.OnHub(r.h)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.h.Watch(ctx, r.io) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if err := r.h.Close(); err != nil {
			t.Error(err)
		}
	})
	r.srv, err = console.NewServer(console.ServerConfig{Product: product.P, Backend: be, Policy: pol, Session: sess, Audit: log, IO: r.io,
		Hub: r.h, Approver: r.h.Approver(console.NewTypedApprover(r.io)), Sanitizer: logconsole.Sanitizer(), Now: r.clock.now, Quantum: -1})
	if err != nil {
		t.Fatal(err)
	}
	r.h.Requests(r.io, func(b audit.Base) { r.srv.AuditBase(context.Background(), b) })
	t.Cleanup(r.srv.Close)
	r.cs = r.mcp(r.token)
	return r
}

// mcp connects an MCP client to the tools of an agent with token tok.
func (r *rig) mcp(tok string) *mcp.ClientSession {
	r.t.Helper()
	conn := &srvConn{r: r, uid: 1000}
	srv := mcptools.New(mcptools.Options{Profiles: func() ([]string, error) { return []string{"staging"}, nil },
		Dial: func(string) (mcptools.Conn, error) { return conn, nil }, Version: "test",
		Requester: ipc.Requester{Agent: "dev-1", Token: plans.HashToken(tok)}})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

// answer is what the agent got from one tool call.
type answer struct {
	text  string
	isErr bool
	out   struct {
		Data    json.RawMessage `json:"data"`
		Refusal *struct {
			Code  string `json:"code"`
			Retry string `json:"retry"`
		} `json:"refusal"`
	}
}

func (a answer) pending() (string, bool) {
	var p struct{ Status, Ticket, Lock, Instance string }
	if json.Unmarshal(a.out.Data, &p) != nil || p.Status != "pending" {
		return "", false
	}
	return p.Ticket, true
}

func (a answer) code() string {
	if a.out.Refusal == nil {
		return ""
	}
	return a.out.Refusal.Code
}

func (r *rig) callWith(cs *mcp.ClientSession, tool string, args map[string]any) answer {
	r.t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		r.t.Fatalf("%s: %v", tool, err)
	}
	var a answer
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	a.text, a.isErr = b.String(), res.IsError
	sc, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(sc, &a.out)
	r.mu.Lock()
	r.outputs = append(r.outputs, a.text, string(sc))
	r.mu.Unlock()
	return a
}

func (r *rig) call(tool string, args map[string]any) answer {
	r.t.Helper()
	return r.callWith(r.cs, tool, args)
}

// mustPending is the ticket of a pending answer: the fixed text, the
// ticket, the lock and the instance, nothing else.
func (r *rig) mustPending(a answer) string {
	r.t.Helper()
	tk, ok := a.pending()
	if !ok || a.isErr {
		r.t.Fatalf("not pending: %s %s", a.text, a.out.Data)
	}
	var m map[string]any
	_ = json.Unmarshal(a.out.Data, &m)
	if len(m) != 4 || m["lock"] != "locklog" || m["instance"] != instance {
		r.t.Fatalf("pending answer %s", a.out.Data)
	}
	if !strings.Contains(a.text, "Pending human approval: ticket "+tk+" on locklog") {
		r.t.Fatalf("pending text %q", a.text)
	}
	return tk
}

// decided calls tool with args until the ticket's decision has arrived.
func (r *rig) decided(tool string, args map[string]any) answer {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		a := r.call(tool, args)
		if _, ok := a.pending(); !ok {
			return a
		}
		if time.Now().After(deadline) {
			r.dump()
			r.t.Fatal("the decision never arrived")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var tokenRe = regexp.MustCompile(`⟦email:[A-Z0-9]+⟧`)

// record is the first record of a free search for the error records: its
// ref and its pseudonyms, in order.
func (r *rig) record() (string, []string) {
	r.t.Helper()
	a := r.call(mcptools.ToolSearch, map[string]any{"from": "2026-10-30T13:00:00Z", "to": "2026-10-30T14:00:00Z",
		"where": []map[string]any{{"field": "status", "op": "=", "value": 502}}})
	var res struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(a.out.Data, &res); err != nil || len(res.Records) != 1 {
		r.t.Fatalf("search: %v %s", err, a.text)
	}
	msg, _ := json.Marshal(res.Records[0])
	toks := tokenRe.FindAllString(string(msg), -1)
	if len(toks) != 2 {
		r.t.Fatalf("pseudonyms of %s", msg)
	}
	return res.Records[0]["ref"].(string), toks
}

func unmaskArgs(ref string, toks []string, tk string) map[string]any {
	m := map[string]any{"ref": ref, "pseudonyms": toks, "reason": "the user asked who failed to pay"}
	if tk != "" {
		m["ticket"] = tk
	}
	return m
}

// auditLog is the console's audit log.
func (r *rig) auditLog() string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.state, product.P.Name, "audit.log"))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

// digestRe finds what a hash or digest looks like: 64 hex, or a 43-char
// base64url run (a keyed digest), or a base32 SHA-256 (52 chars).
var digestRe = regexp.MustCompile(`[0-9a-fA-F]{64}|[A-Za-z0-9_-]{43}|[A-Z2-7]{52}`)

// sealedRe are the refs and cursors, AEAD-sealed: the only long opaque
// strings the agent gets.
var sealedRe = regexp.MustCompile(`"(ref|cursor)":\s*"[^"]*"`)

// checkAgentOutputs: no plan hash, input digest, record digest or policy
// fingerprint in anything the agent got (#26), nor a clear value it was
// not given by an approved unmask.
func (r *rig) checkAgentOutputs(allowClear bool) {
	r.t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.outputs {
		s := sealedRe.ReplaceAllString(o, "")
		s = strings.ReplaceAll(s, `\"`, `"`)
		s = sealedRe.ReplaceAllString(s, "")
		if m := digestRe.FindString(s); m != "" {
			r.t.Errorf("a digest-like value reached the agent (%q) in %s", m, o)
		}
		for _, w := range []string{"plan_hash", "policy_fp", "sha256:", "hub_sig", "inputs"} {
			if strings.Contains(s, w) {
				r.t.Errorf("%s reached the agent in %s", w, o)
			}
		}
		if strings.Contains(o, secret) {
			r.t.Errorf("the secret reached the agent: %s", o)
		}
		if !allowClear && (strings.Contains(o, email1) || strings.Contains(o, email2)) {
			r.t.Errorf("a clear value reached the agent: %s", o)
		}
	}
	// Nor is anything shown in clear on the console's terminal in hub
	// mode: the clear screen goes sealed to the devices only.
	if out := r.io.output(); strings.Contains(out, email1) || strings.Contains(out, email2) || strings.Contains(out, secret) {
		r.t.Errorf("a clear value on the console's terminal:\n%s", out)
	}
}

func (r *rig) dump() { r.t.Log(r.io.output()) }
