//go:build unix

package logconsole

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/sanitize"
)

const localCfg = `version = 1
[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
[profiles.staging.sources.sys]
kind = "journald"
`

const lokiCfg = `
[profiles.staging.sources.loki]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "basic"
user = "reader"
`

func project(t *testing.T, cfg string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLoadPolicyAndProfile(t *testing.T) {
	root := project(t, localCfg)
	b := New(Options{Profile: "staging", Root: root, Network: "", ExtraRoots: []string{"/srv/logs/"}})
	p, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	pr := p.Profile()
	if pr.Name != "staging" || pr.Production || pr.Credentials != console.CredentialsNone || pr.Where != "file, journald" {
		t.Errorf("profile = %+v", pr)
	}
	if got := p.(Policy).ExtraRoots; len(got) != 1 || got[0] != "/srv/logs" {
		t.Errorf("extra roots = %v", got)
	}
	// Diff unwraps the console's approved copy.
	if d := p.Diff(p); len(d) != 0 {
		t.Errorf("Diff(self) = %+v", d)
	}
	// JSON round trip: what the console stores as the approved policy.
	raw, _ := json.Marshal(p)
	var back Policy
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Diff(p)) != 0 {
		t.Errorf("round trip: %v %+v", err, back.Diff(p))
	}

	lp, err := New(Options{Profile: "staging", Root: project(t, localCfg+lokiCfg), Network: "loki_net"}).LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pr := lp.Profile(); pr.Credentials != "ask" || pr.User != "reader" || !strings.Contains(pr.Where, "loki https://loki.example.com") {
		t.Errorf("loki profile = %+v", pr)
	}
	two := localCfg + lokiCfg + strings.ReplaceAll(lokiCfg, "sources.loki]", "sources.loki2]")
	if _, err := New(Options{Profile: "staging", Root: project(t, two), Network: "n"}).LoadPolicy(); err == nil || !strings.Contains(err.Error(), "at most one remote source") {
		t.Errorf("two remote sources: %v", err)
	}
	for _, o := range []Options{{Profile: "nope", Root: root}, {Profile: "staging"}, {Profile: "staging", Root: root, Network: "host"}} {
		if _, err := New(o).LoadPolicy(); err == nil {
			t.Errorf("LoadPolicy(%+v) accepted", o)
		}
	}
}

// fakeEngine records its calls.
type fakeEngine struct {
	method string
	params string
	caller Caller
	result any
	refuse *Refusal
	err    error
	closed bool
}

func (e *fakeEngine) Handle(_ context.Context, m string, p json.RawMessage, c Caller) (any, *Refusal, error) {
	e.method, e.params, e.caller = m, string(p), c
	return e.result, e.refuse, e.err
}
func (e *fakeEngine) Status(context.Context) any { return map[string]string{"engine": "ok"} }
func (e *fakeEngine) Close() error               { e.closed = true; return nil }

func devInoOf(t *testing.T, p string) string {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := devIno(fi)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// filesCfg is a profile reading app.log under dir.
func filesCfg(dir string) string {
	return "version = 1\n[profiles.staging.sources.app]\nkind = \"file\"\npaths = [\"" + dir + "/app.log\"]\n"
}

func TestConnectChecksMounts(t *testing.T) {
	logs := t.TempDir()
	root := project(t, filesCfg(logs))
	eng := &fakeEngine{}
	var opened OpenOptions
	open := func(_ context.Context, o OpenOptions) (Engine, error) { opened = o; return eng, nil }
	good := FromEnv(Options{Profile: "staging", Root: root, Open: open}, func(k string) string {
		return map[string]string{
			"LOCKLOG_EXPECT_DIR":   devInoOf(t, filepath.Join(root, ".locklog")),
			"LOCKLOG_EXPECT_ROOTS": devInoOf(t, logs) + " " + logs + ";",
		}[k]
	})
	if good.InContainer {
		t.Fatal("FromEnv decided InContainer")
	}
	good.InContainer = true
	b := New(good)
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Connect(context.Background(), console.Credentials{Policy: pol, User: "u", Secret: []byte("pw")})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if opened.Policy.Profile.Name != "staging" || opened.Credentials.Secret != "pw" || opened.Credentials.User != "u" {
		t.Errorf("opened with %+v", opened)
	}
	// The engine gets the checked roots of the plan, and the project.
	if !slices.Equal(opened.Roots.Dirs, []string{logs}) || opened.Project != root {
		t.Errorf("opened with roots %+v, project %q", opened.Roots, opened.Project)
	}
	if err := s.Close(); err != nil || !eng.closed {
		t.Error("Close did not close the engine")
	}
	other := t.TempDir()
	for _, tt := range []struct {
		name string
		mod  func(o *Options)
		part string
	}{
		{"no EXPECT_DIR", func(o *Options) { o.ExpectDir = "" }, "LOCKLOG_EXPECT_DIR is not set"},
		{"another .locklog", func(o *Options) { o.ExpectDir = "1:2" }, "not the directory the launcher checked"},
		{"another root", func(o *Options) { o.ExpectRoots = devInoOf(t, other) + " " + logs + ";" }, "not the directory the launcher checked"},
		{"malformed", func(o *Options) { o.ExpectRoots = "garbage;" }, "malformed entry"},
		{"relative", func(o *Options) { o.ExpectRoots = "1:2 rel;" }, "malformed entry"},
		{"missing root", func(o *Options) { o.ExpectRoots = "1:2 /nonexistent-locklog-root;" }, "nonexistent"},
		{"empty path", func(o *Options) { o.ExpectRoots = "1:2 ;" }, "malformed entry"},
		{"no project", func(o *Options) { o.Root = "" }, "no project"},
	} {
		o := good
		tt.mod(&o)
		if _, err := New(o).Connect(context.Background(), console.Credentials{Policy: pol}); err == nil || !strings.Contains(err.Error(), tt.part) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	// A root swapped for a link is refused.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(logs, link); err != nil {
		t.Fatal(err)
	}
	o := good
	o.ExpectRoots = devInoOf(t, logs) + " " + link + ";"
	if _, err := New(o).Connect(context.Background(), console.Credentials{Policy: pol}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("link: %v", err)
	}
	// LoadPolicy checks before it reads the file.
	o = good
	o.ExpectDir = "1:2"
	if _, err := New(o).LoadPolicy(); err == nil || !strings.Contains(err.Error(), "not the directory the launcher checked") {
		t.Errorf("LoadPolicy before the check: %v", err)
	}
	// A .locklog swapped for a link.
	lroot := t.TempDir()
	if err := os.Symlink(filepath.Join(root, ".locklog"), filepath.Join(lroot, ".locklog")); err != nil {
		t.Fatal(err)
	}
	o = good
	o.Root = lroot
	if err := CheckMounts(o); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf(".locklog link: %v", err)
	}
	// Not a locklog policy.
	if _, err := New(good).Connect(context.Background(), console.Credentials{}); err == nil {
		t.Error("Connect without a policy")
	}
	// Outside the container (tests, a developer's build) nothing is checked.
	if _, err := New(Options{Profile: "staging", Root: root, Open: open}).Connect(context.Background(), console.Credentials{Policy: pol}); err != nil {
		t.Errorf("outside the container: %v", err)
	}
	if _, err := New(Options{Profile: "staging", Root: root}).Connect(context.Background(), console.Credentials{Policy: pol}); err == nil {
		t.Error("no engine: connected")
	}
}

func TestChecksNetwork(t *testing.T) {
	net := t.TempDir()
	for _, n := range []string{"lo", "eth0"} {
		if err := os.Mkdir(filepath.Join(net, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	eng := &fakeEngine{}
	open := func(context.Context, OpenOptions) (Engine, error) { return eng, nil }
	for _, tt := range []struct {
		name, cfg, network string
		refuse             bool
	}{
		{"local profile with a network", localCfg, "", true},
		{"local profile with LOCKLOG_NETWORK", localCfg, "shop", false},
		{"remote source", localCfg + lokiCfg, "loki_net", false},
	} {
		b := New(Options{Profile: "staging", Root: project(t, tt.cfg), Network: tt.network, SysClassNet: net, Open: open})
		pol, err := b.LoadPolicy()
		if err != nil {
			t.Fatal(err)
		}
		b.o.InContainer = true
		s := &session{engine: eng, policy: pol.(Policy)}
		f := b.Checks(context.Background(), s)
		if (len(f) > 0 && f[0].Refuse) != tt.refuse {
			t.Errorf("%s: findings %+v", tt.name, f)
		}
	}
}

// fakeEnv is the console behind a handler.
type fakeEnv struct {
	console.Env
	sess     console.Session
	policy   console.Policy
	records  []audit.Record
	failSave bool
	leveled  int
	lines    []string
}

func (e *fakeEnv) Level(context.Context, time.Time) { e.leveled++ }
func (e *fakeEnv) Println(l string)                 { e.lines = append(e.lines, l) }
func (e *fakeEnv) Safe(s string) string             { return s }

// noAuditEnv is a console without WriteAudit.
type noAuditEnv struct{ *fakeEnv }

func (noAuditEnv) WriteAudit() {}

func (e *fakeEnv) Session(context.Context) (console.Session, error) { return e.sess, nil }
func (e *fakeEnv) Policy() console.Policy                           { return e.policy }
func (e *fakeEnv) Sanitizer() *sanitize.Sanitizer                   { return Sanitizer() }
func (e *fakeEnv) Audit(r audit.Record)                             { e.records = append(e.records, r) }
func (e *fakeEnv) WriteAudit(r audit.Record) error {
	if e.failSave {
		return errors.New("disk full")
	}
	e.records = append(e.records, r)
	return nil
}

func TestHandlers(t *testing.T) {
	b := New(Options{Profile: "staging", Root: project(t, localCfg)})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngine{result: map[string]any{"records": []string{"⟦email:7F3KQ2M9ZD4X⟧ failed"}, "complete": true}}
	env := &fakeEnv{sess: &session{engine: eng, policy: pol.(Policy)}, policy: pol}
	ms := b.Methods()
	for _, m := range Methods {
		if ms[m] == nil {
			t.Errorf("method %s not served", m)
		}
	}
	params := json.RawMessage(`{"sources":["nginx","BAD NAME","jane-doe"],"from":"2026-10-30T13:00:00Z","to":"+32470123456","text":"jane@example.com"}`)
	ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
	resp := ms[MethodSearch](ctx, ipc.Request{ID: 7, Method: MethodSearch, Params: params}, env)
	if resp.Error != nil || !strings.Contains(string(resp.Result), "⟦email:7F3KQ2M9ZD4X⟧") {
		t.Fatalf("search: %+v", resp)
	}
	if eng.method != MethodSearch || eng.params != string(params) || eng.caller != (Caller{UID: 1000, PID: 42}) {
		t.Errorf("engine got %q %q %+v", eng.method, eng.params, eng.caller)
	}
	if len(env.records) != 1 {
		t.Fatalf("records = %d", len(env.records))
	}
	rec := env.records[0].(Record)
	raw, _ := json.Marshal(rec)
	if rec.Event != EventCall || rec.Decision != "ok" || rec.Method != MethodSearch || rec.Profile != "staging" ||
		len(rec.Sources) != 1 || rec.Sources[0] != "nginx" || rec.From != "2026-10-30T13:00:00Z" || rec.PeerUID == nil || *rec.PeerUID != 1000 {
		t.Errorf("record = %s", raw)
	}
	// The agent's predicates and values never reach the audit.
	if strings.Contains(string(raw), "jane") || strings.Contains(string(raw), "BAD NAME") || strings.Contains(string(raw), "⟦") || strings.Contains(string(raw), "32470") {
		t.Errorf("record holds call content: %s", raw)
	}

	// A refusal reaches the agent structured, and is audited.
	eng.refuse = &Refusal{Message: "over the budget of this call", Info: refusal.Info{Code: "E_OVER_BUDGET", Hint: "narrow the range or use locklog_scan"}}
	resp = ms[MethodCount](ctx, ipc.Request{ID: 8, Method: MethodCount}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeRefused || resp.Error.Data == nil || resp.Error.Data.Code != "E_OVER_BUDGET" {
		t.Errorf("refusal: %+v", resp.Error)
	}
	if eng.params != "{}" {
		t.Errorf("empty params = %q", eng.params)
	}
	if r := env.records[1].(Record); r.Decision != "refused" || r.Code != "E_OVER_BUDGET" {
		t.Errorf("refusal record: %+v", r)
	}

	// An engine failure: internal, sanitised.
	eng.refuse, eng.err = nil, errors.New(`dial https://reader:hunter2@loki.example.com: parsing "jane@example.com": refused`)
	resp = ms[MethodStatus](ctx, ipc.Request{ID: 9, Method: MethodStatus}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeInternal || resp.Error.Message != errEngineText {
		t.Errorf("failure: %+v", resp.Error)
	}
	if r := env.records[2].(Record); r.Decision != "failed" || r.Error != errEngineText {
		t.Errorf("failure record: %+v", r)
	}
	if len(env.lines) != 1 || strings.Contains(env.lines[0], "hunter2") || !strings.Contains(env.lines[0], "jane@example.com") {
		t.Errorf("console line: %q", env.lines)
	}
	if env.leveled != 3 {
		t.Errorf("Level called %d times, want 3", env.leveled)
	}

	// No answer leaves unaudited.
	eng.err = nil
	env.failSave = true
	resp = ms[MethodSources](ctx, ipc.Request{ID: 10, Method: MethodSources}, env)
	if resp.Error == nil || resp.Result != nil || !strings.Contains(resp.Error.Message, "could not be audited") {
		t.Errorf("unaudited: %+v", resp)
	}
	// A console without the fail-closed write refuses too.
	env.failSave = false
	resp = ms[MethodSources](ctx, ipc.Request{ID: 11, Method: MethodSources}, noAuditEnv{env})
	if resp.Error == nil || resp.Result != nil {
		t.Errorf("no WriteAudit: %+v", resp)
	}
}

func TestInImageAndProfileHost(t *testing.T) {
	none := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	some := func(string) (os.FileInfo, error) { return nil, nil }
	if !InImage(10051, none) || InImage(1000, none) || !InImage(1000, some) {
		t.Error("InImage")
	}
	p, err := New(Options{Profile: "staging", Root: project(t, localCfg+strings.Replace(lokiCfg, "https://loki.example.com", "https://loki.example.com:3101", 1)), Network: "n"}).LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pr := p.Profile(); pr.Host != "loki.example.com" || pr.Port != 3101 || pr.DefaultPort != 443 {
		t.Errorf("host/port = %q %d %d", pr.Host, pr.Port, pr.DefaultPort)
	}
}

func TestChecksInterfacesError(t *testing.T) {
	b := New(Options{Profile: "staging", Root: project(t, localCfg), InContainer: true, SysClassNet: "/nonexistent-sys-class-net"})
	if _, err := b.LoadPolicy(); err == nil {
		// InContainer without EXPECT_DIR: LoadPolicy refuses already.
		t.Fatal("LoadPolicy in the container without LOCKLOG_EXPECT_DIR")
	}
	b2 := New(Options{Profile: "staging", Root: project(t, localCfg)})
	pol, err := b2.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	b.o.InContainer = true
	f := b.Checks(context.Background(), &session{engine: &fakeEngine{}, policy: pol.(Policy)})
	if len(f) != 1 || !f[0].Refuse {
		t.Errorf("findings = %+v", f)
	}
}

func TestStatus(t *testing.T) {
	eng := &fakeEngine{}
	b := New(Options{})
	if got := b.Status(&session{engine: eng}); got.(map[string]string)["engine"] != "ok" {
		t.Errorf("Status = %v", got)
	}
	if b.Status(nil) != nil {
		t.Error("Status of no session")
	}
}
