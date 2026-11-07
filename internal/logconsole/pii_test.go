//go:build unix

package logconsole

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/locklog/internal/product"
)

var testProduct = product.P

// linesIO is a console terminal that answers answer to every prompt.
type linesIO struct {
	mu     sync.Mutex
	lines  []string
	answer string
}

func (l *linesIO) Println(s string) { l.mu.Lock(); defer l.mu.Unlock(); l.lines = append(l.lines, s) }
func (l *linesIO) Ask(context.Context, string, time.Duration) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.answer, l.answer != ""
}
func (l *linesIO) AskSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("no secret")
}
func (l *linesIO) output() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// ruleEngine is a fakeEngine holding agent rules: a pattern naming a
// field it showed is accepted, under a digest.
type ruleEngine struct {
	fakeEngine
	shown  map[string]string // pattern → canonical
	added  []string
	addErr error
}

func (e *ruleEngine) CheckAgentRule(p string) (string, *Refusal) {
	if c, ok := e.shown[p]; ok {
		return c, nil
	}
	return "", &Refusal{Message: "no such field was shown", Info: refusal.Info{Code: "E_UNKNOWN_FIELD", Retry: refusal.RetryRewrite}}
}

func (e *ruleEngine) AddAgentRule(c string) (*Refusal, error) {
	if e.addErr != nil {
		return nil, e.addErr
	}
	for _, a := range e.added {
		if a == c {
			return &Refusal{Message: "a rule already decides this field", Info: refusal.Info{Code: "E_BAD_QUERY"}}, nil
		}
	}
	e.added = append(e.added, c)
	return nil, nil
}

func (e *ruleEngine) PIIRules() ([]string, []string) {
	var m []string
	for range e.added {
		m = append(m, "agent redact (added 2026-11-06T10:00:00Z)")
	}
	return m, nil
}

const maskedName = "jean.secretname@example.com"

// pii.add through the console server: the rule reaches the engine, the
// console's record of it holds the method and the canonical pattern (a
// digest), a refusal is audited with its code, and the audit file never
// holds the name the agent sent.
func TestPIIAddAudited(t *testing.T) {
	root := project(t, localCfg)
	os.WriteFile(filepath.Join(root, ".locklog", "pii.toml"), []byte("[[allow]]\nfield = \"user\"\n"), 0o644)
	digest := strings.Repeat("ab", 32)
	canonical := "agent redact " + digest
	eng := &ruleEngine{shown: map[string]string{"nginx:" + maskedName: canonical}}
	b := New(Options{Profile: "staging", Root: root, Open: func(context.Context, OpenOptions) (Engine, error) { return eng, nil }})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.(Policy).PIIAllow; len(got) != 1 || got[0] != "allow field=user" {
		t.Fatalf("allow rules in the policy = %q", got)
	}
	state := t.TempDir()
	log, err := audit.Open(testProduct, state)
	if err != nil {
		t.Fatal(err)
	}
	// No session yet: pii.list answers the approved allow rules, pii.add
	// is refused.
	if m, a := b.PIIRules(pol); m != nil || len(a) != 1 {
		t.Errorf("no session: %q %q", m, a)
	}
	if _, err := b.CheckMask("nginx:" + maskedName); err == nil {
		t.Fatal("no session: accepted")
	}
	sess, err := b.Connect(context.Background(), console.Credentials{Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	io := &linesIO{}
	srv, err := console.NewServer(console.ServerConfig{Product: testProduct, Backend: b, Policy: pol, Session: sess, Audit: log, IO: io,
		Approver: console.NewTypedApprover(io), Sanitizer: Sanitizer(), Quantum: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	call := func(method string, params any) ipc.Response {
		raw, _ := json.Marshal(params)
		ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
		return srv.Handle(ctx, ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw})
	}
	// A log call first: the console the refusals are audited through.
	call(MethodStatus, nil)
	if r := call(ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "nginx:" + maskedName}); r.Error != nil {
		t.Fatalf("pii.add: %+v", r.Error)
	}
	if len(eng.added) != 1 || eng.added[0] != canonical {
		t.Fatalf("engine rules = %q", eng.added)
	}
	r := call(ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "nginx:never_shown"})
	if r.Error == nil || !strings.Contains(r.Error.Message, "E_UNKNOWN_FIELD") || strings.Contains(r.Error.Message, "never_shown") {
		t.Fatalf("refused pii.add: %+v", r.Error)
	}
	var list ipc.PIIListResult
	r = call(ipc.MethodPIIList, nil)
	if r.Error != nil || json.Unmarshal(r.Result, &list) != nil || len(list.Mask) != 1 || len(list.Allow) != 0 {
		t.Fatalf("pii.list: %s %+v", r.Result, r.Error)
	}
	data, err := os.ReadFile(filepath.Join(state, testProduct.Name, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, w := range []string{maskedName, "jean", "secretname", "never_shown"} {
		if strings.Contains(text, w) {
			t.Errorf("the audit holds %q:\n%s", w, text)
		}
	}
	var added, refused bool
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["method"] != ipc.MethodPIIAdd {
			continue
		}
		switch rec["decision"] {
		case "tightened":
			added = rec["pattern"] == canonical && rec["event"] == audit.EventPolicy
		case "failed":
			// lockkit's record of the backend's refusal (v0.13.1): the
			// client, neither the pattern nor the engine's text.
			refused = rec["event"] == audit.EventPolicy && rec["error"] == piiRefusedPrefix+"invalid pattern" &&
				rec["profile"] == "staging" && rec["pattern"] == nil && rec["peer_uid"] == float64(1000)
		}
	}
	if !added || !refused {
		t.Errorf("pii.add records (added %v, refused %v):\n%s", added, refused, text)
	}
	// Nor is the name on the console's terminal, nor in .locklog.
	if out := io.output(); strings.Contains(out, maskedName) || !strings.Contains(out, digest) {
		t.Errorf("console:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(root, ".locklog", "pii.toml")); strings.Contains(string(b), maskedName) || strings.Contains(string(b), "agent") {
		t.Errorf("pii.toml written: %s", b)
	}
	// The policy is unchanged (an agent rule is not part of it): the
	// session is not reopened.
	if p := srv.Policy().(Policy); p.Fingerprint() != pol.(Policy).Fingerprint() {
		t.Error("pii.add changed the policy")
	}
}

// A rule the engine cannot save is refused with a fixed text; the backend
// audits nothing itself (lockkit records the refusal, AuditRecord adds the
// method); AuditRecord leaves the console's other records alone.
func TestPIIAddSaveFailsAndOtherRecords(t *testing.T) {
	eng := &ruleEngine{shown: map[string]string{"x": "agent redact " + strings.Repeat("0", 64)}, addErr: errors.New("disk full at /home/x")}
	b := New(Options{Profile: "staging", Root: project(t, localCfg), Open: func(context.Context, OpenOptions) (Engine, error) { return eng, nil }})
	pol, _ := b.LoadPolicy()
	if _, err := b.Connect(context.Background(), console.Credentials{Policy: pol}); err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{policy: pol}
	b.env = env
	c, err := b.CheckMask("x")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SaveMask(c); err == nil || err.Error() != errPIISaveText {
		t.Fatalf("SaveMask = %v", err)
	}
	if len(env.records) != 0 {
		t.Errorf("the backend audited the refusal itself (lockkit does): %+v", env.records)
	}
	unsaved := audit.Base{Event: audit.EventPolicy, Decision: "failed", Pattern: c, Error: piiRefusedPrefix + "mask rule not saved: " + errPIISaveText}
	if rec, ok := b.AuditRecord(unsaved).(PIIRecord); !ok || rec.Method != ipc.MethodPIIAdd || rec.Pattern != c || rec.Error != unsaved.Error {
		t.Errorf("lockkit's unsaved record = %+v", b.AuditRecord(unsaved))
	}
	if rec := b.AuditRecord(audit.Base{Event: audit.EventPolicy, Decision: "tightened"}); rec.(audit.Base).Decision != "tightened" {
		t.Errorf("a file tightening = %+v", rec)
	}
	// Once its session closed, no rule is checked against it.
	b.cur.Close()
	if _, err := b.CheckMask("x"); err == nil || err.Error() != errNoPIISessionText {
		t.Errorf("closed session: %v", err)
	}
}
