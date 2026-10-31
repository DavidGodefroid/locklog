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

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/locklog/internal/config"
)

func profileOf(t *testing.T, cfg string) config.Profile {
	t.Helper()
	ps, err := config.ParseProfiles([]byte(cfg), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	return ps["staging"]
}

func TestPlanRoots(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	cfg := "version = 1\n[profiles.staging.sources.app]\nkind = \"file\"\npaths = [\"" + a + "/app.log\", \"" + a + "/app.log.*\"]\n" +
		"[profiles.staging.sources.web]\nkind = \"file\"\npaths = [\"" + b + "/*/access.log\"]\n"
	pr := profileOf(t, cfg)
	both := devInoOf(t, a) + " " + a + ";" + devInoOf(t, b) + " " + b + ";"
	r, err := PlanRoots(Options{InContainer: true, ExpectRoots: both}, pr)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a, b}
	slices.Sort(want)
	if !slices.Equal(r.Dirs, want) || r.Journal != nil || r.Docker != "" || !slices.Equal(r.All(), want) {
		t.Errorf("roots = %+v", r)
	}
	// A planned directory the launcher did not check refuses the policy.
	if _, err := PlanRoots(Options{InContainer: true, ExpectRoots: devInoOf(t, a) + " " + a + ";"}, pr); err == nil || !strings.Contains(err.Error(), b+" is in the mount plan") {
		t.Errorf("unchecked root: %v", err)
	}
	// Outside the image nothing was checked: the plan is the roots.
	if r, err := PlanRoots(Options{}, pr); err != nil || !slices.Equal(r.Dirs, want) {
		t.Errorf("outside the image: %+v %v", r, err)
	}

	// journald: the journal directories the launcher bound and checked.
	jr := profileOf(t, "version = 1\n[profiles.staging.sources.sys]\nkind = \"journald\"\n")
	r, err = PlanRoots(Options{InContainer: true, ExpectRoots: "1:2 /run/log/journal;"}, jr)
	if err != nil || !slices.Equal(r.Journal, []string{"/run/log/journal"}) {
		t.Errorf("journal roots = %+v %v", r, err)
	}
	if _, err := PlanRoots(Options{InContainer: true, ExpectRoots: both}, jr); err == nil || !strings.Contains(err.Error(), "no journal directory") {
		t.Errorf("no journal: %v", err)
	}
}

func TestPlanRootsDocker(t *testing.T) {
	pr := profileOf(t, "version = 1\n[profiles.staging.sources.web]\nkind = \"docker\"\ncontainers = [\"shop-*\"]\n")
	base := t.TempDir()
	root := filepath.Join(base, "containers")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Checked from the host.
	r, err := PlanRoots(Options{InContainer: true, DockerRoot: root, ExpectRoots: devInoOf(t, root) + " " + root + ";"}, pr)
	if err != nil || r.Docker != root || !r.DockerChecked {
		t.Errorf("checked docker root: %+v %v", r, err)
	}
	// The launcher's "not checked from the host" case: a directory at
	// the path it passed.
	r, err = PlanRoots(Options{InContainer: true, DockerRoot: root}, pr)
	if err != nil || r.Docker != root || r.DockerChecked {
		t.Errorf("unchecked docker root: %+v %v", r, err)
	}
	link := filepath.Join(t.TempDir(), "containers")
	os.Symlink(root, link)
	for name, dr := range map[string]string{
		"unset": "", "relative": "containers", "not clean": base + "/../containers", "not containers": base,
		"root": "/containers", "missing": filepath.Join(t.TempDir(), "containers"), "link": link,
	} {
		if _, err := PlanRoots(Options{InContainer: true, DockerRoot: dr}, pr); err == nil {
			t.Errorf("%s docker root %q accepted", name, dr)
		}
	}
}

func TestConnectRefusesUncheckedRoot(t *testing.T) {
	logs, other := t.TempDir(), t.TempDir()
	root := project(t, filesCfg(logs)+"[profiles.staging.sources.other]\nkind = \"file\"\npaths = [\""+other+"/x.log\"]\n")
	opened := false
	o := FromEnv(Options{Profile: "staging", Root: root, InContainer: true, Open: func(context.Context, OpenOptions) (Engine, error) {
		opened = true
		return &fakeEngine{}, nil
	}}, func(k string) string {
		return map[string]string{
			"LOCKLOG_EXPECT_DIR":   devInoOf(t, filepath.Join(root, ".locklog")),
			"LOCKLOG_EXPECT_ROOTS": devInoOf(t, logs) + " " + logs + ";",
		}[k]
	})
	b := New(o)
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Connect(context.Background(), console.Credentials{Policy: pol}); err == nil || !strings.Contains(err.Error(), other+" is in the mount plan") || opened {
		t.Errorf("Connect with an unchecked root: %v (opened %v)", err, opened)
	}
}

// lostEnv records Lost.
type lostEnv struct {
	*fakeEnv
	lost int
}

func (e *lostEnv) Lost() {
	e.lost++
	if e.sess != nil {
		e.sess.Close()
	}
}

// blockingEngine blocks a call until its context ends.
type blockingEngine struct {
	fakeEngine
	started chan struct{}
}

func (e *blockingEngine) Handle(ctx context.Context, _ string, _ json.RawMessage, _ Caller) (any, *Refusal, error) {
	close(e.started)
	<-ctx.Done()
	return nil, &Refusal{Message: "cancelled"}, nil
}

func TestLostSession(t *testing.T) {
	logs := t.TempDir()
	root := project(t, filesCfg(logs))
	b := New(Options{Profile: "staging", Root: root})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	ms := b.Methods()
	ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
	last := func(env *lostEnv) Record { return env.records[len(env.records)-1].(Record) }

	// The engine reports the session lost: the console drops it, the
	// agent gets CodeConnLost, the call is audited.
	eng := &fakeEngine{err: errors.Join(ErrConnLost, errors.New("/var/log/app swapped"))}
	env := &lostEnv{fakeEnv: &fakeEnv{sess: newSession(eng, pol.(Policy)), policy: pol}}
	resp := ms[MethodSearch](ctx, ipc.Request{ID: 1, Method: MethodSearch}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeConnLost || env.lost != 1 || !eng.closed {
		t.Errorf("lost: %+v lost=%d closed=%v", resp.Error, env.lost, eng.closed)
	}
	if r := last(env); r.Decision != "failed" || r.Error != errLostText {
		t.Errorf("lost record: %+v", r)
	}

	// The session closes under a call in flight (Lost from elsewhere, the
	// console ending it): the call is cancelled and ends as lost.
	be := &blockingEngine{started: make(chan struct{})}
	sess := newSession(be, pol.(Policy))
	env = &lostEnv{fakeEnv: &fakeEnv{sess: sess, policy: pol}}
	go func() { <-be.started; sess.Close() }()
	resp = ms[MethodCount](ctx, ipc.Request{ID: 2, Method: MethodCount}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeConnLost || env.lost != 1 {
		t.Errorf("closed under the call: %+v lost=%d", resp.Error, env.lost)
	}

	// The agent's connection closes: the call is cancelled cleanly, no
	// engine failure on the console, the session kept.
	be = &blockingEngine{started: make(chan struct{})}
	env = &lostEnv{fakeEnv: &fakeEnv{sess: newSession(be, pol.(Policy)), policy: pol}}
	cctx, cancel := context.WithCancel(ctx)
	go func() { <-be.started; cancel() }()
	resp = ms[MethodSearch](cctx, ipc.Request{ID: 3, Method: MethodSearch}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeInternal || resp.Error.Message != errCancelledText || env.lost != 0 || len(env.lines) != 0 {
		t.Errorf("cancelled: %+v lost=%d lines=%q", resp.Error, env.lost, env.lines)
	}
	if r := last(env); r.Decision != "failed" || r.Error != errCancelledText {
		t.Errorf("cancelled record: %+v", r)
	}

	// A mount swapped after the start: checked on every call, the
	// session is dropped before the engine runs.
	other := t.TempDir()
	cb := New(Options{Profile: "staging", Root: root, InContainer: true,
		ExpectDir: devInoOf(t, filepath.Join(root, ".locklog")), ExpectRoots: devInoOf(t, other) + " " + logs + ";"})
	eng = &fakeEngine{}
	env = &lostEnv{fakeEnv: &fakeEnv{sess: newSession(eng, pol.(Policy)), policy: pol}}
	resp = cb.Methods()[MethodSearch](ctx, ipc.Request{ID: 4, Method: MethodSearch}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeConnLost || env.lost != 1 || eng.method != "" {
		t.Errorf("swapped mount: %+v lost=%d engine ran %q", resp.Error, env.lost, eng.method)
	}
	if len(env.lines) != 1 || !strings.Contains(env.lines[0], "mounts changed") {
		t.Errorf("console line: %q", env.lines)
	}
}

// reconnectEnv reconnects through the backend after Lost, on the policy in
// force, as lockkit's console does (ReconnectPolicy).
type reconnectEnv struct {
	*fakeEnv
	b    *Backend
	lost int
}

func (e *reconnectEnv) Lost() {
	e.lost++
	if e.sess != nil {
		e.sess.Close()
		e.sess = nil
	}
}

func (e *reconnectEnv) Session(ctx context.Context) (console.Session, error) {
	if e.sess == nil {
		s, err := e.b.Connect(ctx, console.Credentials{Policy: e.policy})
		if err != nil {
			return nil, err
		}
		e.sess = s
	}
	return e.sess, nil
}

func TestPolicyChangeReopensEngine(t *testing.T) {
	logs := t.TempDir()
	root := project(t, filesCfg(logs))
	var engines []*fakeEngine
	b := New(Options{Profile: "staging", Root: root, Open: func(_ context.Context, o OpenOptions) (Engine, error) {
		e := &fakeEngine{result: o.Policy.Fingerprint()}
		engines = append(engines, e)
		return e, nil
	}})
	old, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Connect(context.Background(), console.Credentials{Policy: old})
	if err != nil {
		t.Fatal(err)
	}
	// The human approves a tightened policy: one source fewer.
	cur := old.(Policy)
	cur.Policy.Profile.Sources = nil
	env := &reconnectEnv{fakeEnv: &fakeEnv{sess: s, policy: cur}, b: b}
	resp := b.Methods()[MethodSearch](context.Background(), ipc.Request{ID: 1, Method: MethodSearch}, env)
	if resp.Error != nil || env.lost != 1 || len(engines) != 2 || !engines[0].closed || engines[0].method != "" || engines[1].method != MethodSearch {
		t.Fatalf("policy change: %+v lost=%d engines=%d", resp.Error, env.lost, len(engines))
	}
	if !strings.Contains(string(resp.Result), cur.Fingerprint()) {
		t.Errorf("served by the engine of %s, want the policy in force", resp.Result)
	}
	// The same policy: the session is kept.
	b.Methods()[MethodCount](context.Background(), ipc.Request{ID: 2, Method: MethodCount}, env)
	if env.lost != 1 || len(engines) != 2 {
		t.Errorf("reopened without a change: lost=%d engines=%d", env.lost, len(engines))
	}
}

// A reopen on the policy in force that fails is audited as failed: no call
// goes unrecorded because the engine never ran.
func TestPolicyChangeFailedReopenIsAudited(t *testing.T) {
	logs := t.TempDir()
	root := project(t, filesCfg(logs))
	opens := 0
	b := New(Options{Profile: "staging", Root: root, Open: func(_ context.Context, o OpenOptions) (Engine, error) {
		opens++
		if opens > 1 {
			return nil, errors.New("ref.key: corrupt")
		}
		return &fakeEngine{}, nil
	}})
	old, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Connect(context.Background(), console.Credentials{Policy: old})
	if err != nil {
		t.Fatal(err)
	}
	cur := old.(Policy)
	cur.Policy.Profile.Sources = nil
	env := &reconnectEnv{fakeEnv: &fakeEnv{sess: s, policy: cur}, b: b}
	resp := b.Methods()[MethodSearch](context.Background(), ipc.Request{ID: 1, Method: MethodSearch}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeConnLost || len(env.records) != 1 {
		t.Fatalf("failed reopen: %+v records=%d", resp.Error, len(env.records))
	}
	// The audit gets a fixed text, never the open's error.
	if r := env.records[0].(Record); r.Decision != "failed" || r.Method != MethodSearch || r.Error != errNoSessionText {
		t.Errorf("record: %+v", r)
	}

	// No session at all (the first Session call fails): audited too.
	env = &reconnectEnv{fakeEnv: &fakeEnv{policy: cur}, b: b}
	resp = b.Methods()[MethodCount](context.Background(), ipc.Request{ID: 2, Method: MethodCount}, env)
	if resp.Error == nil || resp.Error.Code != ipc.CodeConnLost || len(env.records) != 1 {
		t.Fatalf("no session: %+v records=%d", resp.Error, len(env.records))
	}
	if r := env.records[0].(Record); r.Decision != "failed" || r.Method != MethodCount || r.Error != errNoSessionText {
		t.Errorf("no-session record: %+v", r)
	}
}
