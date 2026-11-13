//go:build integration && lockfamily_managed_test && unix

package loki_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/locklog/internal/engine/session"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// useManaged makes body the machine's managed file for the test.
func useManaged(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if err := os.WriteFile(path, []byte("version = 1\norganisation = \"Acme\"\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
}

// runIO is the console's terminal under console.Run: it counts every
// question and answers yes.
type runIO struct {
	mu      sync.Mutex
	out     []string
	prompts int
}

func (s *runIO) Println(l string) { s.mu.Lock(); defer s.mu.Unlock(); s.out = append(s.out, l) }
func (s *runIO) Ask(context.Context, string, time.Duration) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts++
	return "y", true
}
func (s *runIO) AskSecret(context.Context, string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts++
	return nil, errors.New("no secret")
}
func (s *runIO) count() int     { s.mu.Lock(); defer s.mu.Unlock(); return s.prompts }
func (s *runIO) output() string { s.mu.Lock(); defer s.mu.Unlock(); return strings.Join(s.out, "\n") }

// isolation is a same-user environment for console.Run.
func isolation() console.IsolationEnv {
	return console.IsolationEnv{
		LoadSys:        func() (*sysconf.Config, error) { return nil, nil },
		Display:        func() sysconf.Display { return sysconf.Display{Kind: sysconf.DisplayWayland} },
		UID:            func() int { return 900 },
		UserName:       func() (string, error) { return "locklog", nil },
		LoginUID:       func() (int, bool) { return 900, true },
		TerminalOwner:  func() (int, bool) { return 900, true },
		ClientAllowed:  func(*sysconf.Config, int) bool { return true },
		ClientGID:      func(*sysconf.Config) (int, error) { return 950, nil },
		AccountExists:  func(int) bool { return true },
		Relay:          func() string { return "" },
		MachinectlUIDs: func() ([]int, bool) { return nil, true },
		DesktopEnv:     func() bool { return false },
		DisplaySet:     func() bool { return false },
		ParentChain:    func() ([]sysconf.Proc, error) { return []sysconf.Proc{{PID: 1, UID: 0, Comm: "systemd"}}, nil },
		NewVerifier:    func(string) (fingerprint.Verifier, error) { return &fingerprint.Fake{}, nil },
		AllowSameUser:  true,
	}
}

// opener opens the engine without Landlock (a test process).
func opener() logconsole.Opener {
	return func(ctx context.Context, oo logconsole.OpenOptions) (logconsole.Engine, error) {
		return session.Open(ctx, session.Options{OpenOptions: oo, FirstOpen: true,
			Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
	}
}

// runConsole is a console.Run on profile it of root, as `locklog
// console` runs it. ready is closed once it listens; done gets its error.
type runConsole struct {
	io    *runIO
	state string
	ready chan struct{}
	done  chan error
}

func startConsole(t *testing.T, root string) *runConsole {
	t.Helper()
	t.Setenv("LOCKLOG_RUNTIME_DIR", t.TempDir())
	home := t.TempDir()
	instance := "it-managed-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	key, err := hubclient.InstanceKey(home, instance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, instance, key.Public().(ed25519.PublicKey))
	hubKey := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(hubKey, []byte(base64.StdEncoding.EncodeToString(hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &runConsole{io: &runIO{}, state: t.TempDir(), ready: make(chan struct{}), done: make(chan error, 1)}
	be := logconsole.New(logconsole.Options{Profile: "it", Root: root, StateDir: filepath.Join(c.state, product.P.Name), Open: opener()})
	env := isolation()
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	go func() {
		c.done <- console.Run(ctx, product.P, be, console.Options{Profile: "it", ProjectRoot: root, IO: c.io, StateDir: c.state,
			Isolation: &env, Harden: func() error { return nil }, Sanitizer: logconsole.Sanitizer(),
			Hub: console.HubOptions{URL: hub.URL(), KeyFile: hubKey, Instance: instance, Home: home}, OnHub: be.OnHub,
			Ready: func(string) { once.Do(func() { close(c.ready) }) }})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Error("the console did not stop")
		}
	})
	return c
}

func (c *runConsole) auditLog() string {
	raw, _ := os.ReadFile(filepath.Join(c.state, product.P.Name, "audit.log"))
	return string(raw)
}

func writeConfig(t *testing.T, root, cfg string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

// approvedFiles are the approved policies kept under state.
func approvedFiles(state string) []string {
	var out []string
	_ = filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(filepath.Dir(p)) == "approved" && strings.HasSuffix(p, ".json") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// lokiProfile is profile "it" over the test Loki, read with run's
// selector.
func lokiProfile(base, run, extra string) string {
	return fmt.Sprintf(`version = 1
[profiles.it]
structured = "redact-unknown"
%s
[profiles.it.sources.loki]
kind = "loki"
format = "json"
url = %q
selector = { run = %q }
trusted_labels = ["app", "level"]
auth = "none"
`, extra, base, run)
}

func hostOf(t *testing.T, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

// With [locklog.bounds] unmask = "never", a profile with unmask =
// "approved" is refused at start, citing the key, with no prompt, and the
// audit has refused-managed. A compliant profile starts and its approval
// carries managed_sha256. A source outside hosts added while it runs is
// refused at the next poll, never pending; tightening max_records is
// accepted.
func TestManagedBoundsConsole(t *testing.T) {
	base := lokiURL(t)
	run := "m" + strconv.FormatInt(time.Now().UnixNano(), 36)
	useManaged(t, fmt.Sprintf("[locklog.bounds]\nunmask = \"never\"\nhosts = [%q]\n", hostOf(t, base)))

	root := t.TempDir()
	writeConfig(t, root, lokiProfile(base, run, `unmask = "approved"`))
	c := startConsole(t, root)
	select {
	case err := <-c.done:
		if !errors.Is(err, console.ErrManaged) || !strings.Contains(strings.Join(console.ManagedLines(err), "\n"), "locklog.bounds.unmask = never (profile it: unmask = approved)") {
			t.Fatalf("start beyond the bounds: %v %q\n%s", err, console.ManagedLines(err), c.io.output())
		}
		c.done <- err
	case <-c.ready:
		t.Fatal("a profile beyond unmask = never started")
	case <-time.After(30 * time.Second):
		t.Fatal("no answer from the console")
	}
	if n := c.io.count(); n != 0 {
		t.Errorf("refused after %d questions, want none", n)
	}
	if !strings.Contains(c.auditLog(), "refused-managed") {
		t.Errorf("no refused-managed in the audit:\n%s", c.auditLog())
	}

	root = t.TempDir()
	writeConfig(t, root, lokiProfile(base, run, `unmask = "never"`))
	c = startConsole(t, root)
	select {
	case <-c.ready:
	case err := <-c.done:
		t.Fatalf("a compliant profile: %v\n%s", err, c.io.output())
	case <-time.After(60 * time.Second):
		t.Fatalf("the console did not start:\n%s", c.io.output())
	}
	files := approvedFiles(c.state)
	if len(files) != 1 {
		t.Fatalf("approved policies %v", files)
	}
	if raw, _ := os.ReadFile(files[0]); !strings.Contains(string(raw), "managed_sha256") {
		t.Fatalf("approved policy without managed_sha256: %s", raw)
	}
	if !strings.Contains(c.io.output(), "Managed by Acme (sha256:") {
		t.Errorf("no managed line at start:\n%s", c.io.output())
	}

	// A source outside hosts, added while it runs.
	before := strings.Count(c.auditLog(), "refused-managed")
	prompts := c.io.count()
	writeConfig(t, root, lokiProfile(base, run, `unmask = "never"`)+fmt.Sprintf(`[profiles.it.sources.other]
kind = "loki"
url = "http://loki-elsewhere.invalid:3100"
selector = { run = %q }
auth = "none"
`, run))
	deadline := time.Now().Add(15 * time.Second)
	for strings.Count(c.auditLog(), "refused-managed") == before && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if strings.Count(c.auditLog(), "refused-managed") == before {
		t.Fatalf("the source beyond hosts was not refused at the poll:\n%s", c.auditLog())
	}
	if !strings.Contains(c.auditLog()+c.io.output(), "locklog.bounds.hosts") {
		t.Errorf("the refusal does not cite locklog.bounds.hosts:\n%s\n%s", c.auditLog(), c.io.output())
	}
	if now := c.io.count(); now != prompts {
		t.Errorf("the refused loosening asked %d questions", now-prompts)
	}
	if strings.Contains(c.auditLog(), `"pending"`) {
		t.Errorf("the loosening went pending:\n%s", c.auditLog())
	}

	// Tightening limits.max_records is accepted: no refusal, no question.
	refused := strings.Count(c.auditLog(), "refused-managed")
	writeConfig(t, root, lokiProfile(base, run, "unmask = \"never\"\nlimits = { max_records = 20 }"))
	time.Sleep(5 * time.Second)
	if strings.Count(c.auditLog(), "refused-managed") != refused {
		t.Errorf("tightening max_records was refused:\n%s", c.auditLog())
	}
	if now := c.io.count(); now != prompts {
		t.Errorf("tightening asked %d questions", now-prompts)
	}
	select {
	case err := <-c.done:
		t.Fatalf("the console ended: %v\n%s", err, c.io.output())
	default:
	}
}

// A managed loki profile is served and a read through it works; a
// project profile of the same name fails the load.
func TestManagedLokiProfileServed(t *testing.T) {
	base := lokiURL(t)
	run := "s" + strconv.FormatInt(time.Now().UnixNano(), 36)
	start := time.Now().Add(-20 * time.Minute).Truncate(5 * time.Minute)
	const n = 40
	push(t, base, run, start, n)
	useManaged(t, strings.Replace(strings.TrimPrefix(lokiProfile(base, run, ""), "version = 1\n"), "[profiles.it", "[locklog.profiles.it", -1))

	root := t.TempDir()
	writeConfig(t, root, "version = 1\n")
	be := logconsole.New(logconsole.Options{Profile: "it", Root: root, StateDir: t.TempDir(), Open: opener()})
	pol, err := be.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !pol.(logconsole.Policy).Policy.Profile.Managed {
		t.Error("the policy's profile is not the managed one")
	}
	sess, err := session.Open(context.Background(), session.Options{
		OpenOptions: logconsole.OpenOptions{Policy: pol.(logconsole.Policy).Policy, StateDir: t.TempDir(), Project: root},
		FirstOpen:   true,
		Confinement: session.Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	window := fmt.Sprintf(`"from":%q,"to":%q`, start.UTC().Format(time.RFC3339Nano), start.Add(10*time.Minute).UTC().Format(time.RFC3339Nano))
	var total int64
	for i := 0; i < 60 && total < n; i++ {
		total = countTotal(handle(t, sess, logconsole.MethodCount, `{`+window+`,"where":[{"label":"level","op":"=","value":"info"}],"by_labels":["level"]}`))
		if total < n/2 {
			time.Sleep(time.Second)
		}
	}
	if total != n/2 {
		t.Fatalf("count through the managed profile: %d, want %d", total, n/2)
	}

	writeConfig(t, root, lokiProfile(base, run, ""))
	if _, err := be.LoadPolicy(); err == nil || !strings.Contains(err.Error(), `profile "it" is provided by the company's managed configuration`) {
		t.Fatalf("a project profile of the managed name: %v", err)
	}
}
