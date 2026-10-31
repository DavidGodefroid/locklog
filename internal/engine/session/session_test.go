//go:build unix

package session

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
)

var t0 = time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)

// fixture is a project with one file source over a log under a temporary
// root, and the console's state directory.
type fixture struct {
	root, logs, state string
	policy            config.Policy
}

func newFixture(t *testing.T, cfg func(logs string) string, lines string) *fixture {
	t.Helper()
	f := &fixture{root: t.TempDir(), state: t.TempDir()}
	f.logs, _ = filepath.EvalSymlinks(t.TempDir())
	if err := os.WriteFile(filepath.Join(f.logs, "app.log"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	ps, err := config.ParseProfiles([]byte(cfg(f.logs)), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if f.policy, err = config.NewPolicy(ps["staging"], "", nil); err != nil {
		t.Fatal(err)
	}
	return f
}

const fileCfg = `version = 1
[profiles.staging]
structured = "redact-unknown"
[profiles.staging.sources.app]
kind = "file"
format = "json"
paths = ["LOGS/app.log"]
trusted = ["level", "status"]
`

func fileProfile(logs string) string { return strings.ReplaceAll(fileCfg, "LOGS", logs) }

func (f *fixture) options(mod func(*Options)) Options {
	o := Options{OpenOptions: logconsole.OpenOptions{Policy: f.policy, StateDir: f.state, Project: f.root,
		Roots: logconsole.Roots{Dirs: []string{f.logs}}},
		FirstOpen: true, Now: func() time.Time { return t0.Add(time.Hour) },
		Confinement: Confinement{Landlock: landlock.Status{State: landlock.Unsupported, Detail: "test"}}}
	if mod != nil {
		mod(&o)
	}
	return o
}

func open(t *testing.T, o Options) *Session {
	t.Helper()
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

const appLog = `{"time":"2026-10-30T13:00:01Z","level":"error","status":502,"msg":"payment failed for jane.doe@example.com","user":"Jane Doe"}
{"time":"2026-10-30T13:00:02Z","level":"info","status":200,"msg":"ok"}
`

func call(t *testing.T, s *Session, method, params string) (any, *logconsole.Refusal) {
	t.Helper()
	res, ref, err := s.Handle(context.Background(), method, json.RawMessage(params), logconsole.Caller{})
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return res, ref
}

func TestOpenSearchMasked(t *testing.T) {
	f := newFixture(t, fileProfile, appLog)
	s := open(t, f.options(nil))
	res, ref := call(t, s, logconsole.MethodSearch, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"}`)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	out, _ := json.Marshal(res)
	got := string(out)
	if strings.Contains(got, "jane") || strings.Contains(got, "Jane") {
		t.Fatalf("unmasked: %s", got)
	}
	// Trusted fields clear, the untrusted user redacted (redact-unknown),
	// the address pseudonymised in the message.
	if !strings.Contains(got, `"level":"error"`) || !strings.Contains(got, `"status":502`) || !strings.Contains(got, mask.Redacted) || !strings.Contains(got, "⟦email:") {
		t.Errorf("search = %s", got)
	}
	// A refusal is structured, with the engine's code.
	_, ref = call(t, s, logconsole.MethodSearch, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z","nope":1}`)
	if ref == nil || ref.Info.Code != "E_BAD_QUERY" || ref.Info.Retry != "rewrite" {
		t.Errorf("unknown field: %+v", ref)
	}
	_, ref = call(t, s, logconsole.MethodSearch, `{"from":"2026-10-01T13:00:00Z","to":"2026-10-30T14:00:00Z","text":"x"}`)
	if ref == nil || ref.Info.Code != "E_OVER_BUDGET" {
		t.Errorf("over the range budget: %+v", ref)
	}

	// log.status and log.sources: no log content.
	st, _ := call(t, s, logconsole.MethodStatus, `{}`)
	sts := st.(Status)
	if sts.Epoch == "" || len(sts.Sources) != 1 || sts.Sources[0] != (SourceStatus{Name: "app", Kind: "file"}) || !strings.Contains(sts.Landlock, "landlock unsupported") || sts.Residuals != nil {
		t.Errorf("status = %+v", sts)
	}
	if _, ref := call(t, s, logconsole.MethodStatus, `{"x":1}`); ref == nil {
		t.Error("log.status took parameters")
	}
	srcs, _ := call(t, s, logconsole.MethodSources, `{}`)
	raw, _ := json.Marshal(srcs)
	if strings.Contains(string(raw), "jane") || !strings.Contains(string(raw), `"name":"app"`) || !strings.Contains(string(raw), `"name":"level"`) {
		t.Errorf("sources = %s", raw)
	}

	// The state: K_ref and the epochs, private.
	dir := filepath.Join(f.state, "engine")
	var key string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Name() == "ref.key" {
			key = p
		}
		return nil
	})
	fi, err := os.Stat(key)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 32 {
		t.Errorf("ref.key: %v %v", fi, err)
	}
}

func TestStateRefusals(t *testing.T) {
	f := newFixture(t, fileProfile, appLog)
	opened := 0
	s := open(t, f.options(func(o *Options) { o.EpochsOpened = func() { opened++ } }))
	if opened != 1 {
		t.Errorf("EpochsOpened called %d times, want 1", opened)
	}
	epoch := s.Status(context.Background()).(Status).Epoch
	s.Close()
	// Reopened (a reconnection): the same epoch.
	s = open(t, f.options(func(o *Options) { o.FirstOpen = false }))
	if e := s.Status(context.Background()).(Status).Epoch; e != epoch {
		t.Errorf("epoch changed on a reconnection: %s -> %s", epoch, e)
	}
	s.Close()
	var dir string
	filepath.WalkDir(f.state, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Name() == "ref.key" {
			dir = filepath.Dir(p)
		}
		return nil
	})
	// A missing K_ref in an existing state refuses the start.
	key, _ := os.ReadFile(filepath.Join(dir, "ref.key"))
	os.Remove(filepath.Join(dir, "ref.key"))
	if _, err := Open(context.Background(), f.options(nil)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("missing K_ref: %v", err)
	}
	// A corrupt one too.
	os.WriteFile(filepath.Join(dir, "ref.key"), key[:16], 0o600)
	if _, err := Open(context.Background(), f.options(nil)); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("corrupt K_ref: %v", err)
	}
	os.Remove(filepath.Join(dir, "ref.key"))
	os.WriteFile(filepath.Join(dir, "ref.key"), key, 0o644)
	if _, err := Open(context.Background(), f.options(nil)); err == nil || !strings.Contains(err.Error(), "private") {
		t.Errorf("exposed K_ref: %v", err)
	}
	os.Chmod(filepath.Join(dir, "ref.key"), 0o600)
	// Missing epoch keys refuse the start.
	os.RemoveAll(filepath.Join(dir, "epochs"))
	if _, err := Open(context.Background(), f.options(nil)); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Errorf("missing epochs: %v", err)
	}
}

func TestSessionRotation(t *testing.T) {
	cfg := func(logs string) string {
		return strings.Replace(fileProfile(logs), `structured = "redact-unknown"`, `structured = "redact-unknown"`+"\npseudonym_rotation = \"session\"", 1)
	}
	f := newFixture(t, cfg, appLog)
	s := open(t, f.options(nil))
	e1 := s.Status(context.Background()).(Status).Epoch
	s.Close()
	s = open(t, f.options(func(o *Options) { o.FirstOpen = false }))
	if e := s.Status(context.Background()).(Status).Epoch; e != e1 {
		t.Errorf("rotated on a reconnection")
	}
	s.Close()
	s = open(t, f.options(nil))
	if e := s.Status(context.Background()).(Status).Epoch; e == e1 {
		t.Errorf("not rotated at a new console session")
	}
}

func TestRefusedProfiles(t *testing.T) {
	loki := func(logs string) string {
		return fileProfile(logs) + `[profiles.staging.sources.loki]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "basic"
user = "reader"
`
	}
	f := newFixture(t, loki, appLog)
	if err := CheckKinds(f.policy.Profile); err == nil || !strings.Contains(err.Error(), "loki source, which this build of locklog does not read yet") {
		t.Errorf("CheckKinds: %v", err)
	}
	if _, err := Open(context.Background(), f.options(nil)); err == nil || !strings.Contains(err.Error(), "does not read yet") {
		t.Errorf("Open loki: %v", err)
	}
	// A file glob outside the checked roots.
	f = newFixture(t, fileProfile, appLog)
	if _, err := Open(context.Background(), f.options(func(o *Options) { o.Roots.Dirs = []string{"/var/log"} })); err == nil || !strings.Contains(err.Error(), "not a checked mount root") {
		t.Errorf("unchecked root: %v", err)
	}
	// No state directory.
	if _, err := Open(context.Background(), f.options(func(o *Options) { o.StateDir = "" })); err == nil {
		t.Error("no state dir")
	}
}

const dockerCfg = `version = 1
[profiles.prod]
production = true
[profiles.prod.sources.web]
kind = "docker"
containers = ["shop-*"]
trusted = ["level"]
`

func TestDockerGuardAndTrust(t *testing.T) {
	ps, err := config.ParseProfiles([]byte(dockerCfg), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := config.NewPolicy(ps["prod"], "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCKLOG_DOCKER_ROOT", "/var/lib/docker/containers")
	o := Options{OpenOptions: logconsole.OpenOptions{Policy: pol, StateDir: t.TempDir(), Roots: logconsole.Roots{Docker: "/var/lib/docker/containers"}},
		Confinement: Confinement{Landlock: landlock.Status{State: landlock.Unsupported}, Openat2: false}}
	if _, err := Open(context.Background(), o); err == nil || !strings.Contains(err.Error(), "neither Landlock nor openat2") {
		t.Errorf("unguarded production docker source: %v", err)
	}
	o.Confinement.Openat2 = true
	o.MapDir = t.TempDir()
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := s.Status(context.Background()).(Status)
	if len(st.Residuals) != 1 || !strings.Contains(st.Residuals[0], "Landlock is not enforced") {
		t.Errorf("residuals = %q", st.Residuals)
	}
	// Trusted names: the container is a label, level a line field; a
	// payload field named container is not trusted.
	if !s.trusted("web", "container", true) || s.trusted("web", "container", false) || !s.trusted("web", "level", false) || s.trusted("web", "level", true) || s.trusted("web", "stream", false) {
		t.Error("docker trust namespaces")
	}
	// #42: a docker record's payload {"container": ...} is redacted under
	// redact-unknown (the production default), the attribute is shown.
	p, err := parse.New(parse.Options{Format: "docker-json",
		StaticAttrs: []parse.Member{{Key: "container", Value: parse.Value{Kind: parse.KindString, Str: "shop-api-1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := p.NewReader(strings.NewReader(`{"log":"{\"container\":\"Jane Doe\",\"level\":\"warn\"}\n","stream":"stdout","time":"2026-10-30T13:00:01Z"}`+"\n"), 0)
	ev, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	rec := s.maskers.Mask("web", ev)
	out, _ := json.Marshal(rec)
	if v, _ := rec.Lookup("container"); v.Text() != mask.Redacted || strings.Contains(string(out), "Jane") || !strings.Contains(string(out), "shop-api-1") || !strings.Contains(string(out), `"level":"warn"`) {
		t.Errorf("docker record = %s", out)
	}
	// A wrong containers root is refused.
	s.Close()
	o.Roots.Docker = "/srv/docker/containers"
	if _, err := Open(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not the checked one") {
		t.Errorf("other docker root: %v", err)
	}
}

func TestProjectAllowRulesNotApplied(t *testing.T) {
	f := newFixture(t, fileProfile, appLog)
	os.WriteFile(filepath.Join(f.root, ".locklog", "pii.toml"), []byte("[[allow]]\nfield = \"user\"\n[[mask]]\nfield = \"msg\"\nmode = \"redact\"\n"), 0o644)
	s := open(t, f.options(nil))
	if n := s.Status(context.Background()).(Status).Notes; len(n) != 1 || !strings.Contains(n[0], "allow rule") {
		t.Errorf("notes = %q", n)
	}
	res, _ := call(t, s, logconsole.MethodSearch, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"}`)
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), "Jane") || strings.Contains(string(out), "payment failed") {
		t.Errorf("rules: %s", out)
	}
}

func TestLimitsAndNames(t *testing.T) {
	l := limits(config.DefaultLimits(false))
	if l.LocalRange != 7*24*time.Hour || l.MaxRecords != 200 || l.MaxOutput != 64<<10 || l.LocalBytes != 512<<20 || l.Deadline != 30*time.Second {
		t.Errorf("limits = %+v", l)
	}
	src := config.Source{Name: "k", Kind: config.KindFile, Format: "cri", Trusted: []string{"level"}}
	fields, labels := trustedNames(src)
	if !slices.Equal(fields, []string{"level"}) || !slices.Equal(labels, []string{"stream"}) {
		t.Errorf("cri: fields %v labels %v", fields, labels)
	}
	if fields, labels := trustedNames(config.Source{Kind: config.KindFile, Format: "json", Trusted: []string{"stream"}}); !slices.Equal(fields, []string{"stream"}) || labels != nil {
		t.Errorf("json: fields %v labels %v", fields, labels)
	}
}

// TestAroundMethodsServed: the console serves every engine method, and
// log.patterns, log.context, log.trace and log.tail reach the engine, masked.
func TestAroundMethodsServed(t *testing.T) {
	for _, m := range []string{engine.MethodSearch, engine.MethodCount, engine.MethodPatterns, engine.MethodContext, engine.MethodTrace, engine.MethodTail} {
		if !slices.Contains(logconsole.Methods, m) {
			t.Errorf("%s not served", m)
		}
	}
	f := newFixture(t, fileProfile, appLog)
	s := open(t, f.options(nil))
	res, ref := call(t, s, logconsole.MethodSearch, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z","limit":1}`)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	sr := res.(engine.SearchResult)
	if len(sr.Records) == 0 {
		t.Fatal("no record")
	}
	var r struct{ Ref string }
	json.Unmarshal(sr.Records[0], &r)
	for _, c := range []struct{ method, params string }{
		{logconsole.MethodPatterns, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"}`},
		{logconsole.MethodContext, `{"ref":"` + r.Ref + `","before":1,"after":1}`},
		{logconsole.MethodTrace, `{"id":"order-1","from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z"}`},
		{logconsole.MethodTail, `{"duration":"1s","max":1}`},
	} {
		res, ref := call(t, s, c.method, c.params)
		if ref != nil {
			t.Fatalf("%s refused: %+v", c.method, ref)
		}
		out, _ := json.Marshal(res)
		if strings.Contains(string(out), "jane") || strings.Contains(string(out), "Jane") {
			t.Fatalf("%s unmasked: %s", c.method, out)
		}
	}
}

// log.patterns is served by an opened session: masked templates only.
func TestOpenPatternsMasked(t *testing.T) {
	f := newFixture(t, fileProfile, appLog)
	s := open(t, f.options(nil))
	res, ref := call(t, s, logconsole.MethodPatterns, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z","top":5}`)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	out, _ := json.Marshal(res)
	got := string(out)
	if strings.Contains(got, "jane") || strings.Contains(got, "Jane") {
		t.Fatalf("unmasked: %s", got)
	}
	if !strings.Contains(got, `"patterns":[`) || !strings.Contains(got, `"records":2`) {
		t.Errorf("patterns = %s", got)
	}
	_, ref = call(t, s, logconsole.MethodPatterns, `{"from":"2026-10-30T13:00:00Z","to":"2026-10-30T14:00:00Z","top":1000}`)
	if ref == nil || ref.Info.Code != "E_BAD_QUERY" {
		t.Errorf("top over the maximum: %+v", ref)
	}
}
