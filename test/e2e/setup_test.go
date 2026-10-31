//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/locklog/internal/agentassets"
)

// e2eEnv is a test's directories, image, launcher and environment.
type e2eEnv struct {
	base, logs, proj, bin, image, launcher string
	env                                    []string
}

// newEnv makes base/{logs,proj,bin} under LOCKLOG_E2E_DIR, writes the rotated
// logs, and installs the launcher as `locklog` in bin, first in PATH (the
// launcher of this commit, running the image built as LOCKLOG_IMAGE).
func newEnv(t *testing.T, name string) (*e2eEnv, int, string, string) {
	t.Helper()
	root := os.Getenv("LOCKLOG_E2E_DIR")
	if root == "" {
		t.Skip("LOCKLOG_E2E_DIR is not set: this test runs in CI")
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	e := &e2eEnv{base: filepath.Join(root, name), image: os.Getenv("LOCKLOG_IMAGE")}
	if e.image == "" {
		e.image = "locklog"
	}
	e.logs, e.proj, e.bin = filepath.Join(e.base, "logs"), filepath.Join(e.base, "proj"), filepath.Join(e.base, "bin")
	for _, d := range []string{e.base, e.logs, e.proj, e.bin} {
		mkdir(t, d)
	}
	src, err := os.ReadFile("../../scripts/locklog")
	if err != nil {
		t.Fatal(err)
	}
	e.launcher = filepath.Join(e.bin, "locklog")
	if err := os.WriteFile(e.launcher, src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	e.env = append(os.Environ(), "PATH="+e.bin+":"+os.Getenv("PATH"), "LOCKLOG_EXTRA_ROOTS="+e.logs, "LOCKLOG_IMAGE="+e.image)
	start := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	want := writeLogs(t, e.logs, start)
	end := start.Add(time.Duration(want-1) * step)
	return e, want, start.Add(-time.Minute).Format(time.RFC3339), end.Add(time.Minute).Format(time.RFC3339)
}

// locklog runs the installed launcher in the project and returns its output.
func (e *e2eEnv) locklog(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(e.launcher, args...)
	cmd.Dir, cmd.Env = e.proj, e.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locklog %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// startConsole starts `locklog console ARGS` in a terminal of its own
// (script(1)) and answers the prompts in order, each once it shows, as a
// human does; it returns once the console listens.
func (e *e2eEnv) startConsole(t *testing.T, args string, answers ...[2]string) {
	t.Helper()
	console := exec.Command("script", "-q", "-f", "-e", "-c", "exec locklog console "+args, "/dev/null")
	console.Dir, console.Env = e.proj, e.env
	keys, err := console.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var screen buffer
	console.Stdout, console.Stderr = &screen, &screen
	if err := console.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = console.Wait(); close(exited) }()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("console output (masked):\n%s", plain(screen.String()))
		}
		_, _ = io.WriteString(keys, ":quit\r")
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			_ = console.Process.Kill()
			<-exited
		}
	})
	for _, a := range answers {
		waitFor(t, &screen, a[0], 3*time.Minute, exited)
		if _, err := io.WriteString(keys, a[1]+"\r"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, &screen, "Listening on ", 2*time.Minute, exited)
}

// connect starts an MCP server with argv and connects a client to it.
func (e *e2eEnv) connect(t *testing.T, ctx context.Context, argv []string) *mcp.ClientSession {
	t.Helper()
	name := argv[0]
	if name == "locklog" {
		// As the agent's PATH finds it: the installed launcher.
		name = e.launcher
	}
	srv := exec.Command(name, argv[1:]...)
	var stderr buffer
	srv.Dir, srv.Env, srv.Stderr = e.proj, e.env, &stderr
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "locklog-e2e", Version: "0"}, nil).Connect(ctx, &mcp.CommandTransport{Command: srv}, nil)
	if err != nil {
		t.Fatalf("mcp connect %q: %v\n%s", argv, err, stderr.String())
	}
	t.Cleanup(func() {
		cs.Close()
		if t.Failed() {
			t.Logf("mcp server stderr:\n%s", stderr.String())
		}
	})
	return cs
}

// masked checks a search answer: pseudonyms, never a clear email.
func masked(t *testing.T, ctx context.Context, cs *mcp.ClientSession, from, to string) {
	t.Helper()
	sraw, stext := call(t, ctx, cs, "locklog_search", map[string]any{"from": from, "to": to, "limit": 20})
	so := decode(t, "locklog_search", sraw)
	j, _ := json.Marshal(sraw)
	t.Logf("locklog_search: %d records, pseudonyms %v", len(so.Records), strings.Contains(stext, "⟦email:"))
	if len(so.Records) == 0 || !strings.Contains(stext, "⟦email:") {
		t.Errorf("locklog_search: no masked records:\n%s", stext)
	}
	for _, clear := range emails {
		if strings.Contains(stext, clear) || strings.Contains(string(j), clear) {
			t.Errorf("locklog_search: the clear value %q reached the agent", clear)
		}
	}
}

// The five-minute path: install (the launcher on PATH), setup scripted,
// the console, and an MCP client spawning the server the written
// .mcp.json names asks a count, under 300 s; the answer is masked, and the
// written allow list holds the free tools only, at project scope.
func TestFiveMinutes(t *testing.T) {
	t0 := time.Now()
	e, want, from, to := newEnv(t, "five")
	out := e.locklog(t, "setup", "--yes", "--no-production", "--agent", "host", "--agents", "claude", "--only", e.logs)
	t.Logf("setup output:\n%s", out)

	var mcpJSON struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	b, err := os.ReadFile(filepath.Join(e.proj, ".mcp.json"))
	if err != nil || json.Unmarshal(b, &mcpJSON) != nil {
		t.Fatalf(".mcp.json: %v: %s", err, b)
	}
	srv, ok := mcpJSON.MCPServers["locklog"]
	if !ok || srv.Command == "" {
		t.Fatalf(".mcp.json has no locklog server: %s", b)
	}
	t.Logf(".mcp.json: locklog server %s %v", srv.Command, srv.Args)

	var settings struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	b, err = os.ReadFile(filepath.Join(e.proj, ".claude", "settings.local.json"))
	if err != nil || json.Unmarshal(b, &settings) != nil {
		t.Fatalf("settings.local.json: %v: %s", err, b)
	}
	t.Logf("permissions.allow: %v", settings.Permissions.Allow)
	if !slices.Equal(settings.Permissions.Allow, agentassets.ClaudeAllow()) {
		t.Errorf("permissions.allow = %v, want the free tools %v", settings.Permissions.Allow, agentassets.ClaudeAllow())
	}
	for _, a := range settings.Permissions.Allow {
		if strings.Contains(a, "request_change") {
			t.Errorf("an approved tool is allowed: %s", a)
		}
	}
	if _, err := os.Stat(filepath.Join(e.proj, ".claude", "settings.json")); err == nil {
		t.Error("the shared .claude/settings.json was written")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e.startConsole(t, "--profile staging", [2]string{"Apply these changes? [y/N]", "y"})
	cs := e.connect(t, ctx, append([]string{srv.Command}, srv.Args...))
	total, _, calls := count(t, ctx, cs, map[string]any{"from": from, "to": to})
	elapsed := time.Since(t0)
	t.Logf("locklog_count: %d records (%d calls), want %d; %s from setup to the answer", total, calls, want, elapsed.Round(time.Second))
	if total != int64(want) {
		t.Errorf("locklog_count = %d, want %d", total, want)
	}
	if elapsed >= 300*time.Second {
		t.Errorf("the five-minute path took %s, want under 300 s", elapsed)
	}
	masked(t, ctx, cs, from, to)
}

// The own-container recipe: an agent image built from the snippet setup
// prints, run as its non-root agent user, calls the console.
func TestOwnContainer(t *testing.T) {
	e, want, from, to := newEnv(t, "own")
	out := e.locklog(t, "setup", "--yes", "--no-production", "--agent", "container", "--only", e.logs)
	lines := strings.Split(out, "\n")
	first := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "# locklog's client") })
	last := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "USER ") })
	if first < 0 || last < first {
		t.Fatalf("no Dockerfile snippet in:\n%s", out)
	}
	snippet := strings.Join(lines[first:last+1], "\n")
	for _, want := range []string{"COPY --from=" + e.image + " ", "/etc/locklog/system.toml", "USER 10052:10050"} {
		if !strings.Contains(snippet, want) {
			t.Errorf("snippet lacks %q", want)
		}
	}
	if !strings.Contains(out, `docker run --rm -it -v locklog-run:/run/locklog -v "$PWD:$PWD" -w "$PWD" your-agent-image`) ||
		!strings.Contains(out, "one locklog-run volume is one trust") {
		t.Errorf("the run line or the trust domain is missing:\n%s", out)
	}
	base := os.Getenv("LOCKLOG_E2E_AGENT_BASE")
	if base == "" {
		base = "alpine:3.22"
	}
	ctxDir := filepath.Join(e.base, "agent-image")
	mkdir(t, ctxDir)
	dockerfile := "FROM " + base + "\n" + snippet + "\n"
	t.Logf("agent Dockerfile:\n%s", dockerfile)
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	tag := "locklog-e2e-agent"
	if b, err := exec.Command("docker", "build", "-q", "-t", tag, ctxDir).CombinedOutput(); err != nil {
		t.Fatalf("docker build of the agent image: %v\n%s", err, b)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	id, err := exec.Command("docker", "run", "--rm", tag, "sh", "-c", "id -u; id -G; command -v sudo || echo no-sudo; stat -c %u:%a /etc/locklog/system.toml").CombinedOutput()
	if err != nil {
		t.Fatalf("agent image: %v\n%s", err, id)
	}
	f := strings.Fields(string(id))
	t.Logf("agent image: uid %s, groups %v, %s, system.toml %s", f[0], f[1:len(f)-2], f[len(f)-2], f[len(f)-1])
	if f[0] != "10052" || !slices.Contains(f[1:len(f)-2], "10050") || f[len(f)-2] != "no-sudo" || f[len(f)-1] != "0:644" {
		t.Errorf("agent image: want uid 10052 in 10050, no sudo, system.toml 0:644; got %q", id)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e.startConsole(t, "--profile staging", [2]string{"Apply these changes? [y/N]", "y"})
	cs := e.connect(t, ctx, []string{"docker", "run", "--rm", "-i", "--network", "none", "-v", "locklog-run:/run/locklog",
		"-v", e.proj + ":" + e.proj, "-w", e.proj, tag, "locklog", "mcp"})
	_, st := call(t, ctx, cs, "locklog_status", nil)
	t.Logf("locklog_status from the agent's own container:\n%s", st)
	total, _, calls := count(t, ctx, cs, map[string]any{"from": from, "to": to})
	t.Logf("locklog_count from the agent's own container: %d records (%d calls), want %d", total, calls, want)
	if total != int64(want) {
		t.Errorf("locklog_count = %d, want %d", total, want)
	}
	masked(t, ctx, cs, from, to)
}

// The production guard: the launcher's mcp (a host agent) is refused on a
// production profile with E_PRODUCTION_HOST_AGENT, for every data tool.
func TestProductionGuard(t *testing.T) {
	e, _, from, to := newEnv(t, "prod")
	e.locklog(t, "setup", "--yes", "--production", "--agent", "host", "--agents", "claude", "--only", e.logs)
	cfg, err := os.ReadFile(filepath.Join(e.proj, ".locklog", "config.toml"))
	if err != nil || !strings.Contains(string(cfg), "[profiles.prod]\nproduction = true\n") {
		t.Fatalf("config: %v\n%s", err, cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e.startConsole(t, "--profile prod", [2]string{"Apply these changes? [y/N]", "y"}, [2]string{`Type the profile name "prod"`, "prod"})
	cs := e.connect(t, ctx, []string{"locklog", "mcp"})
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"locklog_count", map[string]any{"from": from, "to": to}},
		{"locklog_search", map[string]any{"from": from, "to": to, "limit": 5}},
		{"locklog_sources", nil},
	} {
		r, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if err != nil {
			t.Fatalf("%s: %v", c.tool, err)
		}
		j, _ := json.Marshal(r.StructuredContent)
		t.Logf("%s on production as a host agent: isError %v, %s", c.tool, r.IsError, j)
		if !r.IsError || !strings.Contains(string(j)+text(r), "E_PRODUCTION_HOST_AGENT") {
			t.Errorf("%s: want the refusal E_PRODUCTION_HOST_AGENT, got %s %s", c.tool, j, text(r))
		}
		for _, clear := range emails {
			if strings.Contains(string(j)+text(r), clear) {
				t.Errorf("%s: a clear value reached the refused agent", c.tool)
			}
		}
	}
}
