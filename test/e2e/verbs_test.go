//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// The five-minute path: install (the launcher on PATH), lox add's verbs
// (profile add --non-interactive, init claude), the console as lox run
// starts it, and an MCP client spawning the server the written .mcp.json
// names asks a count, under 300 s; the answer is masked, and the written
// allow list holds the free tools only, at project scope.
func TestFiveMinutes(t *testing.T) {
	t0 := time.Now()
	e, want, from, to := newEnv(t, "five")
	out := e.locklog(t, "profile", "add", "--non-interactive", "--json", "--profile", "staging", "--only", e.logs)
	t.Logf("profile add: %s", out)
	if !strings.Contains(out, `{"lock":"locklog","profile":"staging","config":"`+filepath.Join(e.proj, ".locklog", "config.toml")+`","production":false}`) {
		t.Fatalf("profile add --json: %s", out)
	}
	out = e.locklog(t, "init", "claude")
	t.Logf("init claude:\n%s", out)

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
	// The agent's mcp before lox run: refused, saying to run lox run.
	cmd := exec.Command(e.launcher, "mcp")
	cmd.Dir, cmd.Env = e.proj, e.env
	if b, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(b), "run `lox run` first") {
		t.Errorf("mcp without lox run: %v\n%s", err, b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	startLoxRun(t, e, "staging", "", [2]string{"Apply these changes? [y/N]", "y"})
	cs := e.connect(t, ctx, append([]string{srv.Command}, srv.Args...))
	total, _, calls := count(t, ctx, cs, map[string]any{"from": from, "to": to})
	elapsed := time.Since(t0)
	t.Logf("locklog_count: %d records (%d calls), want %d; %s from profile add to the answer", total, calls, want, elapsed.Round(time.Second))
	if total != int64(want) {
		t.Errorf("locklog_count = %d, want %d", total, want)
	}
	if elapsed >= 300*time.Second {
		t.Errorf("the five-minute path took %s, want under 300 s", elapsed)
	}
	masked(t, ctx, cs, from, to)
}

// The own-container recipe (docs/setup.md): an agent image built from its
// Dockerfile snippet, run as its non-root agent user with lox run's socket
// volume read-only, calls the console.
func TestOwnContainer(t *testing.T) { ownContainer(t, 0) }

// TestOwnContainerUID: an agent uid the console's image knows by no
// account is admitted by the console's --allowed-uids (lockfamily.yaml's
// allowed_uids, which lox run passes on).
func TestOwnContainerUID(t *testing.T) { ownContainer(t, 1000) }

// recipe is the own-container recipe's Dockerfile snippet in docs/setup.md
// (its first dockerfile block), for image and the agent's uid.
func recipe(t *testing.T, image, uid string) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/setup.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(doc), "```dockerfile\n")
	block, _, ok2 := strings.Cut(rest, "```")
	if !ok || !ok2 {
		t.Fatal("docs/setup.md has no dockerfile block")
	}
	const ref = "ghcr.io/davidgodefroid/locklog@sha256:<digest>"
	if !strings.Contains(block, "COPY --from="+ref+" ") || !strings.Contains(block, "USER 10052:10050") {
		t.Fatalf("the recipe changed:\n%s", block)
	}
	block = strings.ReplaceAll(block, ref, image)
	return strings.ReplaceAll(block, "10052", uid)
}

// ownContainer runs the own-container recipe end to end, for the agent
// uid (0: the image's agent account, 10052).
func ownContainer(t *testing.T, agentUID int) {
	name, uid, allowed := "own", "10052", ""
	if agentUID != 0 {
		name, uid = "own"+strconv.Itoa(agentUID), strconv.Itoa(agentUID)
		allowed = uid
	}
	e, want, from, to := newEnv(t, name)
	e.locklog(t, "profile", "add", "--non-interactive", "--profile", "staging", "--only", e.logs)
	snippet := recipe(t, e.image, uid)
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
	tag := "locklog-e2e-agent-" + uid
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
	if f[0] != uid || !slices.Contains(f[1:len(f)-2], "10050") || f[len(f)-2] != "no-sudo" || f[len(f)-1] != "0:644" {
		t.Errorf("agent image: want uid %s in 10050, no sudo, system.toml 0:644; got %q", uid, id)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	lr := startLoxRun(t, e, "staging", allowed, [2]string{"Apply these changes? [y/N]", "y"})
	cs := e.connect(t, ctx, []string{"docker", "run", "--rm", "-i", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--network", "none", "-v", lr.sockVol + ":/run/locklog:ro",
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
	e.locklog(t, "profile", "add", "--non-interactive", "--production", "--profile", "prod", "--only", e.logs)
	cfg, err := os.ReadFile(filepath.Join(e.proj, ".locklog", "config.toml"))
	if err != nil || !strings.Contains(string(cfg), "[profiles.prod]\nproduction = true\n") {
		t.Fatalf("config: %v\n%s", err, cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// On production, the policy review takes the profile name typed.
	startLoxRun(t, e, "prod", "", [2]string{`Apply these changes? Type the profile name "prod" to apply them`, "prod"})
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
