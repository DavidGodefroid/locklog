package agentassets

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/agentwire"

	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %s\nwant %s", name, got, want)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p, s string, m os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), m); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func status(res agentwire.Result, path string) string {
	for _, a := range res.Actions {
		if a.Path == path {
			return a.Status
		}
	}
	return ""
}

// The allow list holds the free tools only, as Claude Code names a project
// MCP server's tools; never an approved one.
func TestClaudeAllow(t *testing.T) {
	allow := ClaudeAllow()
	var want []string
	for _, n := range mcptools.FreeNames() {
		want = append(want, "mcp__locklog__"+n)
	}
	if !slices.Equal(allow, want) || len(allow) == 0 {
		t.Fatalf("allow = %v, want %v", allow, want)
	}
	for _, a := range allow {
		n, ok := strings.CutPrefix(a, "mcp__locklog__")
		if !ok || !strings.HasPrefix(n, "locklog_") || !mcptools.Free(n) {
			t.Errorf("allow entry %q is not a free locklog tool", a)
		}
	}
	if slices.Contains(allow, "mcp__locklog__"+mcptools.ToolRequestChange) {
		t.Error("the approved locklog_request_change is allowed")
	}
	if !slices.Equal(Wiring.Assets.ClaudeAllow, allow) || !Wiring.Assets.ClaudeAllowProject {
		t.Error("the wiring does not merge ClaudeAllow at project scope")
	}
}

func TestInitClaude(t *testing.T) {
	root := t.TempDir()
	res, err := InitProject(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Actions) == 0 {
		t.Fatal("no actions")
	}
	mcp, err := os.ReadFile(filepath.Join(root, ".mcp.json"))
	if err != nil || !strings.Contains(string(mcp), `"locklog"`) || !strings.Contains(string(mcp), `"mcp"`) {
		t.Errorf(".mcp.json: %s %v", mcp, err)
	}
	skill, err := os.ReadFile(filepath.Join(root, ".claude", "skills", "locklog", "SKILL.md"))
	if err != nil || !strings.HasPrefix(string(skill), "---\nname: locklog\n") || !strings.Contains(string(skill), "untrusted data") {
		t.Errorf("skill: %v", err)
	}
	cfg, err := os.ReadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil || !strings.HasPrefix(string(cfg), "# locklog") || !strings.Contains(string(cfg), "version = 1") {
		t.Errorf("example config: %v", err)
	}
}

// A fresh project gets the allow list in .claude/settings.local.json
// (mode 0644), never a shared .claude/settings.json; a second run changes
// nothing.
func TestInitClaudeAllowFresh(t *testing.T) {
	root := t.TempDir()
	res, err := InitProject(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(root, ".claude", "settings.local.json")
	got := readFile(t, local)
	golden(t, "settings.local.fresh.json", got)
	checkMode(t, local, 0o644)
	if _, err := os.Lstat(filepath.Join(root, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("the shared settings.json exists: %v", err)
	}
	if s := status(res, ".claude/settings.local.json"); s != agentwire.StatusCreated {
		t.Errorf("settings.local.json status = %q", s)
	}
	var out bytes.Buffer
	Report(&out, res)
	golden(t, "init-claude.txt", out.Bytes())

	res, err = InitProject(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Actions {
		if a.Status != agentwire.StatusUnchanged {
			t.Errorf("second run: %+v", a)
		}
	}
	if !bytes.Equal(readFile(t, local), got) {
		t.Error("second run rewrote settings.local.json")
	}
}

// An existing settings.local.json keeps the human's keys, entries, order
// and mode; only the missing locklog entries are appended. The shared
// settings.json is left byte for byte.
func TestInitClaudeAllowMerge(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, ".claude", "settings.local.json")
	shared := filepath.Join(root, ".claude", "settings.json")
	writeFile(t, local, `{"model":"opus","permissions":{"deny":["Bash(rm:*)"],"allow":["Bash(make test && make lint)","mcp__locklog__locklog_status"]},"env":{"A":"<b>"}}`, 0o600)
	sharedIn := `{"permissions":{"allow":["Bash(go test:*)"]}}` + "\n"
	writeFile(t, shared, sharedIn, 0o640)

	res, err := InitProject(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, local)
	golden(t, "settings.local.merged.json", got)
	if s := status(res, ".claude/settings.local.json"); s != agentwire.StatusUpdated {
		t.Errorf("settings.local.json status = %q", s)
	}
	checkMode(t, local, 0o600)
	checkMode(t, shared, 0o640)
	if string(readFile(t, shared)) != sharedIn {
		t.Error("the shared settings.json was changed")
	}

	if _, err := InitProject(root, "claude"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, local), got) {
		t.Error("second run rewrote settings.local.json")
	}
	if string(readFile(t, shared)) != sharedIn {
		t.Error("second run changed the shared settings.json")
	}
}

// An invalid settings.local.json is refused, not overwritten.
func TestInitClaudeAllowInvalidRefused(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, ".claude", "settings.local.json")
	writeFile(t, local, `{"permissions":{"allow":"all"}}`, 0o600)
	if _, err := InitProject(root, "claude"); err == nil {
		t.Fatal("an allow that is not an array was accepted")
	}
	if string(readFile(t, local)) != `{"permissions":{"allow":"all"}}` {
		t.Error("the invalid file was rewritten")
	}
}

// Only Claude Code gets an allow list.
func TestInitOtherAgentsNoAllow(t *testing.T) {
	for _, a := range []string{"codex", "cursor", "gemini"} {
		root := t.TempDir()
		if _, err := InitProject(root, a); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if _, err := os.Lstat(filepath.Join(root, ".claude")); !os.IsNotExist(err) {
			t.Errorf("%s: .claude written", a)
		}
	}
}
