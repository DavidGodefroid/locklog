package agentassets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeAllow(t *testing.T) {
	allow := ClaudeAllow()
	for _, a := range allow {
		if !strings.HasPrefix(a, "mcp__locklog__locklog_") && !strings.HasPrefix(a, "Bash(locklog ") {
			t.Errorf("unexpected allow entry %q", a)
		}
	}
	if len(allow) < 8 {
		t.Errorf("allow = %v", allow)
	}
}

func TestInitClaude(t *testing.T) {
	root := t.TempDir()
	res, err := Wiring.Init(root, "claude")
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
