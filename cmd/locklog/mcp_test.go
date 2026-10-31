package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `locklog init claude` writes the free tools into the project's
// settings.local.json and prints it; the shared settings.json is not
// created.
func TestInitCmdClaudeAllow(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "src")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	var out, errb bytes.Buffer
	if code := run([]string{"init", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "created .claude/settings.local.json\n") {
		t.Errorf("output:\n%s", out.String())
	}
	b, err := os.ReadFile(filepath.Join(root, ".claude", "settings.local.json"))
	if err != nil || !strings.Contains(string(b), `"mcp__locklog__locklog_search"`) || strings.Contains(string(b), "request_change") {
		t.Errorf("settings.local.json = %s (%v)", b, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("the shared settings.json was created")
	}
}
