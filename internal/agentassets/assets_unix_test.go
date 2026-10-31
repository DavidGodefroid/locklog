//go:build unix

package agentassets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkMode fails unless p has the permission bits want.
func checkMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode(); got != want {
		t.Errorf("%s: mode %v, want %v", filepath.Base(p), got, want)
	}
}

// A settings.local.json that links to the shared settings.json is refused
// and the project is left untouched.
func TestInitClaudeAllowSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, ".claude", "settings.json")
	sharedIn := `{"permissions":{"allow":[]}}` + "\n"
	writeFile(t, shared, sharedIn, 0o644)
	if err := os.Symlink("settings.json", filepath.Join(root, ".claude", "settings.local.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := InitProject(root, "claude"); err == nil || !strings.Contains(err.Error(), "settings.local.json") {
		t.Fatalf("err = %v", err)
	}
	if string(readFile(t, shared)) != sharedIn {
		t.Error("the shared settings.json was written through the link")
	}
	if _, err := os.Lstat(filepath.Join(root, ".mcp.json")); !os.IsNotExist(err) {
		t.Error("a refused init wrote .mcp.json")
	}
}
