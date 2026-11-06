//go:build unix

package setup

import (
	"os"
	"path/filepath"
	"testing"
)

// The writes of profile add go through the .locklog/ directory opened
// after the prompts (#87): a .locklog/ replaced by a link to another
// directory after checkLocklogDir is refused, and nothing is created,
// chmodded or renamed in the link's target. The race is reproduced by its
// outcome: the link is in place when the writes run.
func TestWritesRefuseALinkedLocklogDir(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(dir, cfg string) error
	}{
		{"create", func(dir, cfg string) error { return writeConfig(dir, cfg, []byte("version = 1\n")) }},
		{"append", func(dir, cfg string) error { return replaceConfig(dir, cfg, []byte("version = 1\n")) }},
		{"ca", func(dir, _ string) error {
			r, err := openLocklogDir(dir, false)
			if err != nil {
				return err
			}
			defer r.Close()
			return writeExcl(r, "x-ca.crt", []byte("ca"), 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			target := filepath.Join(base, "elsewhere")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "config.toml"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, ".locklog")
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
			if err := tc.write(dir, filepath.Join(dir, "config.toml")); err == nil {
				t.Error("a linked .locklog/ was written through")
			}
			ents, _ := os.ReadDir(target)
			if len(ents) != 1 {
				t.Errorf("the link's target holds %d files", len(ents))
			}
			if st, err := os.Stat(target); err != nil || st.Mode().Perm() != 0o700 {
				t.Errorf("the link's target was chmodded: %v %v", st.Mode(), err)
			}
			if b, _ := os.ReadFile(filepath.Join(target, "config.toml")); string(b) != "old" {
				t.Errorf("the target's config was replaced: %q", b)
			}
		})
	}
}

// A real .locklog/ is opened: created 0755 (whatever the umask), an
// existing one writable by others refused.
func TestOpenLocklogDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, ".locklog")
	r, err := openLocklogDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
		t.Errorf("created %v %v", st.Mode(), err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if r, err := openLocklogDir(dir, true); err == nil {
		r.Close()
		t.Error("a world-writable .locklog/ was opened")
	}
}
