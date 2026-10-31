//go:build unix

package file

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// Directories that grant search but not read (Docker's 0710 directories,
// reached through the group): a literal path is still opened; a glob that
// must list them matches nothing.
func TestSearchOnlyDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	e := newEnv(t)
	e.write("logs/c/abc/abc-json.log", genLines(t0, 5), time.Time{})
	for _, d := range []string{"logs/c/abc", "logs/c"} {
		if err := os.Chmod(filepath.Join(e.root, d), 0o100); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		os.Chmod(filepath.Join(e.root, "logs/c"), 0o755)
		os.Chmod(filepath.Join(e.root, "logs/c/abc"), 0o755)
	})
	if _, err := os.ReadDir(filepath.Join(e.root, "logs/c")); err == nil {
		t.Fatal("the test directory is listable")
	}
	root := filepath.Join(e.root, "logs/c")
	src := e.source([]string{root + "/abc/abc-json.log"}, func(o *Options) { o.Roots = []string{root}; o.NoXDev = true })
	plan, err := src.Plan(ctx, everything, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if got := scanPlan(t, src, plan); len(got) != 6 { // 5 records and one stack frame line
		t.Fatalf("%d records through search-only directories", len(got))
	}
	// A glob over a directory that cannot be listed matches nothing.
	glob := e.source([]string{root + "/*/abc-json.log"}, func(o *Options) { o.Roots = []string{root} })
	plan, err = glob.Plan(ctx, everything, source.Selector{})
	if err != nil || len(plan.Chunks) != 0 {
		t.Fatalf("glob over an unreadable directory: %v %+v", err, plan)
	}
}
