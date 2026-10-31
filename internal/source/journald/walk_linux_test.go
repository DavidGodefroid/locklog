//go:build linux

package journald

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFallbackWalkRefusesLinks(t *testing.T) {
	forceWalk = true
	defer func() { forceWalk = false }()
	r := root(t, map[string]string{"system.journal": "debian-12/remote.journal.gz"})
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "x.journal"), []byte("x"), 0o644)
	os.Symlink(filepath.Join(other, "x.journal"), filepath.Join(r, mid, "system@l.journal"))
	os.Symlink(other, filepath.Join(r, "fedcba9876543210fedcba9876543210"))
	if f, err := openBeneath(r, mid, "system.journal"); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	if _, err := openBeneath(r, mid, "system@l.journal"); err == nil {
		t.Fatal("walk followed a symlinked file")
	}
	if _, err := openBeneath(r, "fedcba9876543210fedcba9876543210", "x.journal"); err == nil {
		t.Fatal("walk followed a symlinked directory")
	}
	s := newSource(t, Options{Roots: []string{r}})
	if n := len(scanAll(t, s, everything)); n != 300 {
		t.Fatalf("walk: %d records", n)
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/a\040b\134c`); got != `/a b\c` {
		t.Fatalf("%q", got)
	}
}
