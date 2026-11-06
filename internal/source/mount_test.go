//go:build unix

package source

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootGuard(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "logs")
	var g RootGuard
	// Never seen and absent: not an error (pinned once found).
	if err := g.Check(root); err != nil {
		t.Fatalf("absent root never seen: %v", err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := g.Check(root); err != nil {
			t.Fatalf("same root: %v", err)
		}
	}
	// Swapped for another directory.
	if err := os.Rename(root, root+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(root); !errors.Is(err, ErrMountLost) {
		t.Errorf("swapped root: %v", err)
	}
	// Gone.
	os.Remove(root)
	if err := g.Check(root); !errors.Is(err, ErrMountLost) {
		t.Errorf("removed root: %v", err)
	}
	// A link in its place.
	if err := os.Symlink(root+".old", root); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(root); !errors.Is(err, ErrMountLost) {
		t.Errorf("link in place of the root: %v", err)
	}
}

func TestMountLost(t *testing.T) {
	stale := fmt.Errorf("read: %w", &os.PathError{Op: "read", Path: "/var/log/app.log", Err: syscall.ESTALE})
	if err := MountLost(stale); !errors.Is(err, ErrMountLost) || !errors.Is(err, syscall.ESTALE) {
		t.Errorf("ESTALE: %v", err)
	}
	other := errors.New("permission denied")
	if MountLost(other) != other || MountLost(nil) != nil {
		t.Error("another error was wrapped")
	}
}
