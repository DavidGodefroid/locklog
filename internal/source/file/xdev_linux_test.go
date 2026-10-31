//go:build linux

package file

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A mount point under the root is refused with NoXDev, on both open paths:
// /dev/shm (a tmpfs) under /dev stands for a mount propagated under the
// containers root.
func TestNoXDevRefusesMountPoints(t *testing.T) {
	var dev, shm syscall.Stat_t
	if syscall.Stat("/dev", &dev) != nil || syscall.Stat("/dev/shm", &shm) != nil || dev.Dev == shm.Dev {
		t.Skip("/dev/shm is not a separate mount here")
	}
	f, err := os.CreateTemp("/dev/shm", "locklog-xdev-*")
	if err != nil {
		t.Skipf("/dev/shm is not writable: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	rel := "shm/" + filepath.Base(f.Name())
	opens := map[string]func(bool) (*os.File, error){
		"beneath": func(x bool) (*os.File, error) { return openBeneath("/dev", rel, x) },
		"walk":    func(x bool) (*os.File, error) { return walkOpen("/dev", rel, x) },
		"walk-dev": func(x bool) (*os.File, error) {
			forceDevMount = true
			defer func() { forceDevMount = false }()
			return walkOpen("/dev", rel, x)
		},
	}
	for name, open := range opens {
		g, err := open(false)
		if err != nil {
			t.Fatalf("%s: without NoXDev: %v", name, err)
		}
		g.Close()
		if g, err := open(true); err == nil {
			g.Close()
			t.Errorf("%s: crossed the /dev/shm mount", name)
		} else if name != "beneath" && !errors.Is(err, errXDev) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same filesystem is not refused.
	if g, err := walkOpen("/dev/shm", filepath.Base(f.Name()), true); err != nil {
		t.Errorf("same mount refused: %v", err)
	} else {
		g.Close()
	}
}
