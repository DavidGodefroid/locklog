package source

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
)

// ErrMountLost is returned (wrapped) by a source whose mount root is gone
// or is no longer the directory it first read (a stale handle, a root
// unmounted or swapped under the console): its logs can no longer be
// trusted to be the approved ones. The engine answers it as a lost
// session (logconsole.ErrConnLost), never as a refusal: the console drops
// the session and the next call reconnects, checking every mount again.
var ErrMountLost = errors.New("source: a log mount root is gone or was replaced")

// RootGuard pins the mount roots of a source: the first time a root is
// seen its device and inode are recorded, and every later Check compares
// them. It is safe for concurrent use; the zero value is ready.
type RootGuard struct {
	mu  sync.Mutex
	ids map[string]rootID
}

type rootID struct{ dev, ino uint64 }

// Check reports ErrMountLost (wrapped) when root, seen before, is gone,
// stale, no longer a directory or another directory. A root never seen
// that is absent is not an error (a journal directory the host does not
// have): it is pinned the first time it is found.
func (g *RootGuard) Check(root string) error {
	fi, err := os.Lstat(root)
	g.mu.Lock()
	defer g.mu.Unlock()
	was, seen := g.ids[root]
	if err != nil {
		switch {
		case errors.Is(err, syscall.ESTALE):
			return fmt.Errorf("%w: %s: %w", ErrMountLost, root, err)
		case !seen && errors.Is(err, fs.ErrNotExist):
			return nil
		case seen && (errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENODEV)):
			return fmt.Errorf("%w: %s: %w", ErrMountLost, root, err)
		}
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (a link?)", ErrMountLost, root)
	}
	dev, ino, ok := statID(fi)
	if !ok {
		return nil // no device and inode on this system: nothing to pin
	}
	now := rootID{dev, ino}
	if !seen {
		if g.ids == nil {
			g.ids = map[string]rootID{}
		}
		g.ids[root] = now
		return nil
	}
	if now != was {
		return fmt.Errorf("%w: %s is not the directory first read", ErrMountLost, root)
	}
	return nil
}

// MountLost wraps err in ErrMountLost when it says the mount under a read
// is gone (a stale file handle, ESTALE); any other error is returned as
// is.
func MountLost(err error) error {
	if err != nil && !errors.Is(err, ErrMountLost) && errors.Is(err, syscall.ESTALE) {
		return fmt.Errorf("%w: %w", ErrMountLost, err)
	}
	return err
}
