//go:build linux

package file

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// openat2Beneath opens rel beneath root with openat2(RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS) (Linux ≥ 5.6). ok is false
// when the kernel (or a seccomp filter) lacks openat2: the caller falls back
// to the component-wise walk.
func openat2Beneath(root, rel string) (*os.File, error, bool) {
	rfd, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: root, Err: err}, true
	}
	defer unix.Close(rfd)
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rfd, rel, &how)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) && !forceOpenat2 {
		return nil, nil, false
	}
	if err != nil {
		return nil, &fs.PathError{Op: "openat2", Path: root + "/" + rel, Err: err}, true
	}
	f, err := regular(fd, root+"/"+rel)
	return f, err, true
}

// forceOpenat2 is set by tests to tell an EPERM from openat2 apart from a
// seccomp refusal.
var forceOpenat2 = false
