//go:build linux

package file

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// openat2Beneath opens rel beneath root with openat2(RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS, plus RESOLVE_NO_XDEV with
// noXDev) (Linux ≥ 5.6). ok is false only when the kernel (or a seccomp
// filter) lacks openat2 (ENOSYS, EPERM): the caller falls back to the
// component-wise walk. EXDEV and ELOOP are refusals.
func openat2Beneath(root, rel string, noXDev bool) (*os.File, error, bool) {
	rfd, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: root, Err: err}, true
	}
	defer unix.Close(rfd)
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	if noXDev {
		how.Resolve |= unix.RESOLVE_NO_XDEV
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

// pathFlag opens a directory for traversal only: search permission is
// enough.
const pathFlag = unix.O_PATH

// mountKey identifies the mount a file is on: its mount id (statx
// STATX_MNT_ID, Linux >= 5.8), else its device.
type mountKey struct {
	mntID bool
	id    uint64
}

func mountOf(fd int) (mountKey, error) {
	if !forceDevMount {
		var stx unix.Statx_t
		err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx)
		if err == nil && stx.Mask&unix.STATX_MNT_ID != 0 {
			return mountKey{mntID: true, id: stx.Mnt_id}, nil
		}
		if err != nil && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
			return mountKey{}, err
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return mountKey{}, err
	}
	return mountKey{id: st.Dev}, nil
}

// forceDevMount is set by tests to check the device fallback.
var forceDevMount = false
