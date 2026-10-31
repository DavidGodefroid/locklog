//go:build linux

package journald

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// pathFlags opens a directory only to resolve beneath it: search permission
// is enough.
const pathFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// openat2 opens rel beneath dirfd without crossing a symbolic link, a magic
// link or a mount point. ok is false when the kernel (or a seccomp filter)
// lacks openat2.
func openat2(dirfd int, rel string) (int, error, bool) {
	if forceWalk {
		return -1, nil, false
	}
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(dirfd, rel, &how)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		// No openat2 (kernel < 5.6) or a seccomp profile refusing it.
		return -1, nil, false
	}
	return fd, err, true
}

// forceWalk makes tests take the component-wise fallback.
var forceWalk = false

// sameMount reports whether fd, just opened at path, is on the mount of the
// root rfd: by mount id (statx STATX_MNT_ID, kernel >= 5.8), else by device
// plus a check that path itself is not a mount point (/proc/self/mountinfo).
func sameMount(rfd, fd int, path string) error {
	var a, b unix.Statx_t
	ea := unix.Statx(rfd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &a)
	eb := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &b)
	if ea == nil && eb == nil && a.Mask&unix.STATX_MNT_ID != 0 && b.Mask&unix.STATX_MNT_ID != 0 {
		if a.Mnt_id != b.Mnt_id {
			return errCrossMount
		}
		return nil
	}
	var sa, sb unix.Stat_t
	if err := unix.Fstat(rfd, &sa); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &sb); err != nil {
		return err
	}
	if sa.Dev != sb.Dev {
		return errCrossMount
	}
	return notMountPoint(path)
}

func notMountPoint(path string) error {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil // no procfs: the device check above is all there is
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && unescapeMount(f[4]) == path {
			return errCrossMount
		}
	}
	return nil
}

// unescapeMount decodes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				out = append(out, byte(v))
				i += 3
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}
