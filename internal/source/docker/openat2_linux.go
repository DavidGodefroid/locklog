//go:build linux

package docker

import "golang.org/x/sys/unix"

// Openat2 reports whether openat2 with RESOLVE_NO_XDEV works here (Linux >=
// 5.6, not blocked by seccomp): the file source then refuses mount
// crossings in the kernel, not by a comparison.
func Openat2() bool {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &how)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
