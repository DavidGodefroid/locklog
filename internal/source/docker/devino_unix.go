//go:build unix

package docker

import "syscall"

// devIno returns the device and inode of p, not following a final symbolic
// link (search permission on its directories is enough).
func devIno(p string) (uint64, uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true //nolint:unconvert // int32 on darwin
}
