//go:build unix

package setup

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether st is owned by this process's euid.
func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}
