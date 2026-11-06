//go:build unix

package source

import (
	"os"
	"syscall"
)

func statID(fi os.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true //nolint:unconvert // int32 on darwin
}
