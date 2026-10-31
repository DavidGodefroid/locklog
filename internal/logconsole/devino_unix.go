//go:build unix

package logconsole

import (
	"errors"
	"os"
	"strconv"
	"syscall"
)

// devIno is fi's device:inode, as the launcher's stat prints it.
func devIno(fi os.FileInfo) (string, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no device and inode")
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10), nil
}
