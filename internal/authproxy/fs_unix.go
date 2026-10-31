//go:build unix

package authproxy

import (
	"errors"
	"os"
	"syscall"
)

// checkOwner refuses a directory owned by another user.
func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("authproxy: cannot read the directory's owner")
	}
	if int(st.Uid) != os.Geteuid() {
		return errors.New("authproxy: the directory is owned by another user")
	}
	return nil
}

// createFile creates path, which must not exist, with mode (never through
// a symlink).
func createFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
