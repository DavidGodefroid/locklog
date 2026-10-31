//go:build unix

package journald

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return errors.New("journald source: invalid path component")
	}
	return nil
}

// listDir lists the entries of root/rel (rel "" or one component), without
// following a symbolic link anywhere, as (name, isDir, isRegular).
func listDir(root, rel string) ([]dirEntry, error) {
	fd, err := unix.Open(root, dirFlags, 0)
	if err != nil {
		return nil, err
	}
	if rel != "" {
		if err := validName(rel); err != nil {
			unix.Close(fd)
			return nil, err
		}
		sub, err := unix.Openat(fd, rel, dirFlags, 0)
		if err == nil {
			if err = sameMount(fd, sub, root+"/"+rel); err != nil {
				unix.Close(sub)
			}
		}
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = sub
	}
	f := os.NewFile(uintptr(fd), root)
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]dirEntry, 0, len(des))
	for _, de := range des {
		out = append(out, dirEntry{name: de.Name(), dir: de.Type().IsDir(), reg: de.Type().IsRegular()})
	}
	return out, nil
}

var errCrossMount = errors.New("journald source: path crosses a mount point")

// openBeneath opens root/dir/name read-only: openat2 with RESOLVE_BENEATH,
// RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS and RESOLVE_NO_XDEV where the
// kernel has it, else one openat(O_NOFOLLOW) per component on the root's
// device. Regular files only.
func openBeneath(root, dir, name string) (*os.File, error) {
	if err := validName(dir); err != nil {
		return nil, err
	}
	if err := validName(name); err != nil {
		return nil, err
	}
	rfd, err := unix.Open(root, pathFlags, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rfd)
	fd, err, ok := openat2(rfd, dir+"/"+name)
	if !ok {
		var dfd int
		dfd, err = unix.Openat(rfd, dir, pathFlags, 0)
		if err != nil {
			return nil, err
		}
		defer unix.Close(dfd)
		if err := sameMount(rfd, dfd, root+"/"+dir); err != nil {
			return nil, err
		}
		fd, err = unix.Openat(dfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			if err = sameMount(rfd, fd, root+"/"+dir+"/"+name); err != nil {
				unix.Close(fd)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, fmt.Errorf("journald source: not a regular file")
	}
	return os.NewFile(uintptr(fd), name), nil
}
