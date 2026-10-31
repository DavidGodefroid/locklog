//go:build unix

package file

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// dir is an open directory, reached from a root without following any
// symbolic link. It is opened for traversal only (O_PATH on Linux): Docker's
// 0710 directories grant search, not read, to the group the console joins.
// list reopens it for reading.
type dir struct {
	fd   int
	path string // for messages only
}

const dirFlags = pathFlag | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// openRoot opens a mount root. The root path itself is canonical (the
// launcher resolved it and the console checked its dev/inode); its last
// component must not be a symbolic link.
func openRoot(path string) (*dir, error) {
	fd, err := unix.Open(path, dirFlags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return &dir{fd: fd, path: path}, nil
}

func (d *dir) close() { unix.Close(d.fd) }

// validName refuses names that could leave the directory.
func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid path component %q", name)
	}
	return nil
}

// sub opens the subdirectory name, refusing a symbolic link.
func (d *dir) sub(name string) (*dir, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name, dirFlags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: d.path + "/" + name, Err: err}
	}
	return &dir{fd: fd, path: d.path + "/" + name}, nil
}

// entry is a directory entry, typed from lstat (never followed).
type entry struct {
	name string
	dir  bool
	reg  bool
}

// lstat types the entry name without following it.
func (d *dir) lstat(name string) (entry, error) {
	if err := validName(name); err != nil {
		return entry{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return entry{}, err
	}
	t := st.Mode & unix.S_IFMT
	return entry{name: name, dir: t == unix.S_IFDIR, reg: t == unix.S_IFREG}, nil
}

// list returns the directory's entries. It reopens the directory for
// reading: d itself may be open for traversal only.
func (d *dir) list() ([]entry, error) {
	fd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), d.path)
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(des))
	for _, de := range des {
		t := de.Type()
		out = append(out, entry{name: de.Name(), dir: t.IsDir(), reg: t.IsRegular()})
	}
	return out, nil
}

// open opens the regular file name read-only, refusing a symbolic link, a
// device, a FIFO or a socket.
func (d *dir) open(name string) (*os.File, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: d.path + "/" + name, Err: err}
	}
	return regular(fd, d.path+"/"+name)
}

// regular wraps fd after checking it is a regular file.
func regular(fd int, path string) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &fs.PathError{Op: "open", Path: path, Err: errors.New("not a regular file")}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openBeneath opens the regular file at rel (slash-separated, relative)
// beneath root, without following any symbolic link and without leaving
// root. With noXDev it also refuses to cross a mount point (a mount
// propagated under root after the console started).
func openBeneath(root, rel string, noXDev bool) (*os.File, error) {
	for _, p := range strings.Split(rel, "/") {
		if err := validName(p); err != nil {
			return nil, err
		}
	}
	if f, err, ok := openat2Beneath(root, rel, noXDev); ok {
		return f, err
	}
	return walkOpen(root, rel, noXDev)
}

// errXDev refuses a path that crosses a mount point under a noXDev root.
var errXDev = errors.New("the path crosses a mount point")

// walkOpen is the component-wise fallback: one openat(O_NOFOLLOW) per
// component, each relative to the directory before it. With noXDev every
// opened component is compared with the root: by mount id where the kernel
// reports it (Linux >= 5.8), else by device.
func walkOpen(root, rel string, noXDev bool) (*os.File, error) {
	parts := strings.Split(rel, "/")
	d, err := openRoot(root)
	if err != nil {
		return nil, err
	}
	var rootMnt mountKey
	if noXDev {
		if rootMnt, err = mountOf(d.fd); err != nil {
			d.close()
			return nil, err
		}
	}
	same := func(fd int, path string) error {
		if !noXDev {
			return nil
		}
		k, err := mountOf(fd)
		if err != nil {
			return err
		}
		if k != rootMnt {
			return &fs.PathError{Op: "open", Path: path, Err: errXDev}
		}
		return nil
	}
	for _, p := range parts[:len(parts)-1] {
		next, err := d.sub(p)
		d.close()
		if err != nil {
			return nil, err
		}
		d = next
		if err := same(d.fd, d.path); err != nil {
			d.close()
			return nil, err
		}
	}
	defer d.close()
	f, err := d.open(parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	if err := same(int(f.Fd()), f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// devIno returns the device and inode of a file.
func devIno(fi os.FileInfo) (uint64, uint64, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("no device and inode")
	}
	return uint64(st.Dev), uint64(st.Ino), nil //nolint:unconvert // int32 on darwin
}
