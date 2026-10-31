//go:build unix

package file

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// dir is an open directory, reached from a root without following any
// symbolic link.
type dir struct {
	fd   int
	path string // for messages only
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

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

// list returns the directory's entries.
func (d *dir) list() ([]entry, error) {
	fd, err := unix.Dup(d.fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
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
// root.
func openBeneath(root, rel string) (*os.File, error) {
	if f, err, ok := openat2Beneath(root, rel); ok {
		return f, err
	}
	return walkOpen(root, rel)
}

// walkOpen is the component-wise fallback: one openat(O_NOFOLLOW) per
// component, each relative to the directory before it.
func walkOpen(root, rel string) (*os.File, error) {
	parts := strings.Split(rel, "/")
	d, err := openRoot(root)
	if err != nil {
		return nil, err
	}
	for _, p := range parts[:len(parts)-1] {
		next, err := d.sub(p)
		d.close()
		if err != nil {
			return nil, err
		}
		d = next
	}
	defer d.close()
	return d.open(parts[len(parts)-1])
}
