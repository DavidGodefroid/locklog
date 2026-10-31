//go:build unix

package authproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Test hooks: trustedRoot is the directory whose own ancestors are not
// checked ("/": all of them); afterOpen runs once Dir is open, before any
// file is written.
var (
	trustedRoot = "/"
	afterOpen   = func() {}
)

// safeAncestor reports whether a directory may be an ancestor of Dir: a
// real directory, owned by root or by euid, writable by no one else (a
// sticky world-writable directory such as /tmp is refused too). Anyone else
// who could write it could swap what lies below it.
func safeAncestor(mode, uid uint32, euid int) bool {
	return mode&unix.S_IFMT == unix.S_IFDIR && (uid == 0 || int(uid) == euid) && mode&0o022 == 0
}

// checkAncestors Lstats every component of dir's parent, from trustedRoot
// down, and returns the parent's stat.
func checkAncestors(parent string) (unix.Stat_t, error) {
	var st unix.Stat_t
	p := "/"
	comps := strings.Split(strings.TrimPrefix(parent, "/"), "/")
	for i := -1; i < len(comps); i++ {
		if i >= 0 {
			if comps[i] == "" {
				continue
			}
			p = filepath.Join(p, comps[i])
		}
		if p != trustedRoot && !inside(p, trustedRoot) {
			continue
		}
		if err := unix.Lstat(p, &st); err != nil {
			return st, fmt.Errorf("authproxy: %s: %w", p, err)
		}
		if !safeAncestor(uint32(st.Mode), st.Uid, os.Geteuid()) {
			return st, fmt.Errorf("authproxy: %s must be a real directory (not a symlink) owned by root or you, and writable by no one else", p)
		}
	}
	return st, nil
}

// writeFiles creates dir (or takes it empty) and writes files in it,
// working on descriptors: the parent is opened after its ancestors are
// checked (no one else can swap them), dir is opened O_NOFOLLOW, checked by
// fstat and fchmod'ed 0700, each file is created relative to it
// (O_EXCL|O_NOFOLLOW), and dir's path must still be the directory written
// at the end (else the files are removed and it fails).
func writeFiles(dir string, files []file) error {
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	pst, err := checkAncestors(parent)
	if err != nil {
		return err
	}
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("authproxy: %s: %w", parent, err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil || st.Dev != pst.Dev || st.Ino != pst.Ino {
		return errors.New("authproxy: the parent directory changed while it was checked")
	}
	created := true
	if err := unix.Mkdirat(pfd, base, 0o700); errors.Is(err, unix.EEXIST) {
		created = false
	} else if err != nil {
		return fmt.Errorf("authproxy: %s: %w", dir, err)
	}
	dfd, err := unix.Openat(pfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("authproxy: the directory must be a real directory, not a symlink: %w", err)
	}
	d := os.NewFile(uintptr(dfd), dir)
	defer d.Close()
	var dst unix.Stat_t
	if err := unix.Fstat(dfd, &dst); err != nil {
		return err
	}
	var written []string
	// cleanup removes the files written and, when this call created the
	// directory and its name still is that directory, the directory.
	cleanup := func() {
		for _, n := range written {
			unix.Unlinkat(dfd, n, 0)
		}
		var cur unix.Stat_t
		if created && unix.Fstatat(pfd, base, &cur, unix.AT_SYMLINK_NOFOLLOW) == nil && cur.Dev == dst.Dev && cur.Ino == dst.Ino {
			unix.Unlinkat(pfd, base, unix.AT_REMOVEDIR)
		}
	}
	if dst.Mode&unix.S_IFMT != unix.S_IFDIR || int(dst.Uid) != os.Geteuid() {
		cleanup()
		return errors.New("authproxy: the directory is not a directory of yours")
	}
	// 0700 first: nothing can be added by others once it is checked empty.
	if err := unix.Fchmod(dfd, 0o700); err != nil {
		cleanup()
		return err
	}
	if names, err := d.Readdirnames(-1); err != nil || len(names) > 0 {
		cleanup()
		return errors.New("authproxy: the directory exists and is not empty")
	}
	afterOpen()
	for _, f := range files {
		fd, err := unix.Openat(dfd, f.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			cleanup()
			return fmt.Errorf("authproxy: %s: %w", f.name, err)
		}
		written = append(written, f.name)
		w := os.NewFile(uintptr(fd), f.name)
		err = unix.Fchmod(fd, uint32(f.mode.Perm()))
		if err == nil {
			_, err = w.Write(f.data)
		}
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			cleanup()
			return fmt.Errorf("authproxy: %s: %w", f.name, err)
		}
	}
	var now unix.Stat_t
	if err := unix.Lstat(dir, &now); err != nil || now.Dev != dst.Dev || now.Ino != dst.Ino {
		cleanup()
		return errors.New("authproxy: the directory was replaced while the files were written: nothing is left in it")
	}
	return nil
}
