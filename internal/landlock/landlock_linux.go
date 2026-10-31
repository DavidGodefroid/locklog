//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The filesystem rights of each ABI.
const (
	abi1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	// ABI 2: linking or renaming into another directory.
	abi2 = abi1 | unix.LANDLOCK_ACCESS_FS_REFER
	// ABI 3: truncate.
	abi3 = abi2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	// ABI 5: ioctl on devices.
	abi5 = abi3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	read     = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	readExec = read | unix.LANDLOCK_ACCESS_FS_EXECUTE
	// Writes: files, directories, sockets (the socket volume), renames
	// and truncation; never devices, FIFOs, symbolic links or ioctls.
	write = read | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	// The rights a rule on a file (not a directory) may carry.
	fileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// rulesetAttr is struct landlock_ruleset_attr up to handled_access_fs (the
// ABI 1 size: every kernel with Landlock accepts it).
type rulesetAttr struct {
	handledAccessFS uint64
}

// pathBeneathAttr is the packed struct landlock_path_beneath_attr (12
// bytes; the kernel reads no more).
type pathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             int32
}

// handled returns the rights of an ABI version.
func handled(abi int) uint64 {
	switch {
	case abi >= 5:
		return abi5
	case abi >= 3:
		return abi3
	case abi == 2:
		return abi2
	}
	return abi1
}

// ABI returns the Landlock ABI version, or 0 and why there is none.
func ABI() (int, string) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	switch {
	case errno == unix.ENOSYS:
		return 0, "the kernel has no Landlock (Linux >= 5.13 needed)"
	case errno == unix.EOPNOTSUPP:
		return 0, "Landlock is disabled at boot (add it to the lsm= list)"
	case errno == unix.EPERM:
		return 0, "the Landlock syscalls are blocked (seccomp profile)"
	case errno != 0:
		return 0, "Landlock version query failed: " + errno.Error()
	}
	return int(v), ""
}

// Restrict applies r to the whole process (no_new_privs first, as Landlock
// requires without CAP_SYS_ADMIN). Without Landlock it confines nothing
// and returns Unsupported with a nil error; an error means Landlock exists
// but the ruleset could not be applied (nothing was restricted then,
// except no_new_privs).
func Restrict(r Rules) (Status, error) {
	r, err := r.resolve()
	if err != nil {
		return Status{State: Unsupported, Detail: "invalid rules"}, err
	}
	abi, why := ABI()
	if abi == 0 {
		return Status{State: Unsupported, Detail: why}, nil
	}
	st := Status{State: Enforced, ABI: abi}
	if abi < 3 {
		st.State = Partial
		st.Detail = "ABI " + itoa(abi) + " does not handle truncate (Linux >= 6.2)"
		if abi == 1 {
			st.Detail += "; renames into another directory are refused everywhere"
		}
	}
	h := handled(abi)
	attr := rulesetAttr{handledAccessFS: h}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return Status{State: Unsupported, ABI: abi, Detail: "creating the ruleset failed"}, fmt.Errorf("landlock: create ruleset: %w", errno)
	}
	defer unix.Close(int(fd))
	for _, set := range []struct {
		paths  []string
		access uint64
	}{{r.ReadOnly, read}, {r.Exec, readExec}, {r.ReadWrite, write}} {
		for _, p := range set.paths {
			if err := addRule(int(fd), p, set.access&h); err != nil {
				return Status{State: Unsupported, ABI: abi, Detail: "adding a rule failed"}, err
			}
		}
	}
	// no_new_privs and the restriction are per thread: both go to every
	// thread of the process (syscall.AllThreadsSyscall; it needs a binary
	// built without cgo, as the console is).
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return Status{State: Unsupported, ABI: abi, Detail: "no_new_privs failed"}, fmt.Errorf("landlock: no_new_privs: %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return Status{State: Unsupported, ABI: abi, Detail: "restricting failed"}, fmt.Errorf("landlock: restrict: %w", errno)
	}
	return st, nil
}

// addRule grants access beneath path (a file gets only file rights). A
// missing path is skipped.
func addRule(ruleset int, path string, access uint64) error {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("landlock: open %s: %w", path, err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return fmt.Errorf("landlock: stat %s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFLNK:
		return fmt.Errorf("landlock: %s is a symbolic link", path)
	default:
		access &= fileRights
	}
	attr := pathBeneathAttr{allowedAccess: access, parentFd: int32(pfd)}
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock: rule for %s: %w", path, errno)
	}
	return nil
}
