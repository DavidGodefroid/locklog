//go:build linux

package landlock

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const childEnv = "LOCKLOG_LANDLOCK_TEST_CHILD"

// TestRestrict restricts a re-executed child (Landlock cannot be undone).
// Beneath the read-only root, each write right is exercised alone and must
// give EACCES: append write (WRITE_FILE), mknod of a regular file
// (MAKE_REG), of a character and a block device (MAKE_CHAR, MAKE_BLOCK:
// Landlock refuses before the CAP_MKNOD check), remove (REMOVE_FILE),
// mkdir (MAKE_DIR), rmdir (REMOVE_DIR), symlink (MAKE_SYM), mkfifo
// (MAKE_FIFO), unix socket bind (MAKE_SOCK), exec (EXECUTE, when the
// binary is static, with a positive control under the exec root),
// truncate (TRUNCATE, ABI >= 3) and a device ioctl on a read-only device
// rule (IOCTL_DEV, ABI >= 5). Beneath the read-write root, writes, renames
// across directories and sockets work, while exec, FIFOs, symbolic links,
// devices and device ioctls are refused. Reads beneath the read-only root
// work; paths outside every rule are refused. The same writes are refused
// beneath the exec root. Adding any one of these rights to the read-only
// rule fails the test, except REFER, which allows nothing without a MAKE_*
// right there; so does adding any write right except REFER to the exec
// rule (IOCTL_DEV through the /dev/full exec rule), and EXECUTE, MAKE_SYM,
// MAKE_FIFO, MAKE_CHAR, MAKE_BLOCK or IOCTL_DEV to the read-write rule (its
// other rights are granted already).
func TestRestrict(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		return // the child runs TestRestrictChild only
	}
	// CI sets LOCKLOG_REQUIRE_LANDLOCK_ABI: there, a missing or older
	// Landlock fails instead of skipping the test or its ABI-gated checks.
	abi, why := ABI()
	if req := os.Getenv("LOCKLOG_REQUIRE_LANDLOCK_ABI"); req != "" {
		n, err := strconv.Atoi(req)
		if err != nil || abi < n {
			t.Fatalf("LOCKLOG_REQUIRE_LANDLOCK_ABI=%s, the kernel has ABI %d (%s)", req, abi, why)
		}
	}
	if abi == 0 {
		t.Skip(why)
	}
	base := t.TempDir()
	ro, rw, out := filepath.Join(base, "ro"), filepath.Join(base, "rw"), filepath.Join(base, "outside")
	ex := filepath.Join(base, "ex")
	for _, d := range []string{ro, rw, out, ex, filepath.Join(ro, "d"), filepath.Join(ro, "s"), filepath.Join(rw, "a"), filepath.Join(rw, "b"), filepath.Join(rw, "e"), filepath.Join(ex, "d")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Empty directories to remove.
	os.Remove(filepath.Join(ro, "d", "f"))
	os.Remove(filepath.Join(ex, "d", "f"))
	os.Remove(filepath.Join(rw, "e", "f"))
	// Copies of this test binary, to execute: refused beneath the
	// read-only root, run beneath the exec root.
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{ro, rw, ex} {
		if err := os.WriteFile(filepath.Join(d, "bin"), bin, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestrictChild$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+base)
	b, err := cmd.CombinedOutput()
	if strings.Contains(string(b), "SKIP-CHILD") {
		if os.Getenv("LOCKLOG_REQUIRE_LANDLOCK_ABI") != "" {
			t.Fatalf("the child skipped:\n%s", b)
		}
		t.Skip(strings.TrimSpace(string(b)))
	}
	if err != nil || !strings.Contains(string(b), "CHILD-OK") {
		t.Fatalf("child: %v\n%s", err, b)
	}
	t.Log(strings.TrimSpace(string(b)))
}

func TestRestrictChild(t *testing.T) {
	base := os.Getenv(childEnv)
	if base == "" {
		t.Skip("run by TestRestrict")
	}
	ro, rw, out, ex := filepath.Join(base, "ro"), filepath.Join(base, "rw"), filepath.Join(base, "outside"), filepath.Join(base, "ex")
	// Device file rules: /dev/null read-only, /dev/zero read-write,
	// /dev/full exec.
	st, err := Restrict(Rules{ReadOnly: []string{ro, "/dev/null"}, ReadWrite: []string{rw, "/dev/zero"}, Exec: []string{ex, "/dev/full"}})
	if errors.Is(err, syscall.ENOTSUP) {
		fmt.Println("SKIP-CHILD: built with cgo: AllThreadsSyscall is unavailable")
		return
	}
	if err != nil || !st.Available() {
		t.Fatalf("restrict: %+v %v", st, err)
	}
	// Beneath the read-only root, every kind of write is refused, each
	// by its own right.
	refusedIn := func(where, what string, err error, want ...error) {
		t.Helper()
		if len(want) == 0 {
			want = []error{syscall.EACCES}
		}
		for _, w := range want {
			if errors.Is(err, w) {
				return
			}
		}
		t.Errorf("%s beneath the %s root: %v, want %v", what, where, err, want)
	}
	refused := func(what string, err error, want ...error) {
		t.Helper()
		refusedIn("read-only", what, err, want...)
	}
	// The same writes are refused beneath the read-only and the exec
	// roots.
	for where, dir := range map[string]string{"read-only": ro, "exec": ex} {
		f, err := os.OpenFile(filepath.Join(dir, "f"), os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			f.Close()
		}
		refusedIn(where, "an append write (WRITE_FILE)", err)
		refusedIn(where, "a create (MAKE_REG)", unix.Mknod(filepath.Join(dir, "new"), unix.S_IFREG|0o644, 0))
		refusedIn(where, "a remove (REMOVE_FILE)", os.Remove(filepath.Join(dir, "f")))
		refusedIn(where, "a mkdir (MAKE_DIR)", os.Mkdir(filepath.Join(dir, "nd"), 0o755))
		refusedIn(where, "a rmdir (REMOVE_DIR)", os.Remove(filepath.Join(dir, "d")))
		refusedIn(where, "a symlink (MAKE_SYM)", os.Symlink("f", filepath.Join(dir, "sym")))
		refusedIn(where, "a mkfifo (MAKE_FIFO)", syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644))
		refusedIn(where, "a unix socket bind (MAKE_SOCK)", bindUnix(filepath.Join(dir, "sock")))
		// Exactly EACCES: EPERM would be the missing CAP_MKNOD, checked
		// after Landlock.
		refusedIn(where, "a character device (MAKE_CHAR)", unix.Mknod(filepath.Join(dir, "chr"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))))
		refusedIn(where, "a block device (MAKE_BLOCK)", unix.Mknod(filepath.Join(dir, "blk"), unix.S_IFBLK|0o644, int(unix.Mkdev(7, 0))))
		if st.ABI >= 3 {
			refusedIn(where, "a truncate (TRUNCATE)", os.Truncate(filepath.Join(dir, "f"), 0))
		}
	}
	if static(t, filepath.Join(ro, "bin")) {
		run := func(p string) error {
			// Its own standard files: os/exec would open /dev/null
			// for them, a rule without exec rights here.
			cmd := exec.Command(p, "-test.run=^$")
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
			return cmd.Run()
		}
		refused("an exec (EXECUTE)", run(filepath.Join(ro, "bin")))
		refusedIn("read-write", "an exec (EXECUTE)", run(filepath.Join(rw, "bin")))
		if err := run(filepath.Join(ex, "bin")); err != nil {
			t.Errorf("exec beneath the exec root (control): %v", err)
		}
	}
	// Links and renames between read-only directories are refused (EXDEV
	// without REFER, EACCES without MAKE_REG or REMOVE_FILE).
	refused("a cross-directory link", os.Link(filepath.Join(ro, "f"), filepath.Join(ro, "s", "g")), syscall.EXDEV, syscall.EACCES)
	refused("a cross-directory rename", os.Rename(filepath.Join(ro, "s", "f"), filepath.Join(ro, "d", "f")), syscall.EXDEV, syscall.EACCES)
	if st.ABI >= 5 {
		// A device ioctl: EACCES from Landlock, not ENOTTY from the
		// device, on a read-only and on a read-write device rule.
		for where, dev := range map[string]string{"read-only": "/dev/null", "read-write": "/dev/zero", "exec": "/dev/full"} {
			fd, err := unix.Open(dev, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Errorf("open %s: %v", dev, err)
				continue
			}
			_, err = unix.IoctlGetTermios(fd, unix.TCGETS)
			unix.Close(fd)
			refusedIn(where, "a device ioctl (IOCTL_DEV) on "+dev, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(ro, "f")); err != nil || string(b) != "content" {
		t.Errorf("read beneath a read-only root: %q %v", b, err)
	}
	if _, err := os.ReadDir(ro); err != nil {
		t.Errorf("list beneath a read-only root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rw, "g"), []byte("x"), 0o644); err != nil {
		t.Errorf("write beneath the read-write root: %v", err)
	}
	if err := os.Rename(filepath.Join(rw, "g"), filepath.Join(rw, "h")); err != nil {
		t.Errorf("rename beneath the read-write root: %v", err)
	}
	if st.ABI >= 2 {
		if err := os.Rename(filepath.Join(rw, "a", "f"), filepath.Join(rw, "b", "g")); err != nil {
			t.Errorf("cross-directory rename beneath the read-write root (REFER): %v", err)
		}
	}
	if err := os.Truncate(filepath.Join(rw, "h"), 0); err != nil {
		t.Errorf("truncate beneath the read-write root: %v", err)
	}
	if err := os.Remove(filepath.Join(rw, "e")); err != nil {
		t.Errorf("rmdir beneath the read-write root: %v", err)
	}
	if err := bindUnix(filepath.Join(rw, "sock")); err != nil {
		t.Errorf("unix socket beneath the read-write root: %v", err)
	}
	// Never granted, even read-write: FIFOs, symbolic links, devices.
	refusedIn("read-write", "a FIFO (MAKE_FIFO)", syscall.Mkfifo(filepath.Join(rw, "fifo"), 0o644))
	refusedIn("read-write", "a symbolic link (MAKE_SYM)", os.Symlink("h", filepath.Join(rw, "sym")))
	refusedIn("read-write", "a character device (MAKE_CHAR)", unix.Mknod(filepath.Join(rw, "chr"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))))
	refusedIn("read-write", "a block device (MAKE_BLOCK)", unix.Mknod(filepath.Join(rw, "blk"), unix.S_IFBLK|0o644, int(unix.Mkdev(7, 0))))
	if _, err := os.ReadFile(filepath.Join(out, "f")); !errors.Is(err, syscall.EACCES) {
		t.Errorf("read outside every rule: %v", err)
	}
	if !t.Failed() {
		fmt.Println("CHILD-OK", st.String())
	}
}

func TestStatusString(t *testing.T) {
	for st, want := range map[Status]string{
		{State: Enforced, ABI: 5}:                           "landlock enforced (ABI 5)",
		{State: Partial, ABI: 2, Detail: "no truncate"}:     "landlock partial (ABI 2): no truncate",
		{State: Unsupported, Detail: "the kernel has none"}: "landlock unsupported: the kernel has none",
	} {
		if got := st.String(); got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	if (Status{State: Unsupported}).Available() || !(Status{State: Partial}).Available() {
		t.Error("Available")
	}
}

// bindUnix binds a unix socket at p (raw syscalls: no net package, so the
// test binary stays static).
func bindUnix(p string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Bind(fd, &unix.SockaddrUnix{Name: p})
}

// Rules on nested paths add up: a read-only path beneath a read-write one
// is refused before anything is restricted, also through a symbolic link.
func TestRestrictRefusesReadOnlyBeneathReadWrite(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		return
	}
	base := t.TempDir()
	rw := filepath.Join(base, "rw")
	if err := os.MkdirAll(filepath.Join(rw, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(rw, "logs"), filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rules{
		{ReadOnly: []string{filepath.Join(rw, "logs")}, ReadWrite: []string{rw}},
		{ReadOnly: []string{rw + "/./logs/"}, ReadWrite: []string{rw}},
		{ReadOnly: []string{filepath.Join(base, "alias")}, ReadWrite: []string{rw}},
		{Exec: []string{rw}, ReadWrite: []string{rw}},
		{Exec: []string{base}, ReadWrite: []string{rw}},
		{Exec: []string{rw}, ReadWrite: []string{filepath.Join(rw, "logs")}},
		{ReadOnly: []string{"relative"}},
	} {
		if _, err := Restrict(r); err == nil {
			t.Fatalf("%+v accepted (and this process is now restricted)", r)
		}
	}
	// Siblings and parents are fine: checked, not applied, here.
	if _, err := (Rules{ReadOnly: []string{base, filepath.Join(base, "missing")}, ReadWrite: []string{rw}}).resolve(); err != nil {
		t.Errorf("a read-only parent refused: %v", err)
	}
}

// static reports whether the ELF file at p has no interpreter (a static
// binary runs without reading ld.so, outside every rule).
func static(t *testing.T, p string) bool {
	t.Helper()
	f, err := elf.Open(p)
	if err != nil {
		t.Logf("exec checks skipped: %v", err)
		return false
	}
	defer f.Close()
	for _, ph := range f.Progs {
		if ph.Type == elf.PT_INTERP {
			fmt.Println("EXEC-SKIPPED: the test binary is dynamically linked")
			if os.Getenv("CGO_ENABLED") == "0" {
				t.Error("CGO_ENABLED=0, yet the test binary has an interpreter")
			}
			return false
		}
	}
	return true
}
