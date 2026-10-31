//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const childEnv = "LOCKLOG_LANDLOCK_TEST_CHILD"

// TestRestrict restricts a re-executed child (Landlock cannot be undone):
// writes beneath a read-only root fail with EACCES, reads there still
// work, writes beneath the read-write root work, and paths outside every
// rule are refused.
func TestRestrict(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		return // the child runs TestRestrictChild only
	}
	if abi, why := ABI(); abi == 0 {
		t.Skip(why)
	}
	base := t.TempDir()
	ro, rw, out := filepath.Join(base, "ro"), filepath.Join(base, "rw"), filepath.Join(base, "outside")
	for _, d := range []string{ro, rw, out, filepath.Join(ro, "d"), filepath.Join(ro, "s"), filepath.Join(rw, "a"), filepath.Join(rw, "b")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.Remove(filepath.Join(ro, "d", "f")) // an empty directory to remove
	// A copy of this (static, cgo-free) test binary, to execute.
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ro, "bin"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestrictChild$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+base)
	b, err := cmd.CombinedOutput()
	if strings.Contains(string(b), "SKIP-CHILD") {
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
	ro, rw, out := filepath.Join(base, "ro"), filepath.Join(base, "rw"), filepath.Join(base, "outside")
	st, err := Restrict(Rules{ReadOnly: []string{ro}, ReadWrite: []string{rw}, Exec: []string{"/nonexistent"}})
	if errors.Is(err, syscall.ENOTSUP) {
		fmt.Println("SKIP-CHILD: built with cgo: AllThreadsSyscall is unavailable")
		return
	}
	if err != nil || !st.Available() {
		t.Fatalf("restrict: %+v %v", st, err)
	}
	// Beneath the read-only root, every kind of write is refused, each
	// by its own right (a mutation that adds any one of them to the
	// read-only set fails one of these).
	refused := func(what string, err error, want ...error) {
		t.Helper()
		if len(want) == 0 {
			want = []error{syscall.EACCES}
		}
		for _, w := range want {
			if errors.Is(err, w) {
				return
			}
		}
		t.Errorf("%s beneath the read-only root: %v", what, err)
	}
	f, err := os.OpenFile(filepath.Join(ro, "f"), os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		f.Close()
	}
	refused("an append write (WRITE_FILE)", err)
	refused("a create (MAKE_REG)", unix.Mknod(filepath.Join(ro, "new"), unix.S_IFREG|0o644, 0))
	refused("a remove (REMOVE_FILE)", os.Remove(filepath.Join(ro, "f")))
	refused("a mkdir (MAKE_DIR)", os.Mkdir(filepath.Join(ro, "nd"), 0o755))
	refused("a rmdir (REMOVE_DIR)", os.Remove(filepath.Join(ro, "d")))
	refused("a symlink (MAKE_SYM)", os.Symlink("f", filepath.Join(ro, "sym")))
	refused("a mkfifo (MAKE_FIFO)", syscall.Mkfifo(filepath.Join(ro, "fifo"), 0o644))
	refused("a unix socket bind (MAKE_SOCK)", bindUnix(filepath.Join(ro, "sock")))
	// Its own standard files: os/exec would open /dev/null, outside every
	// rule.
	cmd := exec.Command(filepath.Join(ro, "bin"), "-test.run=^$")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	refused("an exec (EXECUTE)", cmd.Run())
	// A file linked from a read-only directory into another one: Landlock
	// answers EXDEV when REFER is missing, EACCES for the missing MAKE_REG.
	refused("a cross-directory link (REFER)", os.Link(filepath.Join(ro, "f"), filepath.Join(ro, "s", "g")), syscall.EXDEV, syscall.EACCES)
	refused("a cross-directory rename (REFER)", os.Rename(filepath.Join(ro, "s", "f"), filepath.Join(ro, "d", "f")), syscall.EXDEV, syscall.EACCES)
	if st.ABI >= 3 {
		refused("a truncate (TRUNCATE)", os.Truncate(filepath.Join(ro, "f"), 0))
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
	if err := bindUnix(filepath.Join(rw, "sock")); err != nil {
		t.Errorf("unix socket beneath the read-write root: %v", err)
	}
	// Never granted, even read-write: FIFOs, symbolic links, devices.
	if err := syscall.Mkfifo(filepath.Join(rw, "fifo"), 0o644); !errors.Is(err, syscall.EACCES) {
		t.Errorf("a FIFO beneath the read-write root: %v", err)
	}
	if err := os.Symlink("h", filepath.Join(rw, "sym")); !errors.Is(err, syscall.EACCES) {
		t.Errorf("a symbolic link beneath the read-write root: %v", err)
	}
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
