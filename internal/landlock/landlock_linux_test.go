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
	for _, d := range []string{ro, rw, out} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
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
	if !errors.Is(os.WriteFile(filepath.Join(ro, "f"), []byte("x"), 0o644), syscall.EACCES) {
		t.Error("wrote a file beneath a read-only root")
	}
	if _, err := os.Create(filepath.Join(ro, "new")); !errors.Is(err, syscall.EACCES) {
		t.Errorf("created a file beneath a read-only root: %v", err)
	}
	if err := os.Remove(filepath.Join(ro, "f")); !errors.Is(err, syscall.EACCES) {
		t.Errorf("removed a file beneath a read-only root: %v", err)
	}
	if st.ABI >= 3 {
		if err := os.Truncate(filepath.Join(ro, "f"), 0); !errors.Is(err, syscall.EACCES) {
			t.Errorf("truncated a file beneath a read-only root: %v", err)
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
