//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/landlock"
)

const confineChildEnv = "LOCKLOG_CONFINE_TEST_CHILD"

// TestConfinedConsoleResolvesNames: once confined by its ruleset, the
// console still resolves host names the way Go's resolver does without
// cgo (remote sources, the hub): it reads /etc/hosts, /etc/resolv.conf and
// /etc/nsswitch.conf. It may also open the controlling terminal (a
// secret's re-prompt). Run in a re-executed child: Landlock cannot be
// undone.
func TestConfinedConsoleResolvesNames(t *testing.T) {
	if os.Getenv(confineChildEnv) != "" {
		return
	}
	abi, why := landlock.ABI()
	if req := os.Getenv("LOCKLOG_REQUIRE_LANDLOCK_ABI"); req != "" {
		if n, err := strconv.Atoi(req); err != nil || abi < n {
			t.Fatalf("LOCKLOG_REQUIRE_LANDLOCK_ABI=%s, the kernel has ABI %d (%s)", req, abi, why)
		}
	}
	if abi == 0 {
		t.Skip(why)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfinedConsoleResolvesNamesChild$", "-test.v")
	cmd.Env = append(os.Environ(), confineChildEnv+"=1")
	b, err := cmd.CombinedOutput()
	if strings.Contains(string(b), "SKIP-CHILD") {
		t.Skip(strings.TrimSpace(string(b)))
	}
	if err != nil || !strings.Contains(string(b), "CHILD-OK") {
		t.Fatalf("child: %v\n%s", err, b)
	}
}

func TestConfinedConsoleResolvesNamesChild(t *testing.T) {
	if os.Getenv(confineChildEnv) == "" {
		t.Skip("run by TestConfinedConsoleResolvesNames")
	}
	hosts, _ := os.ReadFile("/etc/hosts")
	localhost := strings.Contains(string(hosts), "localhost")
	r, err := confineRules(confineInput{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := landlock.Restrict(r)
	if errors.Is(err, syscall.ENOTSUP) {
		fmt.Println("SKIP-CHILD: built with cgo: AllThreadsSyscall is unavailable")
		return
	}
	if err != nil || !st.Available() {
		t.Fatalf("restrict: %+v %v", st, err)
	}
	for _, p := range []string{"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf"} {
		if _, err := os.ReadFile(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("read %s once confined: %v", p, err)
		}
	}
	if localhost {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res := &net.Resolver{PreferGo: true}
		if addrs, err := res.LookupHost(ctx, "localhost"); err != nil || len(addrs) == 0 {
			t.Errorf("localhost (in /etc/hosts) once confined: %v %v", addrs, err)
		}
	}
	// The controlling terminal: none under go test (ENXIO), but never
	// refused by the ruleset.
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
	} else if errors.Is(err, syscall.EACCES) {
		t.Errorf("open /dev/tty once confined: %v", err)
	}
	if !t.Failed() {
		fmt.Println("CHILD-OK", st.String())
	}
}
