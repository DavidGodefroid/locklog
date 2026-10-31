//go:build integration && linux

package docker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/file"

	"golang.org/x/sys/unix"
)

// TestIntegrationLandlockShm runs alone (Landlock cannot be undone): the
// reader restricts itself as the console does, tells the job it is ready
// (LL11_SYNC/ready), and the job then starts an --ipc=shareable container,
// whose /dev/shm the engine propagates under the containers root, and
// writes its id to LL11_SYNC/shm-id. Through the docker source's open
// discipline nothing under it opens; a raw write there is refused by
// Landlock; the approved logs are still read.
func TestIntegrationLandlockShm(t *testing.T) {
	root := itEnv(t, RootEnv)
	glob := itEnv(t, "LL11_GLOB")
	sync := itEnv(t, "LL11_SYNC")
	s, err := New(Options{Name: "it", Containers: []string{glob}, Root: root})
	if err != nil {
		t.Fatal(err)
	}
	st, err := landlock.Restrict(landlock.Rules{ReadOnly: []string{root, DefaultMapDir}, ReadWrite: []string{"/tmp", sync}})
	if err != nil || st.State != landlock.Enforced {
		t.Fatalf("landlock: %v %v", st, err)
	}
	t.Log(st.String(), "openat2:", Openat2())
	if err := os.WriteFile(filepath.Join(sync, "ready"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var shmID string
	for i := 0; i < 120 && shmID == ""; i++ {
		if b, err := os.ReadFile(filepath.Join(sync, "shm-id")); err == nil {
			shmID = strings.TrimSpace(string(b))
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !validID(shmID) {
		t.Fatalf("no shareable container id: %q", shmID)
	}
	shm := filepath.Join(root, shmID, "mounts", "shm")
	probe := filepath.Join(shm, "ll11-probe")
	// The propagated mount is there (gid 0 traverses the 0710 directories).
	var stt syscall.Stat_t
	if err := syscall.Stat(probe, &stt); err != nil {
		t.Fatalf("the propagated /dev/shm is not visible: %v", err)
	}
	// The mount is writable as far as the kernel's mount flags and the
	// file's mode go (0666 in a 1777 tmpfs): only Landlock refuses below.
	var sfs unix.Statfs_t
	if err := unix.Statfs(shm, &sfs); err != nil || sfs.Flags&unix.ST_RDONLY != 0 {
		t.Fatalf("the propagated /dev/shm is read-only or unknown (flags %#x, %v): the checks below would prove nothing", sfs.Flags, err)
	}
	if stt.Mode&0o777 != 0o666 {
		t.Fatalf("probe mode %o, want 0666", stt.Mode&0o777)
	}
	// The kernel refuses the crossing: openat2 RESOLVE_NO_XDEV gives
	// EXDEV; without it (a positive control) the file opens for reading.
	rfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rfd)
	rel := shmID + "/mounts/shm/ll11-probe"
	if fd, err := unix.Openat2(rfd, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV}); !errors.Is(err, unix.EXDEV) {
		if err == nil {
			unix.Close(fd)
		}
		t.Errorf("openat2 RESOLVE_NO_XDEV across the propagated mount: %v, want EXDEV", err)
	}
	if fd, err := unix.Openat2(rfd, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH}); err != nil {
		t.Errorf("control: openat2 without RESOLVE_NO_XDEV: %v", err)
	} else {
		unix.Close(fd)
	}
	// The docker source's discipline: no open across the mount.
	p, _ := parse.New(parse.Options{Format: "docker-json"})
	fs, err := file.New(file.Options{Name: "it", Paths: []string{probe}, Roots: []string{root}, Parser: p, NoXDev: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan, err := fs.Plan(ctx, itRange, source.Selector{}); err != nil || len(plan.Chunks) != 0 {
		t.Errorf("opened a file of a propagated mount: %+v %v", plan, err)
	}
	// Writes there: refused by Landlock, exactly EACCES.
	for what, w := range map[string]func() error{
		"append write": func() error {
			f, err := os.OpenFile(probe, os.O_WRONLY|os.O_APPEND, 0)
			if err == nil {
				f.Close()
			}
			return err
		},
		"truncate": func() error { return os.Truncate(probe, 0) },
		"create": func() error {
			f, err := os.OpenFile(filepath.Join(shm, "ll11-created"), os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err == nil {
				f.Close()
			}
			return err
		},
		"remove": func() error { return os.Remove(probe) },
		"mkdir":  func() error { return os.Mkdir(filepath.Join(shm, "ll11-dir"), 0o755) },
	} {
		if err := w(); !errors.Is(err, syscall.EACCES) {
			t.Errorf("%s under the propagated /dev/shm: %v, want EACCES", what, err)
		}
	}
	// The approved logs are still read.
	if got := itRead(t, s); len(got) == 0 {
		t.Error("the approved containers' logs were not read")
	}
}
