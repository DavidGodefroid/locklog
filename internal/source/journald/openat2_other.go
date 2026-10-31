//go:build unix && !linux

package journald

import "golang.org/x/sys/unix"

// pathFlags: no O_PATH outside Linux.
const pathFlags = dirFlags

func openat2(int, string) (int, error, bool) { return -1, nil, false }

// sameMount compares devices (no mount ids outside Linux).
func sameMount(rfd, fd int, _ string) error {
	var a, b unix.Stat_t
	if err := unix.Fstat(rfd, &a); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &b); err != nil {
		return err
	}
	if a.Dev != b.Dev {
		return errCrossMount
	}
	return nil
}
