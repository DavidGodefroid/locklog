//go:build unix && !linux

package file

import (
	"os"

	"golang.org/x/sys/unix"
)

// openat2Beneath: openat2 is Linux-only; the walk is used elsewhere.
func openat2Beneath(root, rel string, noXDev bool) (*os.File, error, bool) { return nil, nil, false }

// pathFlag: no O_PATH outside Linux; directories are opened for reading.
const pathFlag = unix.O_RDONLY

// mountKey identifies the mount a file is on: its device, outside Linux.
type mountKey struct {
	mntID bool
	id    uint64
}

func mountOf(fd int) (mountKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return mountKey{}, err
	}
	return mountKey{id: uint64(st.Dev)}, nil //nolint:unconvert // int32 on darwin
}
