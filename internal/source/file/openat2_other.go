//go:build unix && !linux

package file

import "os"

// openat2Beneath: openat2 is Linux-only; the walk is used elsewhere.
func openat2Beneath(root, rel string) (*os.File, error, bool) { return nil, nil, false }
