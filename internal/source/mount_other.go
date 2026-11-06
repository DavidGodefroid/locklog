//go:build !unix

package source

import "os"

// The console runs on Linux; elsewhere a root has no device and inode to
// pin.
func statID(os.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
