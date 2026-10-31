//go:build !unix

package setup

import "io/fs"

// ownedByMe cannot be told here: setup runs on the host (Linux, macOS) or
// in the image.
func ownedByMe(fs.FileInfo) bool { return true }
