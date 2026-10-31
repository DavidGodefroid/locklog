//go:build !unix

package authproxy

import (
	"errors"
	"os"
)

// The proxy material is generated on the Unix host of the Compose stack;
// this file only keeps the module building elsewhere.

var errUnsupported = errors.New("authproxy: needs a Unix system")

func checkOwner(os.FileInfo) error                 { return errUnsupported }
func createFile(string, []byte, os.FileMode) error { return errUnsupported }
