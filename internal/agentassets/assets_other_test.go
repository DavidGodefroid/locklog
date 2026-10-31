//go:build !unix

package agentassets

import (
	"os"
	"testing"
)

// checkMode is a no-op where permission bits are not POSIX ones.
func checkMode(*testing.T, string, os.FileMode) {}
