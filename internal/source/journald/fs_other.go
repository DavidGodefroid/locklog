//go:build !unix

package journald

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("journald source: only on Unix")

func listDir(string, string) ([]dirEntry, error) { return nil, errUnsupported }

func openBeneath(string, string, string) (*os.File, error) { return nil, errUnsupported }
