//go:build !unix

package logconsole

import (
	"errors"
	"os"
)

func devIno(os.FileInfo) (string, error) {
	return "", errors.New("the console runs on Linux only")
}
