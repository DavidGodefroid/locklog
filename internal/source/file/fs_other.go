//go:build !unix

package file

import (
	"errors"
	"os"
)

// The console runs on Linux (in Docker); this file only keeps the module
// building elsewhere.

var errUnsupported = errors.New("file sources need a Unix system")

type dir struct{ path string }

type entry struct {
	name     string
	dir, reg bool
}

func openRoot(path string) (*dir, error)             { return nil, errUnsupported }
func (d *dir) close()                                {}
func (d *dir) sub(string) (*dir, error)              { return nil, errUnsupported }
func (d *dir) lstat(string) (entry, error)           { return entry{}, errUnsupported }
func (d *dir) list() ([]entry, error)                { return nil, errUnsupported }
func (d *dir) open(string) (*os.File, error)         { return nil, errUnsupported }
func openBeneath(root, rel string) (*os.File, error) { return nil, errUnsupported }

func devIno(os.FileInfo) (uint64, uint64, error) { return 0, 0, errUnsupported }
