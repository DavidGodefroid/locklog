//go:build !unix

package authproxy

import "errors"

// The proxy material is generated on the Unix host of the Compose stack;
// this file only keeps the module building elsewhere.

func writeFiles(string, []file) error { return errors.New("authproxy: needs a Unix system") }
