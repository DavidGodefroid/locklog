//go:build !linux

package docker

// Openat2: Linux-only.
func Openat2() bool { return false }
