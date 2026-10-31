//go:build !unix

package docker

func devIno(string) (uint64, uint64, bool) { return 0, 0, false }
