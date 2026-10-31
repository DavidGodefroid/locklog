//go:build !linux

package landlock

// ABI: no Landlock outside Linux.
func ABI() (int, string) { return 0, "Landlock is Linux-only" }

// Restrict confines nothing outside Linux.
func Restrict(Rules) (Status, error) {
	return Status{State: Unsupported, Detail: "Landlock is Linux-only"}, nil
}
