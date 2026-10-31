//go:build !linux

package landlock

// ABI: no Landlock outside Linux.
func ABI() (int, string) { return 0, "Landlock is Linux-only" }

// Restrict confines nothing outside Linux (the rules are still checked).
func Restrict(r Rules) (Status, error) {
	if _, err := r.resolve(); err != nil {
		return Status{State: Unsupported, Detail: "invalid rules"}, err
	}
	return Status{State: Unsupported, Detail: "Landlock is Linux-only"}, nil
}
