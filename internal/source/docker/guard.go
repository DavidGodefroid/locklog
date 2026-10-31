package docker

import (
	"errors"

	"github.com/DavidGodefroid/locklog/internal/landlock"
)

// The two guards against mounts the engine propagates under the containers
// root after the console started (another container's /dev/shm, swarm
// secrets), spike S2:
//
//  1. the open discipline: openat2 with RESOLVE_NO_XDEV (Linux >= 5.6),
//     else a walk comparing mount ids (Linux >= 5.8), else devices (a bind
//     mount of the same filesystem is then not seen). It limits reads and
//     writes, while the process is not compromised;
//  2. Landlock (landlock.Restrict): no write, create, remove, rename or
//     (ABI >= 3) truncate beneath the read-only roots, even for a
//     compromised console. It does not limit reads.

// ErrUnguarded refuses a docker source on a production profile that has
// neither guard at full strength.
var ErrUnguarded = errors.New("docker source refused on a production profile: neither Landlock nor openat2 with RESOLVE_NO_XDEV is available, " +
	"so mounts propagated under the containers root (other containers' /dev/shm, swarm secrets) are guarded only by a mount comparison in this process; " +
	"use a kernel with Landlock (>= 5.13, in the lsm= list) or openat2 (>= 5.6) and a seccomp profile that allows them")

// Guard decides whether a docker source may start: on a production profile
// it needs Landlock (enforced or partial) or openat2 with RESOLVE_NO_XDEV;
// with only one of them it starts, and Residuals names what is missing.
func Guard(production bool, ll landlock.Status, openat2 bool) error {
	if production && !ll.Available() && !openat2 {
		return ErrUnguarded
	}
	return nil
}

// Residuals names the missing guards (for :status and doctor, LL-15).
func Residuals(ll landlock.Status, openat2 bool) []string {
	var out []string
	if !ll.Available() {
		out = append(out, "Landlock is not enforced ("+ll.String()+"): a compromised console could write in mounts propagated under the containers root")
	} else if ll.State == landlock.Partial {
		out = append(out, "Landlock is partial ("+ll.String()+")")
	}
	if !openat2 {
		out = append(out, "openat2 with RESOLVE_NO_XDEV is unavailable: mounts under the containers root are detected by a mount id (or device) comparison only")
	}
	return out
}
