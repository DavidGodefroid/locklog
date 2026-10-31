// Package landlock confines the console's own file access with Landlock
// (Linux >= 5.13): once Restrict ran, the process (every thread) may only
// read beneath the read-only roots, read and execute beneath the exec roots,
// and write only beneath the read-write ones. It cannot be undone.
//
// It is the second guard of the docker source (spike S2): mounts that the
// engine propagates under the containers root after the console started
// (another container's /dev/shm, swarm secrets) are writable tmpfs; beneath
// a read-only root, Landlock refuses every write, create, remove, rename
// and, from ABI 3, truncate there. It does not limit reads: beneath a
// read-only root it grants read on propagated mounts too. Only the docker
// source's open discipline (RESOLVE_NO_XDEV, the mount-id walk) keeps reads
// to the approved log files.
//
// Call site (the console, LL-07): after opening the socket and the home
// directory and reading its configuration, before opening any source:
//
//	st, err := landlock.Restrict(landlock.Rules{
//		ReadOnly:  append(logRoots, dockerRoot, "/run/locklog-map", <system files read later>),
//		ReadWrite: []string{"/run/locklog", "/home/locklog", "/tmp"},
//		Exec:      <binaries run later, e.g. the vault CLI>,
//	})
//
// Every path the console reads after Restrict must be listed (CA bundles,
// zone info, /proc/self files): anything else is refused.
package landlock

import "strings"

// State of the confinement.
const (
	// Enforced: every right of ABI 3 or later is handled (writes,
	// creation, removal, renames and truncation are refused outside the
	// read-write roots).
	Enforced = "enforced"
	// Partial: Landlock runs, but its ABI lacks rights (ABI 1-2: truncate
	// is not handled, so a file writable by permissions can still be
	// truncated).
	Partial = "partial"
	// Unsupported: no Landlock (kernel < 5.13, the LSM disabled, the
	// syscalls blocked by seccomp, or not Linux): nothing is confined.
	Unsupported = "unsupported"
)

// Status is the result of Restrict.
type Status struct {
	State string
	// ABI is the Landlock ABI version (0 when unsupported).
	ABI int
	// Detail says why the state is not Enforced (no secret, no path).
	Detail string
}

// Available reports whether a ruleset is enforced, fully or partly.
func (s Status) Available() bool { return s.State == Enforced || s.State == Partial }

// String is the line doctor and :status show, e.g. "landlock enforced
// (ABI 5)" or "landlock unsupported: kernel without Landlock".
func (s Status) String() string {
	var b strings.Builder
	b.WriteString("landlock ")
	b.WriteString(s.State)
	if s.ABI > 0 {
		b.WriteString(" (ABI ")
		b.WriteString(itoa(s.ABI))
		b.WriteString(")")
	}
	if s.Detail != "" {
		b.WriteString(": ")
		b.WriteString(s.Detail)
	}
	return b.String()
}

// Rules are the paths granted: anything else is refused once restricted.
// A missing path is skipped.
type Rules struct {
	ReadOnly  []string
	ReadWrite []string
	Exec      []string
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
