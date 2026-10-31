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
// zone info, /proc/self files, and device files such as /dev/null or
// /dev/tty): anything else is refused. IOCTL_DEV is never granted, not even
// beneath the read-write roots. Only filesystem access is confined: network
// and scoping (abstract sockets, signals) are not handled.
package landlock

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// State of the confinement.
const (
	// Enforced: every filesystem right of ABI 3 or later is handled (writes,
	// creation, removal, renames and truncation are refused outside the
	// read-write roots).
	Enforced = "enforced"
	// Partial: Landlock runs, but its ABI lacks rights (ABI 1-2: truncate
	// is not handled, so a file writable by permissions can still be
	// truncated).
	Partial = "partial"
	// Unsupported: no Landlock (kernel < 5.13, the LSM disabled, the
	// syscalls blocked by seccomp, or not Linux): no filesystem access is
	// confined.
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
// A missing path is skipped. Rules on nested paths add up, so a ReadOnly or
// Exec path at or beneath a ReadWrite one is refused (it would be
// writable).
type Rules struct {
	ReadOnly  []string
	ReadWrite []string
	Exec      []string
}

// resolve cleans the paths and resolves their symbolic links (a missing
// path is dropped), and refuses a read-only or exec path at or beneath a
// read-write one.
func (r Rules) resolve() (Rules, error) {
	res := func(ps []string) ([]string, error) {
		var out []string
		for _, p := range ps {
			if !filepath.IsAbs(p) {
				return nil, fmt.Errorf("landlock: %q is not an absolute path", p)
			}
			q, err := filepath.EvalSymlinks(filepath.Clean(p))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("landlock: %s: %w", p, err)
			}
			out = append(out, q)
		}
		return out, nil
	}
	var out Rules
	var err error
	if out.ReadOnly, err = res(r.ReadOnly); err != nil {
		return Rules{}, err
	}
	if out.ReadWrite, err = res(r.ReadWrite); err != nil {
		return Rules{}, err
	}
	if out.Exec, err = res(r.Exec); err != nil {
		return Rules{}, err
	}
	for _, w := range out.ReadWrite {
		for _, p := range append(append([]string{}, out.ReadOnly...), out.Exec...) {
			if p == w || strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
				return Rules{}, fmt.Errorf("landlock: %s is beneath the read-write %s: it would be writable", p, w)
			}
		}
	}
	return out, nil
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
