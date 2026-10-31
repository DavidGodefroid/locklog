package docker

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

var (
	containerDirRe = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)
	shortIDRe      = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// selfMountPoints are the files Docker bind-mounts into a container from
// its own directory under the containers root.
var selfMountPoints = map[string]bool{"/etc/hostname": true, "/etc/hosts": true, "/etc/resolv.conf": true}

// SelfIDs returns the ids (full, or the 12-character prefix) of the
// container this process runs in: from the sources of the /etc/hostname,
// /etc/hosts and /etc/resolv.conf mounts in /proc/self/mountinfo, and from a
// hostname of 12 hex characters (Docker's default). Empty outside a
// container.
func SelfIDs() []string {
	var out []string
	if f, err := os.Open("/proc/self/mountinfo"); err == nil {
		out = selfFromMountinfo(f)
		f.Close()
	}
	if h, err := os.Hostname(); err == nil && shortIDRe.MatchString(h) {
		out = append(out, h)
	}
	return out
}

// selfFromMountinfo reads mountinfo lines: "id parent maj:min root
// mountpoint ...". The root of the bind mounts of selfMountPoints is the
// file in the container's directory.
func selfFromMountinfo(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(io.LimitReader(r, 4<<20))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || !selfMountPoints[f[4]] {
			continue
		}
		if m := containerDirRe.FindStringSubmatch(f[3]); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// isSelf reports whether id is one of self's (full ids, or prefixes of at
// least 12 characters).
func isSelf(self []string, id string) bool {
	for _, s := range self {
		if len(s) >= 12 && strings.HasPrefix(id, s) {
			return true
		}
	}
	return false
}
