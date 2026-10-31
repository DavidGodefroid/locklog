package logconsole

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/mountplan"
)

// JournalDirs are the journal directories the launcher binds for a
// journald source, when they exist on the host.
var JournalDirs = []string{"/var/log/journal", "/run/log/journal"}

// Roots are the mount roots of a policy's local sources, each one the
// launcher bound and checked (LOCKLOG_EXPECT_ROOTS): the only directories
// the sources are given.
type Roots struct {
	// Dirs are the directories of the file sources' globs
	// (mountplan.Dir), sorted.
	Dirs []string
	// Journal are the journal directories bound (JournalDirs that
	// exist on the host).
	Journal []string
	// Docker is the containers root (LOCKLOG_DOCKER_ROOT), "" without a
	// docker source.
	Docker string
	// DockerChecked is set when the launcher could stat the containers
	// root from the host and passed its device:inode; usually it cannot
	// (/var/lib/docker is 0710 root), and the root is then the launcher's
	// "not checked from the host" case.
	DockerChecked bool
}

// All returns every root, sorted.
func (r Roots) All() []string {
	out := slices.Concat(r.Dirs, r.Journal)
	if r.Docker != "" {
		out = append(out, r.Docker)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// expectedRoots parses LOCKLOG_EXPECT_ROOTS into its paths (CheckMounts
// validates the entries and their devices and inodes).
func expectedRoots(s string) map[string]bool {
	out := map[string]bool{}
	for _, e := range strings.Split(s, ";") {
		if _, p, ok := strings.Cut(e, " "); ok && p != "" {
			out[p] = true
		}
	}
	return out
}

// PlanRoots derives the mount plan of pr (mountplan.Lines) and returns its
// roots. In the launcher's container (o.InContainer) every planned
// directory must be one the launcher checked, after CheckMounts passed: a
// file glob's directory and each journal directory an entry of
// LOCKLOG_EXPECT_ROOTS, the containers root LOCKLOG_DOCKER_ROOT either
// such an entry or the launcher's "not checked from the host" case (a
// clean absolute path ending in /containers, a directory and not a link).
// A planned root the launcher did not check refuses the policy: the
// console was not started by the launcher with this plan. Outside the
// image (a developer's build) nothing was checked, and the planned
// directories are the roots.
func PlanRoots(o Options, pr config.Profile) (Roots, error) {
	lines, err := mountplan.Lines(pr)
	if err != nil {
		return Roots{}, err
	}
	checked := expectedRoots(o.ExpectRoots)
	verified := func(dir string) bool { return !o.InContainer || checked[dir] }
	var r Roots
	for _, l := range lines {
		switch l.Kind {
		case config.KindFile:
			if !verified(l.Dir) {
				return Roots{}, fmt.Errorf("%s is in the mount plan of profile %q but the launcher did not bind and check it: start the console with the launcher (locklog console --profile %s), which mounts the plan of the approved sources", l.Dir, pr.Name, pr.Name)
			}
			if !slices.Contains(r.Dirs, l.Dir) {
				r.Dirs = append(r.Dirs, l.Dir)
			}
		case config.KindJournald:
			for _, d := range JournalDirs {
				if o.InContainer && checked[d] {
					r.Journal = append(r.Journal, d)
				} else if !o.InContainer {
					if fi, err := os.Lstat(d); err == nil && fi.IsDir() {
						r.Journal = append(r.Journal, d)
					}
				}
			}
			if len(r.Journal) == 0 {
				return Roots{}, fmt.Errorf("profile %q has a journald source but no journal directory (%s) was bound and checked: the host has none, or the console was not started by the launcher", pr.Name, strings.Join(JournalDirs, ", "))
			}
		case config.KindDocker:
			if r.Docker != "" {
				continue
			}
			root := o.DockerRoot
			if err := dockerRoot(root); err != nil {
				return Roots{}, err
			}
			r.Docker, r.DockerChecked = root, checked[root]
			if o.InContainer && !r.DockerChecked {
				// The launcher's "not checked from the host" case: it
				// bound the root at its own path but could not stat it.
				fi, err := os.Lstat(root)
				if err != nil {
					return Roots{}, fmt.Errorf("the containers root %s: %w", root, err)
				}
				if !fi.IsDir() {
					return Roots{}, fmt.Errorf("the containers root %s is not a directory (a link?): refused", root)
				}
			}
		}
	}
	slices.Sort(r.Dirs)
	return r, nil
}

// dockerRoot checks LOCKLOG_DOCKER_ROOT as the launcher writes it: the
// Docker root directory + /containers, absolute and clean.
func dockerRoot(root string) error {
	switch {
	case root == "":
		return errors.New("the profile has a docker source but LOCKLOG_DOCKER_ROOT is not set: start the console with the launcher")
	case !strings.HasPrefix(root, "/") || path.Clean(root) != root || root == "/containers" || path.Base(root) != "containers":
		return errors.New("LOCKLOG_DOCKER_ROOT is not the Docker root directory's containers directory (an absolute, clean path ending in /containers): refused")
	}
	return nil
}
