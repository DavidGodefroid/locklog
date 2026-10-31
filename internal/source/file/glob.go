package file

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	// MaxRecursion is the deepest "**" expansion (directories below the
	// point where "**" appears).
	MaxRecursion = 4
	// MaxFiles bounds the files one glob may match.
	MaxFiles = 10000
)

// match is a file found by a glob: its mount root and its slash-separated
// path relative to the root.
type match struct {
	root string
	rel  string
}

func (m match) path() string { return m.root + "/" + m.rel }

// rootOf returns the longest root that contains the absolute, clean path p.
func rootOf(roots []string, p string) (string, error) {
	best := ""
	for _, r := range roots {
		r = strings.TrimSuffix(r, "/")
		if r == "" {
			continue // "/" is never a mount root
		}
		if strings.HasPrefix(p, r+"/") && len(r) > len(best) {
			best = r
		}
	}
	if best == "" {
		return "", fmt.Errorf("path %q is under no mounted root", p)
	}
	return best, nil
}

// checkPattern validates a configured glob.
func checkPattern(pattern string, recursive bool) error {
	if !path.IsAbs(pattern) || path.Clean(pattern) != pattern {
		return fmt.Errorf("glob %q: want an absolute, clean path", pattern)
	}
	n := 0
	for _, seg := range strings.Split(pattern[1:], "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("glob %q: '.' and '..' are not allowed", pattern)
		}
		if seg == "**" {
			n++
		} else if strings.Contains(seg, "**") {
			return fmt.Errorf("glob %q: '**' must be a whole path component", pattern)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("glob %q: %w", pattern, err)
		}
	}
	if n > 0 && !recursive {
		return fmt.Errorf("glob %q: '**' needs recursive = true", pattern)
	}
	if n > 1 {
		return fmt.Errorf("glob %q: at most one '**'", pattern)
	}
	if strings.HasSuffix(pattern, "/**") {
		return fmt.Errorf("glob %q: '**' cannot be the last component", pattern)
	}
	return nil
}

var errTooMany = errors.New("glob matches too many files")

// expand returns the regular files matching pattern, beneath its root,
// sorted by path. Symbolic links are never followed, neither to directories
// nor to files.
func expand(roots []string, pattern string, recursive bool) ([]match, error) {
	if err := checkPattern(pattern, recursive); err != nil {
		return nil, err
	}
	root, err := rootOf(roots, pattern)
	if err != nil {
		return nil, err
	}
	d, err := openRoot(root)
	if err != nil {
		return nil, err
	}
	defer d.close()
	seen := map[string]bool{}
	var out []match
	var walk func(d *dir, prefix string, segs []string, depth int) error
	walk = func(d *dir, prefix string, segs []string, depth int) error {
		seg, last := segs[0], len(segs) == 1
		var ents []entry
		if !hasMeta(seg) {
			// A literal component is probed by name: its directory
			// may grant search but not read (Docker's 0710 dirs).
			e, err := d.lstat(seg)
			if err != nil {
				return nil // absent or unreadable: no match
			}
			ents = []entry{e}
		} else {
			var err error
			if ents, err = d.list(); err != nil {
				return nil // unreadable directory: no match
			}
		}
		if seg == "**" {
			if err := walk(d, prefix, segs[1:], depth); err != nil {
				return err
			}
			if depth >= MaxRecursion {
				return nil
			}
			for _, e := range ents {
				if !e.dir {
					continue
				}
				if err := descend(d, e.name, func(sub *dir) error {
					return walk(sub, join(prefix, e.name), segs, depth+1)
				}); err != nil {
					return err
				}
			}
			return nil
		}
		for _, e := range ents {
			if ok, _ := path.Match(seg, e.name); !ok {
				continue
			}
			rel := join(prefix, e.name)
			switch {
			case last && e.reg:
				if !seen[rel] {
					seen[rel] = true
					out = append(out, match{root: root, rel: rel})
					if len(out) > MaxFiles {
						return errTooMany
					}
				}
			case !last && e.dir:
				if err := descend(d, e.name, func(sub *dir) error {
					return walk(sub, rel, segs[1:], depth)
				}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	rel := strings.TrimPrefix(pattern, root+"/")
	if err := walk(d, "", strings.Split(rel, "/"), 0); err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// descend opens the subdirectory name and calls fn on it. A directory that
// vanished or cannot be opened (permissions, a symbolic link replacing it) is
// skipped: globs see what the console may read.
func descend(d *dir, name string, fn func(*dir) error) error {
	sub, err := d.sub(name)
	if err != nil {
		return nil
	}
	defer sub.close()
	return fn(sub)
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func hasMeta(seg string) bool { return strings.ContainsAny(seg, "*?[\\") }
