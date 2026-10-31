// Package mountplan turns a profile's local sources into the mount plan
// the launcher applies on the host: one line per directory to bind
// read-only into the console, with the globs the console may open under
// it. The launcher (scripts/locklog) checks every line again on the host
// (allowed roots, real paths, groups); this side only derives them.
//
// Line format, one per line, fields separated by one space:
//
//	file <dir> <glob>     a file source: bind <dir>, open only <glob> in it
//	journald              the journal directories (/var/log/journal, /run/log/journal)
//
// No field holds a space, a comma, ';', ':', '=', a quote or a control character:
// the config refuses such globs, and Lines refuses them again.
package mountplan

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// Line is one entry of the plan.
type Line struct {
	Kind string // "file" or "journald"
	Dir  string // file: the directory to bind
	Glob string // file: the absolute glob opened under Dir
}

// String is the line as the launcher reads it.
func (l Line) String() string {
	if l.Kind == config.KindJournald {
		return "journald"
	}
	return "file " + l.Dir + " " + l.Glob
}

// Dir returns the directory to bind for an absolute file glob: the
// leading components before the first one holding a glob character, the
// file name itself excluded.
func Dir(glob string) string {
	comps := strings.Split(glob[1:], "/")
	n := len(comps) - 1 // the last component is the file name pattern
	for i, c := range comps[:n] {
		if c == "**" || strings.ContainsAny(c, "*?[") {
			n = i
			break
		}
	}
	return "/" + strings.Join(comps[:n], "/")
}

// Lines is the plan of p: its file sources and, when it has one, the
// journal. Docker and remote sources mount nothing here.
func Lines(p config.Profile) ([]Line, error) {
	var out []Line
	journald := false
	for _, s := range p.Sources {
		switch s.Kind {
		case config.KindFile:
			for _, g := range s.Paths {
				if strings.ContainsAny(g, " ,;=:\"'`\\\t\r\n") {
					return nil, fmt.Errorf("source %s: path %q cannot be mounted", s.Name, g)
				}
				d := Dir(g)
				if d == "/" {
					return nil, fmt.Errorf("source %s: path %q would mount the root directory", s.Name, g)
				}
				out = append(out, Line{Kind: config.KindFile, Dir: path.Clean(d), Glob: g})
			}
		case config.KindJournald:
			journald = true
		case config.KindDocker:
			return nil, fmt.Errorf("source %s: docker sources are not supported by this version", s.Name)
		}
	}
	slices.SortFunc(out, func(a, b Line) int { return strings.Compare(a.String(), b.String()) })
	out = slices.Compact(out)
	if journald {
		out = append(out, Line{Kind: config.KindJournald})
	}
	return out, nil
}
