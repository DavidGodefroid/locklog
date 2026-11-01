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
//	docker <glob>         an approved container name glob of a docker source: the
//	                      launcher binds the containers root and maps the
//	                      containers whose name matches
//	remote                the profile reads a remote source (Loki,
//	                      Elasticsearch, OpenSearch): nothing to bind, but the
//	                      console needs the network LOCKLOG_NETWORK names
//	                      (`locklog mounts` prints it last; Lines does not
//	                      return it)
//
// No field holds a space, a comma, ';', ':', '=', a quote or a control character:
// the config refuses such globs, and Lines refuses them again.
package mountplan

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// RemoteLine is the plan's line of a profile with a remote source.
const RemoteLine = "remote"

// Line is one entry of the plan.
type Line struct {
	Kind string // "file", "journald" or "docker"
	Dir  string // file: the directory to bind
	Glob string // file: the absolute glob opened under Dir; docker: the container name glob
}

// String is the line as the launcher reads it.
func (l Line) String() string {
	switch l.Kind {
	case config.KindJournald:
		return "journald"
	case config.KindDocker:
		return "docker " + l.Glob
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

// Lines is the plan of p: its file sources, the container globs of its
// docker sources and, when it has one, the journal. Remote sources mount
// nothing.
func Lines(p config.Profile) ([]Line, error) {
	if err := config.CheckDockerAlone(p.Sources); err != nil {
		return nil, err
	}
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
			for _, g := range s.Containers {
				if g == "" || strings.Trim(g, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.*?-") != "" ||
					strings.HasPrefix(g, "-") {
					return nil, fmt.Errorf("source %s: container glob %q cannot be mapped", s.Name, g)
				}
				out = append(out, Line{Kind: config.KindDocker, Glob: g})
			}
		}
	}
	slices.SortFunc(out, func(a, b Line) int { return strings.Compare(a.String(), b.String()) })
	out = slices.Compact(out)
	if journald {
		out = append(out, Line{Kind: config.KindJournald})
	}
	return out, nil
}

// ConsoleHome is the console's home volume in its image: only the console
// mounts it (agents never do).
const ConsoleHome = "/home/locklog"

// imageCAs are the image's CA bundle directories.
const imageCAs = "/etc/ssl"

// beneath reports whether p is dir or under it.
func beneath(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// realPath is p cleaned and, where it exists here, with its symbolic
// links resolved (its longest existing prefix is resolved and the rest
// appended), so that a link cannot move a file in or out of a directory.
func realPath(p string) string {
	p = path.Clean(p)
	rest := ""
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return path.Join(filepath.ToSlash(r), rest)
		}
		parent := path.Dir(cur)
		if parent == cur {
			return p
		}
		rest = path.Join(path.Base(cur), rest)
		cur = parent
	}
}

// under reports whether p is strictly beneath dir.
func under(p, dir string) bool { return p != dir && beneath(p, dir) }

// TLSFiles checks that the console can read the tls_ca, tls_cert and
// tls_key files of p's remote sources without any mount of their own,
// and that no agent can read a client key: the launcher binds only the
// project's .locklog/ (read-only, also readable by agents) and the
// console's home volume, and the console confines its reads to them and
// the image's /etc/ssl. A CA certificate (public) may be in
// project/.locklog/, the home volume or /etc/ssl; a client certificate
// and its key only in the home volume, never under the project (a
// project inside the home volume is refused). project is the project
// root on the host, where .locklog/ is bound at the same path. Paths are
// compared cleaned; those under the project with their links resolved.
func TLSFiles(p config.Profile, project string) error {
	// Only paths under the project are resolved: it is bound at the same
	// path in the console, so its links are the console's. Every other
	// path names a file of the console's image or volume, not of here.
	raw, proj := "", ""
	if project != "" {
		raw, proj = path.Clean(project), realPath(project)
	}
	home := ConsoleHome
	hasTLS := false
	for _, s := range p.Sources {
		if r := s.Remote; r != nil && (r.TLSCA != "" || r.TLSCert != "" || r.TLSKey != "") {
			hasTLS = true
		}
	}
	if hasTLS && proj != "" && (beneath(raw, home) || beneath(proj, home)) {
		return fmt.Errorf("the project %s is inside the console's home volume %s: refused (its files would be readable by agents)", proj, home)
	}
	ll := path.Join(proj, ".locklog")
	for _, s := range p.Sources {
		r := s.Remote
		if r == nil {
			continue
		}
		for _, f := range []struct{ key, val string }{{"tls_ca", r.TLSCA}, {"tls_cert", r.TLSCert}, {"tls_key", r.TLSKey}} {
			if f.val == "" {
				continue
			}
			if !path.IsAbs(f.val) || path.Clean(f.val) != f.val {
				return fmt.Errorf("source %s: %s %q: want an absolute, clean path", s.Name, f.key, f.val)
			}
			c := f.val
			if raw != "" && (beneath(c, raw) || beneath(c, proj)) {
				c = realPath(c)
			}
			inProject := proj != "" && beneath(c, proj)
			switch {
			case f.key == "tls_ca" && (proj != "" && under(c, ll) || beneath(c, imageCAs) || under(c, home)):
			case f.key != "tls_ca" && under(c, home) && !inProject:
			case f.key == "tls_ca":
				return fmt.Errorf("source %s: tls_ca %s is not readable by the console: copy the CA certificate into %s/ (the console sees only the project's .locklog/, its home volume %s and the image's %s)",
					s.Name, c, ll, home, imageCAs)
			default:
				return fmt.Errorf("source %s: %s %s is not readable by the console, or would be readable by agents: put the client certificate and key in the console's home volume (%s/..., the locklog-home volume), never in the project",
					s.Name, f.key, c, home)
			}
		}
	}
	return nil
}
