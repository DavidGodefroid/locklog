// Package setup is `locklog setup`: the project's first .locklog/config.toml
// from what the host holds (log files with their rotated and compressed
// siblings, the journal, the running containers, a Compose Loki), the
// production question, the agent wiring at project scope, the
// authenticating proxy of a Compose Loki, and the own-container recipe.
//
// Everything it writes is a proposal: the console shows the profile and
// every loosening to the human before any log is read.
package setup

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

// FileSource is one detected log file family: a file and its rotated and
// compressed siblings, under one glob (or two, when a shorter family in
// the same directory would otherwise take its files).
type FileSource struct {
	Name  string
	Paths []string
}

// Loki is a Loki service of a Compose project, found among the running
// containers.
type Loki struct {
	Container, Service, Project string
	Networks                    []string
}

// Detected is what the host offers for a first profile.
type Detected struct {
	Files      []FileSource
	Journald   bool
	Containers []string
	Lokis      []Loki
}

var (
	// Compression suffixes logrotate (and the like) add.
	compressed = []string{".gz", ".xz", ".bz2", ".zst", ".lz4", ".Z"}
	// rotation suffixes: .1, .2 ...; -20250101 (dateext), with an hour; .2025-01-01.
	rotatedRe = regexp.MustCompile(`(\.[0-9]{1,4}|-[0-9]{8}([0-9]{2})?|\.[0-9]{4}-[0-9]{2}-[0-9]{2})$`)
	// Plain-text system logs without a .log suffix.
	knownLogs = []string{"syslog", "messages", "secure", "maillog", "cron", "dmesg", "debug", "daemon", "kern", "user"}
	// Binary or non-log files that live beside the logs.
	binaryLogs = []string{"wtmp", "btmp", "lastlog", "faillog", "utmp", "tallylog"}
	nameBadRe  = regexp.MustCompile(`[^a-z0-9_-]+`)
)

// stem is the name of the file family of base (its rotation and
// compression suffixes removed), and whether base is a text log at all.
func stem(base string) (string, bool) {
	s := base
	for _, c := range compressed {
		if strings.HasSuffix(s, c) {
			s = strings.TrimSuffix(s, c)
			break
		}
	}
	for i := 0; i < 3; i++ {
		t := rotatedRe.ReplaceAllString(s, "")
		if t == s || t == "" {
			break
		}
		s = t
	}
	if slices.Contains(binaryLogs, s) || strings.HasSuffix(s, ".journal") || strings.HasSuffix(s, ".journal~") {
		return "", false
	}
	if strings.HasSuffix(s, ".log") || strings.HasSuffix(s, "_log") || slices.Contains(knownLogs, s) {
		return s, true
	}
	return "", false
}

// mountable reports whether a glob passes the config's and the mount
// plan's rules (no space, comma, quote, ':', ';', '=' or control
// character; absolute and clean).
func mountable(g string) bool {
	_, err := config.ParseProfiles([]byte("version = 1\n[profiles.x.sources.f]\nkind = \"file\"\npaths = ["+tomlString(g)+"]\n"), "probe")
	return err == nil
}

// Detect groups the facts into sources.
func Detect(f hostfacts.Facts) Detected {
	var d Detected
	type fam struct{ dir, stem string }
	fams := map[fam]bool{}
	for _, p := range f.Logs {
		if !path.IsAbs(p) || path.Clean(p) != p {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if dir == "" || strings.Contains(dir, "/journal") {
			continue
		}
		if s, ok := stem(base); ok {
			fams[fam{dir, s}] = true
		}
	}
	keys := make([]fam, 0, len(fams))
	for k := range fams {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].dir != keys[j].dir {
			return keys[i].dir < keys[j].dir
		}
		return keys[i].stem < keys[j].stem
	})
	used := map[string]bool{}
	for _, k := range keys {
		// A family whose name starts another one's in the same directory
		// (debug and debug.log) gets exact globs: stem* would take the
		// other family's files.
		overlap := false
		for o := range fams {
			if o.dir == k.dir && o.stem != k.stem && strings.HasPrefix(o.stem, k.stem) {
				overlap = true
			}
		}
		paths := []string{k.dir + "/" + k.stem + "*"}
		if overlap {
			paths = []string{k.dir + "/" + k.stem, k.dir + "/" + k.stem + ".*"}
		}
		ok := true
		for _, g := range paths {
			ok = ok && mountable(g)
		}
		if !ok {
			continue
		}
		d.Files = append(d.Files, FileSource{Name: uniqueName(sourceName(k.dir, k.stem), used), Paths: paths})
	}
	d.Journald = len(f.Journals) > 0
	for _, c := range f.Containers {
		if strings.HasPrefix(c.Name, config.ConsolePrefix) || !config.ValidContainerName(c.Name) {
			continue
		}
		if !slices.Contains(d.Containers, c.Name) {
			d.Containers = append(d.Containers, c.Name)
		}
		if isLoki(c.Image) && c.Service != "" && c.Project != "" {
			d.Lokis = append(d.Lokis, Loki{Container: c.Name, Service: c.Service, Project: c.Project, Networks: c.Networks})
		}
	}
	sort.Strings(d.Containers)
	return d
}

// isLoki reports whether an image reference is Grafana's Loki.
func isLoki(image string) bool {
	repo := image
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	return repo == "grafana/loki" || strings.HasSuffix(repo, "/grafana/loki")
}

// sourceName is a source name for a family: its directory's name and its
// stem, without ".log" ("nginx-access"; "syslog" directly under a log
// directory).
func sourceName(dir, stem string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(stem, ".log"), "_log")
	if b := path.Base(dir); b != "log" && b != "logs" {
		s = b + "-" + s
	}
	s = strings.Trim(nameBadRe.ReplaceAllString(strings.ToLower(s), "-"), "-_")
	if s == "" {
		s = "log"
	}
	if s[0] == '_' || s[0] == '-' {
		s = "log" + s
	}
	if len(s) > 44 {
		s = strings.TrimRight(s[:44], "-_")
	}
	return s
}

// uniqueName adds -2, -3... to a name already used.
func uniqueName(n string, used map[string]bool) string {
	out := n
	for i := 2; used[out]; i++ {
		out = n + "-" + itoa(i)
	}
	used[out] = true
	return out
}

func itoa(n int) string {
	const digits = "0123456789"
	if n < 10 {
		return digits[n : n+1]
	}
	return itoa(n/10) + digits[n%10:n%10+1]
}
