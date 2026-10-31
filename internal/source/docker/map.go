package docker

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// The map file format. The launcher writes it; the console only reads it.
const (
	mapPrefix  = "map.v"
	mapHeader  = "locklog-map 1"
	maxMapSize = 1 << 20
	// MaxFiles bounds a container's max-file (Docker's json-file accepts
	// more; the launcher clamps to it).
	MaxFiles = 100
)

// Container is one mapped json-file container.
type Container struct {
	ID       string // 64 lower-case hex characters
	Name     string
	MaxFile  int // 1..MaxFiles: the live file and MaxFile-1 rotated ones
	Compress bool
}

// Map is one valid version of the containers map.
type Map struct {
	Version    uint64
	Containers []Container
	// Consoles are the ids of locklog console containers: never served.
	Consoles map[string]bool
}

var errMap = errors.New("docker source: malformed containers map")

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseMap parses the content of one map version. It is strict: any
// malformed line refuses the whole version.
func ParseMap(b []byte) (Map, error) {
	if len(b) > maxMapSize || !bytes.HasSuffix(b, []byte("\n")) {
		return Map{}, errMap
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if lines[0] != mapHeader {
		return Map{}, errMap
	}
	m := Map{Consoles: map[string]bool{}}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, l := range lines[1:] {
		f := strings.Split(l, " ")
		switch {
		case len(f) == 5 && f[0] == "c":
			id, name := f[1], f[2]
			if !validID(id) || !config.ValidContainerName(name) || ids[id] || names[name] {
				return Map{}, errMap
			}
			n, err := strconv.Atoi(f[3])
			if err != nil || n < 1 || n > MaxFiles || strconv.Itoa(n) != f[3] {
				return Map{}, errMap
			}
			if f[4] != "0" && f[4] != "1" {
				return Map{}, errMap
			}
			ids[id], names[name] = true, true
			m.Containers = append(m.Containers, Container{ID: id, Name: name, MaxFile: n, Compress: f[4] == "1"})
		case len(f) == 2 && f[0] == "x":
			if !validID(f[1]) || m.Consoles[f[1]] {
				return Map{}, errMap
			}
			m.Consoles[f[1]] = true
		default:
			return Map{}, errMap
		}
	}
	return m, nil
}

// mapVersion returns N of a "map.v<N>" file name (decimal, no leading zero,
// N >= 1).
func mapVersion(name string) (uint64, bool) {
	s, ok := strings.CutPrefix(name, mapPrefix)
	if !ok || s == "" || len(s) > 18 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// mapFiles lists the map versions of dir, newest first, and a key that
// changes whenever one of them does (name, size, mtime).
func mapFiles(dir string) ([]string, string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, ""
	}
	type ver struct {
		n    uint64
		name string
	}
	var vs []ver
	var key strings.Builder
	for _, e := range ents {
		n, ok := mapVersion(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		vs = append(vs, ver{n, e.Name()})
		if fi, err := e.Info(); err == nil {
			key.WriteString(e.Name() + ":" + strconv.FormatInt(fi.Size(), 10) + ":" + strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ";")
		}
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].n > vs[j].n })
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.name
	}
	return out, key.String()
}

// ReadMap returns the newest map version in dir. When it is malformed (or
// unreadable), ok is false and nothing is served: an older version is never
// used instead (fail closed; versions are written atomically, so the newest
// is never partial).
func ReadMap(dir string) (Map, bool) {
	names, _ := mapFiles(dir)
	return readNewest(dir, names)
}

func readNewest(dir string, names []string) (Map, bool) {
	if len(names) == 0 {
		return Map{}, false
	}
	b, ok := readSmall(filepath.Join(dir, names[0]))
	if !ok {
		return Map{}, false
	}
	m, err := ParseMap(b)
	if err != nil {
		return Map{}, false
	}
	m.Version, _ = mapVersion(names[0])
	return m, true
}

// readSmall reads a regular file of at most maxMapSize bytes, refusing a
// symbolic link.
func readSmall(p string) ([]byte, bool) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxMapSize {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if now, err := f.Stat(); err != nil || !os.SameFile(fi, now) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMapSize+1))
	if err != nil || len(b) > maxMapSize {
		return nil, false
	}
	return b, true
}
