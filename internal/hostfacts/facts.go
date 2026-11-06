// Package hostfacts holds what `locklog profile add` and `locklog doctor` know of
// the machine the agent runs on: its account (euid, groups, sudo), Docker's
// reach, the log files and journals, the containers and the installed
// agents.
//
// The launcher (scripts/locklog) gathers them on the host, where the agent
// runs, and passes them to the image in a facts file (Parse): profile add
// and doctor run in a container that would otherwise see only itself. Without
// the launcher (the binary copied into an agent's own image, or a test),
// Gather reads them where the binary runs.
//
// Facts are names, paths, ids and states only: never a log line, a response
// body or a secret.
package hostfacts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Header is the first line of a facts file.
const Header = "locklog-facts 1"

// Sudo states.
const (
	SudoAbsent   = "absent"   // no sudo command
	SudoPassword = "password" // sudo asks for a password (sudo -n fails)
	SudoNoPasswd = "nopasswd" // sudo -n true succeeds
)

// Docker states.
const (
	DockerAbsent      = "absent"      // no docker command and no socket
	DockerUnreachable = "unreachable" // a client, but no engine answers
	DockerReachable   = "reachable"   // an engine answers this account
)

// Container is one container `docker ps` lists, with its Compose labels
// ("" when unset) and its networks.
type Container struct {
	Name, Image, Service, Project string
	Networks                      []string
}

// Facts are what the checks read. A zero field is unknown, never "fine".
type Facts struct {
	// EUID is the effective uid (-1: unknown).
	EUID int
	// Groups are the account's group names. GroupsAmbiguous is set when
	// they come from id -Gn's line and a name may hold a space (SSSD, AD:
	// "docker users@corp.example" reads as "docker" and a piece): a name
	// of Groups may then be a piece of another.
	Groups          []string
	GroupsAmbiguous bool
	// Sudo is one of the Sudo states ("" unknown).
	Sudo string
	// Docker is one of the Docker states ("" unknown); DockerHost is set
	// when DOCKER_HOST is (its value is never kept).
	Docker     string
	DockerHost bool
	// Readable and Unreadable are the sensitive paths checked.
	Readable, Unreadable []string
	// CredFiles are cloud credential files present (shown with ~).
	CredFiles []string
	// IPCShareable are containers with IpcMode "shareable"; Swarm is the
	// swarm state ("active", "inactive"...; "" unknown).
	IPCShareable []string
	Swarm        string
	// Agents are the installed agents (agentwire's names).
	Agents []string
	// Journals are the journal directories present.
	Journals []string
	// Containers are the running containers.
	Containers []Container
	// Logs are log file paths under the allowed roots.
	Logs []string
}

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,254}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	groupRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$`)
	gidRe   = regexp.MustCompile(`^[0-9]{1,10}$`)
	// A group's full name, as getent gives it: spaces allowed.
	fullGroupRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
	agentRe     = regexp.MustCompile(`^[a-z]{1,16}$`)
	pathRe      = regexp.MustCompile(`^(/|~/)[^\x00-\x1f\x7f]{0,1000}$`)
	stateRe     = regexp.MustCompile(`^[a-z-]{1,32}$`)
	maxLines    = 20000
)

// Parse reads a facts file. Unknown keys are skipped (a newer launcher);
// a malformed value of a known key is an error. Everything after "logs0"
// is log paths, NUL-delimited (find -print0): a newline in a file or
// directory name cannot forge a path, and such a path is dropped. After
// "logs" (an older launcher), every line is a log path: a path that would
// break a line can only add log paths, which profile add checks like any
// other.
func Parse(r io.Reader) (Facts, error) {
	f := Facts{EUID: -1}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	nul := false
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if !nul {
			return bufio.ScanLines(data, atEOF)
		}
		if i := bytes.IndexByte(data, 0); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	if !sc.Scan() || sc.Text() != Header {
		return f, fmt.Errorf("hostfacts: not a facts file (want %q first)", Header)
	}
	logs := false
	n := 0
	// The groups: id -Gn's line (names split on spaces), id -G's gids and
	// the name of each gid ("group GID NAME", NAME whole), settled at the end.
	var pieces, gids []string
	piecesBad := false
	named := map[string]string{}
	for sc.Scan() {
		n++
		if n > maxLines {
			return f, errors.New("hostfacts: too many lines")
		}
		line := sc.Text()
		if logs {
			if pathRe.MatchString(line) && strings.HasPrefix(line, "/") {
				f.Logs = append(f.Logs, line)
			}
			continue
		}
		if line == "" {
			continue
		}
		key, rest, _ := strings.Cut(line, " ")
		bad := func() error { return fmt.Errorf("hostfacts: line %d: malformed %s", n+1, key) }
		switch key {
		case "logs":
			logs = true
		case "logs0":
			logs, nul = true, true
		case "euid":
			v, err := strconv.Atoi(rest)
			if err != nil || v < 0 {
				return f, bad()
			}
			f.EUID = v
		case "groups":
			// id -Gn splits on spaces: a directory group with a space or
			// an '@' (SSSD, AD: "domain users@corp.example") gives pieces.
			// The ones that are no group name are skipped.
			pieces = []string{}
			for _, g := range strings.Fields(rest) {
				if groupRe.MatchString(g) {
					pieces = append(pieces, g)
				} else {
					piecesBad = true
				}
			}
		case "gids":
			gids = []string{}
			for _, g := range strings.Fields(rest) {
				if !gidRe.MatchString(g) {
					return f, bad()
				}
				gids = append(gids, g)
			}
		case "group":
			gid, name, ok := strings.Cut(rest, " ")
			if !ok || !gidRe.MatchString(gid) || !fullGroupRe.MatchString(name) {
				return f, bad()
			}
			named[gid] = name
		case "sudo":
			if rest != SudoAbsent && rest != SudoPassword && rest != SudoNoPasswd {
				return f, bad()
			}
			f.Sudo = rest
		case "docker":
			if rest != DockerAbsent && rest != DockerUnreachable && rest != DockerReachable {
				return f, bad()
			}
			f.Docker = rest
		case "docker_host":
			f.DockerHost = rest == "set"
		case "readable", "unreadable", "credfile", "journal":
			if !pathRe.MatchString(rest) {
				return f, bad()
			}
			switch key {
			case "readable":
				f.Readable = append(f.Readable, rest)
			case "unreadable":
				f.Unreadable = append(f.Unreadable, rest)
			case "credfile":
				f.CredFiles = append(f.CredFiles, rest)
			default:
				f.Journals = append(f.Journals, rest)
			}
		case "ipc_shareable":
			// Names come from the engine: one that does not parse is
			// still a shareable container.
			if !nameRe.MatchString(rest) {
				rest = "(unnamed)"
			}
			f.IPCShareable = append(f.IPCShareable, rest)
		case "swarm":
			if !stateRe.MatchString(rest) {
				return f, bad()
			}
			f.Swarm = rest
		case "agent":
			if !agentRe.MatchString(rest) {
				return f, bad()
			}
			f.Agents = append(f.Agents, rest)
		case "container":
			// A container whose record does not parse (a legacy linked
			// name, a label with a space) is skipped: profile add proposes only
			// what it can name.
			if c, ok := parseContainer(rest); ok {
				f.Containers = append(f.Containers, c)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return f, fmt.Errorf("hostfacts: %w", err)
	}
	f.Groups, f.GroupsAmbiguous = settleGroups(pieces, piecesBad, gids, named)
	return f, nil
}

// settleGroups returns the account's group names: the name of every gid
// when each has one (exact), else id -Gn's pieces, ambiguous when a piece
// was no name or there are more pieces than gids.
func settleGroups(pieces []string, piecesBad bool, gids []string, named map[string]string) ([]string, bool) {
	if len(gids) > 0 {
		names := make([]string, 0, len(gids))
		for _, g := range gids {
			n, ok := named[g]
			if !ok {
				names = nil
				break
			}
			names = append(names, n)
		}
		if names != nil {
			return names, false
		}
	}
	if pieces == nil {
		return nil, false
	}
	return pieces, piecesBad || (len(gids) > 0 && len(pieces) != len(gids))
}

// parseContainer reads "NAME IMAGE SERVICE PROJECT NETWORKS" ("-" for an
// unset label or no network; networks comma-separated).
func parseContainer(s string) (Container, bool) {
	fs := strings.Fields(s)
	if len(fs) != 5 || !nameRe.MatchString(fs[0]) || !imageRe.MatchString(fs[1]) {
		return Container{}, false
	}
	c := Container{Name: fs[0], Image: fs[1]}
	for i, dst := range []*string{&c.Service, &c.Project} {
		v := fs[2+i]
		if v == "-" {
			continue
		}
		if !labelRe.MatchString(v) {
			return Container{}, false
		}
		*dst = v
	}
	if fs[4] != "-" {
		for _, n := range strings.Split(fs[4], ",") {
			if !nameRe.MatchString(n) {
				return Container{}, false
			}
			c.Networks = append(c.Networks, n)
		}
	}
	return c, true
}

// InGroup reports whether the account is in group g.
func (f Facts) InGroup(g string) bool {
	for _, x := range f.Groups {
		if x == g {
			return true
		}
	}
	return false
}
