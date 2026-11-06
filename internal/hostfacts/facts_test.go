package hostfacts

import (
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := Header + `
euid 1000
groups david adm docker
sudo password
docker reachable
docker_host set
readable /var/log/journal
unreadable /var/lib/docker
credfile ~/.aws/credentials
ipc_shareable shm-1
swarm inactive
agent claude
agent codex
journal /var/log/journal
container web nginx:1.27 web shop bridge,shop_default
container loki grafana/loki:3.5.7 loki shop shop_default
container bare alpine - - -
container a,b img - - -
container c img svc proj net work
future-key something
logs
/var/log/syslog
/var/log/app/app.log.2.gz
agent gemini
relative/path
`
	f, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if f.EUID != 1000 || !f.InGroup("adm") || f.InGroup("wheel") || f.Sudo != SudoPassword || f.Docker != DockerReachable || !f.DockerHost {
		t.Errorf("account facts: %+v", f)
	}
	if !slices.Equal(f.Readable, []string{"/var/log/journal"}) || !slices.Equal(f.Unreadable, []string{"/var/lib/docker"}) ||
		!slices.Equal(f.CredFiles, []string{"~/.aws/credentials"}) || !slices.Equal(f.IPCShareable, []string{"shm-1"}) || f.Swarm != "inactive" {
		t.Errorf("paths: %+v", f)
	}
	// "agent gemini" after "logs" is not an agent: only a path, and not an
	// absolute one, so dropped.
	if !slices.Equal(f.Agents, []string{"claude", "codex"}) {
		t.Errorf("agents = %v", f.Agents)
	}
	if !slices.Equal(f.Logs, []string{"/var/log/syslog", "/var/log/app/app.log.2.gz"}) {
		t.Errorf("logs = %v", f.Logs)
	}
	if len(f.Containers) != 3 || f.Containers[1].Service != "loki" || f.Containers[1].Project != "shop" ||
		!slices.Equal(f.Containers[0].Networks, []string{"bridge", "shop_default"}) || f.Containers[2].Service != "" || f.Containers[2].Networks != nil {
		t.Errorf("containers = %+v", f.Containers)
	}
}

// After "logs0" the log paths are NUL-delimited (find -print0, #87): a
// file or directory name with a newline cannot forge another path line,
// and such a path, which no mount can carry, is dropped.
func TestParseLogsNUL(t *testing.T) {
	in := Header + "\neuid 1000\nlogs0\n" +
		"/var/log/app/app.log\x00" +
		"/var/log/app/x\n/etc/forged.log\x00" +
		"/var/log/app/sub\nsudo nopasswd/a.log\x00" +
		"relative.log\x00" +
		"/var/log/app/app.log.1.gz\x00"
	f, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Logs, []string{"/var/log/app/app.log", "/var/log/app/app.log.1.gz"}) || f.Sudo != "" || f.EUID != 1000 {
		t.Errorf("facts = %+v", f)
	}
	// Without a trailing NUL, and empty.
	if f, err := Parse(strings.NewReader(Header + "\nlogs0\n/var/log/a.log")); err != nil || !slices.Equal(f.Logs, []string{"/var/log/a.log"}) {
		t.Errorf("no trailing NUL: %+v %v", f.Logs, err)
	}
	if f, err := Parse(strings.NewReader(Header + "\nlogs0\n")); err != nil || f.Logs != nil {
		t.Errorf("no log: %+v %v", f.Logs, err)
	}
}

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"not-facts\n",
		Header + "\neuid -1\n",
		Header + "\neuid x\n",
		Header + "\nsudo maybe\n",
		Header + "\ndocker yes\n",
		Header + "\nreadable relative\n",
		Header + "\nagent Claude\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestUnknownEUID(t *testing.T) {
	f, err := Parse(strings.NewReader(Header + "\n"))
	if err != nil || f.EUID != -1 || f.Groups != nil || f.Sudo != "" || f.Docker != "" {
		t.Errorf("empty facts = %+v, %v", f, err)
	}
}

// Without the gids' names (an older launcher, no getent), id -Gn's line is
// all there is: a directory group's pieces ("domain users@corp.example")
// that are no group name are skipped, not an error, and the names are
// marked ambiguous: "docker" may be a piece of "docker users@...".
func TestParseDirectoryGroups(t *testing.T) {
	f, err := Parse(strings.NewReader(Header + "\ngroups david domain users@corp.example docker bad;group\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Groups, []string{"david", "domain", "docker"}) || !f.InGroup("docker") || !f.GroupsAmbiguous {
		t.Errorf("groups = %v, ambiguous %v", f.Groups, f.GroupsAmbiguous)
	}
	// Pieces that all look like names, but more of them than gids.
	f, err = Parse(strings.NewReader(Header + "\ngids 1000 1001\ngroups david docker users\n"))
	if err != nil || !f.GroupsAmbiguous || !f.InGroup("docker") {
		t.Errorf("more names than gids: %+v %v", f, err)
	}
	// As many names as gids: no name holds a space.
	f, err = Parse(strings.NewReader(Header + "\ngids 1000 1001\ngroups david docker\n"))
	if err != nil || f.GroupsAmbiguous || !f.InGroup("docker") {
		t.Errorf("one name per gid: %+v %v", f, err)
	}
}

// With a name per gid (#87), the names are exact: an AD/SSSD group
// "docker users@corp.example" is not the docker group.
func TestParseGroupsByGID(t *testing.T) {
	in := Header + `
gids 1000 1001 1002
groups david docker users@corp.example adm
group 1000 david
group 1001 docker users@corp.example
group 1002 adm
group 4242 docker
`
	f, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Groups, []string{"david", "docker users@corp.example", "adm"}) || f.InGroup("docker") || !f.InGroup("adm") || f.GroupsAmbiguous {
		t.Errorf("groups = %q, ambiguous %v", f.Groups, f.GroupsAmbiguous)
	}
	// A gid without its name: back to id -Gn's line, ambiguous.
	f, err = Parse(strings.NewReader(Header + "\ngids 1000 1001\ngroups david docker users@corp.example\ngroup 1000 david\n"))
	if err != nil || !f.GroupsAmbiguous || !f.InGroup("docker") {
		t.Errorf("a gid unnamed: %+v %v", f, err)
	}
	for _, bad := range []string{"gids 10x\n", "gids -1\n", "group x docker\n", "group 1000\n"} {
		if _, err := Parse(strings.NewReader(Header + "\n" + bad)); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}
