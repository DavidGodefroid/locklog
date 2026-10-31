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

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"not-facts\n",
		Header + "\neuid -1\n",
		Header + "\neuid x\n",
		Header + "\nsudo maybe\n",
		Header + "\ndocker yes\n",
		Header + "\ngroups ok bad;group\n",
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
