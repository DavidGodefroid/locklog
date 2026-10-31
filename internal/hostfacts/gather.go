package hostfacts

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/agentwire"
)

// SensitivePaths are the directories doctor checks the account cannot
// read: the journal and Docker's state (every container's logs and
// configuration).
var SensitivePaths = []string{"/var/log/journal", "/var/lib/docker"}

// JournalDirs are where journald keeps its files.
var JournalDirs = []string{"/var/log/journal", "/run/log/journal"}

// CredFiles are the cloud credential files doctor looks for, under the
// home directory.
var CredFiles = []string{".aws/credentials", ".config/gcloud/application_default_credentials.json",
	".azure/msal_token_cache.json", ".azure/accessTokens.json"}

// Env is where Gather looks. Zero fields take the running process's.
type Env struct {
	// LogRoots are walked for log files (default /var/log).
	LogRoots []string
	Home     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
	// Run runs a command and returns its standard output.
	Run func(name string, args ...string) ([]byte, error)
	// DockerSocket is the engine's socket (default /var/run/docker.sock).
	DockerSocket string
}

func (e *Env) defaults() {
	if e.LogRoots == nil {
		e.LogRoots = []string{"/var/log"}
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Home == "" {
		e.Home, _ = os.UserHomeDir()
	}
	if e.LookPath == nil {
		e.LookPath = exec.LookPath
	}
	if e.Run == nil {
		e.Run = func(n string, a ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, n, a...)
			cmd.WaitDelay = time.Second
			return cmd.Output()
		}
	}
	if e.DockerSocket == "" {
		e.DockerSocket = "/var/run/docker.sock"
	}
}

// maxLogFiles bounds the walk of the log roots.
const maxLogFiles = 5000

// Gather reads the facts where this process runs.
func Gather(e Env) Facts {
	e.defaults()
	f := Facts{EUID: os.Geteuid()}
	if gids, err := os.Getgroups(); err == nil {
		seen := map[string]bool{}
		for _, gid := range append(gids, os.Getegid()) {
			name := strconv.Itoa(gid)
			if g, err := user.LookupGroupId(name); err == nil {
				name = g.Name
			}
			if !seen[name] {
				seen[name] = true
				f.Groups = append(f.Groups, name)
			}
		}
	}
	f.Sudo = SudoAbsent
	if _, err := e.LookPath("sudo"); err == nil {
		f.Sudo = SudoPassword
		if _, err := e.Run("sudo", "-n", "true"); err == nil {
			f.Sudo = SudoNoPasswd
		}
	}
	f.DockerHost = e.Getenv("DOCKER_HOST") != ""
	f.Docker = dockerState(e)
	for _, p := range SensitivePaths {
		switch readable(p) {
		case 1:
			f.Readable = append(f.Readable, p)
		case 0:
			f.Unreadable = append(f.Unreadable, p)
		}
	}
	if e.Home != "" {
		for _, c := range CredFiles {
			if st, err := os.Stat(filepath.Join(e.Home, c)); err == nil && st.Mode().IsRegular() {
				f.CredFiles = append(f.CredFiles, "~/"+c)
			}
		}
	}
	for _, j := range JournalDirs {
		if st, err := os.Lstat(j); err == nil && st.IsDir() {
			f.Journals = append(f.Journals, j)
		}
	}
	if f.Docker == DockerReachable {
		if _, err := e.LookPath("docker"); err == nil {
			f.Containers, f.IPCShareable = dockerContainers(e)
			if out, err := e.Run("docker", "info", "--format", "{{.Swarm.LocalNodeState}}"); err == nil {
				if s := strings.TrimSpace(string(out)); stateRe.MatchString(s) {
					f.Swarm = s
				}
			}
		}
	}
	if ae, err := agentwire.SystemEnv(); err == nil {
		ae.Home, ae.Getenv, ae.LookPath = e.Home, e.Getenv, e.LookPath
		f.Agents = agentwire.Detect(ae)
	}
	f.Logs = walkLogs(e.LogRoots)
	return f
}

// readable is 1 when the directory p lists, 0 when it exists but does not,
// -1 when it does not exist.
func readable(p string) int {
	d, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return -1
	}
	if err != nil {
		return 0
	}
	defer d.Close()
	if _, err := d.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return 0
	}
	return 1
}

// dockerState asks the engine through the docker CLI, else pings the
// socket (status only).
func dockerState(e Env) string {
	if _, err := e.LookPath("docker"); err == nil {
		if out, err := e.Run("docker", "version", "--format", "{{.Server.Version}}"); err == nil && strings.TrimSpace(string(out)) != "" {
			return DockerReachable
		}
		return DockerUnreachable
	}
	if st, err := os.Stat(e.DockerSocket); err != nil || st.Mode()&fs.ModeSocket == 0 {
		if e.Getenv("DOCKER_HOST") != "" {
			return DockerUnreachable
		}
		return DockerAbsent
	}
	c := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", e.DockerSocket)
		},
	}}
	resp, err := c.Get("http://docker/_ping")
	if err != nil {
		return DockerUnreachable
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return DockerReachable
	}
	return DockerUnreachable
}

// dockerContainers lists the running containers and those with IpcMode
// shareable, through the docker CLI. The label template yields "-" for an
// unset label; a record that does not parse is skipped.
func dockerContainers(e Env) ([]Container, []string) {
	out, err := e.Run("docker", "ps", "--format", PSFormat)
	if err != nil {
		return nil, nil
	}
	var cs []Container
	for _, l := range strings.Split(string(out), "\n") {
		if c, ok := parseContainer(l); ok {
			cs = append(cs, c)
		}
	}
	var shm []string
	for _, c := range cs {
		mode, err := e.Run("docker", "inspect", "--type", "container", "--format", "{{.HostConfig.IpcMode}}", c.Name)
		if err == nil && strings.TrimSpace(string(mode)) == "shareable" {
			shm = append(shm, c.Name)
		}
	}
	return cs, shm
}

// PSFormat is the `docker ps --format` template of a container fact (the
// launcher uses the same one).
const PSFormat = `{{.Names}} {{.Image}} {{with .Label "com.docker.compose.service"}}{{.}}{{else}}-{{end}} ` +
	`{{with .Label "com.docker.compose.project"}}{{.}}{{else}}-{{end}} {{with .Networks}}{{.}}{{else}}-{{end}}`

// walkLogs lists the regular files under roots, three levels deep at
// most, never following a symbolic link.
func walkLogs(roots []string) []string {
	var out []string
	for _, r := range roots {
		base := strings.Count(filepath.Clean(r), string(filepath.Separator))
		_ = filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(out) >= maxLogFiles {
				return fs.SkipAll
			}
			if d.IsDir() {
				if strings.Count(p, string(filepath.Separator))-base >= 3 {
					return fs.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}
