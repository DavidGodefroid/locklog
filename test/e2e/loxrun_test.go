//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
)

// The console runs hub-attached only, started by `lox run` (lockhub). The
// locklog type of lox run is lockhub's work (lockhub#84, #86, #87): until
// it ships, these tests stand in for it, as lockhub's docs/lox-run.md
// describes it. A lock "logs" of the workspace (the project), with:
//
//   - the console's home and socket volumes, with lox run's labels;
//   - lockkit's fake lockhub (hubtest) in this process, reached over an
//     internal Docker network of its own (the console's only network, as
//     lox run's hub network: no route out), through a forwarder on that
//     network's gateway; a local-only console accepts that network and no
//     other (#136);
//   - the console in the image, hub-attached, as the console account, its
//     project's .locklog read-only and the log directory bound read-only
//     at its own path, checked by device and inode (LOCKLOG_EXPECT_*), in
//     a terminal of its own (script(1)), labelled as compose labels lox
//     run's consoles (so that the launcher trusts its socket volume);
//   - the workspace's .lockfamily/up.json, as lox run writes it.
//
// The agent then runs the launcher's commands from the workspace, as a
// host agent does.

const instance = "logs"

// loxRun is a lock "logs" started as lox run would.
type loxRun struct {
	hub                       *hubtest.Hub
	project, sockVol, homeVol string
	network, name             string
}

// loxProject is lox run's compose project of the workspace ws.
func loxProject(ws string) string {
	h := sha256.Sum256([]byte(ws))
	return "lockfamily-" + hex.EncodeToString(h[:4])
}

// devIno is path's device:inode, as the console compares them.
func devIno(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	b, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, b)
	}
	return strings.TrimSpace(string(b))
}

// startLoxRun starts the console of profile in the workspace e.proj,
// hub-attached, answers its prompts in order, each once it shows, and
// returns once it listens. allowed is its --allowed-uids ("" none).
func startLoxRun(t *testing.T, e *e2eEnv, profile, allowed string, answers ...[2]string) *loxRun {
	t.Helper()
	r, screen, exited := launchLoxRun(t, e, true, profile, allowed, answers...)
	waitFor(t, screen, "Listening on ", 2*time.Minute, exited)
	writeUpJSON(t, e.proj, r.project)
	return r
}

// launchLoxRun starts the console as startLoxRun does, on an internal hub
// network (internal false: a plain bridge network, with a route out),
// answers its prompts and returns its screen and a channel closed once it
// exits.
func launchLoxRun(t *testing.T, e *e2eEnv, internal bool, profile, allowed string, answers ...[2]string) (*loxRun, *buffer, <-chan struct{}) {
	t.Helper()
	ws := e.proj
	r := &loxRun{project: loxProject(ws)}
	r.sockVol, r.homeVol = r.project+"_"+instance+"-run", r.project+"_"+instance+"-home"
	r.network, r.name = r.project+"_lockhub", r.project+"-"+instance+"-1"
	state := filepath.Join(e.base, "state")
	workdir := filepath.Join(state, "lockfamily", r.project)
	mkdir(t, workdir)
	// The launcher finds lox run's state directory through XDG_STATE_HOME.
	e.env = append(e.env, "XDG_STATE_HOME="+state)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", r.name).Run()
		_ = exec.Command("docker", "volume", "rm", r.sockVol, r.homeVol).Run()
		_ = exec.Command("docker", "network", "rm", r.network).Run()
	})

	docker(t, "volume", "create", "--label", "com.docker.compose.project="+r.project, "--label", "com.docker.compose.volume="+instance+"-run",
		"--label", "dev.lockfamily.role=socket", "--label", "dev.lockfamily.instance="+instance, "--label", "dev.lockfamily.type=locklog",
		"--label", "dev.lockfamily.workspace="+ws, r.sockVol)
	docker(t, "volume", "create", "--label", "com.docker.compose.project="+r.project, "--label", "com.docker.compose.volume="+instance+"-home", r.homeVol)

	// The instance key, made in the console's home, pinned at the hub.
	pubB64 := docker(t, "run", "--rm", "--user", "locklog", "--network", "none", "--log-driver", "none", "-v", r.homeVol+":/home/locklog",
		e.image, "hub-key", "--instance", instance)
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("hub-key: %q: %v", pubB64, err)
	}
	r.hub = hubtest.New(t, instance, ed25519.PublicKey(pub))

	// The hub's network, the console's only one, internal as lox run's,
	// and the hub on its gateway (the fake hub listens on the loopback
	// only).
	netArgs := []string{"network", "create"}
	if internal {
		netArgs = append(netArgs, "--internal")
	}
	docker(t, append(netArgs, r.network)...)
	gw := docker(t, "network", "inspect", "-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}", r.network)
	// The hub by a service name, as lox run's consoles name it (plain http
	// only to a name without a dot or a private address).
	hubURL := "http://lockhub:" + forward(t, gw, r.hub.URL())
	hubDir := filepath.Join(e.base, "hub")
	mkdir(t, hubDir)
	hubKey := filepath.Join(hubDir, "hub.pub")
	if err := os.WriteFile(hubKey, []byte(base64.StdEncoding.EncodeToString(r.hub.Pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hubKey, 0o644); err != nil {
		t.Fatal(err)
	}

	ll := filepath.Join(e.proj, ".locklog")
	args := []string{"run", "--rm", "-it", "--name", r.name, "--label", "locklog.console=1",
		"--label", "com.docker.compose.project=" + r.project, "--label", "com.docker.compose.project.working_dir=" + workdir,
		"--label", "com.docker.compose.project.config_files=-",
		"--user", "locklog", "--log-driver", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "--pids-limit", "256", "--memory", "1g", "--network", r.network,
		"--add-host", "lockhub:" + gw,
		"-e", "LOCKLOG_EXPECT_DIR=" + devIno(t, ll), "-e", "LOCKLOG_EXPECT_ROOTS=" + devIno(t, e.logs) + " " + e.logs + ";",
		"-e", "LOCKLOG_EXTRA_ROOTS=" + e.logs,
		"--mount", "type=volume,src=" + r.sockVol + ",dst=/run/locklog", "--mount", "type=volume,src=" + r.homeVol + ",dst=/home/locklog",
		"--mount", "type=bind,src=" + ll + ",dst=" + ll + ",readonly", "--mount", "type=bind,src=" + e.logs + ",dst=" + e.logs + ",readonly",
		"--mount", "type=bind,src=" + hubKey + ",dst=/run/lockfamily-hub/hub.pub,readonly",
		"-w", e.proj, e.image, "console", "--profile", profile, "--hub", hubURL, "--hub-plain-http",
		"--hub-key-file", "/run/lockfamily-hub/hub.pub", "--instance", instance}
	if allowed != "" {
		args = append(args, "--allowed-uids", allowed)
	}
	line := "exec docker"
	for _, a := range args {
		line += " '" + a + "'"
	}
	console := exec.Command("script", "-q", "-f", "-e", "-c", line, "/dev/null")
	console.Env = e.env
	keys, err := console.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var screen buffer
	console.Stdout, console.Stderr = &screen, &screen
	if err := console.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = console.Wait(); close(exited) }()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("console output (masked):\n%s", plain(screen.String()))
		}
		_, _ = io.WriteString(keys, ":quit\r")
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			_ = console.Process.Kill()
			<-exited
		}
	})
	for _, a := range answers {
		waitFor(t, &screen, a[0], 3*time.Minute, exited)
		if _, err := io.WriteString(keys, a[1]+"\r"); err != nil {
			t.Fatal(err)
		}
	}
	return r, &screen, exited
}

// forward serves target (http://127.0.0.1:port) on ip, a port of its own
// (returned): the hub's address on the console's network.
func forward(t *testing.T, ip, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on the hub network's gateway %s: %v", ip, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", u.Host)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// writeUpJSON writes the workspace's .lockfamily/up.json as lox run does
// (json.MarshalIndent, two spaces; the user's, 0644 in a 0755 directory).
func writeUpJSON(t *testing.T, ws, project string) {
	t.Helper()
	type lock struct {
		Type   string `json:"type"`
		Socket string `json:"socket_volume"`
		GID    string `json:"client_gid"`
	}
	up := struct {
		Version    int             `json:"version"`
		Project    string          `json:"project"`
		Workspace  string          `json:"workspace"`
		HubNetwork string          `json:"hub_network"`
		HubURL     string          `json:"hub_url"`
		Locks      map[string]lock `json:"locks"`
	}{1, project, ws, project + "_lockhub", "http://lockhub:8443",
		map[string]lock{instance: {Type: "locklog", Socket: project + "_" + instance + "-run", GID: "10050"}}}
	b, err := json.MarshalIndent(up, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	lf := filepath.Join(ws, ".lockfamily")
	mkdir(t, lf)
	p := filepath.Join(lf, "up.json")
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// auditLog is the console's audit log, read from its home volume.
func (r *loxRun) auditLog(t *testing.T, image string) []byte {
	t.Helper()
	b, err := exec.Command("docker", "run", "--rm", "--network", "none", "--user", "locklog",
		"--entrypoint", "cat", "-v", r.homeVol+":/home/locklog:ro", image,
		"/home/locklog/.local/state/locklog/audit.log").CombinedOutput()
	if err != nil {
		t.Fatalf("reading the audit log: %v: %s", err, b)
	}
	return b
}
