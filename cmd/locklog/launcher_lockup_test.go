//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The agent commands reach the locklog lock `lox run` runs for the
// workspace (lockhub's docs/lox-run.md, "up.json (version 1)"): its socket
// volume, named in <workspace>/.lockfamily/up.json, mounted read-only once
// Docker confirms it is lox run's. These tests fake Docker's answers for
// that volume and the containers that mount it.

// upLock and upState are lox run's up.json (lockhub's family.UpState),
// with members the launcher does not read, nested as lox run writes them.
type upLock struct {
	Type          string   `json:"type"`
	Profile       string   `json:"profile,omitempty"`
	Socket        string   `json:"socket_volume"`
	GateHome      string   `json:"gate_home_volume,omitempty"`
	GID           string   `json:"client_gid"`
	Devices       bool     `json:"devices,omitempty"`
	RequireDevice []string `json:"require_device,omitempty"`
}

type upState struct {
	Version      int               `json:"version"`
	Project      string            `json:"project"`
	Workspace    string            `json:"workspace"`
	HubNetwork   string            `json:"hub_network"`
	HubURL       string            `json:"hub_url"`
	HubKey       string            `json:"hub_key"`
	FacadeKeys   any               `json:"facade_keys,omitempty"`
	LockHTTPGate int               `json:"lockhttp_gate"`
	Locks        map[string]upLock `json:"locks"`
}

// loxProject is lox run's compose project of the workspace ws.
func loxProject(ws string) string {
	h := sha256.Sum256([]byte(ws))
	return "lockfamily-" + hex.EncodeToString(h[:4])
}

// jsonString is s as Docker's {{json}} prints it (no HTML escaping).
func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// gids are the clients groups of the lock types' images.
var gids = map[string]string{"locklog": "10050", "locksql": "10000", "lockhttp": "10020"}

// loxRun makes ws a workspace whose locks (instance: type) lox run runs:
// its up.json (the user's, 0644 in a 0755 .lockfamily) and Docker's view
// of each socket volume (lox run's labels; one console container, run by
// compose from lox run's state directory).
func (f *launcherFixture) loxRun(t *testing.T, ws string, locks map[string]string) upState {
	t.Helper()
	p := loxProject(ws)
	s := upState{Version: 1, Project: p, Workspace: ws, HubNetwork: p + "_lockhub", HubURL: "http://lockhub:8443", HubKey: "a2V5",
		FacadeKeys: map[string]any{"v": 1, "facades": []map[string]string{{"facade": "tty", "key": "cHVi"}}}, LockHTTPGate: 1, Locks: map[string]upLock{}}
	for name, typ := range locks {
		l := upLock{Type: typ, Socket: p + "_" + name + "-run", GID: gids[typ]}
		if typ == "lockhttp" {
			l.GateHome, l.Devices, l.RequireDevice = p+"_"+name+"-gate", true, []string{"write"}
		}
		s.Locks[name] = l
		f.dockerVolume(t, l.Socket, volumeLabels(p, name, typ, ws))
		h := sha256.Sum256([]byte(name))
		id := hex.EncodeToString(h[:])
		f.dockerContainers(t, l.Socket, map[string]string{id: containerLabels(p, f.stateDir(p), "-", "rw ")})
	}
	f.writeUpState(t, ws, s)
	return s
}

// writeUpState writes s as lox run does (json.MarshalIndent, two spaces).
func (f *launcherFixture) writeUpState(t *testing.T, ws string, s upState) {
	t.Helper()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.writeUpFile(t, ws, append(b, '\n'))
}

func (f *launcherFixture) writeUpFile(t *testing.T, ws string, b []byte) {
	t.Helper()
	lf := filepath.Join(ws, ".lockfamily")
	if err := os.MkdirAll(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(lf, "up.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// stateDir is lox run's state directory of project, for the fixture's
// HOME (no XDG_STATE_HOME).
func (f *launcherFixture) stateDir(project string) string {
	return filepath.Join(f.root, "home", ".local", "state", "lockfamily", project)
}

// volumeLabels is what the launcher's docker volume inspect prints for a
// volume with lox run's labels of the lock name.
func volumeLabels(project, name, typ, ws string) string {
	var out []string
	for _, v := range []string{project, name + "-run", "socket", name, typ, ws} {
		out = append(out, jsonString(v))
	}
	return strings.Join(out, "\n") + "\n"
}

// containerLabels is what the launcher's docker inspect prints for a
// container: compose's project, working directory and files (empty
// strings when compose did not make it), then rw or ro for each of its
// mounts of the volume.
func containerLabels(project, wd, files, mounts string) string {
	return strings.Join([]string{jsonString(project), jsonString(wd), jsonString(files), mounts}, "\n") + "\n"
}

// dockerVolume makes the fake docker know the volume vol, with labels (its
// docker volume inspect output).
func (f *launcherFixture) dockerVolume(t *testing.T, vol, labels string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.fake, "volume-"+vol), []byte(labels), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dockerContainers makes the containers (id: docker inspect output) the
// ones that mount vol.
func (f *launcherFixture) dockerContainers(t *testing.T, vol string, cs map[string]string) {
	t.Helper()
	var ids []string
	for id, out := range cs {
		ids = append(ids, id)
		if err := os.WriteFile(filepath.Join(f.fake, "container-"+id), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(ids)
	if err := os.WriteFile(filepath.Join(f.fake, "ps-"+vol), []byte(strings.Join(ids, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mountOf is the read-only mount of lox run's socket volume of lock name
// in the workspace ws.
func mountOf(ws, name string) []string {
	return []string{"--mount", "type=volume,src=" + loxProject(ws) + "_" + name + "-run,dst=/run/locklog,readonly"}
}

// imageArgs is args from the image on: the image and its command line.
func imageArgs(args []string, image string) []string {
	for i, a := range args {
		if a == image && (i == 0 || args[i-1] != "--user") {
			return args[i:]
		}
	}
	return nil
}

// hasRun reports whether calls hold a docker run.
func hasRun(calls [][]string) bool {
	for _, c := range calls {
		if len(c) > 0 && c[0] == "run" {
			return true
		}
	}
	return false
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(interface{ ExitCode() int }); ok {
		return e.ExitCode()
	}
	return -1
}

// mcp runs as the agent account, with no network and no terminal, the
// project read-only and lox run's socket volume read-only on
// /run/locklog, from the workspace or any directory below it; never the
// fixed locklog-run. The command line the image gets is unchanged.
func TestLauncherMCP(t *testing.T) {
	f := newLauncherFixture(t)
	for _, dir := range []string{f.project, filepath.Join(f.project, "sub")} {
		out, calls, err := f.run(t, dir, nil, "mcp", "--profile", "staging")
		if err != nil {
			t.Fatalf("mcp from %s: %v\n%s", dir, err, out)
		}
		noEngineSocket(t, calls)
		run := lastRun(t, calls)
		confined(t, run)
		for _, seq := range [][]string{{"-i"}, {"--user", "agent"}, {"--network", "none"}, {"--log-driver", "none"},
			{"-e", "LOCKLOG_HOST_AGENT=1"}, mountOf(f.root, "logs"), {"-v", f.project + ":" + f.project + ":ro"},
			{"-w", dir}, {"locklog", "mcp", "--profile", "staging"}} {
			if !hasSeq(run, seq...) {
				t.Errorf("mcp run lacks %q: %q", seq, run)
			}
		}
		if slices := strings.Join(run, " "); strings.Contains(slices, "-it ") || strings.Contains(slices, "locklog-run") || strings.Contains(slices, "locklog-home") {
			t.Errorf("mcp has a terminal or a fixed volume: %q", run)
		}
	}
}

// The console (and its instance key) is lox run's: the launcher refuses
// it, saying what to do, and runs nothing.
func TestLauncherConsoleRefused(t *testing.T) {
	f := newLauncherFixture(t)
	for _, args := range [][]string{{"console"}, {"console", "--profile", "staging"}, {"hub-key", "--instance", "logs"}} {
		out, calls, err := f.run(t, f.project, nil, args...)
		if exitCode(err) != 2 || !strings.Contains(out, "is run by `lox run` only (lockhub)") || !strings.Contains(out, "lox add locklog") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
		if len(calls) != 0 {
			t.Errorf("%v: docker called: %q", args, calls)
		}
	}
}

// Without lox run's state, or with one the launcher cannot trust, mcp says
// why and what to do (run lox run first), exits 2 as a client that finds
// no console, and runs nothing: never the fixed volume instead.
func TestLauncherLockUpRefusals(t *testing.T) {
	upFile := func(f *launcherFixture) string { return filepath.Join(f.root, ".lockfamily", "up.json") }
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *launcherFixture)
		want  string
		args  []string
		// docker's own failures: nothing for lox run to fix
		noHint bool
	}{
		{"no up.json", func(t *testing.T, f *launcherFixture) {
			os.RemoveAll(filepath.Join(f.root, ".lockfamily"))
		}, "no .lockfamily/up.json in ", nil, false},
		{"up.json a link", func(t *testing.T, f *launcherFixture) {
			real := filepath.Join(f.root, "elsewhere.json")
			b, _ := os.ReadFile(upFile(f))
			os.WriteFile(real, b, 0o644)
			os.Remove(upFile(f))
			if err := os.Symlink(real, upFile(f)); err != nil {
				t.Fatal(err)
			}
		}, "up.json is not a regular file (a link?)", nil, false},
		{".lockfamily a link", func(t *testing.T, f *launcherFixture) {
			lf := filepath.Join(f.root, ".lockfamily")
			os.Rename(lf, filepath.Join(f.root, "lf-real"))
			if err := os.Symlink("lf-real", lf); err != nil {
				t.Fatal(err)
			}
		}, ".lockfamily is not a directory (a link?)", nil, false},
		{"up.json group-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(upFile(f), 0o664)
		}, "up.json is not yours, or others than you may write it", nil, false},
		{"up.json others-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(upFile(f), 0o646)
		}, "up.json is not yours, or others than you may write it", nil, false},
		{".lockfamily group-writable", func(t *testing.T, f *launcherFixture) {
			os.Chmod(filepath.Join(f.root, ".lockfamily"), 0o775)
		}, ".lockfamily is not yours, or others than you may write it", nil, false},
		{"up.json someone else's", func(t *testing.T, f *launcherFixture) {
			// id -u answers another uid: the files are not that user's.
			os.Remove(filepath.Join(f.bin, "id"))
			writeExec(t, filepath.Join(f.bin, "id"), "#!/bin/sh\n[ \"$1\" = -u ] && { echo 4242; exit 0; }\nexit 1\n")
		}, "is not yours, or others than you may write it", nil, false},
		{"larger than 1 MiB", func(t *testing.T, f *launcherFixture) {
			b, _ := os.ReadFile(upFile(f))
			f.writeUpFile(t, f.root, append(b, bytes.Repeat([]byte(" "), 1<<20)...))
		}, "is larger than 1 MiB", nil, false},
		{"another workspace's up.json", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			s.Workspace = f.project
			f.writeUpState(t, f.root, s)
		}, "not this workspace's", nil, false},
		{"another project", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			s.Project = "lockfamily-00000000"
			f.writeUpState(t, f.root, s)
		}, "not this workspace's", nil, false},
		{"not version 1", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			s.Version = 2
			f.writeUpState(t, f.root, s)
		}, "is not lox run's state (version 1)", nil, false},
		{"not lox run's layout", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			b, _ := json.Marshal(s)
			f.writeUpFile(t, f.root, b)
		}, "is not lox run's state (version 1)", nil, false},
		{"an escaped value", func(t *testing.T, f *launcherFixture) {
			b, _ := os.ReadFile(upFile(f))
			b = bytes.Replace(b, []byte(`"type": "locklog"`), []byte(`"type": "lock\u006cog"`), 1)
			f.writeUpFile(t, f.root, b)
		}, "is not lox run's state (version 1)", nil, false},
		{"no locklog lock", func(t *testing.T, f *launcherFixture) {
			os.RemoveAll(filepath.Join(f.root, ".lockfamily"))
			f.loxRun(t, f.root, map[string]string{"crm": "locksql"})
		}, "lox run runs no locklog lock in", nil, false},
		{"two locklog locks", func(t *testing.T, f *launcherFixture) {
			f.loxRun(t, f.root, map[string]string{"logs": "locklog", "app-logs": "locklog", "web": "lockhttp"})
		}, "lox run runs several locklog locks in ", nil, false},
		{"an unknown instance", func(t *testing.T, f *launcherFixture) {
			f.loxRun(t, f.root, map[string]string{"logs": "locklog", "app-logs": "locklog"})
		}, "lox run runs no locklog lock nope in", []string{"mcp", "--instance", "nope"}, false},
		{"an instance of another type", func(t *testing.T, f *launcherFixture) {
			f.loxRun(t, f.root, map[string]string{"logs": "locklog", "crm": "locksql"})
		}, "lox run runs no locklog lock crm in", []string{"mcp", "--instance=crm"}, false},
		{"a bad instance name", func(t *testing.T, f *launcherFixture) {}, "--instance: not an instance name", []string{"mcp", "--instance", "../x"}, false},
		{"another socket volume", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			l := s.Locks["logs"]
			l.Socket = s.Project + "_logs-home"
			s.Locks["logs"] = l
			f.writeUpState(t, f.root, s)
		}, "is not lox run's ", nil, false},
		{"another clients group", func(t *testing.T, f *launcherFixture) {
			s := f.loxRun(t, f.root, map[string]string{"logs": "locklog"})
			l := s.Locks["logs"]
			l.GID = "10000"
			s.Locks["logs"] = l
			f.writeUpState(t, f.root, s)
		}, "clients group 10000, this image's is 10050", nil, false},
		{"no volume", func(t *testing.T, f *launcherFixture) {
			os.Remove(filepath.Join(f.fake, "volume-"+loxProject(f.root)+"_logs-run"))
		}, "no volume ", nil, false},
		{"a volume without lox run's labels", func(t *testing.T, f *launcherFixture) {
			f.dockerVolume(t, loxProject(f.root)+"_logs-run", volumeLabels(loxProject(f.root), "logs", "locklog", f.project))
		}, "is not lox run's socket volume of it (its labels)", nil, false},
		{"a home volume", func(t *testing.T, f *launcherFixture) {
			l := strings.Replace(volumeLabels(loxProject(f.root), "logs", "locklog", f.root), `"socket"`, `"home"`, 1)
			f.dockerVolume(t, loxProject(f.root)+"_logs-run", l)
		}, "is not lox run's socket volume of it (its labels)", nil, false},
		{"a compose container run from elsewhere", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_logs-run", map[string]string{
				strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
				strings.Repeat("b", 64): containerLabels(p, f.root, f.root+"/compose.yaml", "rw "),
			})
		}, "which lox run did not start", nil, false},
		{"a compose container of another file", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_logs-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), f.root+"/compose.yaml", "rw ")})
		}, "which lox run did not start", nil, false},
		{"a container docker made read-write", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_logs-run", map[string]string{
				strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
				strings.Repeat("e", 64): containerLabels("", "", "", "ro rw "),
			})
		}, "is mounted read-write by container eeee", nil, false},
		{"a container with no mount by that name", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			f.dockerContainers(t, p+"_logs-run", map[string]string{strings.Repeat("e", 64): containerLabels("", "", "", "")})
		}, "is mounted read-write by container eeee", nil, false},
		{"a container docker cannot inspect", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			os.WriteFile(filepath.Join(f.fake, "ps-"+p+"_logs-run"), []byte(strings.Repeat("c", 64)+"\n"), 0o644)
		}, "cannot read the containers of", nil, true},
		{"a bad container id", func(t *testing.T, f *launcherFixture) {
			p := loxProject(f.root)
			os.WriteFile(filepath.Join(f.fake, "ps-"+p+"_logs-run"), []byte("*\n"), 0o644)
		}, "cannot read the containers of", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLauncherFixture(t)
			tc.setup(t, f)
			args := tc.args
			if args == nil {
				args = []string{"mcp"}
			}
			out, calls, err := f.run(t, f.project, nil, args...)
			if code := exitCode(err); code != 2 {
				t.Errorf("exit %d (%v), want 2\n%s", code, err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
			if !tc.noHint && !strings.Contains(out, "lox ") && !strings.Contains(out, "--instance") && !strings.Contains(out, "update locklog") {
				t.Errorf("output says nothing to do:\n%s", out)
			}
			if hasRun(calls) {
				t.Errorf("docker run: %q", calls)
			}
		})
	}
}

// Two locklog locks: the error names both; --instance picks one, and the
// launcher takes the option out of the command line.
func TestLauncherLockUpInstance(t *testing.T) {
	f := newLauncherFixture(t)
	f.loxRun(t, f.root, map[string]string{"logs": "locklog", "app-logs": "locklog", "web": "lockhttp"})
	out, _, err := f.run(t, f.project, nil, "mcp")
	if exitCode(err) != 2 || !strings.Contains(out, "(app-logs logs): name one with --instance NAME") {
		t.Errorf("%v\n%s", err, out)
	}
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"app-logs", []string{"mcp", "--instance", "app-logs"}, []string{"mcp"}},
		{"logs", []string{"mcp", "--instance=logs", "--profile", "p"}, []string{"mcp", "--profile", "p"}},
		{"logs", []string{"mcp", "--profile", "p", "--instance", "logs"}, []string{"mcp", "--profile", "p"}},
	} {
		out, calls, err := f.run(t, f.project, nil, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, out)
		}
		run := lastRun(t, calls)
		if !hasSeq(run, mountOf(f.root, tc.name)...) {
			t.Errorf("%v: %q", tc.args, run)
		}
		if got := imageArgs(run, "locklog")[1:]; strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%v: command %q, want %q", tc.args, got, tc.want)
		}
	}
	out, _, err = f.run(t, f.project, nil, "mcp", "--instance")
	if err == nil || !strings.Contains(out, "--instance: name the lock") {
		t.Errorf("%v\n%s", err, out)
	}
}

// lox run's own compose run, with the file on stdin or its state
// directory's compose.yaml, is trusted (XDG_STATE_HOME's state directory
// too); any other container only if it mounts the volume read-only.
func TestLauncherLockUpContainers(t *testing.T) {
	f := newLauncherFixture(t)
	p := loxProject(f.root)
	f.dockerContainers(t, p+"_logs-run", map[string]string{
		strings.Repeat("a", 64): containerLabels(p, f.stateDir(p), "-", "rw "),
		strings.Repeat("b", 64): containerLabels(p, f.stateDir(p), f.stateDir(p)+"/compose.yaml", "rw "),
		strings.Repeat("d", 64): containerLabels("", "", "", "ro "),
		strings.Repeat("e", 64): containerLabels(p, f.root, "-", "ro ro "),
	})
	if out, calls, err := f.run(t, f.project, nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "logs")...) {
		t.Errorf("%v\n%s", err, out)
	}
	state := filepath.Join(f.root, "xdg")
	if out, _, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state}, "mcp"); exitCode(err) != 2 || !strings.Contains(out, "which lox run did not start") {
		t.Errorf("XDG_STATE_HOME ignored: %v\n%s", err, out)
	}
	f.dockerContainers(t, p+"_logs-run", map[string]string{strings.Repeat("a", 64): containerLabels(p, state+"/lockfamily/"+p, "-", "rw ")})
	if out, calls, err := f.run(t, f.project, []string{"XDG_STATE_HOME=" + state + "/"}, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "logs")...) {
		t.Errorf("XDG_STATE_HOME: %v\n%s", err, out)
	}
	// No container at all (lox run stopped): the volume is still lox run's.
	f.dockerContainers(t, p+"_logs-run", nil)
	if out, calls, err := f.run(t, f.project, nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "logs")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// The nearest workspace up from here with up.json wins; a sub-project's
// .lockfamily without one is passed over.
func TestLauncherLockUpNearestWorkspace(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, ".lockfamily"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.root, "logs")...) {
		t.Errorf("%v\n%s", err, out)
	}
	f.loxRun(t, f.project, map[string]string{"app": "locklog"})
	if out, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "mcp"); err != nil || !hasSeq(lastRun(t, calls), mountOf(f.project, "app")...) {
		t.Errorf("%v\n%s", err, out)
	}
}

// doctor checks the account without lox run too: with no socket, saying
// why.
func TestLauncherDoctorWithoutLockUp(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.RemoveAll(filepath.Join(f.root, ".lockfamily")); err != nil {
		t.Fatal(err)
	}
	out, calls, err := f.run(t, f.project, nil, "doctor")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if run := strings.Join(lastRun(t, calls), " "); strings.Contains(run, "/run/locklog") {
		t.Errorf("a socket: %s", run)
	}
	if !strings.Contains(out, "no .lockfamily/up.json in "+f.project) || !strings.Contains(out, "lox run") {
		t.Errorf("output:\n%s", out)
	}
}
