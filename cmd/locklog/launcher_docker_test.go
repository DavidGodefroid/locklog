//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func cid(c byte) string { return strings.Repeat(string(c), 64) }

func hid(s string) string { return strings.Repeat(s, 64/len(s)) }

// dockerEnv is a host with containers: the stubbed engine's answers, a
// containers root you can stat, and a runtime directory for the map.
func dockerEnv(t *testing.T, f *launcherFixture) (env []string, root, xdg string) {
	t.Helper()
	dr := filepath.Join(f.root, "dockerroot")
	root = filepath.Join(dr, "containers")
	xdg = filepath.Join(f.root, "xdg")
	if err := os.MkdirAll(root, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(xdg, 0o700); err != nil {
		t.Fatal(err)
	}
	// The engine: `docker ps -q` ids (one listed twice), and one inspect
	// record per id: "<id> <label 0|1> <driver> <max-file|-> <compress|-> /<name>".
	ps := []string{cid('a'), cid('b'), cid('c'), cid('d'), cid('e'), cid('f'), "abc", strings.ToUpper(cid('9')),
		cid('7'), cid('8'), cid('6'), cid('1'), cid('2'), cid('3'), cid('4'), cid('5'), cid('0'), cid('0'),
		hid("ab"), hid("ac"), hid("ad"), hid("ae")}
	rec := map[byte]string{
		'a': "0 json-file 3 true /shop-a",
		'b': "0 local - - /shop-b",                                             // not json-file: skipped
		'c': "0 json-file - - /api-1",                                          // defaults
		'd': "0 json-file - - /other",                                          // no glob matches
		'e': "0 json-file - - /locklog-console-1",                              // console by name
		'f': "1 json-file - - /shop-labelled",                                  // console by label
		'7': "0 json-file 010 false /shop-010",                                 // leading zeros
		'8': "0 json-file 500 true /shop-big",                                  // clamped
		'6': "0 json-file 1 false /locklog-console-2",                          // console by name
		'1': "0 json-file - - /shop-evil\\nc " + cid('9') + " shop-forged 3 1", // a newline: two lines
		'2': "0 json-file 3 1 /shop-z - /shop-y",                               // a log option with spaces
		'3': "0 json-file - - /shop|x",                                         // not a container name
		'4': "0 json-file - - /shop d",                                         // a space in the name
		'5': "0 json-file - - /shop-five",                                      // claims another id (below)
		'0': "0 json-file - - /shop-dup",                                       // listed twice
	}
	env = []string{"PLAN=profile staging false\\ndocker shop-*\\ndocker api-1\\n", "DOCKER_ROOT_DIR=" + dr,
		"XDG_RUNTIME_DIR=" + xdg, "DOCKER_PS=" + strings.Join(ps, "\\n") + "\\n"}
	for h, r := range map[string]string{
		"ab": "0 json-file 3\\nc " + cid('9') + " shop-forged2 3 1 - /shop-nl", // a newline in a log option
		"ac": "0 json-file 3\\t1 - /shop-tab",                                  // a tab in a log option
		"ad": "0 json-file - - /shop-twin",                                     // one name, two ids
		"ae": "0 json-file - - /shop-twin",
	} {
		env = append(env, "I_"+hid(h)+"="+hid(h)+" "+r)
	}
	for c, r := range rec {
		id := cid(c)
		if c == '5' {
			env = append(env, "I_"+id+"="+cid('a')+" "+r)
			continue
		}
		env = append(env, "I_"+id+"="+id+" "+r)
	}
	return env, root, xdg
}

// wantMap is the map dockerEnv's engine gives (lines sorted).
var wantMap = []string{
	"c " + cid('7') + " shop-010 10 0",
	"c " + cid('8') + " shop-big 100 1",
	"c " + cid('a') + " shop-a 3 1",
	"c " + cid('c') + " api-1 1 0",
	"locklog-map 1",
	"x " + cid('0'),
	"x " + cid('1'),
	"x " + cid('2'),
	"x " + cid('3'),
	"x " + cid('4'),
	"x " + cid('5'),
	"x " + cid('6'),
	"x " + hid("ab"),
	"x " + hid("ac"),
	"x " + hid("ad"),
	"x " + hid("ae"),
	"x " + cid('e'),
	"x " + cid('f'),
}

// mapDir returns the one console map directory under base.
func mapDir(t *testing.T, base string) string {
	t.Helper()
	ds, _ := filepath.Glob(filepath.Join(base, "locklog-console-*"))
	if len(ds) != 1 {
		t.Fatalf("map directories under %s: %q", base, ds)
	}
	return ds[0]
}

// mapVersions returns the versions in a map directory and the newest's
// sorted lines, checking the modes.
func mapVersions(t *testing.T, dir string) ([]int, []string) {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("map dir %s: %v %v", dir, fi.Mode(), err)
	}
	ents, _ := os.ReadDir(dir)
	var vs []int
	for _, e := range ents {
		v, ok := strings.CutPrefix(e.Name(), "map.v")
		n, err := strconv.Atoi(v)
		if !ok || err != nil {
			t.Fatalf("stray file in the map dir: %s", e.Name())
		}
		if info, _ := e.Info(); info.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v", e.Name(), info.Mode())
		}
		vs = append(vs, n)
	}
	sort.Ints(vs)
	if len(vs) == 0 {
		t.Fatalf("no map in %s", dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "map.v"+strconv.Itoa(vs[len(vs)-1])))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "locklog-map 1\n") {
		t.Errorf("map header: %q", b)
	}
	ls := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	sort.Strings(ls)
	return vs, ls
}

func TestLauncherConsoleDocker(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, root, xdg := dockerEnv(t, f)
	base := filepath.Join(xdg, "locklog", "map")
	// The console exits once the loop rewrote the map on the event.
	env = append(env, "EVENTS_OUT=create\\n", "CONSOLE_WAIT="+filepath.Join(base, "*", "map.v2"), "CONSOLE_RC=3")
	start := time.Now().Unix()
	out, calls, err := f.run(t, f.project, env, "console")
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("console exit status not propagated: %v\n%s", err, out)
	}
	noEngineSocket(t, calls)
	run := lastRun(t, calls)
	confined(t, run)
	dir := mapDir(t, base)
	for _, seq := range [][]string{
		{"--label", "locklog.console=1"}, {"--group-add", "0"}, {"-e", "LOCKLOG_DOCKER_ROOT=" + root},
		{"--mount", "type=bind,src=" + root + ",dst=" + root + ",readonly,bind-recursive=disabled"},
		{"--mount", "type=bind,src=" + dir + ",dst=/run/locklog-map,readonly"},
		{"locklog", "console"},
	} {
		if !hasSeq(run, seq...) {
			t.Errorf("console run lacks %q:\n%q", seq, run)
		}
	}
	if !slices.ContainsFunc(run, func(a string) bool {
		return strings.HasPrefix(a, "LOCKLOG_EXPECT_ROOTS=") && strings.Contains(a, " "+root+";")
	}) {
		t.Errorf("the containers root's dev:inode is not passed: %q", run)
	}
	if !strings.Contains(out, "bind "+root+" (read-only, non-recursive; the Docker containers root, group 0 for it only)") ||
		!strings.Contains(out, "containers map "+dir+" at /run/locklog-map (read-only): 4 mapped, 13 console containers excluded, 8 skipped") {
		t.Errorf("plan text:\n%s", out)
	}
	// The map: approved globs only, console containers excluded by label and
	// by name (at listing or at inspect), non-json-file and bad ids skipped.
	vs, ls := mapVersions(t, dir)
	if !slices.Equal(vs, []int{1, 2}) || !slices.Equal(ls, wantMap) {
		t.Errorf("versions %v, map\n%s", vs, strings.Join(ls, "\n"))
	}
	if fi, err := os.Stat(base); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("map base %v %v", fi.Mode(), err)
	}
	// No record parsed from a hostile name, label or log option.
	for _, l := range ls {
		if strings.Contains(l, "forged") || strings.Contains(l, cid('9')) || strings.Contains(l, "shop-y") || strings.Contains(l, "shop-dup") ||
			strings.Contains(l, "shop-twin") || strings.Contains(l, "shop-tab") || strings.Contains(l, "shop-nl") {
			t.Errorf("injected entry: %q", l)
		}
	}
	// The events loop: subscribed from before the first snapshot, stopped
	// with the console.
	var ev []string
	for _, c := range calls {
		if len(c) > 0 && c[0] == "events" {
			ev = c
		}
	}
	if len(ev) < 3 || ev[1] != "--since" || !hasSeq(ev, "--filter", "type=container", "--filter", "event=create",
		"--filter", "event=rename", "--filter", "event=destroy", "--format", "{{.Action}}") {
		t.Fatalf("events call %q", ev)
	}
	if since, err := strconv.ParseInt(ev[2], 10, 64); err != nil || since < start-1 || since > time.Now().Unix() {
		t.Errorf("--since %s (start %d)", ev[2], start)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "events.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	gone := false
	for i := 0; i < 50 && !gone; i++ {
		gone = syscall.Kill(pid, 0) != nil
		if !gone {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !gone {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Error("docker events still runs after the console exited")
	}
}

func TestLauncherConsoleDockerRootNotChecked(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, _, _ := dockerEnv(t, f)
	env = append(env, "DOCKER_ROOT_DIR=/nonexistent/docker")
	out, calls, err := f.run(t, f.project, env, "console")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	run := lastRun(t, calls)
	r := "/nonexistent/docker/containers"
	if !hasSeq(run, "--mount", "type=bind,src="+r+",dst="+r+",readonly,bind-recursive=disabled") ||
		!strings.Contains(out, "owned by root: not checked from the host") {
		t.Errorf("run %q\n%s", run, out)
	}
	if slices.ContainsFunc(run, func(a string) bool { return strings.HasPrefix(a, "LOCKLOG_EXPECT_ROOTS=") && strings.Contains(a, r) }) {
		t.Errorf("an unchecked root in LOCKLOG_EXPECT_ROOTS: %q", run)
	}
}

// The non-recursive option follows the CLI, which parses it (#15).
func TestLauncherConsoleDockerCLIVersions(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, root, _ := dockerEnv(t, f)
	for _, tt := range []struct {
		client, engine, opt string
	}{
		{"29.7.2", "24.0.7", "bind-recursive=disabled"},
		{"25.0.0", "25.0.0", "bind-recursive=disabled"},
		{"24.0.7", "29.7.2", "bind-nonrecursive=true"},
		{"19.03.15", "20.10.24", "bind-nonrecursive=true"},
	} {
		out, calls, err := f.run(t, f.project, append(slices.Clone(env), "DOCKER_CLIENT_VERSION="+tt.client, "DOCKER_VERSION="+tt.engine), "console")
		if err != nil {
			t.Fatalf("%v: %v\n%s", tt, err, out)
		}
		if !hasSeq(lastRun(t, calls), "--mount", "type=bind,src="+root+",dst="+root+",readonly,"+tt.opt) {
			t.Errorf("CLI %s engine %s: %q", tt.client, tt.engine, lastRun(t, calls))
		}
	}
	for _, tt := range []struct{ client, engine, part string }{
		{"18.09.9", "24.0.7", "Docker CLI 18.09.9 is too old"},
		{"24.0.7", "19.02.0", "Docker engine 19.02.0 is too old"},
		{"x", "24.0.7", "unknown Docker CLI version"},
	} {
		out, calls, err := f.run(t, f.project, append(slices.Clone(env), "DOCKER_CLIENT_VERSION="+tt.client, "DOCKER_VERSION="+tt.engine), "console")
		if err == nil || !strings.Contains(out, tt.part) {
			t.Errorf("%v: %v\n%s", tt, err, out)
		}
		for _, c := range calls {
			if slices.Contains(c, "console") {
				t.Errorf("%v: the console started", tt)
			}
		}
	}
}

// Without a docker line: no gid 0, no root, no map, no loop, and the
// console replaces the launcher (exec).
func TestLauncherConsoleWithoutDocker(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{plan(f), "XDG_RUNTIME_DIR=" + t.TempDir()}, "console")
	if err != nil {
		t.Fatal(err)
	}
	run := lastRun(t, calls)
	if !hasSeq(run, "--label", "locklog.console=1") {
		t.Errorf("no console label: %q", run)
	}
	for i, a := range run {
		if (a == "--group-add" && run[i+1] == "0") || strings.Contains(a, "LOCKLOG_DOCKER_ROOT") || strings.Contains(a, "/run/locklog-map") {
			t.Errorf("docker arguments without a docker source: %q", run)
		}
	}
	for _, c := range calls {
		if len(c) > 0 && (c[0] == "events" || c[0] == "ps") {
			t.Errorf("engine queried for containers: %q", c)
		}
	}
}

func TestLauncherRefresh(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, _, xdg := dockerEnv(t, f)
	base := filepath.Join(xdg, "locklog", "map")
	for v := 1; v <= 3; v++ {
		out, calls, err := f.run(t, f.project, env, "refresh", "--profile", "staging")
		if err != nil {
			t.Fatalf("refresh: %v\n%s", err, out)
		}
		if !strings.Contains(out, "containers map v"+strconv.Itoa(v)+" of locklog-console-") ||
			!strings.Contains(out, ": 4 mapped, 13 console containers excluded, 8 skipped") {
			t.Errorf("refresh output:\n%s", out)
		}
		for _, c := range calls {
			if slices.Contains(c, "console") || (len(c) > 0 && c[0] == "events") {
				t.Errorf("refresh started a console or a loop: %q", c)
			}
			if slices.Contains(c, "mounts") && !hasSeq(c, "mounts", "--profile", "staging") {
				t.Errorf("plan call %q", c)
			}
		}
	}
	vs, ls := mapVersions(t, mapDir(t, base))
	if !slices.Equal(vs, []int{2, 3}) || !slices.Equal(ls, wantMap) {
		t.Errorf("versions %v (want the last two), map\n%s", vs, strings.Join(ls, "\n"))
	}
	// A temporary file a killed writer left is removed.
	if err := os.WriteFile(filepath.Join(mapDir(t, base), ".map.tmp.stale"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _, err := f.run(t, f.project, env, "refresh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if vs, _ := mapVersions(t, mapDir(t, base)); !slices.Equal(vs, []int{3, 4}) {
		t.Errorf("versions %v", vs)
	}
	// Without a runtime directory: under ~/.local/state.
	home := filepath.Join(f.root, "home")
	env2 := append(slices.Clone(env), "XDG_RUNTIME_DIR=", "HOME="+home)
	if out, _, err := f.run(t, f.project, env2, "refresh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if vs, _ := mapVersions(t, mapDir(t, filepath.Join(home, ".local", "state", "locklog", "map"))); !slices.Equal(vs, []int{1}) {
		t.Errorf("versions under HOME: %v", vs)
	}
	// No docker source: nothing to write.
	out, _, err := f.run(t, f.project, []string{plan(f), "XDG_RUNTIME_DIR=" + xdg}, "refresh")
	if err == nil || !strings.Contains(out, "no docker source") {
		t.Errorf("refresh without a docker source: %v\n%s", err, out)
	}
	// An engine that does not answer: the map is not rewritten.
	b, _ := os.ReadFile(filepath.Join(f.bin, "docker"))
	writeExec(t, filepath.Join(f.bin, "docker"), strings.Replace(string(b), "ps) printf '%b' \"${DOCKER_PS:-}\" ;;", "ps) exit 1 ;;", 1))
	out, _, err = f.run(t, f.project, env, "refresh")
	if err == nil || !strings.Contains(out, "could not write the containers map") {
		t.Errorf("failing docker ps: %v\n%s", err, out)
	}
	if vs, _ := mapVersions(t, mapDir(t, base)); !slices.Equal(vs, []int{3, 4}) {
		t.Errorf("versions after a failure: %v", vs)
	}
}

// docker events exiting is restarted, from when it exited, and the map is
// rewritten then.
func TestLauncherMapLoopRestarts(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, _, xdg := dockerEnv(t, f)
	base := filepath.Join(xdg, "locklog", "map")
	env = append(env, "EVENTS_EXIT=1", "CONSOLE_WAIT="+filepath.Join(base, "*", "map.v4"))
	out, calls, err := f.run(t, f.project, env, "console")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var since []int64
	for _, c := range calls {
		if len(c) > 2 && c[0] == "events" {
			n, _ := strconv.ParseInt(c[2], 10, 64)
			since = append(since, n)
		}
	}
	if len(since) < 2 || since[1] < since[0] {
		t.Errorf("events not restarted: --since %v", since)
	}
	if vs, _ := mapVersions(t, mapDir(t, base)); len(vs) != 2 || vs[1] < 4 {
		t.Errorf("versions %v", vs)
	}
}

// gid 0 applies to the whole console: a docker line beside a file or
// journald line is refused, before anything is bound or mapped.
func TestLauncherConsoleDockerAlone(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, _, xdg := dockerEnv(t, f)
	dir := filepath.Join(f.logs, "app")
	for _, p := range []string{
		"PLAN=profile staging false\\ndocker shop-*\\nfile " + dir + " " + dir + "/*.log\\n",
		"PLAN=profile staging false\\nfile " + dir + " " + dir + "/*.log\\ndocker shop-*\\n",
		"PLAN=profile staging false\\ndocker shop-*\\njournald\\n",
	} {
		out, calls, err := f.run(t, f.project, append(slices.Clone(env), p), "console")
		if err == nil || !strings.Contains(out, "cannot share a console with file or journald sources") {
			t.Errorf("%s: %v\n%s", p, err, out)
		}
		for _, c := range calls {
			if slices.Contains(c, "console") || (len(c) > 0 && (c[0] == "ps" || c[0] == "events")) {
				t.Errorf("%s: went on: %q", p, c)
			}
		}
	}
	if ds, _ := filepath.Glob(filepath.Join(xdg, "locklog", "map", "*", "map.v*")); len(ds) > 0 {
		t.Errorf("a map was written: %q", ds)
	}
}

// startConsole starts the launcher's console in the background (its output
// to a file, so that nothing waits on a pipe) and waits for docker events.
func startConsole(t *testing.T, f *launcherFixture, env []string) *exec.Cmd {
	t.Helper()
	_ = os.Remove(f.calls)
	out, err := os.Create(filepath.Join(f.root, "console.out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	cmd := exec.Command(filepath.Join(f.bin, "sh"), f.script, "console")
	cmd.Dir = f.project
	cmd.Env = append(slices.Clone(f.env), env...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(f.root, "events.pid")); err == nil {
			return cmd
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Kill()
	b, _ := os.ReadFile(filepath.Join(f.root, "console.out"))
	t.Fatalf("docker events never started:\n%s", b)
	return nil
}

// eventsGone waits for the stubbed docker events to be gone.
func eventsGone(t *testing.T, f *launcherFixture) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, "events.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Error("docker events still runs after the console is gone")
}

// The console replaces the launcher: a signal to the launcher's pid reaches
// the console; when that pid is gone, killed or not, the loop ends.
func TestLauncherConsoleSignals(t *testing.T) {
	consoleHost(t)
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newLauncherFixture(t)
			env, _, _ := dockerEnv(t, f)
			// The console stub waits for a file that never comes (10 s).
			cmd := startConsole(t, f, append(env, "CONSOLE_WAIT="+filepath.Join(f.root, "never")))
			start := time.Now()
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			cmd.Wait()
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("the console took %v to end", d)
			}
			_, err := os.Stat(filepath.Join(f.root, "console.term"))
			if sig == syscall.SIGTERM && err != nil {
				t.Error("TERM did not reach the console")
			}
			eventsGone(t, f)
		})
	}
}

// A burst of events costs one rewrite, not one per event.
func TestLauncherMapLoopCoalesces(t *testing.T) {
	consoleHost(t)
	f := newLauncherFixture(t)
	env, _, xdg := dockerEnv(t, f)
	base := filepath.Join(xdg, "locklog", "map")
	env = append(env, "EVENTS_OUT="+strings.Repeat("create\\n", 200), "CONSOLE_WAIT="+filepath.Join(base, "*", "map.v2"), "CONSOLE_AFTER=2")
	if out, _, err := f.run(t, f.project, env, "console"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if vs, _ := mapVersions(t, mapDir(t, base)); vs[len(vs)-1] > 3 {
		t.Errorf("200 events gave versions %v", vs)
	}
}
