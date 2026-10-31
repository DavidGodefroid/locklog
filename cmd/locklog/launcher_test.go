//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// launcherFixture runs scripts/locklog, the host launcher, with a fake
// docker that records each call, one argument per line, a call ending
// with "--". PATH holds only the tools the launcher needs.
type launcherFixture struct {
	root, bin, project, logs, calls, script string
	env                                      []string
}

var launcherTools = []string{"sh", "dirname", "mkdir", "id", "cat", "printf", "awk", "sha256sum", "shasum", "tar",
	"gzip", "install", "mktemp", "rm", "uname", "sed", "tr", "tail", "grep", "stat", "cksum", "getconf", "nproc", "cut"}

func newLauncherFixture(t *testing.T) *launcherFixture {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &launcherFixture{
		root:    root,
		bin:     filepath.Join(root, "bin"),
		project: filepath.Join(root, "project"),
		logs:    filepath.Join(root, "logs"),
		calls:   filepath.Join(root, "calls"),
	}
	for _, d := range []string{f.bin, filepath.Join(f.project, ".locklog"), filepath.Join(f.project, "sub"), filepath.Join(f.logs, "app")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.logs, "app", "app.log"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tool := range launcherTools {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeExec(t, filepath.Join(f.bin, "docker"), `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done >> '`+f.calls+`'
echo -- >> '`+f.calls+`'
case "$1" in
version) printf '%s\n' "${DOCKER_VERSION:-27.3.1}" ;;
info) printf '%s\n' "${DOCKER_INFO:-[name=seccomp,profile=builtin]}" ;;
volume) [ "$2" = inspect ] && exit "${VOLUME_MISSING:-0}" ;;
run)
	for a in "$@"; do
		case "$a" in
		locklog-run:/run/locklog) vol=run ;;
		locklog-home:/home/locklog) vol=home ;;
		esac
	done
	for a in "$@"; do
		case "$a" in
		stat)
			[ "$vol" = run ] && printf '%s\n' "${RUN_OWNER:-10051:10050:2750}"
			[ "$vol" = home ] && printf '%s\n' "${HOME_OWNER:-10051:10051:700}"
			exit 0 ;;
		mounts) printf '%b' "${PLAN:-profile staging false\n}"; exit "${PLAN_RC:-0}" ;;
		version) echo "locklog 9.9.9"; exit 0 ;;
		esac
	done ;;
esac
exit 0
`)
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "locklog"))
	if err != nil {
		t.Fatal(err)
	}
	f.script = filepath.Join(root, "locklog")
	writeExec(t, f.script, string(launcher))
	f.env = []string{"PATH=" + f.bin, "HOME=" + filepath.Join(root, "home"), "LOCKLOG_EXTRA_ROOTS=" + f.logs}
	return f
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// run runs the launcher with args from dir, and returns its output and the
// docker calls, each a list of arguments.
func (f *launcherFixture) run(t *testing.T, dir string, env []string, args ...string) (string, [][]string, error) {
	t.Helper()
	_ = os.Remove(f.calls)
	cmd := exec.Command(filepath.Join(f.bin, "sh"), append([]string{f.script}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, f.env...), env...)
	out, err := cmd.CombinedOutput()
	var calls [][]string
	b, _ := os.ReadFile(f.calls)
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "--" {
			calls = append(calls, cur)
			cur = nil
		} else if l != "" {
			cur = append(cur, l)
		}
	}
	return string(out), calls, err
}

// lastRun is the last `docker run` call.
func lastRun(t *testing.T, calls [][]string) []string {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if len(calls[i]) > 0 && calls[i][0] == "run" {
			return calls[i]
		}
	}
	t.Fatalf("no docker run in %q", calls)
	return nil
}

// hasSeq reports whether args hold seq, in order and adjacent.
func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

// noEngineSocket: no call mounts or names a Docker or Podman socket (LL1).
func noEngineSocket(t *testing.T, calls [][]string) {
	t.Helper()
	for _, c := range calls {
		for _, a := range c {
			if strings.Contains(a, "docker.sock") || strings.Contains(a, "podman.sock") || strings.Contains(a, "DOCKER_HOST") {
				t.Errorf("a call names an engine socket: %q", c)
			}
		}
	}
}

func confined(t *testing.T, run []string) {
	t.Helper()
	for _, seq := range [][]string{{"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"}, {"--read-only"}, {"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("run lacks %q: %q", seq, run)
		}
	}
}

const filePlan = "profile staging false\\nfile %s/app %s/app/*.log\\n"

func plan(f *launcherFixture) string {
	return "PLAN=" + strings.ReplaceAll(filePlan, "%s", f.logs)
}

func TestLauncherConsole(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, filepath.Join(f.project, "sub"), []string{plan(f)}, "console", "--profile", "staging", "--allowed-uids", "1000")
	if err != nil {
		t.Fatalf("console: %v\n%s", err, out)
	}
	noEngineSocket(t, calls)
	// The mount plan is read in the image, as the agent, without network,
	// with only .locklog/ (read-only).
	var planCall []string
	for _, c := range calls {
		if slices.Contains(c, "mounts") {
			planCall = c
		}
	}
	ll := filepath.Join(f.project, ".locklog")
	if planCall == nil || !hasSeq(planCall, "--user", "agent") || !hasSeq(planCall, "--network", "none") ||
		!hasSeq(planCall, "-v", ll+":"+ll+":ro") || !hasSeq(planCall, "locklog", "mounts", "--profile", "staging", "--allowed-uids", "1000") {
		t.Errorf("mount plan call = %q", planCall)
	}
	run := lastRun(t, calls)
	confined(t, run)
	dir := filepath.Join(f.logs, "app")
	for _, seq := range [][]string{
		{"--user", "locklog"}, {"--log-driver", "none"}, {"--pids-limit", "256"}, {"--memory", "1g"}, {"--network", "none"},
		{"-v", "locklog-run:/run/locklog"}, {"-v", "locklog-home:/home/locklog"}, {"-v", ll + ":" + ll + ":ro"},
		{"--mount", "type=bind,src=" + dir + ",dst=" + dir + ",readonly,bind-recursive=disabled"},
		{"-w", f.project}, {"locklog", "console", "--profile", "staging", "--allowed-uids", "1000"},
	} {
		if !hasSeq(run, seq...) {
			t.Errorf("console run lacks %q:\n%q", seq, run)
		}
	}
	i := slices.Index(run, "--cpus")
	if i < 0 || (run[i+1] != "1" && run[i+1] != "2") {
		t.Errorf("--cpus min(2, nproc): %q", run)
	}
	if !slices.ContainsFunc(run, func(a string) bool {
		return strings.HasPrefix(a, "LOCKLOG_EXPECT_ROOTS=") && strings.HasSuffix(a, " "+dir+";") && strings.Count(a, ":") == 1
	}) {
		t.Errorf("no LOCKLOG_EXPECT_ROOTS dev:inode for %s: %q", dir, run)
	}
	if !slices.ContainsFunc(run, func(a string) bool { return strings.HasPrefix(a, "LOCKLOG_EXPECT_DIR=") }) {
		t.Errorf("no LOCKLOG_EXPECT_DIR: %q", run)
	}
	if !strings.HasPrefix(run[slices.Index(run, "--name")+1], "locklog-console-") {
		t.Errorf("console name: %q", run)
	}
	// The plan is printed before docker run.
	if !strings.Contains(out, "bind "+dir+" (read-only, non-recursive)") || !strings.Contains(out, "network none") {
		t.Errorf("plan not printed:\n%s", out)
	}
	// The run volume is checked for its owner before the console starts.
	checked := false
	for _, c := range calls {
		if hasSeq(c, "-v", "locklog-run:/run/locklog") && slices.Contains(c, "stat") && hasSeq(c, "--network", "none") {
			checked = true
		}
	}
	if !checked {
		t.Error("the locklog-run owner was not checked")
	}
}

func TestLauncherConsoleEngines(t *testing.T) {
	f := newLauncherFixture(t)
	dir := filepath.Join(f.logs, "app")
	_, calls, err := f.run(t, f.project, []string{plan(f), "DOCKER_VERSION=24.0.7"}, "console")
	if err != nil {
		t.Fatal(err)
	}
	if !hasSeq(lastRun(t, calls), "--mount", "type=bind,src="+dir+",dst="+dir+",readonly,bind-nonrecursive=true") {
		t.Errorf("Docker 24 mount: %q", lastRun(t, calls))
	}
	for _, tt := range []struct {
		env  []string
		part string
	}{
		{[]string{"DOCKER_VERSION=18.09.1"}, "too old"},
		{[]string{"DOCKER_VERSION=19.02.0"}, "too old"},
		{[]string{"DOCKER_VERSION=weird"}, "unknown Docker engine version"},
		{[]string{"DOCKER_INFO=[name=seccomp name=rootless]"}, "rootless Docker is not supported"},
	} {
		out, _, err := f.run(t, f.project, append([]string{plan(f)}, tt.env...), "console")
		if err == nil || !strings.Contains(out, tt.part) {
			t.Errorf("%v: err %v, out %s", tt.env, err, out)
		}
	}
}

func TestLauncherConsoleRefusals(t *testing.T) {
	f := newLauncherFixture(t)
	if err := os.Symlink(filepath.Join(f.logs, "app"), filepath.Join(f.logs, "link")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	for _, tt := range []struct {
		env  []string
		part string
	}{
		{[]string{"PLAN=profile staging false\\nfile " + outside + " " + outside + "/a.log\\n"}, "not under an allowed log root"},
		{[]string{"PLAN=profile staging false\\nfile " + f.logs + "/link " + f.logs + "/link/a.log\\n"}, "no symbolic link"},
		{[]string{"PLAN=profile staging false\\nfile / /a.log\\n"}, "/ cannot be bound"},
		{[]string{"PLAN=profile staging false\\nfile " + f.logs + "/app /etc/shadow\\n"}, "is not under"},
		{[]string{"PLAN=profile staging false\\nfile " + f.logs + "/a,b " + f.logs + "/a,b/x\\n"}, "cannot carry"},
		{[]string{"PLAN=profile staging false\\nfile " + f.logs + "/app\\n"}, "malformed line"},
		{[]string{"PLAN=profile staging false\\ndocker x\\n"}, "unknown line"},
		{[]string{"PLAN=nonsense\\n"}, "malformed header"},
		{[]string{"PLAN_RC=1"}, "could not read the mount plan"},
		{[]string{plan(f), "RUN_OWNER=1000:1000:777"}, "not created by locklog"},
		{[]string{plan(f), "HOME_OWNER=10051:10051:755"}, "not created by locklog"},
		{[]string{plan(f), "LOCKLOG_NETWORK=host"}, "not host"},
		{[]string{plan(f), "LOCKLOG_NETWORK=a b"}, "invalid network name"},
		{[]string{plan(f), "LOCKLOG_EXTRA_ROOTS=/"}, "/ cannot be a log root"},
		{[]string{plan(f), "LOCKLOG_EXTRA_ROOTS=rel"}, "not an absolute path"},
		{[]string{plan(f), "LOCKLOG_EXTRA_ROOTS=" + f.logs + "/link"}, "no symbolic link"},
	} {
		out, calls, err := f.run(t, f.project, tt.env, "console")
		if err == nil || !strings.Contains(out, tt.part) {
			t.Errorf("%v: err %v, want %q in:\n%s", tt.env, err, tt.part, out)
			continue
		}
		for _, c := range calls {
			if slices.Contains(c, "console") {
				t.Errorf("%v: the console started anyway: %q", tt.env, c)
			}
		}
	}
	// No .locklog/: setup first.
	empty := t.TempDir()
	out, _, err := f.run(t, empty, nil, "console")
	if err == nil || !strings.Contains(out, "run locklog setup first") {
		t.Errorf("no .locklog: %v %s", err, out)
	}
}

func TestLauncherConsoleNetwork(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, []string{plan(f), "LOCKLOG_NETWORK=shop_default"}, "console")
	if err != nil {
		t.Fatal(err)
	}
	run := lastRun(t, calls)
	if !hasSeq(run, "--network", "shop_default") || !hasSeq(run, "-e", "LOCKLOG_NETWORK=shop_default") {
		t.Errorf("network: %q", run)
	}
}

func TestLauncherConsoleJournald(t *testing.T) {
	journals := []string{}
	for _, j := range []string{"/var/log/journal", "/run/log/journal"} {
		if fi, err := os.Lstat(j); err == nil && fi.IsDir() {
			journals = append(journals, j)
		}
	}
	f := newLauncherFixture(t)
	dir := filepath.Join(f.logs, "app")
	out, calls, err := f.run(t, f.project, []string{"PLAN=profile staging false\\nfile " + dir + " " + dir + "/*.log\\njournald\\n"}, "console")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	run := lastRun(t, calls)
	if !hasSeq(run, "--mount", "type=bind,src="+dir+",dst="+dir+",readonly,bind-recursive=disabled") {
		t.Errorf("file dir not bound with the journal: %q", run)
	}
	for _, j := range journals {
		if !hasSeq(run, "--mount", "type=bind,src="+j+",dst="+j+",readonly,bind-recursive=disabled") {
			t.Errorf("journal %s not bound: %q", j, run)
		}
	}
	if len(journals) == 0 && !strings.Contains(out, "no journal directory") {
		t.Errorf("no warning without a journal:\n%s", out)
	}
	// Only allowlisted groups are ever added.
	for i, a := range run {
		if a == "--group-add" {
			if run[i+1] == "0" {
				t.Errorf("gid 0 added: %q", run)
			}
		}
	}
}

func TestLauncherMCP(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	noEngineSocket(t, calls)
	run := lastRun(t, calls)
	confined(t, run)
	for _, seq := range [][]string{{"-i"}, {"--user", "agent"}, {"--network", "none"}, {"--log-driver", "none"},
		{"-e", "LOCKLOG_HOST_AGENT=1"}, {"-v", "locklog-run:/run/locklog"}, {"-v", f.project + ":" + f.project + ":ro"},
		{"-w", filepath.Join(f.project, "sub")}, {"locklog", "mcp"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("mcp run lacks %q: %q", seq, run)
		}
	}
	if slices.Contains(run, "-it") || slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "locklog-home") }) {
		t.Errorf("mcp has a terminal or the home volume: %q", run)
	}
}

func TestLauncherVersionAndDefault(t *testing.T) {
	f := newLauncherFixture(t)
	out, calls, err := f.run(t, f.project, nil, "version")
	if err != nil || !strings.Contains(out, "locklog launcher dev (image locklog)") || !strings.Contains(out, "locklog 9.9.9") {
		t.Fatalf("version: %v\n%s", err, out)
	}
	if run := lastRun(t, calls); !hasSeq(run, "--user", "agent") || !hasSeq(run, "--network", "none") {
		t.Errorf("version run: %q", run)
	}
	out, _, err = f.run(t, f.project, []string{"LOCKLOG_IMAGE=example/locklog:x"}, "version")
	if err != nil || !strings.Contains(out, "(image example/locklog:x)") {
		t.Errorf("LOCKLOG_IMAGE: %v %s", err, out)
	}
	_, calls, err = f.run(t, f.project, nil, "status")
	if err != nil {
		t.Fatal(err)
	}
	run := lastRun(t, calls)
	confined(t, run)
	if !hasSeq(run, "--user", "agent") || !hasSeq(run, "locklog", "status") || slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "locklog-home") }) {
		t.Errorf("default run: %q", run)
	}
}

func TestLauncherReleaseImage(t *testing.T) {
	f := newLauncherFixture(t)
	b, _ := os.ReadFile(f.script)
	s := strings.Replace(string(b), "\nlauncher_version=dev\n", "\nlauncher_version=1.2.3\n", 1)
	digest := "sha256:" + strings.Repeat("a", 64)
	vdigest := "sha256:" + strings.Repeat("b", 64)
	s = strings.Replace(s, "\nimage_digest=\n", "\nimage_digest="+digest+"\n", 1)
	s = strings.Replace(s, "\nvault_image_digest=\n", "\nvault_image_digest="+vdigest+"\n", 1)
	writeExec(t, f.script, s)
	for _, tt := range []struct {
		env  []string
		want string
	}{
		{nil, "ghcr.io/davidgodefroid/locklog@" + digest},
		{[]string{"LOCKLOG_VAULT=1"}, "ghcr.io/davidgodefroid/locklog@" + vdigest},
	} {
		out, _, err := f.run(t, f.project, tt.env, "version")
		if err != nil || !strings.Contains(out, "(image "+tt.want+")") {
			t.Errorf("%v: %v %s", tt.env, err, out)
		}
	}
}
