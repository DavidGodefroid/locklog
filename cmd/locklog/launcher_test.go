//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

// launcherFixture runs scripts/locklog, the host launcher, with a fake
// docker that records each call, one argument per line, a call ending
// with "--". PATH holds only the tools the launcher needs.
type launcherFixture struct {
	root, bin, fake, project, logs, calls, script string
	// managed and managedMac are the launcher's managed directories (the
	// host's /etc/lockfamily, and /Library/Application Support/lockfamily
	// on macOS): the fixture's, absent until a test makes them.
	managed, managedMac string
	env                 []string
}

var launcherTools = []string{"sh", "dirname", "mkdir", "id", "cat", "printf", "awk", "sha256sum", "shasum", "tar",
	"gzip", "install", "mktemp", "rm", "uname", "sed", "tr", "tail", "grep", "stat", "cksum", "getconf", "nproc", "cut", "ls",
	"mv", "chmod", "date", "sleep", "find", "rmdir", "cp", "pwd", "wc", "sort", "getent"}

func newLauncherFixture(t *testing.T) *launcherFixture {
	t.Helper()
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &launcherFixture{
		root:    root,
		bin:     filepath.Join(root, "bin"),
		fake:    filepath.Join(root, "fake"),
		project: filepath.Join(root, "project"),
		logs:    filepath.Join(root, "logs"),
		calls:   filepath.Join(root, "calls"),
	}
	for _, d := range []string{f.bin, f.fake, filepath.Join(f.project, ".locklog"), filepath.Join(f.project, "sub"), filepath.Join(f.logs, "app")} {
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
	// The fake docker: lox run's volumes and the containers that mount
	// them are files in f.fake (launcher_lockup_test.go).
	writeExec(t, filepath.Join(f.bin, "docker"), `#!/bin/sh
rec=
for a in "$@"; do rec="$rec$a
"; done
printf '%s--\n' "$rec" >> '`+f.calls+`'
case "$1 $2" in
"volume inspect") eval "v=\${$#}"; cat '`+f.fake+`'/"volume-$v" 2>/dev/null || exit 1; exit 0 ;;
"ps "*) for a in "$@"; do case "$a" in volume=*) cat '`+f.fake+`'/"ps-${a#volume=}" 2>/dev/null ;; esac; done; printf '%b' "${DOCKER_PS:-}"; exit 0 ;;
"inspect --type")
	eval "c=\${$#}"
	[ -f '`+f.fake+`'/"container-$c" ] && { cat '`+f.fake+`'/"container-$c"; exit 0; }
	eval "rec=\${I_$c:-}"
	[ -n "$rec" ] || exit 1
	printf '%b\n' "$rec"; exit 0 ;;
esac
case "$1" in
version) printf '%s\n' "${DOCKER_VERSION:-27.3.1}" ;;
info) printf '%s\n' "${DOCKER_INFO:-[name=seccomp,profile=builtin]}" ;;
run)
	for a in "$@"; do
		case "$a" in
		*:/run/locklog-facts:ro) cp "${a%%:*}" '`+filepath.Join(root, "facts.copy")+`'; ls -l "${a%%:*}" | cut -c1-10 > '`+filepath.Join(root, "facts.mode")+`' ;;
		doctor) cat > '`+filepath.Join(root, "facts.stdin")+`' ;;
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
	// The machine's managed directories: the fixture's, never the host's.
	f.managed = filepath.Join(root, "managed dir", "lockfamily")
	f.managedMac = filepath.Join(root, "Application Support", "lockfamily")
	s := string(launcher)
	for line, dir := range map[string]string{
		`Darwin) managed_dir="/Library/Application Support/lockfamily" ;;`: f.managedMac,
		`*) managed_dir=/etc/lockfamily ;;`:                                f.managed,
	} {
		if !strings.Contains(s, line) {
			t.Fatalf("launcher lacks %q", line)
		}
		s = strings.Replace(s, line, line[:strings.Index(line, "managed_dir=")]+`managed_dir="`+dir+`" ;;`, 1)
	}
	writeExec(t, f.script, s)
	f.env = []string{"PATH=" + f.bin, "HOME=" + filepath.Join(root, "home"), "LOCKLOG_EXTRA_ROOTS=" + f.logs}
	// The workspace is root: lox run runs its locklog lock "logs".
	f.loxRun(t, root, map[string]string{"logs": "locklog"})
	return f
}

// fakeUname makes uname -s print sysname, so the launcher picks that OS's
// managed directory whatever the host (the macOS runner prints Darwin);
// every other uname call is the real one.
func (f *launcherFixture) fakeUname(t *testing.T, sysname string) {
	t.Helper()
	real, err := exec.LookPath("uname")
	if err != nil {
		t.Skip("no uname")
	}
	uname := filepath.Join(f.bin, "uname")
	if err := os.Remove(uname); err != nil {
		t.Fatal(err)
	}
	writeExec(t, uname, `#!/bin/sh
case "$1" in -s) echo `+sysname+` ;; *) exec '`+real+`' "$@" ;; esac
`)
}

// allGroupsNamed reports whether getent names every gid of this account.
func allGroupsNamed() bool {
	out, err := exec.Command("id", "-G").Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if exec.Command("getent", "group", g).Run() != nil {
			return false
		}
	}
	return true
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

// profile add runs in the image as you, with the project writable, the
// facts of this host and the proxies' directory (0700, outside the
// project); no network. --project DIR is that project, passed on as an
// absolute path. doctor runs as the agent account with the host's
// network, the project read-only and lox run's socket volume read-only;
// doctor --fix as you, with the project writable. init as you.
func TestLauncherProfileDoctorInit(t *testing.T) {
	f := newLauncherFixture(t)
	writeExec(t, filepath.Join(f.bin, "claude"), "#!/bin/sh\n")
	// A directory whose name holds a newline (#87): with NUL-delimited
	// facts its file cannot read as another path ("/a.log").
	nl := filepath.Join(f.logs, "x\n")
	if err := os.Mkdir(nl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nl, "a.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, calls, err := f.run(t, f.project, []string{"DOCKER_PS=web nginx:1 web shop shop_default\\n"}, "profile", "add", "--non-interactive", "--json")
	if err != nil {
		t.Fatal(err)
	}
	noEngineSocket(t, calls)
	run := lastRun(t, calls)
	confined(t, run)
	me := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	proxy := filepath.Join(f.root, "home", ".config", "locklog", "proxy")
	for _, seq := range [][]string{{"--user", me}, {"--network", "none"}, {"--log-driver", "none"}, {"-v", f.project + ":" + f.project},
		{"-v", proxy + ":" + proxy}, {"-w", f.project},
		{"locklog", "profile", "add", "--facts", "/run/locklog-facts", "--proxy-dir", proxy, "--non-interactive", "--json"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("profile add run lacks %q: %q", seq, run)
		}
	}
	if slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "-run") || strings.Contains(a, "-home") }) {
		t.Errorf("profile add has a console volume: %q", run)
	}
	if st, err := os.Stat(proxy); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("proxy dir: %v %v", st, err)
	}
	facts, err := os.ReadFile(filepath.Join(f.root, "facts.copy"))
	if err != nil {
		t.Fatal(err)
	}
	if mode, _ := os.ReadFile(filepath.Join(f.root, "facts.mode")); strings.TrimSpace(string(mode)) != "-rw-------" {
		t.Errorf("the facts file has mode %q, want -rw------- (0600)", mode)
	}
	if !hasSeq(run, "-e", "LOCKLOG_HOST_HOME=") {
		t.Errorf("profile add run lacks LOCKLOG_HOST_HOME: %q", run)
	}
	fs, err := hostfacts.Parse(strings.NewReader(string(facts)))
	if err != nil {
		t.Fatalf("facts: %v\n%s", err, facts)
	}
	if fs.EUID != os.Geteuid() || fs.Sudo != hostfacts.SudoAbsent || fs.Docker != hostfacts.DockerReachable ||
		!slices.Contains(fs.Agents, "claude") || len(fs.Containers) != 1 || fs.Containers[0].Project != "shop" ||
		!slices.Contains(fs.Logs, filepath.Join(f.logs, "app", "app.log")) {
		t.Errorf("facts = %+v\n%s", fs, facts)
	}
	if !strings.Contains(string(facts), "\nlogs0\n") || slices.Contains(fs.Logs, "/a.log") || slices.ContainsFunc(fs.Logs, func(p string) bool { return strings.Contains(p, "\n") }) {
		t.Errorf("log paths not NUL-delimited, or a forged one: %q", fs.Logs)
	}
	// The gids, and their whole names where getent has them.
	if !strings.Contains(string(facts), "\ngids ") || len(fs.Groups) == 0 {
		t.Errorf("groups: %q\n%s", fs.Groups, facts)
	}
	if allGroupsNamed() && fs.GroupsAmbiguous {
		t.Errorf("groups ambiguous although getent names every gid: %q\n%s", fs.Groups, facts)
	}

	// --project DIR: that project, absolute.
	other := filepath.Join(f.root, "other")
	if err := os.MkdirAll(filepath.Join(other, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--project", "../other"}, {"--project=../other"}} {
		_, calls, err := f.run(t, f.project, nil, append([]string{"profile", "add", "--non-interactive"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		r := lastRun(t, calls)
		if !hasSeq(r, "-v", other+":"+other) || !hasSeq(r, "-w", other) || !hasSeq(r, "--non-interactive", "--project="+other) {
			t.Errorf("%v: %q", args, r)
		}
	}
	for _, args := range [][]string{{"--project", filepath.Join(f.root, "missing")}, {"--project"}, {"--project="}} {
		out, calls, err := f.run(t, f.project, nil, append([]string{"profile", "add"}, args...)...)
		if err == nil || !strings.Contains(out, "--project") || hasRun(calls) {
			t.Errorf("%v: %v\n%s\n%q", args, err, out, calls)
		}
	}

	// An untrusted .locklog/ after the run fails profile add.
	if err := os.Chmod(filepath.Join(f.project, ".locklog"), 0o777); err != nil {
		t.Fatal(err)
	}
	if out, _, err := f.run(t, f.project, nil, "profile", "add", "--non-interactive"); err == nil || !strings.Contains(out, "fix it before lox run") {
		t.Errorf("untrusted .locklog accepted: %v\n%s", err, out)
	}
	os.Chmod(filepath.Join(f.project, ".locklog"), 0o755)

	// init and doctor --fix: as you, the project writable.
	for _, args := range [][]string{{"init", "claude"}, {"doctor", "--fix", "--yes", "--json"}} {
		_, calls, err := f.run(t, filepath.Join(f.project, "sub"), nil, args...)
		if err != nil {
			t.Fatal(err)
		}
		r := lastRun(t, calls)
		if !hasSeq(r, "--user", me) || !hasSeq(r, "-v", f.project+":"+f.project) || !hasSeq(r, "-w", filepath.Join(f.project, "sub")) ||
			!hasSeq(r, append([]string{"locklog"}, args[0])...) {
			t.Errorf("%v: %q", args, r)
		}
		if args[0] == "doctor" && (!hasSeq(r, "--facts", "/run/locklog-facts", "--fix", "--yes", "--json") || !hasSeq(r, mountOf(f.root, "logs")...)) {
			t.Errorf("doctor --fix: %q", r)
		}
	}

	_, calls, err = f.run(t, filepath.Join(f.project, "sub"), nil, "doctor", "--profile", "x")
	if err != nil {
		t.Fatal(err)
	}
	run = lastRun(t, calls)
	confined(t, run)
	for _, seq := range [][]string{{"--user", "agent"}, {"--network", "host"}, {"-v", f.project + ":" + f.project + ":ro"},
		{"-w", filepath.Join(f.project, "sub")}, {"locklog", "doctor", "--facts", "-", "--profile", "x"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("doctor run lacks %q: %q", seq, run)
		}
	}
	// lox run's socket volume, read-only; no facts mount, no fixed volume.
	if !hasSeq(run, mountOf(f.root, "logs")...) {
		t.Errorf("doctor lacks lox run's socket volume: %q", run)
	}
	if slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "locklog-run") || strings.Contains(a, "locklog-facts") }) {
		t.Errorf("doctor has the fixed socket volume or a facts mount: %q", run)
	}
	// The facts reach the agent account on its input, not in a file.
	if in, err := os.ReadFile(filepath.Join(f.root, "facts.stdin")); err != nil || !strings.HasPrefix(string(in), hostfacts.Header+"\n") {
		t.Errorf("doctor's input: %q %v", in, err)
	}
}

// profile rules runs as the agent account with the project read-only, no
// network and no volume: it reads the project's config file only.
func TestLauncherProfileRules(t *testing.T) {
	f := newLauncherFixture(t)
	_, calls, err := f.run(t, f.project, nil, "profile", "rules", "--json")
	if err != nil {
		t.Fatal(err)
	}
	noEngineSocket(t, calls)
	run := lastRun(t, calls)
	confined(t, run)
	for _, seq := range [][]string{{"--user", "agent"}, {"--network", "none"}, {"--log-driver", "none"},
		{"-v", f.project + ":" + f.project + ":ro"}, {"-w", f.project}, {"locklog", "profile", "rules", "--json"}} {
		if !hasSeq(run, seq...) {
			t.Errorf("profile rules run lacks %q: %q", seq, run)
		}
	}
	if slices.ContainsFunc(run, func(a string) bool { return strings.Contains(a, "-run") || strings.Contains(a, "-home") }) {
		t.Errorf("profile rules has a console volume: %q", run)
	}
}

// The home directory is never a project: profile add refuses it, and the walk
// from below it ignores a ~/.locklog/.
func TestLauncherHomeIsNoProject(t *testing.T) {
	f := newLauncherFixture(t)
	home := filepath.Join(f.root, "home")
	sub := filepath.Join(home, "work")
	for _, d := range []string{filepath.Join(home, ".locklog"), sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(home, 0o755)
	out, _, err := f.run(t, home, nil, "profile", "add", "--non-interactive")
	if err == nil || !strings.Contains(out, "not in your home directory") {
		t.Errorf("profile add in home: %v\n%s", err, out)
	}
	out, calls, err := f.run(t, sub, nil, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ignoring "+home+"/.locklog: your home directory is not a project") {
		t.Errorf("no warning for ~/.locklog:\n%s", out)
	}
	if run := lastRun(t, calls); !hasSeq(run, "-v", sub+":"+sub+":ro") {
		t.Errorf("the project is not the subdirectory: %q", run)
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

func TestLauncherProjectRoot(t *testing.T) {
	f := newLauncherFixture(t)
	mk := func(p string, mode os.FileMode) string {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// projectOf runs a default command from dir and returns the -w the
	// launcher chose (the project, or dir itself).
	projectOf := func(dir string, env ...string) (string, string) {
		t.Helper()
		out, calls, err := f.run(t, dir, env, "status")
		if err != nil {
			t.Fatalf("status from %s: %v\n%s", dir, err, out)
		}
		run := lastRun(t, calls)
		for i, a := range run {
			if a == "-v" && strings.HasSuffix(run[i+1], ":ro") && !strings.HasPrefix(run[i+1], "locklog-") {
				return strings.SplitN(run[i+1], ":", 2)[0], out
			}
		}
		t.Fatalf("no project mount: %q", run)
		return "", ""
	}
	// The nearest trusted .locklog wins.
	if p, _ := projectOf(filepath.Join(f.project, "sub")); p != f.project {
		t.Errorf("project = %s, want %s", p, f.project)
	}
	// A .locklog in a sticky, world-writable directory (as /tmp) is never
	// taken, and the walk stops there.
	tmpLike := mk(filepath.Join(f.root, "tmp"), 0o1777)
	mk(filepath.Join(tmpLike, ".locklog"), 0o755)
	sub := mk(filepath.Join(tmpLike, "work"), 0o755)
	if p, _ := projectOf(sub); p != sub {
		t.Errorf("planted .locklog in a sticky dir taken: %s", p)
	}
	// The same for a group-writable parent.
	gw := mk(filepath.Join(f.root, "gw"), 0o775)
	mk(filepath.Join(gw, ".locklog"), 0o755)
	gsub := mk(filepath.Join(gw, "work"), 0o755)
	if p, _ := projectOf(gsub); p != gsub {
		t.Errorf("planted .locklog in a group-writable dir taken: %s", p)
	}
	// A group-writable .locklog, a writable config.toml, a symbolic link:
	// ignored with a warning.
	for _, tt := range []struct {
		name  string
		setup func(dir string)
	}{
		{"group-writable .locklog", func(dir string) { mk(filepath.Join(dir, ".locklog"), 0o775) }},
		{"world-writable config.toml", func(dir string) {
			mk(filepath.Join(dir, ".locklog"), 0o755)
			if err := os.WriteFile(filepath.Join(dir, ".locklog", "config.toml"), []byte("version = 1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, ".locklog", "config.toml"), 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"symbolic link", func(dir string) {
			if err := os.Symlink(filepath.Join(f.project, ".locklog"), filepath.Join(dir, ".locklog")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		dir := mk(filepath.Join(f.root, "case-"+strings.ReplaceAll(tt.name, " ", "-")), 0o755)
		tt.setup(dir)
		work := mk(filepath.Join(dir, "work"), 0o755)
		p, out := projectOf(work)
		if p != work || !strings.Contains(out, "warning: ignoring "+dir+"/.locklog") {
			t.Errorf("%s: project %s, out %s", tt.name, p, out)
		}
	}
	// The walk stops at $HOME: a .locklog above it is not taken.
	above := mk(filepath.Join(f.root, "above"), 0o755)
	mk(filepath.Join(above, ".locklog"), 0o755)
	home := mk(filepath.Join(above, "home"), 0o755)
	work := mk(filepath.Join(home, "work"), 0o755)
	if p, _ := projectOf(work, "HOME="+home); p != work {
		t.Errorf(".locklog above $HOME taken: %s", p)
	}
	// From the root directory, / is never the project.
	for _, cmd := range []string{"mcp", "status"} {
		out, calls, err := f.run(t, "/", nil, cmd)
		if err == nil || !strings.Contains(out, "not from /") || len(calls) > 0 {
			t.Errorf("%s from /: %v %q %s", cmd, err, calls, out)
		}
	}
}

// The launcher picks GNU (-c) or BSD (-f) stat by what the stat in PATH
// takes, not by uname -s: the macOS runner's BSD stat under a pinned
// Linux, GNU coreutils first in PATH on macOS. With either OS and either
// stat it finds the project and still refuses a sticky directory's
// .locklog.
func TestLauncherStatFlavour(t *testing.T) {
	real, err := exec.LookPath("stat")
	if err != nil {
		t.Skip("no stat")
	}
	gnu := exec.Command(real, "-c", "%u", "/").Run() == nil
	for _, sysname := range []string{"Linux", "Darwin"} {
		for _, emulate := range []bool{false, true} {
			if emulate && !gnu {
				continue // the BSD stat is emulated with a GNU one
			}
			f := newLauncherFixture(t)
			f.fakeUname(t, sysname)
			if emulate {
				// BSD stat: no -c; -f with the two formats the launcher uses.
				stat := filepath.Join(f.bin, "stat")
				if err := os.Remove(stat); err != nil {
					t.Fatal(err)
				}
				writeExec(t, stat, `#!/bin/sh
[ "$1" = -f ] || { echo "stat: illegal option -- c" >&2; exit 1; }
case "$2" in
'%Mp%Lp') printf '%04d\n' "$('`+real+`' -c '%a' "$3")" ;;
'%u') exec '`+real+`' -c '%u' "$3" ;;
*) exit 1 ;;
esac
`)
			}
			projectOf := func(dir string) string {
				t.Helper()
				out, calls, err := f.run(t, dir, nil, "status")
				if err != nil {
					t.Fatalf("%s, BSD stat %v: status from %s: %v\n%s", sysname, emulate || !gnu, dir, err, out)
				}
				run := lastRun(t, calls)
				for i, a := range run {
					if a == "-v" && strings.HasSuffix(run[i+1], ":ro") && !strings.HasPrefix(run[i+1], "locklog-") {
						return strings.SplitN(run[i+1], ":", 2)[0]
					}
				}
				t.Fatalf("no project mount: %q", run)
				return ""
			}
			if p := projectOf(filepath.Join(f.project, "sub")); p != f.project {
				t.Errorf("%s, BSD stat %v: project = %s, want %s", sysname, emulate || !gnu, p, f.project)
			}
			tmpLike := filepath.Join(f.root, "tmp")
			sub := filepath.Join(tmpLike, "work")
			for _, d := range []string{filepath.Join(tmpLike, ".locklog"), sub} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(tmpLike, 0o1777); err != nil {
				t.Fatal(err)
			}
			if p := projectOf(sub); p != sub {
				t.Errorf("%s, BSD stat %v: planted .locklog in a sticky dir taken: %s", sysname, emulate || !gnu, p)
			}
		}
	}
}
