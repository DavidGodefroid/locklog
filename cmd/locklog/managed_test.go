//go:build unix && lockfamily_managed_test

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

// testDir is the package directory: the tests change the working
// directory to their project.
var testDir, _ = os.Getwd()

var updateManaged = flag.Bool("update-managed", false, "rewrite the golden files of managed show, managed check and doctor")

// useManaged makes body the machine's managed file ("" for none) and
// returns its path.
func useManaged(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), managed.FileName)
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	managed.SetTestPath(path)
	t.Cleanup(func() { managed.SetTestPath("") })
	return path
}

// managedGolden compares got, with the managed path made <managed>, with
// testdata/managed/<name>.golden.
func managedGolden(t *testing.T, name, path, got string) {
	t.Helper()
	got = strings.ReplaceAll(got, path, "<managed>")
	file := filepath.Join(testDir, "testdata", "managed", name+".golden")
	if *updateManaged {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (run go test -tags lockfamily_managed_test ./cmd/locklog -update-managed)", err)
	}
	if got != string(want) {
		t.Errorf("%s:\n--- got\n%s--- want\n%s", name, got, want)
	}
}

const managedFile = `version = 1
organisation = "Acme"

[locklog.bounds]
unmask = "never"
kinds = ["file", "journald", "loki"]
hosts = ["*.example.com"]
limits = { max_records = 100, max_session = "8h" }
detectors = ["iban"]

[[locklog.bounds.pii_mask]]
sources = ["app-*"]
field = "user.email"

[locklog.defaults]
lookup = "approved"
limits = { max_records = 50 }

[locklog.profiles.shared]
production = true
limits = { max_session = "8h" }
[locklog.profiles.shared.sources.lk]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "bearer"
`

const okProfile = `version = 1
[profiles.dev]
unmask = "never"
limits = { max_session = "8h" }
[profiles.dev.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]
`

const badProfiles = okProfile + `[profiles.qa]
unmask = "approved"
limits = { max_session = "8h" }
[profiles.qa.sources.es]
kind = "elastic"
url = "https://es.other.org"
indices = ["logs-*"]
auth = "api_key"
`

// managedProject writes a project's config and returns its root, the
// working directory of the test.
func managedProject(t *testing.T, cfg string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return root
}

func runOut(args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, "exit " + strconv.Itoa(code) + "\n--- stdout\n" + out.String() + "--- stderr\n" + errb.String()
}

// The output and exit codes of managed show and managed check are a
// contract: lox runs managed check before it starts the lock
// (lockhub#179), the launcher too (#146).
func TestManagedShowGolden(t *testing.T) {
	managedProject(t, okProfile)
	for _, c := range []struct {
		name, body string
		code       int
	}{
		{"show-none", "", 0},
		{"show-file", managedFile, 0},
		{"show-refused", "version = 1\n[locklog.bounds]\nbogus = 1\n", exitManaged},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := useManaged(t, c.body)
			code, out := runOut("managed", "show")
			if code != c.code {
				t.Errorf("exit %d, want %d\n%s", code, c.code, out)
			}
			managedGolden(t, c.name, path, out)
		})
	}
}

func TestManagedCheckGolden(t *testing.T) {
	for _, c := range []struct {
		name, body, cfg string
		args            []string
		code            int
	}{
		{"check-none", "", badProfiles, nil, 0},
		{"check-ok", managedFile, okProfile, nil, 0},
		{"check-profile", managedFile, badProfiles, []string{"--profile", "dev"}, 0},
		{"check-violation", managedFile, badProfiles, nil, exitManaged},
		{"check-redefined", managedFile, okProfile + strings.ReplaceAll(okProfile[len("version = 1\n"):], "profiles.dev", "profiles.shared"), nil, exitManaged},
	} {
		t.Run(c.name, func(t *testing.T) {
			managedProject(t, c.cfg)
			path := useManaged(t, c.body)
			code, out := runOut(append([]string{"managed", "check"}, c.args...)...)
			if code != c.code {
				t.Errorf("exit %d, want %d\n%s", code, c.code, out)
			}
			managedGolden(t, c.name, path, out)
		})
	}
}

// doctor has a managed line: the file's description, none, or the
// error (a failure).
func TestDoctorManagedGolden(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"doctor-none", ""},
		{"doctor-file", managedFile},
		{"doctor-refused", "version = 2\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			managedProject(t, okProfile)
			path := useManaged(t, c.body)
			in := strings.NewReader(hostfacts.Header + "\neuid 1000\ngroups users\nsudo absent\ndocker absent\n")
			var out, errb bytes.Buffer
			code := doctorCmd([]string{"--facts", "-"}, in, &out, &errb)
			var line string
			for _, l := range strings.Split(out.String(), "\n") {
				if strings.Contains(l, "managed: ") {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("no managed line:\n%s", out.String())
			}
			if c.name == "doctor-refused" && code != 1 {
				t.Errorf("exit %d with a refused managed file", code)
			}
			managedGolden(t, c.name, path, line+"\n")
		})
	}
}
