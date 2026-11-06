package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/product"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const rulesConfig = `version = 1
[profiles.local]
auto = "full-auto"
[profiles.local.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]

[profiles.prod]
production = true
[profiles.prod.auto]
read = "auto"
lookup = "deny"
[profiles.prod.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]

[profiles.staging.sources.app]
kind = "file"
paths = ["/var/log/app/app.log"]
`

// rulesProject is a project with three profiles, and a state base where
// the console approved prod with stricter rules than the file's (read
// asked) and staging as it is.
func rulesProject(t *testing.T) (root, state string) {
	t.Helper()
	root, state = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".locklog", "config.toml"), []byte(rulesConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	ps, err := config.LoadFile(filepath.Join(root, ".locklog", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	prod := ps["prod"]
	prod.Auto = &config.AutoRules{Lookup: config.AutoDeny}
	for _, p := range []config.Profile{prod, ps["staging"]} {
		pol, err := config.NewPolicy(p, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := kconfig.SaveApproved(product.P, state, kconfig.ApprovedKey(root, p.Name), pol); err != nil {
			t.Fatal(err)
		}
	}
	return root, state
}

// `locklog profile rules --json` is what lox run reads: the approved
// rules where the console approved a policy (prod flagged pending review:
// its file loosens read), the file's elsewhere.
func TestProfileRulesJSONGolden(t *testing.T) {
	root, state := rulesProject(t)
	var out, errb bytes.Buffer
	if rc := profileRulesCmd([]string{"--json"}, filepath.Join(root, ".locklog"), state, &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	golden := filepath.Join("testdata", "profile-rules.golden.json")
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Errorf("profile rules --json:\n%s\nwant:\n%s", out.String(), want)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("not one line of JSON: %q", out.String())
	}
	var parsed profileRulesOut
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil || len(parsed.Profiles) != 3 {
		t.Fatalf("%v %+v", err, parsed)
	}
}

func TestProfileRulesText(t *testing.T) {
	root, state := rulesProject(t)
	var out, errb bytes.Buffer
	if rc := profileRulesCmd([]string{"--project", root, "--profile", "prod"}, t.TempDir(), state, &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	if got, want := out.String(), "prod (production): read ask · unmask ask · lookup deny [approved; the config file differs: pending :review]\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Without the console's state: the file's rules, said so.
	out.Reset()
	if rc := profileRulesCmd([]string{"--project", root, "--profile", "local"}, t.TempDir(), "", &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	if got, want := out.String(), "local: read auto · unmask auto · lookup auto (full-auto) [config file: not approved yet]\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProfileRulesRefusals(t *testing.T) {
	root, state := rulesProject(t)
	for _, tt := range []struct {
		args []string
		cwd  string
		rc   int
		want string
	}{
		{[]string{"--json", "--profile", "nope"}, root, 2, `"code":"usage"`},
		{[]string{"--json", "extra"}, root, 2, `"code":"usage"`},
		{[]string{"--json"}, t.TempDir(), 1, `no .locklog/ here or above`},
	} {
		var out, errb bytes.Buffer
		if rc := profileRulesCmd(tt.args, tt.cwd, state, &out, &errb); rc != tt.rc || !strings.Contains(out.String(), tt.want) {
			t.Errorf("%v: rc %d, %s%s", tt.args, rc, out.String(), errb.String())
		}
	}
}
