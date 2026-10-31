package setup

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %s\nwant %s", name, got, want)
	}
}

func TestStem(t *testing.T) {
	for in, want := range map[string]string{
		"syslog": "syslog", "syslog.1": "syslog", "syslog.2.gz": "syslog", "auth.log": "auth.log",
		"auth.log.4.gz": "auth.log", "app.log-20250101": "app.log", "app.log-2025010112.gz": "app.log",
		"app.log.2025-01-01": "app.log", "error_log": "error_log", "access.log.10.zst": "access.log",
		"messages-20250101.xz": "messages",
	} {
		if got, ok := stem(in); !ok || got != want {
			t.Errorf("stem(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"wtmp", "btmp.1", "lastlog", "system.journal", "user-1000.journal~", "README", "dpkg.status", "app.pid"} {
		if got, ok := stem(in); ok {
			t.Errorf("stem(%q) = %q, want no log", in, got)
		}
	}
}

// The host's files become one source per family (rotated and compressed
// siblings under one glob), the journal one source, the containers one
// docker source (never a console), and a Compose Loki is recognised.
func TestDetect(t *testing.T) {
	f := hostfacts.Facts{
		Logs: []string{
			"/var/log/syslog", "/var/log/syslog.1", "/var/log/syslog.2.gz",
			"/var/log/nginx/access.log", "/var/log/nginx/access.log.1", "/var/log/nginx/access.log.2.gz",
			"/var/log/nginx/error.log",
			"/var/log/debug", "/var/log/debug.log",
			"/var/log/wtmp", "/var/log/journal/abc/system.journal",
			"/var/log/odd dir/app.log", "/var/log/a,b.log", "relative.log", "/var/log/../etc/x.log",
			"/srv/app/logs/app.log", "/srv/app/logs/app.log.1.gz",
		},
		Journals: []string{"/var/log/journal"},
		Containers: []hostfacts.Container{
			{Name: "web", Image: "nginx:1.27"},
			{Name: "locklog-console-123", Image: "locklog"},
			{Name: "loki-1", Image: "grafana/loki:3.5.7", Service: "loki", Project: "shop", Networks: []string{"shop_default"}},
			{Name: "other-loki", Image: "grafana/loki@sha256:abc"},
			{Name: "web", Image: "nginx:1.27"},
		},
	}
	d := Detect(f)
	want := []FileSource{
		{Name: "app", Paths: []string{"/srv/app/logs/app.log*"}},
		{Name: "debug", Paths: []string{"/var/log/debug", "/var/log/debug.*"}},
		{Name: "debug-2", Paths: []string{"/var/log/debug.log*"}},
		{Name: "syslog", Paths: []string{"/var/log/syslog*"}},
		{Name: "nginx-access", Paths: []string{"/var/log/nginx/access.log*"}},
		{Name: "nginx-error", Paths: []string{"/var/log/nginx/error.log*"}},
	}
	if len(d.Files) != len(want) {
		t.Fatalf("files = %+v", d.Files)
	}
	for i := range want {
		if d.Files[i].Name != want[i].Name || !slices.Equal(d.Files[i].Paths, want[i].Paths) {
			t.Errorf("file %d = %+v, want %+v", i, d.Files[i], want[i])
		}
	}
	if !d.Journald || !slices.Equal(d.Containers, []string{"loki-1", "other-loki", "web"}) {
		t.Errorf("journald %v, containers %v", d.Journald, d.Containers)
	}
	if len(d.Lokis) != 1 || d.Lokis[0].Service != "loki" || d.Lokis[0].Project != "shop" {
		t.Errorf("lokis = %+v", d.Lokis)
	}
}

func testPlan(prod bool) Plan {
	return Plan{Profile: "prod", Production: prod, Detected: Detected{
		Files:      []FileSource{{Name: "syslog", Paths: []string{"/var/log/syslog*"}}, {Name: "nginx-access", Paths: []string{"/var/log/nginx/access.log*"}}},
		Journald:   true,
		Containers: []string{"api", "web"},
	}}
}

// The written config loads, with the containers in a profile of their own
// (a docker source needs its own console).
func TestRender(t *testing.T) {
	out, err := Render(testPlan(true))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-prod.toml", out)
	ps, err := config.ParseProfiles(out, "x")
	if err != nil {
		t.Fatal(err)
	}
	if !ps["prod"].Production || !ps["prod-docker"].Production || len(ps["prod"].Sources) != 3 || len(ps["prod-docker"].Sources) != 1 {
		t.Errorf("profiles = %+v", ps)
	}

	empty, err := Render(Plan{Profile: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-empty.toml", empty)

	p := testPlan(true)
	p.LokiProxy = &LokiSource{URL: "https://locklog-loki-proxy:3101", User: "locklog", CACert: "/p/.locklog/locklog-loki-proxy-ca.crt",
		Credentials: "ask", Network: "shop_default"}
	commented, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-loki-commented.toml", commented)
	p.LokiProxy.Selector = "app=api"
	p.LokiProxy.Credentials, p.LokiProxy.VaultPath = "vault", "secret/data/loki"
	active, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "config-loki.toml", active)
	ps, err = config.ParseProfiles(active, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := ps["prod-loki"].Source("loki"); !ok || s.Remote.TLSCA != "/p/.locklog/locklog-loki-proxy-ca.crt" || s.Remote.Credentials != "vault" {
		t.Errorf("loki source = %+v", s)
	}
}

const digestRef = "ghcr.io/davidgodefroid/locklog@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestContainerRecipe(t *testing.T) {
	var b bytes.Buffer
	ContainerRecipe(&b, RecipeOptions{Image: digestRef, Profile: "prod"})
	golden(t, "recipe-container.txt", b.Bytes())

	b.Reset()
	ContainerRecipe(&b, RecipeOptions{Image: "locklog", AgentUID: 1000, Profile: "prod"})
	golden(t, "recipe-container-uid.txt", b.Bytes())

	b.Reset()
	LeaRecipe(&b)
	golden(t, "recipe-lea.txt", b.Bytes())
}

func TestSourceNames(t *testing.T) {
	used := map[string]bool{}
	for _, c := range []struct{ dir, stem, want string }{
		{"/var/log", "syslog", "syslog"},
		{"/var/log/nginx", "access.log", "nginx-access"},
		{"/var/log/Weird App", "x.log", "weird-app-x"},
		{"/var/log", "syslog", "syslog-2"},
		{"/var/log", "_x_log", "x"},
	} {
		if got := uniqueName(sourceName(c.dir, c.stem), used); got != c.want {
			t.Errorf("name(%s, %s) = %q, want %q", c.dir, c.stem, got, c.want)
		}
	}
}

func TestOnlyUnder(t *testing.T) {
	f := OnlyUnder(hostfacts.Facts{Logs: []string{"/var/log/syslog", "/srv/app/logs/app.log", "/srv/app/logs2/x.log"},
		Journals: []string{"/var/log/journal"}, Containers: []hostfacts.Container{{Name: "web"}}}, []string{"/srv/app/logs/"})
	if !slices.Equal(f.Logs, []string{"/srv/app/logs/app.log"}) || f.Journals != nil || f.Containers != nil {
		t.Errorf("OnlyUnder = %+v", f)
	}
}
