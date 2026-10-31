package mountplan

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/config"
)

func TestDir(t *testing.T) {
	for glob, want := range map[string]string{
		"/var/log/nginx/access.log*":    "/var/log/nginx",
		"/var/log/app.log":              "/var/log",
		"/var/log/*/app.log":            "/var/log",
		"/var/log/pods/**/*.log":        "/var/log/pods",
		"/var/log/a/b?/c/d.log":         "/var/log/a",
		"/srv/logs/[ab]/x.log":          "/srv/logs",
		"/var/log/nginx/error.log.1.gz": "/var/log/nginx",
	} {
		if got := Dir(glob); got != want {
			t.Errorf("Dir(%q) = %q, want %q", glob, got, want)
		}
	}
}

func profile(t *testing.T, body string) config.Profile {
	t.Helper()
	ps, err := config.ParseProfiles([]byte("version = 1\n"+body), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	return ps["p"]
}

func TestLines(t *testing.T) {
	p := profile(t, `
[profiles.p.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*", "/var/log/nginx/error.log*"]
[profiles.p.sources.app]
kind = "file"
paths = ["/srv/app/logs/**/*.log"]
recursive = true
[profiles.p.sources.sys]
kind = "journald"
[profiles.p.sources.sys2]
kind = "journald"
units = ["a.service"]
[profiles.p.sources.api]
kind = "docker"
containers = ["shop-api-1", "shop-worker-*"]
[profiles.p.sources.api2]
kind = "docker"
containers = ["shop-api-1"]
[profiles.p.sources.loki]
kind = "loki"
url = "https://loki.example.com"
selector = { app = "x" }
auth = "bearer"
`)
	ls, err := Lines(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range ls {
		got = append(got, l.String())
	}
	want := "docker shop-api-1\ndocker shop-worker-*\nfile /srv/app/logs /srv/app/logs/**/*.log\nfile /var/log/nginx /var/log/nginx/access.log*\nfile /var/log/nginx /var/log/nginx/error.log*\njournald"
	if strings.Join(got, "\n") != want {
		t.Errorf("Lines =\n%s\nwant\n%s", strings.Join(got, "\n"), want)
	}
}

func TestLinesRefusals(t *testing.T) {
	p := profile(t, `
[profiles.p.sources.api]
kind = "docker"
containers = ["shop-api-1"]
`)
	// Hand-built container globs are checked again.
	for _, g := range []string{"a b", "-x", "a,b", "a=b", "", "a/b", "[ab]"} {
		p.Sources[0].Containers = []string{g}
		if _, err := Lines(p); err == nil || !strings.Contains(err.Error(), "cannot be mapped") {
			t.Errorf("docker glob %q: %v", g, err)
		}
	}
	// A file directly under / mounts the root: refused (config lets
	// /app.log through; the plan does not).
	p = profile(t, `
[profiles.p.sources.x]
kind = "file"
paths = ["/app.log"]
`)
	if _, err := Lines(p); err == nil || !strings.Contains(err.Error(), "root directory") {
		t.Errorf("root: %v", err)
	}
	// Hand-built profiles are checked again.
	p.Sources[0].Paths = []string{"/var/log/a b.log"}
	if _, err := Lines(p); err == nil {
		t.Error("space accepted")
	}
}
