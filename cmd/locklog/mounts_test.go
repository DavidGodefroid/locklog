package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMounts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	if err := os.MkdirAll(filepath.Join(dir, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `version = 1
[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]
[profiles.staging.sources.sys]
kind = "journald"
`
	if err := os.WriteFile(filepath.Join(dir, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var out, errb bytes.Buffer
	if code := run([]string{"mounts"}, &out, &errb); code != 0 {
		t.Fatalf("mounts = %d: %s", code, errb.String())
	}
	want := "profile staging false\nfile /var/log/nginx /var/log/nginx/access.log*\njournald\n"
	if out.String() != want {
		t.Errorf("mounts =\n%s\nwant\n%s", out.String(), want)
	}
	for _, tt := range []struct {
		args []string
		code int
		part string
	}{
		{[]string{"mounts", "--profile", "nope"}, 1, `no profile "nope"`},
		{[]string{"mounts", "--profile=staging"}, 0, ""},
		{[]string{"mounts", "extra"}, 2, "unexpected argument"},
	} {
		out.Reset()
		errb.Reset()
		if code := run(tt.args, &out, &errb); code != tt.code || !strings.Contains(errb.String(), tt.part) {
			t.Errorf("%v = %d %q", tt.args, code, errb.String())
		}
	}
}

// A remote source mounts nothing; the plan ends with a remote line.
func TestMountsRemote(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	if err := os.MkdirAll(filepath.Join(dir, ".locklog"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `version = 1
[profiles.search.sources.es]
kind = "opensearch"
url = "https://search.example.com:9200"
indices = ["logs-*"]
auth = "basic"
user = "reader"
`
	if err := os.WriteFile(filepath.Join(dir, ".locklog", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var out, errb bytes.Buffer
	if code := run([]string{"mounts"}, &out, &errb); code != 0 {
		t.Fatalf("mounts = %d: %s", code, errb.String())
	}
	if want := "profile search false\nremote\n"; out.String() != want {
		t.Errorf("mounts =\n%s\nwant\n%s", out.String(), want)
	}
}
