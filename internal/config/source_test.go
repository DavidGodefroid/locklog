package config

import (
	"slices"
	"strings"
	"testing"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

func src(body string) string { return "[profiles.staging.sources.s]\n" + body + "\n" }

const lokiOK = `kind = "loki"
url = "https://loki.example.com"
selector = { app = "api" }
auth = "bearer"
`

func prodSrc(body string) string {
	return "[profiles.prod]\nproduction = true\n[profiles.prod.sources.s]\n" + body + "\n"
}

func TestSourceCommon(t *testing.T) {
	for _, tt := range []struct{ body, part string }{
		{`kind = "syslogd"`, "kind: want one of"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `format = "xml"`, "format: want one of"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `multiline = "java"`, "multiline: want one of"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `trusted = ["user email"]`, "invalid field name"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `trusted = ["email"]`, "looks like personal data"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `trusted = ["user_ip"]`, "looks like personal data"},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `units = ["a.service"]`, `units applies only to kind = "journald"`},
		{`kind = "journald"` + "\n" + `containers = ["a"]`, `containers applies only to kind = "docker"`},
		{`kind = "docker"` + "\n" + `containers = ["a"]` + "\n" + `url = "https://x"`, `applies only to kind = "loki"`},
		{`kind = "loki"` + "\n" + `paths = ["/var/log/a"]`, `paths applies only to kind = "file"`},
	} {
		wantErr(t, src(tt.body), tt.part)
	}
	wantErr(t, "[profiles.staging.sources.Bad]\nkind = \"journald\"\n", "invalid source name")
}

func TestFileSource(t *testing.T) {
	p := mustParse(t, src(`kind = "file"
paths = ["/var/log/b/*.log", "/var/log/a/**/*.log.gz", "/var/log/b/*.log"]
recursive = true
trusted = ["vhost", "level"]`))["staging"]
	s := p.Sources[0]
	if !slices.Equal(s.Paths, []string{"/var/log/a/**/*.log.gz", "/var/log/b/*.log"}) || !s.Recursive || s.Format != "auto" {
		t.Errorf("source = %+v", s)
	}
	if !slices.Equal(s.TrustedFields(), []string{"level", "vhost"}) {
		t.Errorf("trusted = %v", s.TrustedFields())
	}
	for _, tt := range []struct{ path, part string }{
		{"var/log/a", "absolute, clean"},
		{"/var/log/../etc/shadow", "absolute, clean"},
		{"/var/log/a/", "absolute, clean"},
		{"/", "root directory"},
		{"/var/log/a,b", "mount plan refuses"},
		{"/var/log/a=b", "mount plan refuses"},
		{"/var/log/\"a", "mount plan refuses"},
		{"/var/log/a\u202eb", "mount plan refuses"},
		{"/var/log/[a", "invalid glob"},
		{"/var/log/a**b", "whole path component"},
		{"/var/log/**/*.log", "needs recursive = true"},
		{"/*/log/a", "first path component"},
	} {
		wantErr(t, src(`kind = "file"`+"\n"+`paths = [`+quote(tt.path)+`]`), tt.part)
	}
	for _, tt := range []struct{ path, part string }{
		{"/var/**/log/**/*.log", "at most one **"},
		{"/var/log/**", "followed by a file name pattern"},
	} {
		wantErr(t, src(`kind = "file"`+"\n"+`recursive = true`+"\n"+`paths = [`+quote(tt.path)+`]`), tt.part)
	}
	wantErr(t, src(`kind = "file"`), "at least one absolute path glob")
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func TestJournaldSource(t *testing.T) {
	p := mustParse(t, src(`kind = "journald"
units = ["nginx.service", "shop-*.service"]
allow = ["MY_REQUEST_ID"]`))["staging"]
	s := p.Sources[0]
	if !slices.Contains(s.TrustedFields(), "_SYSTEMD_UNIT") || !slices.Contains(s.TrustedFields(), "PRIORITY") || slices.Contains(s.TrustedFields(), "MESSAGE") {
		t.Errorf("journald trusted = %v", s.TrustedFields())
	}
	for _, f := range []string{"COREDUMP_ENVIRON", "COREDUMP", "_CMDLINE", "_EXE", "_AUDIT_SESSION", "_COREDUMP_X"} {
		wantErr(t, src(`kind = "journald"`+"\n"+`allow = ["`+f+`"]`), "can never be allowed")
	}
	wantErr(t, src(`kind = "journald"`+"\n"+`allow = ["MESSAGE"]`), "always served")
	wantErr(t, src(`kind = "journald"`+"\n"+`allow = ["lower"]`), "invalid journald field name")
	wantErr(t, src(`kind = "journald"`+"\n"+`units = ["a b"]`), "invalid unit name")
	wantErr(t, src(`kind = "journald"`+"\n"+`units = ["user@1000.service"]`), "need user_journals = true")
	mustParse(t, src(`kind = "journald"`+"\n"+`units = ["user@1000.service"]`)+"[profiles.staging]\nuser_journals = true\n")
	// No units: every unit.
	mustParse(t, src(`kind = "journald"`))
}

func TestDockerSource(t *testing.T) {
	p := mustParse(t, src(`kind = "docker"
containers = ["shop-worker-*", "shop-api-1"]
format = "json"`))["staging"]
	if s := p.Sources[0]; !slices.Equal(s.Containers, []string{"shop-api-1", "shop-worker-*"}) {
		t.Errorf("containers = %v", s.Containers)
	}
	for _, g := range []string{"*", "locklog-*", "locklog-console*", "*-console-*", "locklog-console-?"} {
		wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["`+g+`"]`), "matches a locklog console container")
	}
	wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["a/b"]`), "invalid container name")
	wantErr(t, src(`kind = "docker"`), "at least one container")
	wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["a"]`+"\n"+`attrs = ["a b"]`), "invalid attribute name")
}

func TestLokiSource(t *testing.T) {
	p := mustParse(t, src(lokiOK+`trusted_labels = ["level", "app"]
org_id = "tenant-1"`))["staging"]
	r := p.Sources[0].Remote
	if r == nil || r.TLS != kconfig.TLSVerifyFull || r.Credentials != kconfig.CredentialsAsk || !slices.Equal(r.TrustedLabels, []string{"app", "level"}) {
		t.Fatalf("remote = %+v", r)
	}
	for _, tt := range []struct{ body, part string }{
		{strings.Replace(lokiOK, "https://loki.example.com", "https://u:p@loki.example.com", 1), "embedded password"},
		{strings.Replace(lokiOK, "https://loki.example.com", "https://u@loki.example.com", 1), "must not hold a user or password"},
		{strings.Replace(lokiOK, "https://loki.example.com", "ftp://loki.example.com", 1), "want http:// or https://"},
		{strings.Replace(lokiOK, "https://loki.example.com", "https://loki.example.com/?x=1", 1), "query or a fragment"},
		{strings.Replace(lokiOK, `selector = { app = "api" }`, "", 1), "at least one label matcher"},
		{strings.Replace(lokiOK, `selector = { app = "api" }`, `selector = { "a-b" = "x" }`, 1), "invalid label name"},
		{strings.Replace(lokiOK, `auth = "bearer"`, "", 1), "auth is required"},
		{strings.Replace(lokiOK, `auth = "bearer"`, `auth = "token"`, 1), "unknown auth"},
		{strings.Replace(lokiOK, `auth = "bearer"`, `auth = "basic"`, 1), `needs user`},
		{lokiOK + `user = "x"`, `takes no user`},
		{strings.Replace(lokiOK, `auth = "bearer"`, `auth = "mtls"`, 1), "needs tls_cert and tls_key"},
		{lokiOK + `credentials = "keychain"`, "unknown credentials mode"},
		{lokiOK + `credentials = "vault"`, "needs vault_path"},
		{lokiOK + `vault_path = "a/b"`, "only used with credentials"},
		{lokiOK + `tls = "disable"`, `"disable" with an https://`},
		{lokiOK + `tls = "prefer"`, `"prefer" does not apply`},
		{lokiOK + `tls_cert = "/c.pem"`, "go together"},
		{lokiOK + `trusted_labels = ["email"]`, "looks like personal data"},
		{lokiOK + `org_id = "a b"`, "invalid tenant id"},
		{strings.Replace(lokiOK, "https://loki.example.com", "http://loki.example.com", 1), "plain http://"},
		{strings.Replace(lokiOK, "https://loki.example.com", "http://loki.example.com", 1) + `tls = "verify-full"`, "needs an https:// URL"},
	} {
		wantErr(t, src(tt.body), tt.part)
	}
	// Plain http on loopback, and no auth, are fine off production.
	mustParse(t, src(strings.Replace(lokiOK, "https://loki.example.com", "http://127.0.0.1:3100", 1)))
	mustParse(t, src(strings.Replace(strings.Replace(lokiOK, "https://loki.example.com", "http://loki:3100", 1), `auth = "bearer"`, `auth = "none"`, 1)))
	wantErr(t, src(strings.Replace(lokiOK, `auth = "bearer"`, `auth = "none"`, 1)+`user = "x"`), "takes no user")
}

func TestLokiProduction(t *testing.T) {
	none := strings.Replace(lokiOK, `auth = "bearer"`, `auth = "none"`, 1)
	wantErr(t, prodSrc(none), `auth = "none" is refused on a production profile`)
	wantErr(t, prodSrc(none+`org_id = "t1"`), "an org_id alone is not authentication")
	wantErr(t, prodSrc(strings.Replace(lokiOK, "https://loki.example.com", "http://127.0.0.1:3100", 1)), "needs an https:// URL")
	wantErr(t, prodSrc(lokiOK+`tls = "verify-ca"`), `needs tls = "verify-full"`)
	p := mustParse(t, prodSrc(lokiOK+`credentials = "vault"`+"\n"+`vault_path = "secret/data/loki"`))["prod"]
	if r := p.Sources[0].Remote; r.Credentials != kconfig.CredentialsVault || r.VaultPath != "secret/data/loki" {
		t.Errorf("remote = %+v", r)
	}
}
