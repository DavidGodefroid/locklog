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
		{"/var/log/a:b", "mount plan refuses"},
		{"/var/log/a;b", "mount plan refuses"},
		{"/var/log/a b", "mount plan refuses"},
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

func TestMessageFieldsNotTrusted(t *testing.T) {
	for _, f := range []string{"msg", "message", "log", "Message", "attrs.msg", "error", "stack_trace"} {
		wantErr(t, src(`kind = "file"`+"\n"+`paths = ["/var/log/a"]`+"\n"+`trusted = ["`+f+`"]`), "message text")
	}
	wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["a"]`+"\n"+`trusted = ["log"]`), "message text")
}

func TestErrorsDoNotEchoValues(t *testing.T) {
	const secret = "glsa_SuperSecretToken123"
	for _, key := range []string{"credentials", "auth", "tls"} {
		body := lokiOK
		if key == "auth" {
			body = strings.Replace(lokiOK, `auth = "bearer"`, "", 1)
		}
		_, err := parse(t, src(body+key+` = "`+secret+`"`))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error %v echoes the value", key, err)
		}
	}
	for _, key := range []string{"structured", "text", "unmask", "lookup"} {
		_, err := parse(t, fileSrc+"[profiles.staging]\n"+key+` = "`+secret+`"`+"\n")
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error %v echoes the value", key, err)
		}
	}
}

func TestJournaldSource(t *testing.T) {
	p := mustParse(t, src(`kind = "journald"
units = ["nginx.service", "shop-*.service"]
allow = ["MY_REQUEST_ID"]`))["staging"]
	s := p.Sources[0]
	if !slices.Contains(s.TrustedFields(), "_SYSTEMD_UNIT") || !slices.Contains(s.TrustedFields(), "PRIORITY") || slices.Contains(s.TrustedFields(), "MESSAGE") {
		t.Errorf("journald trusted = %v", s.TrustedFields())
	}
	for _, f := range []string{"COREDUMP_ENVIRON", "COREDUMP", "_CMDLINE", "_EXE", "_AUDIT_SESSION", "_COREDUMP_X",
		"OBJECT_CMDLINE", "OBJECT_EXE", "OBJECT_AUDIT_LOGINUID", "OBJECT_COMM", "OBJECT_PID", "AUDIT_FIELD_X", "MY_CMDLINE", "CHILD_EXE"} {
		for _, key := range []string{"allow", "trusted"} {
			wantErr(t, src(`kind = "journald"`+"\n"+key+` = ["`+f+`"]`), "can never be served")
		}
	}
	for _, f := range []string{"MESSAGE", "SYSLOG_RAW"} {
		for _, key := range []string{"allow", "trusted"} {
			wantErr(t, src(`kind = "journald"`+"\n"+key+` = ["`+f+`"]`), "holds the message text")
		}
	}
	for _, u := range []string{"user*", "*@1000.service", "u?er@1000.service", "*"} {
		wantErr(t, src(`kind = "journald"`+"\n"+`units = ["`+u+`"]`), "need user_journals = true")
	}
	wantErr(t, src(`kind = "journald"`+"\n"+`units = ["a\\x2d.service"]`), "invalid unit name")
	wantErr(t, src(`kind = "journald"`+"\n"+`trusted = ["lower"]`), "invalid journald field name")
	wantErr(t, src(`kind = "journald"`+"\n"+`allow = ["_PID"]`), "always served; remove it")
	mustParse(t, src(`kind = "journald"`+"\n"+`trusted = ["MY_SERVICE_VERSION"]`))
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
	for _, g := range []string{"*", "locklog-*", "locklog-console*", "*-console-*", "locklog-console-?", "locklog-c*e-x*",
		"*console-x*", "l?cklog-console", "locklog-console", "*g-c*", "????????????????*", "l*", "*e"} {
		wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["`+g+`"]`), "can match a locklog console container")
	}
	for _, g := range []string{"shop-*", "locklog-consolx*", "x*", "locklog-cons", "?", "locklog-console-*-x-[a]"} {
		if g == "locklog-console-*-x-[a]" {
			// Classes are refused by the name check before the console check.
			wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["`+g+`"]`), "invalid container name")
			continue
		}
		mustParse(t, src(`kind = "docker"`+"\n"+`containers = ["`+g+`"]`))
	}
	wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["a/b"]`), "invalid container name")
	wantErr(t, src(`kind = "docker"`), "at least one container")
	wantErr(t, src(`kind = "docker"`+"\n"+`containers = ["a"]`+"\n"+`attrs = ["a b"]`), "invalid attribute name")
}

func TestCanMatchPrefix(t *testing.T) {
	for _, tt := range []struct {
		glob string
		want bool
	}{
		{"locklog-console", true}, {"locklog-console-abc", true}, {"locklog-consol", false}, {"*", true},
		{"?", false}, {"???????????????", true}, {"??????????????", false}, {"l*e", true}, {"l*x", true},
		{"x*", false}, {"locklog-console?x", true}, {"*-console*", true}, {"*-consolx*", true}, {"lockl0g*", false},
	} {
		if got := canMatchPrefix(tt.glob, ConsolePrefix); got != tt.want {
			t.Errorf("canMatchPrefix(%q) = %t, want %t", tt.glob, got, tt.want)
		}
	}
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
		{lokiOK + `org_id = "a|b"`, "no '|' federation"},
		{lokiOK + `trusted_metadata = ["msg"]`, "is message text"},
		{lokiOK + "trusted_labels = [\"level\"]\ntrusted_metadata = [\"level\"]", "both a stream label and structured metadata"},
		{lokiOK + `trusted_metadata = ["app"]`, "both a stream label and structured metadata"},
		{strings.Replace(lokiOK, `auth = "bearer"`, `auth = "basic"`, 1) + `user = "admin:hunter2"`, "user: a login name without"},
		{strings.Replace(lokiOK, `selector = { app = "api" }`, `selector = { app = "a\"b" }`, 1), "without quotes, backslashes"},
		{strings.Replace(lokiOK, `selector = { app = "api" }`, `selector = { app = "a\\b" }`, 1), "without quotes, backslashes"},
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

func TestValidContainerName(t *testing.T) {
	for n, want := range map[string]bool{
		"shop-api-1": true, "a": true, "A.b_c-9": true, "": false, "-x": false, "_x": false,
		"shop-*": false, "a?": false, "a b": false, "a/b": false, "a,b": false, strings.Repeat("a", 129): false,
	} {
		if got := ValidContainerName(n); got != want {
			t.Errorf("ValidContainerName(%q) = %v", n, got)
		}
	}
}

const elasticOK = `kind = "elastic"
url = "https://es.example.com:9200"
indices = ["logs-app-*", "audit"]
auth = "api_key"
`

func TestElasticSource(t *testing.T) {
	p := mustParse(t, src(elasticOK+`trusted_fields = ["service.name", "log.level", "log.level"]
selector = { "service.environment" = "prod" }
tiebreaker = "event.id"`))["staging"]
	s := p.Sources[0]
	r := s.Remote
	if r == nil || s.Kind != KindElastic || r.Auth != AuthAPIKey || r.Credentials != kconfig.CredentialsAsk || r.TLS != kconfig.TLSVerifyFull ||
		!slices.Equal(r.Indices, []string{"audit", "logs-app-*"}) || !slices.Equal(r.TrustedFields, []string{"log.level", "service.name"}) ||
		r.TimeField != "@timestamp" || r.MessageField != "message" || r.TieBreaker != "event.id" || r.Selector["service.environment"] != "prod" {
		t.Fatalf("remote = %+v", r)
	}
	// The selector is optional: the indices scope the source.
	mustParse(t, src(elasticOK))
	mustParse(t, src(strings.Replace(elasticOK, `auth = "api_key"`, "auth = \"basic\"\nuser = \"reader\"", 1)))
	mustParse(t, src(strings.Replace(elasticOK, `auth = "api_key"`, `auth = "bearer"`, 1)+`credentials = "vault"`+"\n"+`vault_path = "secret/data/es"`))
	mustParse(t, src(elasticOK+"time_field = \"event.created\"\nmessage_field = \"log.original\""))
	for _, tt := range []struct{ body, part string }{
		{strings.Replace(elasticOK, `indices = ["logs-app-*", "audit"]`, "", 1), "at least one index"},
		{strings.Replace(elasticOK, `"audit"`, `"_all"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `".security"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `"*"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `"logs-*-x"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `"remote:logs"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `"Logs"`, 1), "invalid index name"},
		{strings.Replace(elasticOK, `"audit"`, `"a,b"`, 1), "invalid index name"},
		{elasticOK + `trusted_fields = ["message"]`, "is message text"},
		{elasticOK + "message_field = \"body.text\"\ntrusted_fields = [\"body.text\"]", "is message text"},
		{elasticOK + `trusted_fields = ["@timestamp"]`, "is the time field"},
		{elasticOK + `trusted_fields = ["user.email"]`, "looks like personal data"},
		{elasticOK + `trusted_fields = ["a*"]`, "invalid field name"},
		{elasticOK + `trusted_fields = ["a..b"]`, "invalid field name"},
		{elasticOK + `time_field = "a b"`, "invalid field name"},
		{elasticOK + `tiebreaker = "x\""`, "invalid field name"},
		{elasticOK + `selector = { "a*" = "x" }`, "invalid field name"},
		{elasticOK + `selector = { env = "" }`, "needs a non-empty value"},
		{elasticOK + `selector = { message = "x" }`, "message or time field"},
		{elasticOK + `trusted_labels = ["app"]`, `applies only to kind = "loki"`},
		{elasticOK + `org_id = "t"`, `applies only to kind = "loki"`},
		{elasticOK + `read_only_roles = ["r"]`, `applies only to kind = "opensearch"`},
		{elasticOK + `user = "x"`, `"api_key" takes no user`},
		{strings.Replace(elasticOK, `auth = "api_key"`, `auth = "token"`, 1), "want none, basic, bearer, api_key or mtls"},
		{strings.Replace(elasticOK, `auth = "api_key"`, "", 1), "auth is required"},
		{strings.Replace(elasticOK, "https://es.example.com:9200", "http://es.example.com:9200", 1), "plain http://"},
		{lokiOK + `indices = ["a"]`, `applies only to kind = "elastic" or "opensearch"`},
		{strings.Replace(lokiOK, `auth = "bearer"`, `auth = "api_key"`, 1), `applies only to kind = "elastic"`},
		{`kind = "file"` + "\n" + `paths = ["/var/log/a"]` + "\n" + `trusted_fields = ["a"]`, `applies only to kind = "elastic" or "opensearch"`},
	} {
		wantErr(t, src(tt.body), tt.part)
	}
}

const openSearchOK = `kind = "opensearch"
url = "https://os.example.com:9200"
indices = ["logs-*"]
auth = "basic"
user = "reader"
`

func TestOpenSearchSource(t *testing.T) {
	p := mustParse(t, src(openSearchOK+`read_only_roles = ["logs_reader", "logs_reader"]
trusted_fields = ["level"]`))["staging"]
	r := p.Sources[0].Remote
	if p.Sources[0].Kind != KindOpenSearch || !slices.Equal(r.ReadOnlyRoles, []string{"logs_reader"}) || !slices.Equal(r.TrustedFields, []string{"level"}) {
		t.Fatalf("remote = %+v", r)
	}
	wantErr(t, src(strings.Replace(openSearchOK, "auth = \"basic\"\nuser = \"reader\"", `auth = "api_key"`, 1)), `applies only to kind = "elastic"`)
	wantErr(t, src(openSearchOK+`read_only_roles = ["a b"]`), "invalid role name")
	wantErr(t, src(strings.Replace(openSearchOK, `auth = "basic"`, `auth = "token"`, 1)), "want none, basic, bearer or mtls")
}

func TestElasticProduction(t *testing.T) {
	for _, ok := range []string{elasticOK, openSearchOK} {
		none := strings.Replace(strings.Replace(ok, `auth = "api_key"`, `auth = "none"`, 1), "auth = \"basic\"\nuser = \"reader\"", `auth = "none"`, 1)
		wantErr(t, prodSrc(none), `auth = "none" is refused on a production profile`)
		wantErr(t, prodSrc(strings.Replace(strings.Replace(ok, "https://es.example.com:9200", "http://127.0.0.1:9200", 1), "https://os.example.com:9200", "http://127.0.0.1:9200", 1)), "needs an https:// URL")
		wantErr(t, prodSrc(ok+`tls = "verify-ca"`), `needs tls = "verify-full"`)
		mustParse(t, prodSrc(ok+`credentials = "vault"`+"\n"+`vault_path = "secret/data/es"`))
	}
	// Off production, plain http on loopback and no auth are fine.
	mustParse(t, src(strings.Replace(elasticOK, "https://es.example.com:9200", "http://127.0.0.1:9200", 1)))
	mustParse(t, src(strings.Replace(strings.Replace(elasticOK, "https://es.example.com:9200", "http://es:9200", 1), `auth = "api_key"`, `auth = "none"`, 1)))
}
