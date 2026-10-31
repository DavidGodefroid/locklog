package doctor

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

var update = flag.Bool("update", false, "rewrite the golden files")

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

// secretBody is what every probed server answers: it must never be shown.
const secretBody = `{"status":"success","data":["user_email","SECRET-VALUE-4242"],"Token":"AKIA-SECRET"}`

func server(t *testing.T, status int) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("a probe sent credentials: %v", r.Header)
		}
		w.WriteHeader(status)
		w.Write([]byte(secretBody))
	}))
	t.Cleanup(s.Close)
	return s
}

func profiles(t *testing.T, prod bool, urls ...string) map[string]config.Profile {
	t.Helper()
	var b strings.Builder
	b.WriteString("version = 1\n[profiles.main]\n")
	if prod {
		b.WriteString("production = true\n")
	}
	b.WriteString("[profiles.main.sources.app]\nkind = \"file\"\npaths = [\"/var/log/app.log\"]\n")
	for i, u := range urls {
		b.WriteString("[profiles.main.sources.loki" + string(rune('a'+i)) + "]\nkind = \"loki\"\nauth = \"none\"\nselector = { app = \"x\" }\nurl = \"" + u + "\"\n")
	}
	ps, err := config.ParseProfiles([]byte(b.String()), "x")
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

var hostPort = regexp.MustCompile(`127\.0\.0\.1:[0-9]+`)

func badHost() hostfacts.Facts {
	return hostfacts.Facts{
		EUID: 0, Groups: []string{"root", "docker", "adm", "systemd-journal"}, Sudo: hostfacts.SudoNoPasswd,
		Docker: hostfacts.DockerReachable, DockerHost: true,
		Readable: []string{"/var/log/journal", "/var/lib/docker"}, CredFiles: []string{"~/.aws/credentials"},
		IPCShareable: []string{"shm-1"}, Swarm: "active",
	}
}

func run(t *testing.T, o Options) (string, int, Report) {
	t.Helper()
	r, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	code := Print(&b, r)
	out := b.String()
	for _, s := range []string{"SECRET-VALUE-4242", "AKIA-SECRET", "user_email", `"data"`} {
		if strings.Contains(out, s) {
			t.Errorf("a response body reached the report (%q):\n%s", s, out)
		}
	}
	return hostPort.ReplaceAllString(out, "HOST"), code, r
}

// Every check of an exposed host is a finding, with its remedy; on a
// production profile they are red and doctor fails; response bodies are
// never shown.
func TestDoctorExposedProduction(t *testing.T) {
	open, closed := server(t, http.StatusOK), server(t, http.StatusUnauthorized)
	meta := []Endpoint{{Cloud: "AWS", Method: http.MethodGet, URL: open.URL + "/latest/meta-data/iam/security-credentials/"}}
	out, code, r := run(t, Options{Facts: badHost(), Profiles: profiles(t, false, open.URL, closed.URL), Metadata: meta,
		Landlock: func() (int, string) { return 0, "ENOSYS" }})
	// The Loki sources are non-production (auth none), so this report is
	// warnings; the same host on production is red.
	if code != 0 || r.Production {
		t.Errorf("non-production: exit %d", code)
	}
	golden(t, "exposed-nonprod.txt", []byte(out))

	ps := profiles(t, true)
	out, code, r = run(t, Options{Facts: badHost(), Profiles: ps, Metadata: meta, Landlock: func() (int, string) { return 0, "ENOSYS" }})
	if code != 1 || !r.Production || r.Count() != 10 {
		t.Errorf("production: exit %d, %d findings", code, r.Count())
	}
	golden(t, "exposed-prod.txt", []byte(out))
	if !strings.Contains(out, "  RED   the Docker engine answers") || strings.Contains(out, "warn  the Docker") {
		t.Errorf("production findings are not red:\n%s", out)
	}
}

// A clean host: no finding, exit 0 even on production.
func TestDoctorClean(t *testing.T) {
	meta := []Endpoint{{Cloud: "AWS", Method: http.MethodGet, URL: server(t, http.StatusNotFound).URL}}
	f := hostfacts.Facts{EUID: 1000, Groups: []string{"dev"}, Sudo: hostfacts.SudoAbsent, Docker: hostfacts.DockerAbsent,
		Unreadable: []string{"/var/log/journal", "/var/lib/docker"}, Swarm: "inactive"}
	out, code, r := run(t, Options{Facts: f, Profiles: profiles(t, true), Metadata: meta, Landlock: func() (int, string) { return 5, "" }})
	if code != 0 || r.Count() != 0 || !r.Production {
		t.Errorf("exit %d, %d findings", code, r.Count())
	}
	golden(t, "clean-prod.txt", []byte(out))
}

// Unknown facts are never "ok", and a pinned profile must exist.
func TestDoctorUnknown(t *testing.T) {
	out, _, _ := run(t, Options{Facts: hostfacts.Facts{EUID: -1}, Metadata: []Endpoint{}})
	for _, want := range []string{"?     Docker: unknown", "?     group docker: the account's groups are unknown", "?     sudo: unknown", "?     euid: unknown"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := Run(context.Background(), Options{Profile: "nope", Metadata: []Endpoint{}}); err == nil {
		t.Error("an unknown profile was accepted")
	}
}

// A backend that answers 200 with another API is still a finding; one not
// reachable is not.
func TestBackendProbe(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>SECRET-VALUE-4242</html>")) }))
	defer other.Close()
	lk := config.Source{Name: "s", Kind: config.KindLoki, Remote: &config.Remote{URL: other.URL}}
	it := backendItem(context.Background(), "p/s", lk, 0)
	if !it.Finding || !strings.Contains(it.Text, "API not recognised") || strings.Contains(it.Text, "SECRET") {
		t.Errorf("item = %+v", it)
	}
	other.Close()
	if it := backendItem(context.Background(), "p/s", lk, 0); it.Finding || !strings.Contains(it.Text, "not reachable") {
		t.Errorf("closed: %+v", it)
	}
}

// Elasticsearch and OpenSearch: the probe reads the mappings of the
// source's indices without credentials.
func TestBackendProbeElastic(t *testing.T) {
	var paths []string
	open := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("a probe sent credentials: %v", r.Header)
		}
		paths = append(paths, r.URL.Path)
		if !open {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"SECRET-VALUE-4242"}`))
			return
		}
		w.Write([]byte(`{"logs-a":{"mappings":{"properties":{"user_email":{"type":"keyword"},"note":{"type":"text","meta":"SECRET-VALUE-4242"}}}}}`))
	}))
	defer srv.Close()
	for _, kind := range []string{config.KindElastic, config.KindOpenSearch} {
		paths = nil
		open = true
		src := config.Source{Name: "es", Kind: kind, Remote: &config.Remote{URL: srv.URL, Indices: []string{"logs-*", "audit"}}}
		it := backendItem(context.Background(), "p/es", src, 0)
		if !it.Finding || !strings.Contains(it.Text, "read without credentials") || strings.Contains(it.Text, "SECRET") || strings.Contains(it.Text, "user_email") {
			t.Errorf("%s open: %+v", kind, it)
		}
		if len(paths) != 1 || paths[0] != "/audit,logs-*/_mapping" {
			t.Errorf("%s probed %v", kind, paths)
		}
		open = false
		if it := backendItem(context.Background(), "p/es", src, 0); it.Finding || !strings.Contains(it.Text, "needs credentials (status 401)") {
			t.Errorf("%s closed: %+v", kind, it)
		}
	}
}

// No metadata probe asks for a token (it would mint one on a VM with an
// identity); Azure's answer reads as a possible identity.
func TestMetadataEndpoints(t *testing.T) {
	for _, e := range Metadata {
		if strings.Contains(e.URL, "token") || strings.Contains(e.URL, "oauth2") {
			t.Errorf("%s probes %s, which issues a token", e.Cloud, e.URL)
		}
	}
	s := server(t, http.StatusOK)
	it := metadataItem(context.Background(), Endpoint{Cloud: "Azure", Method: http.MethodGet, URL: s.URL,
		Answers: Metadata[2].Answers}, 0)
	if !it.Finding || !strings.Contains(it.Text, "an identity may be available") || strings.Contains(it.Text, "SECRET") {
		t.Errorf("azure item = %+v", it)
	}
}
