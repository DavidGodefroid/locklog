//go:build integration && linux

// The integration test runs in CI (job "docker source"), in a container
// confined like the console (uid 10051, --group-add 0, no capability,
// read-only, no network), with the containers root bound read-only and
// non-recursive at its own path and the launcher's map at /run/locklog-map.
// Environment:
//
//	LOCKLOG_DOCKER_ROOT  the containers root
//	LL11_GLOB            the approved glob
//	LL11_EXPECT          a directory with one file per approved container,
//	                     named after it: its `docker logs` output
//	LL11_CONSOLE_ID      the id of a console container (label and name)
//	LL11_CONSOLE_NAME    its name

package docker

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

func itEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Skipf("%s is not set: run in the CI job", k)
	}
	return v
}

var itRange = source.Range{From: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}

// itRead returns the raw text of every record, by container name.
func itRead(t *testing.T, s *Source) map[string][]string {
	t.Helper()
	plan, err := s.Plan(ctx, itRange, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range plan.Chunks {
		it, err := s.Scan(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		for {
			r, err := it.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			got[attr(r, ContainerField)] = append(got[attr(r, ContainerField)], r.Event.Raw)
		}
		it.Close()
	}
	return got
}

func TestIntegrationReadsApprovedContainers(t *testing.T) {
	root := itEnv(t, RootEnv)
	glob := itEnv(t, "LL11_GLOB")
	expectDir := itEnv(t, "LL11_EXPECT")
	s, err := New(Options{Name: "it", Containers: []string{glob}, Root: root})
	if err != nil {
		t.Fatal(err)
	}
	got := itRead(t, s)
	ents, err := os.ReadDir(expectDir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("expectations: %v", err)
	}
	want := map[string][]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(expectDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		want[e.Name()] = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	if len(got) != len(want) {
		names := []string{}
		for n := range got {
			names = append(names, n)
		}
		t.Errorf("served containers %q, want %d", names, len(want))
	}
	for name, w := range want {
		g := slices.Clone(got[name])
		sort.Strings(g)
		sort.Strings(w)
		if !slices.Equal(g, w) {
			t.Errorf("%s: %d records, want %d (docker logs)", name, len(g), len(w))
		}
	}
	d, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Each container rotated: the live file and two compressed ones.
	if d.Streams != 3*len(want) {
		t.Errorf("%d streams, want %d (the live and two rotated .gz files each)", d.Streams, 3*len(want))
	}
}

func TestIntegrationNeverServesConsoles(t *testing.T) {
	root := itEnv(t, RootEnv)
	consoleID := itEnv(t, "LL11_CONSOLE_ID")
	consoleName := itEnv(t, "LL11_CONSOLE_NAME")
	m, ok := ReadMap(DefaultMapDir)
	if !ok {
		t.Fatal("no valid map")
	}
	if !m.Consoles[consoleID] {
		t.Errorf("the launcher did not list the console container as excluded")
	}
	for _, c := range m.Containers {
		if c.ID == consoleID {
			t.Errorf("the launcher mapped the console container")
		}
	}
	// A map that maps the console container anyway, read with a glob that
	// matches every name: by its name and by its x line.
	b, err := os.ReadFile(filepath.Join(DefaultMapDir, "map.v"+strconv.FormatUint(m.Version, 10)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	forged := string(b) + "c " + consoleID + " " + consoleName + " 3 1\n"
	if err := os.WriteFile(filepath.Join(dir, "map.v1"), []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	// And under another name, excluded by its x line alone.
	forged = string(b) + "c " + consoleID + " alias-of-the-console 3 1\n"
	if err := os.WriteFile(filepath.Join(dir, "map.v2"), []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"map.v2", "map.v1"} {
		s, err := New(Options{Name: "it", Containers: []string{"*"}, Root: root, MapDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		got := itRead(t, s)
		if len(got[consoleName]) > 0 || len(got["alias-of-the-console"]) > 0 {
			t.Errorf("%s: the console container's logs were served", v)
		}
		if len(got) == 0 {
			t.Errorf("%s: nothing served at all", v)
		}
		os.Remove(filepath.Join(dir, v))
	}
}

func TestIntegrationCannotListOrWrite(t *testing.T) {
	root := itEnv(t, RootEnv)
	m, ok := ReadMap(DefaultMapDir)
	if !ok || len(m.Containers) == 0 {
		t.Fatal("no mapped container")
	}
	id := m.Containers[0].ID
	if _, err := os.ReadDir(root); !errors.Is(err, os.ErrPermission) {
		t.Errorf("listing the containers root: %v", err)
	}
	if _, err := os.ReadDir(filepath.Join(root, id)); !errors.Is(err, os.ErrPermission) {
		t.Errorf("listing a container directory: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(root, id, "config.v2.json")); err == nil {
		t.Error("config.v2.json is readable")
	}
	if _, err := os.ReadFile(filepath.Join(root, id, id+"-json.log")); err != nil {
		t.Errorf("the json log is not readable by name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "x"), nil, 0o644); err == nil {
		t.Error("wrote in the containers root")
	}
	if _, err := os.ReadDir(DefaultMapDir); err != nil {
		t.Errorf("the map directory cannot be listed: %v", err)
	}
}
