//go:build unix

package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

var (
	ctx        = context.Background()
	t0         = time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)
	everything = source.Range{From: t0.Add(-24 * time.Hour), To: t0.Add(24 * time.Hour)}
)

func id(c byte) string { return strings.Repeat(string(c), 64) }

// frames returns n json-file lines "<tag> <i>" one second apart.
func frames(tag string, n int, start time.Time) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"log":"%s %d\n","stream":"stdout","attrs":{"team":"shop","env":"SECRET=1"},"time":"%s"}`+"\n",
			tag, i, start.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
	}
	return b.String()
}

func gz(t *testing.T, s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.String()
}

type env struct {
	t      *testing.T
	root   string
	mapDir string
	now    time.Time
	store  *index.Store
	self   []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: filepath.Join(base, "containers"), mapDir: filepath.Join(base, "map"), now: t0.Add(time.Hour)}
	for _, d := range []string{e.root, e.mapDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if e.store, err = index.Open(filepath.Join(base, "index")); err != nil {
		t.Fatal(err)
	}
	// Docker's modes: 0710 directories (search only for the group).
	if err := os.Chmod(e.root, 0o710); err != nil {
		t.Fatal(err)
	}
	return e
}

// write writes <root>/<id>/<name> (the directory 0710).
func (e *env) write(cid, name, content string) {
	e.t.Helper()
	d := filepath.Join(e.root, cid)
	if err := os.MkdirAll(d, 0o710); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o640); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) writeMap(v int, body string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.mapDir, fmt.Sprintf("map.v%d", v)), []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) source(globs ...string) *Source {
	e.t.Helper()
	s, err := New(Options{Name: "web", Containers: globs, Attrs: []string{"team"}, Root: e.root, MapDir: e.mapDir,
		Trusted: []string{"stream"}, Index: e.store, Now: func() time.Time { return e.now }, Self: func() []string { return e.self }})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func scanAll(t *testing.T, s *Source, sel source.Selector) []source.RawRecord {
	t.Helper()
	plan, err := s.Plan(ctx, everything, sel)
	if err != nil {
		t.Fatal(err)
	}
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		if c.Source != "web" {
			t.Fatalf("chunk source %q", c.Source)
		}
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
			out = append(out, r)
		}
		it.Close()
	}
	return out
}

func attr(r source.RawRecord, k string) string {
	v, _ := parse.Get(r.Event.Attrs, k)
	return v.Str
}

// messages returns "<container>: <message>" per record, sorted.
func messages(rs []source.RawRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, attr(r, ContainerField)+": "+r.Event.Message)
	}
	sort.Strings(out)
	return out
}

func lines(tag string, ns ...int) []string {
	var out []string
	for _, n := range ns {
		out = append(out, fmt.Sprintf("%s: %s %d", strings.SplitN(tag, "|", 2)[0], strings.SplitN(tag, "|", 2)[1], n))
	}
	return out
}

func TestServesOnlyApprovedContainers(t *testing.T) {
	e := newEnv(t)
	a, b, cons, x, self, short := id('a'), id('b'), id('c'), id('d'), id('e'), id('f')
	// a: compressed rotation, max-file 3: the live file, .1.gz and .2.gz.
	e.write(a, a+"-json.log", frames("live", 2, t0.Add(20*time.Second)))
	e.write(a, a+"-json.log.1.gz", gz(t, frames("rot1", 2, t0.Add(10*time.Second))))
	e.write(a, a+"-json.log.2.gz", gz(t, frames("rot2", 2, t0)))
	e.write(a, a+"-json.log.3.gz", gz(t, frames("beyond", 1, t0))) // N >= max-file
	e.write(a, "config.v2.json", `{"log":"config\n"}`+"\n")
	for _, c := range []string{b, cons, x, self, short} {
		e.write(c, c+"-json.log", frames("other", 1, t0))
	}
	e.write(id('9'), id('9')+"-json.log", frames("unmapped", 1, t0))
	e.self = []string{self, short[:12]}
	e.writeMap(1, "locklog-map 1\n"+
		"c "+a+" shop-api-1 3 1\n"+
		"c "+b+" other-1 1 0\n"+
		"c "+cons+" locklog-console-9 1 0\n"+
		"c "+x+" shop-labelled 1 0\n"+
		"c "+self+" shop-self 1 0\n"+
		"c "+short+" shop-short 1 0\n"+
		"x "+x+"\n")
	got := messages(scanAll(t, e.source("shop-*"), source.Selector{}))
	want := append(append(lines("shop-api-1|live", 0, 1), lines("shop-api-1|rot1", 0, 1)...), lines("shop-api-1|rot2", 0, 1)...)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("served\n%q\nwant\n%q", got, want)
	}
	// Even a glob matching everything never serves a console container
	// (by name, by the map's x line, by the console's own id).
	got = messages(scanAll(t, e.source("*"), source.Selector{}))
	want = append(want, "other-1: other 0")
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Errorf("served with '*'\n%q\nwant\n%q", got, want)
	}
}

func TestRecordsCarryTrustedFields(t *testing.T) {
	e := newEnv(t)
	a := id('a')
	e.write(a, a+"-json.log", `{"log":"{\"container\":\"spoof\",\"msg\":\"par","stream":"stderr","time":"2026-10-31T01:00:05.5Z"}`+"\n"+
		`{"log":"t\"}\n","stream":"stderr","time":"2026-10-31T01:00:06Z"}`+"\n")
	e.writeMap(1, "locklog-map 1\nc "+a+" shop-api-1 1 0\n")
	s := e.source("shop-*")
	rs := scanAll(t, s, source.Selector{})
	if len(rs) != 1 {
		t.Fatalf("%d records", len(rs))
	}
	r := rs[0]
	if r.Event.Message != "part" || !r.Event.Time.Equal(t0.Add(5500*time.Millisecond)) || attr(r, "stream") != "stderr" ||
		attr(r, ContainerField) != "shop-api-1" || attr(r, "attrs.env") != "" {
		t.Fatalf("%+v", r.Event)
	}
	if v, _ := index.Lookup(r.Event, ContainerField); v != "shop-api-1" {
		t.Errorf("the payload's container field stands for the trusted one: %q", v)
	}
	if !strings.HasPrefix(r.Ref.Stream, a+"/shop-api-1/") || r.Ref.Source != "web" {
		t.Errorf("ref %+v", r.Ref)
	}
	// Reread and Around through the wrapped stream.
	got, err := s.Reread(ctx, r.Ref)
	if err != nil || got.Event.Message != "part" || got.Ref != r.Ref {
		t.Fatalf("reread: %+v %v", got, err)
	}
	around, err := s.Around(ctx, r.Ref, 2, 2)
	if err != nil || len(around) != 1 || around[0].Ref != r.Ref {
		t.Fatalf("around: %+v %v", around, err)
	}
	if _, err := s.Reread(ctx, source.RawRef{Source: "web", Stream: id('b') + "/x/1-2-3"}); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("unknown container: %v", err)
	}
	if _, err := s.Reread(ctx, source.RawRef{Source: "web", Stream: "../../etc/passwd"}); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("bad stream: %v", err)
	}
}

func TestMapChangesPickedUp(t *testing.T) {
	e := newEnv(t)
	a, b := id('a'), id('b')
	e.write(a, a+"-json.log", frames("a", 2, t0))
	e.write(b, b+"-json.log", frames("b", 1, t0))
	s := e.source("shop-*")
	if rs := scanAll(t, s, source.Selector{}); len(rs) != 0 {
		t.Fatalf("no map: %d records", len(rs))
	}
	e.writeMap(1, "locklog-map 1\nc "+a+" shop-a 1 0\n")
	e.now = e.now.Add(3 * time.Second)
	rs := scanAll(t, s, source.Selector{})
	if got := messages(rs); !slices.Equal(got, lines("shop-a|a", 0, 1)) {
		t.Fatalf("v1: %q", got)
	}
	ref := rs[0].Ref
	// v2: a renamed, b added.
	e.writeMap(2, "locklog-map 1\nc "+a+" shop-a2 1 0\nc "+b+" shop-b 1 0\n")
	e.now = e.now.Add(3 * time.Second)
	if got := messages(scanAll(t, s, source.Selector{})); !slices.Equal(got, append(lines("shop-a2|a", 0, 1), "shop-b: b 0")) {
		t.Fatalf("v2: %q", got)
	}
	if _, err := s.Reread(ctx, ref); !errors.Is(err, source.ErrStale) {
		t.Errorf("a reference from before the rename: %v", err)
	}
	// A malformed newest version serves nothing (no fallback to v2).
	e.writeMap(3, "locklog-map 1\nc "+a+" shop-a3 1 0\nbroken\n")
	e.now = e.now.Add(3 * time.Second)
	if rs := scanAll(t, s, source.Selector{}); len(rs) != 0 {
		t.Fatalf("malformed newest map: %d records", len(rs))
	}
	// v4: b gone.
	e.writeMap(4, "locklog-map 1\nc "+a+" shop-a2 1 0\n")
	e.now = e.now.Add(3 * time.Second)
	if got := messages(scanAll(t, s, source.Selector{})); !slices.Equal(got, lines("shop-a2|a", 0, 1)) {
		t.Fatalf("v4: %q", got)
	}
	// Every version malformed or removed: nothing served.
	for _, v := range []int{1, 2, 3, 4} {
		os.Remove(filepath.Join(e.mapDir, fmt.Sprintf("map.v%d", v)))
	}
	e.now = e.now.Add(3 * time.Second)
	if rs := scanAll(t, s, source.Selector{}); len(rs) != 0 {
		t.Fatalf("no valid map: %d records", len(rs))
	}
}

func TestIndexCountsAndSelector(t *testing.T) {
	e := newEnv(t)
	a, b := id('a'), id('b')
	e.write(a, a+"-json.log", frames("a", 3, t0))
	e.write(b, b+"-json.log", frames("b", 2, t0))
	e.writeMap(1, "locklog-map 1\nc "+a+" shop-a 1 0\nc "+b+" shop-b 1 0\n")
	s := e.source("shop-*")
	sel := source.Selector{Terms: []source.Term{{Field: ContainerField, Op: "=", Values: []string{"shop-b"}}}}
	if got := messages(scanAll(t, s, sel)); !slices.Equal(got, lines("shop-b|b", 0, 1)) {
		t.Fatalf("selector: %q", got)
	}
	for {
		_, done, err := s.IndexStep(ctx, 1<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
	}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: everything, By: []string{ContainerField}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range res.Rows {
		got[r.Vals[0]] += r.N
	}
	if got["shop-a"] != 3 || got["shop-b"] != 2 || len(got) != 2 || len(res.Residual.Chunks) != 0 || !res.IndexedFrom.Equal(t0) {
		t.Fatalf("counts %v residual %d from %v", got, len(res.Residual.Chunks), res.IndexedFrom)
	}
	res, err = s.IndexCounts(ctx, source.CountQuery{Range: everything, Selector: sel, By: []string{"stream"}})
	if err != nil || len(res.Rows) != 1 || res.Rows[0].N != 2 || res.Rows[0].Vals[0] != "stdout" {
		t.Fatalf("selected counts %+v %v", res, err)
	}
	d, err := s.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != Kind || d.Streams != 2 || !d.FullyIndexed || d.Format != "docker-json" {
		t.Fatalf("describe %+v", d)
	}
	for _, f := range d.Fields {
		if f.Name == ContainerField && !slices.Equal(f.Values, []string{"shop-a", "shop-b"}) {
			t.Errorf("container values %v", f.Values)
		}
	}
}

func TestParseMap(t *testing.T) {
	a := id('a')
	ok := []string{
		"locklog-map 1\n",
		"locklog-map 1\nc " + a + " shop-api-1 3 1\nx " + id('b') + "\n",
	}
	for _, s := range ok {
		if _, err := ParseMap([]byte(s)); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	bad := []string{
		"",
		"locklog-map 1",
		"locklog-map 2\n",
		"locklog-map 1\n\n",
		"locklog-map 1\nc " + a + " shop 1 0",
		"locklog-map 1\nc " + strings.ToUpper(a) + " shop 1 0\n",
		"locklog-map 1\nc " + a[:63] + " shop 1 0\n",
		"locklog-map 1\nc " + a + " shop* 1 0\n",
		"locklog-map 1\nc " + a + " -shop 1 0\n",
		"locklog-map 1\nc " + a + " shop 0 0\n",
		"locklog-map 1\nc " + a + " shop 101 0\n",
		"locklog-map 1\nc " + a + " shop 01 0\n",
		"locklog-map 1\nc " + a + " shop 1 2\n",
		"locklog-map 1\nc " + a + " shop 1 0 extra\n",
		"locklog-map 1\nc " + a + "  shop 1 0\n",
		"locklog-map 1\nc " + a + " shop 1 0\nc " + a + " shop2 1 0\n",
		"locklog-map 1\nc " + a + " shop 1 0\nc " + id('b') + " shop 1 0\n",
		"locklog-map 1\nx " + a + "\nx " + a + "\n",
		"locklog-map 1\nx shop\n",
		"locklog-map 1\ny " + a + "\n",
		"locklog-map 1\r\n",
	}
	for _, s := range bad {
		if _, err := ParseMap([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		} else if strings.Contains(err.Error(), "shop") {
			t.Errorf("the error holds map content: %v", err)
		}
	}
	for name, want := range map[string]bool{"map.v1": true, "map.v42": true, "map.v0": false, "map.v01": false,
		"map.v": false, "map.v1.tmp": false, "map.v-1": false, ".map.v1": false, "map.v1234567890123456789": false} {
		if _, got := mapVersion(name); got != want {
			t.Errorf("mapVersion(%q) = %v", name, got)
		}
	}
}

func TestReadMapNewestValid(t *testing.T) {
	e := newEnv(t)
	a := id('a')
	if _, ok := ReadMap(e.mapDir); ok {
		t.Error("empty dir: a map")
	}
	if _, ok := ReadMap(filepath.Join(e.mapDir, "missing")); ok {
		t.Error("missing dir: a map")
	}
	e.writeMap(1, "locklog-map 1\nc "+a+" one 1 0\n")
	e.writeMap(9, "locklog-map 1\nc "+a+" nine 1 0\n")
	e.writeMap(10, "locklog-map 1\nc "+a+" ten 1 0\n")
	// A symbolic link is not a version.
	if err := os.Symlink(filepath.Join(e.mapDir, "map.v1"), filepath.Join(e.mapDir, "map.v12")); err != nil {
		t.Fatal(err)
	}
	m, ok := ReadMap(e.mapDir)
	if !ok || m.Version != 10 || m.Containers[0].Name != "ten" {
		t.Fatalf("%+v %v", m, ok)
	}
	// A malformed newest version: nothing, never v10 (fail closed).
	e.writeMap(11, "garbage\n")
	if m, ok := ReadMap(e.mapDir); ok {
		t.Fatalf("fell back to %+v", m)
	}
}

func TestSelfFromMountinfo(t *testing.T) {
	a := id('a')
	mi := "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw\n" +
		"600 590 8:1 /var/lib/docker/containers/" + a + "/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n" +
		"601 590 8:1 /lib/docker/containers/" + a + "/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n" +
		"602 590 8:1 /containers/" + id('b') + "/x /data rw - ext4 /dev/sda1 rw\n"
	got := selfFromMountinfo(strings.NewReader(mi))
	if !slices.Equal(got, []string{a, a}) {
		t.Errorf("%q", got)
	}
	if !isSelf([]string{a[:12]}, a) || isSelf([]string{a[:11]}, a) || isSelf(nil, a) {
		t.Error("isSelf")
	}
}

func TestNewRefusals(t *testing.T) {
	for _, o := range []Options{
		{Name: "", Containers: []string{"a"}, Root: "/r"},
		{Name: "d", Root: "/r"},
		{Name: "d", Containers: []string{"[ab]"}, Root: "/r"},
		{Name: "d", Containers: []string{"a/b"}, Root: "/r"},
		{Name: "d", Containers: []string{"a"}, Root: "r"},
		{Name: "d", Containers: []string{"a"}, Root: "/"},
		{Name: "d", Containers: []string{"a"}, Root: "/r/../s"},
	} {
		o.Self = func() []string { return nil }
		if _, err := New(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

// With compression, .1 is read while it exists (Docker gzips it in the
// background, and the .1.gz beside it is still being written), else .1.gz;
// never both.
func TestFirstRotationBeforeCompression(t *testing.T) {
	e := newEnv(t)
	a := id('a')
	e.write(a, a+"-json.log", frames("live", 1, t0.Add(time.Minute)))
	e.write(a, a+"-json.log.1", frames("rot1", 2, t0))
	e.write(a, a+"-json.log.1.gz", gz(t, frames("rot1", 1, t0))[:10]) // partial
	e.writeMap(1, "locklog-map 1\nc "+a+" shop-a 2 1\n")
	s := e.source("shop-*")
	want := append(lines("shop-a|live", 0), lines("shop-a|rot1", 0, 1)...)
	sort.Strings(want)
	if got := messages(scanAll(t, s, source.Selector{})); !slices.Equal(got, want) {
		t.Fatalf(".1 and a partial .1.gz: %q", got)
	}
	// Compressed: .1 gone, .1.gz complete.
	os.Remove(filepath.Join(e.root, a, a+"-json.log.1"))
	e.write(a, a+"-json.log.1.gz", gz(t, frames("rot1", 2, t0)))
	e.now = e.now.Add(time.Minute)
	if got := messages(scanAll(t, s, source.Selector{})); !slices.Equal(got, want) {
		t.Fatalf(".1.gz: %q", got)
	}
}

// countsBy indexes s fully, then counts its records by container.
func countsBy(t *testing.T, s *Source, index bool, sel source.Selector) (map[string]int64, source.CountResult) {
	t.Helper()
	for index {
		_, done, err := s.IndexStep(ctx, 1<<20, true)
		if err != nil {
			t.Fatal(err)
		}
		index = !done
	}
	res, err := s.IndexCounts(ctx, source.CountQuery{Range: everything, Selector: sel, By: []string{ContainerField}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range res.Rows {
		got[r.Vals[0]] += r.N
	}
	return got, res
}

// The index counts the container name: a renamed container's granules are
// rebuilt, never counted under the old name, whether the rename is seen
// directly, across a restart, or through a name that is not served.
func TestIndexFollowsRenames(t *testing.T) {
	a := id('a')
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		e.write(a, a+"-json.log", frames("a", 3, t0))
		e.writeMap(1, "locklog-map 1\nc "+a+" shop-a 1 0\n")
		if got, _ := countsBy(t, e.source("shop-*"), true, source.Selector{}); got["shop-a"] != 3 {
			t.Fatalf("before: %v", got)
		}
		return e
	}
	check := func(t *testing.T, e *env, s *Source, name string) {
		t.Helper()
		// Before indexing again: nothing under the old name, the rest a
		// residual to scan.
		got, res := countsBy(t, s, false, source.Selector{})
		if got["shop-a"] != 0 || len(res.Residual.Chunks) == 0 {
			t.Errorf("stale counts %v, residual %d", got, len(res.Residual.Chunks))
		}
		sel := source.Selector{Terms: []source.Term{{Field: ContainerField, Op: "=", Values: []string{name}}}}
		got, res = countsBy(t, s, true, sel)
		if got[name] != 3 || len(got) != 1 || len(res.Residual.Chunks) != 0 {
			t.Errorf("after indexing: %v, residual %d", got, len(res.Residual.Chunks))
		}
	}
	t.Run("direct", func(t *testing.T) {
		e := setup(t)
		s := e.source("shop-*")
		countsBy(t, s, false, source.Selector{})
		e.writeMap(2, "locklog-map 1\nc "+a+" shop-a2 1 0\n")
		e.now = e.now.Add(3 * time.Second)
		check(t, e, s, "shop-a2")
	})
	t.Run("restart", func(t *testing.T) {
		e := setup(t)
		if err := e.store.Flush(); err != nil {
			t.Fatal(err)
		}
		st, err := index.Open(e.store.Dir())
		if err != nil {
			t.Fatal(err)
		}
		e.store = st
		e.writeMap(2, "locklog-map 1\nc "+a+" shop-a2 1 0\n")
		check(t, e, e.source("shop-*"), "shop-a2")
	})
	t.Run("through an unserved name", func(t *testing.T) {
		e := setup(t)
		s := e.source("shop-*")
		countsBy(t, s, false, source.Selector{})
		e.writeMap(2, "locklog-map 1\nc "+a+" tmp-a 1 0\n")
		e.now = e.now.Add(3 * time.Second)
		if got, _ := countsBy(t, s, false, source.Selector{}); len(got) != 0 {
			t.Errorf("an unserved name counted: %v", got)
		}
		e.writeMap(3, "locklog-map 1\nc "+a+" shop-a3 1 0\n")
		e.now = e.now.Add(3 * time.Second)
		check(t, e, s, "shop-a3")
	})
}

// Every container's file source refuses to cross a mount point, whatever
// the map says.
func TestFileSourcesNeverCrossMounts(t *testing.T) {
	e := newEnv(t)
	s := e.source("*")
	for _, c := range []Container{{ID: id('a'), Name: "a", MaxFile: 1}, {ID: id('b'), Name: "b", MaxFile: 100, Compress: true}} {
		fo, err := s.fileOptions(c)
		if err != nil {
			t.Fatal(err)
		}
		if !fo.NoXDev || len(fo.Roots) != 1 || fo.Roots[0] != e.root || fo.Recursive || fo.Tag != c.Name {
			t.Errorf("%s: %+v", c.Name, fo)
		}
		for _, p := range append(slices.Clone(fo.Paths), fo.Alternates[fo.Paths[min(1, len(fo.Paths)-1)]]) {
			if p != "" && !strings.HasPrefix(p, e.root+"/"+c.ID+"/"+c.ID+"-json.log") {
				t.Errorf("%s: path %s", c.Name, p)
			}
		}
	}
}
