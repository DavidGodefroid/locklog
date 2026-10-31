//go:build unix

package file

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

var levels = []string{"info", "info", "info", "warn", "error"}

// genLines returns n logfmt lines, one every second from start; every 7th
// record is followed by an indented stack frame.
func genLines(start time.Time, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		fmt.Fprintf(&b, "time=%s level=%s status=%d msg=\"request %d handled with some padding text to make lines longer\"\n",
			ts, levels[i%len(levels)], 200+100*(i%4), i)
		if i%7 == 0 {
			b.WriteString("  at frame.go:12\n")
		}
	}
	return b.String()
}

type env struct {
	t     *testing.T
	root  string
	store *index.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := index.Open(filepath.Join(t.TempDir(), "index"))
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, root: root, store: st}
}

func (e *env) write(rel, content string, mtime time.Time) string {
	e.t.Helper()
	p := filepath.Join(e.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			e.t.Fatal(err)
		}
	}
	return p
}

func (e *env) source(paths []string, opts ...func(*Options)) *Source {
	e.t.Helper()
	p, err := parse.New(parse.Options{})
	if err != nil {
		e.t.Fatal(err)
	}
	o := Options{Name: "app", Paths: paths, Roots: []string{e.root}, Parser: p, Trusted: []string{"level", "status"}, Index: e.store}
	for _, f := range opts {
		f(&o)
	}
	s, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

var ctx = context.Background()

func all(t *testing.T, it source.Iterator) []source.RawRecord {
	t.Helper()
	defer it.Close()
	var out []source.RawRecord
	for {
		r, err := it.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
}

func scanPlan(t *testing.T, s *Source, plan source.Byteplan) []source.RawRecord {
	t.Helper()
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		it, err := s.Scan(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, all(t, it)...)
	}
	return out
}

var everything = source.Range{From: t0.Add(-24 * time.Hour), To: t0.Add(24 * time.Hour)}

func TestGranuleChunksAgreeWithWholeScan(t *testing.T) {
	e := newEnv(t)
	content := genLines(t0, 30000) // ~3.8 MiB: 4 granules
	e.write("logs/app.log", content, time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	plan, err := s.Plan(ctx, everything, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Chunks) != 1 || plan.Granules() != 4 || plan.Bytes() != int64(len(content)) {
		t.Fatalf("plan %d chunks, %d granules, %d bytes", len(plan.Chunks), plan.Granules(), plan.Bytes())
	}
	whole := scanPlan(t, s, plan)
	// Granule by granule, each read on its own.
	var parts []source.RawRecord
	c := plan.Chunks[0]
	for i := range c.Granules {
		one := c
		one.Granules = c.Granules[i : i+1]
		got := scanPlan(t, s, source.Byteplan{Chunks: []source.Chunk{one}})
		for _, r := range got {
			if int64(r.Granule) != one.Start()/source.GranuleBytes {
				t.Fatalf("record at %d in granule %d", r.Ref.Offset, r.Granule)
			}
		}
		parts = append(parts, got...)
	}
	if !reflect.DeepEqual(whole, parts) {
		t.Fatalf("whole %d records, by granule %d", len(whole), len(parts))
	}
	// Every line is in some record exactly once.
	var raws []string
	for _, r := range whole {
		raws = append(raws, r.Event.Raw)
	}
	if got := strings.Join(raws, "\n") + "\n"; got != content {
		t.Fatal("records do not reassemble the file")
	}
}

func TestCompressedFilesScanLikePlain(t *testing.T) {
	e := newEnv(t)
	content := genLines(t0, 12000)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(content))
	zw.Close()
	enc, _ := zstd.NewWriter(nil)
	zs := enc.EncodeAll([]byte(content), nil)
	e.write("logs/plain.log", content, t0)
	e.write("logs/a.log.1.gz", gz.String(), t0)
	e.write("logs/a.log.2.zst", string(zs), t0)
	text := func(recs []source.RawRecord) []string {
		var out []string
		for _, r := range recs {
			out = append(out, fmt.Sprint(r.Ref.Offset, r.Ref.Length, r.Event.Raw, r.Event.Time))
		}
		return out
	}
	var want []string
	for _, name := range []string{"plain.log", "a.log.1.gz", "a.log.2.zst"} {
		s := e.source([]string{e.root + "/logs/" + name})
		plan, err := s.Plan(ctx, everything, source.Selector{})
		if err != nil {
			t.Fatal(err)
		}
		got := text(scanPlan(t, s, plan))
		if want == nil {
			want = got
			continue
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: %d records differ from plain (%d)", name, len(got), len(want))
		}
		// Once indexed, the compressed stream has exact granules and
		// scanning one granule alone gives the same records.
		if _, _, err := s.IndexStep(ctx, 1<<40, true); err != nil {
			t.Fatal(err)
		}
		plan, _ = s.Plan(ctx, everything, source.Selector{})
		if plan.Granules() != 2 || !plan.Chunks[0].Granules[1].Indexed {
			t.Fatalf("%s: indexed plan %+v", name, plan)
		}
		c := plan.Chunks[0]
		c.Granules = c.Granules[1:]
		second := text(scanPlan(t, s, source.Byteplan{Chunks: []source.Chunk{c}}))
		if len(second) == 0 || !slices.Equal(second, want[len(want)-len(second):]) {
			t.Fatalf("%s: second granule alone differs", name)
		}
	}
}

func TestDecompressionRatioCap(t *testing.T) {
	e := newEnv(t)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(bytes.Repeat([]byte("a"), 64<<20))
	zw.Close()
	e.write("logs/bomb.gz", gz.String(), time.Time{})
	s := e.source([]string{e.root + "/logs/bomb.gz"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	it, err := s.Scan(ctx, plan.Chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	for {
		_, err := it.Next()
		if err == nil {
			continue
		}
		if !errors.Is(err, errRatio) {
			t.Fatalf("want the ratio error, got %v", err)
		}
		break
	}
	if it.Processed() > 101*int64(gz.Len())+(4<<20) {
		t.Fatalf("processed %d bytes past the cap", it.Processed())
	}
}

func TestGlobs(t *testing.T) {
	e := newEnv(t)
	for _, f := range []string{"logs/a.log", "logs/a.log.1", "logs/b.txt", "logs/x/1/a.log", "logs/x/1/2/3/a.log", "logs/x/1/2/3/4/a.log"} {
		e.write(f, "line\n", time.Time{})
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.log"), []byte("s\n"), 0o644)
	os.Symlink(filepath.Join(outside, "secret.log"), filepath.Join(e.root, "logs/link.log"))
	os.Symlink(outside, filepath.Join(e.root, "logs/x/linkdir"))
	syscall.Mkfifo(filepath.Join(e.root, "logs/fifo.log"), 0o644)
	rels := func(pattern string, rec bool) []string {
		ms, err := expand([]string{e.root}, e.root+pattern, rec)
		if err != nil {
			t.Fatalf("%s: %v", pattern, err)
		}
		var out []string
		for _, m := range ms {
			out = append(out, m.rel)
		}
		return out
	}
	if got := rels("/logs/a.log*", false); !slices.Equal(got, []string{"logs/a.log", "logs/a.log.1"}) {
		t.Fatal(got)
	}
	if got := rels("/logs/*.log", false); !slices.Equal(got, []string{"logs/a.log"}) {
		t.Fatalf("symlink or fifo matched: %v", got)
	}
	if got := rels("/logs/**/*.log", true); !slices.Equal(got, []string{"logs/a.log", "logs/x/1/2/3/a.log", "logs/x/1/a.log"}) {
		t.Fatalf("** then a wildcard: %v", got)
	}
	got := rels("/logs/**/a.log", true)
	want := []string{"logs/a.log", "logs/x/1/2/3/a.log", "logs/x/1/a.log"}
	if !slices.Equal(got, want) {
		t.Fatalf("recursive: %v (depth > 4 and linked dirs must not match)", got)
	}
	for _, bad := range []struct {
		p   string
		rec bool
	}{
		{"/logs/**/a.log", false}, {"/logs/../etc/passwd", false}, {"/logs/a**b", true},
		{"/logs/**/x/**/a", true}, {"/logs/**", true}, {"logs/a.log", false},
	} {
		if _, err := expand([]string{e.root}, e.root+bad.p, bad.rec); err == nil {
			t.Fatalf("%s accepted", bad.p)
		}
	}
	if _, err := expand([]string{e.root + "/logs/x"}, e.root+"/logs/a.log", false); err == nil {
		t.Fatal("a path outside every root was accepted")
	}
	if _, err := New(Options{Name: "a", Paths: []string{"/etc/passwd"}, Roots: []string{e.root}, Parser: mustParser(t)}); err == nil {
		t.Fatal("New accepted a path outside the roots")
	}
}

func mustParser(t *testing.T) *parse.Parser {
	p, err := parse.New(parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenRefusesSymlinkComponents(t *testing.T) {
	e := newEnv(t)
	e.write("logs/real/a.log", "x\n", time.Time{})
	os.Symlink(filepath.Join(e.root, "logs/real"), filepath.Join(e.root, "logs/via"))
	for name, open := range map[string]func(string, string) (*os.File, error){"beneath": openBeneath, "walk": walkOpen} {
		if f, err := open(e.root, "logs/real/a.log"); err != nil {
			t.Fatalf("%s: %v", name, err)
		} else {
			f.Close()
		}
		if f, err := open(e.root, "logs/via/a.log"); err == nil {
			f.Close()
			t.Fatalf("%s: opened through a symlinked directory", name)
		}
		if f, err := open(e.root, "logs/../logs/real/a.log"); err == nil {
			f.Close()
			t.Fatalf("%s: '..' accepted", name)
		}
	}
}

func TestNoWriteFlagsInSources(t *testing.T) {
	// Read-only by construction: no source file opens for writing.
	for _, dir := range []string{".", ".."} {
		ents, _ := os.ReadDir(dir)
		for _, en := range ents {
			if en.IsDir() || !strings.HasSuffix(en.Name(), ".go") || strings.HasSuffix(en.Name(), "_test.go") {
				continue
			}
			b, _ := os.ReadFile(filepath.Join(dir, en.Name()))
			for _, bad := range []string{"O_CREAT", "O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND", "os.Create", "os.OpenFile", "WriteFile",
				"os.Remove", "os.Rename", "Chmod", "Chtimes", "os.Truncate", "Ftruncate", "os.Link", "Symlink", "Mkdir", "Unlinkat", "Renameat", "Fchmod", "Mknod", "Linkat"} {
				if bytes.Contains(b, []byte(bad)) {
					t.Errorf("%s uses %s", en.Name(), bad)
				}
			}
		}
	}
}

// fullCounts counts records by (minute bucket, level) from a full scan.
func fullCounts(t *testing.T, s *Source, r source.Range, bucket time.Duration) map[string]int64 {
	t.Helper()
	plan, err := s.Plan(ctx, r, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, rec := range scanPlan(t, s, plan) {
		ev := rec.Event
		if !ev.HasTime && !ev.Inherited || !r.Contains(ev.Time.Truncate(time.Minute)) {
			continue
		}
		lvl, _ := index.Lookup(ev, "level")
		b := r.From.Add(ev.Time.Truncate(time.Minute).Sub(r.From) / bucket * bucket)
		out[b.String()+"|"+lvl]++
	}
	return out
}

// indexPlusResidual answers the count from the index and scans the
// residual plan, as the engine does for partly indexed ranges.
func indexPlusResidual(t *testing.T, s *Source, r source.Range, bucket time.Duration) (map[string]int64, CountResult) {
	t.Helper()
	res, err := s.IndexCounts(ctx, CountQuery{Range: r, By: []string{"level"}, Bucket: bucket})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, row := range res.Rows {
		out[row.Bucket.String()+"|"+row.Vals[0]] += row.N
	}
	for _, rec := range scanPlan(t, s, res.Residual) {
		ev := rec.Event
		if !ev.HasTime && !ev.Inherited || !r.Contains(ev.Time.Truncate(time.Minute)) {
			continue
		}
		lvl, _ := index.Lookup(ev, "level")
		b := r.From.Add(ev.Time.Truncate(time.Minute).Sub(r.From) / bucket * bucket)
		out[b.String()+"|"+lvl]++
	}
	return out, res
}

func TestColdStartNewestFirstBackfill(t *testing.T) {
	e := newEnv(t)
	// Two rotated files: app.log.1 (older) and app.log (newer).
	e.write("logs/app.log.1", genLines(t0, 20000), t0.Add(20000*time.Second))
	e.write("logs/app.log", genLines(t0.Add(20000*time.Second), 20000), t0.Add(40000*time.Second))
	s := e.source([]string{e.root + "/logs/app.log*"})
	r := source.Range{From: t0, To: t0.Add(40020 * time.Second)} // whole minutes
	want := fullCounts(t, s, r, 10*time.Minute)

	sch, _ := s.Describe(ctx)
	if !sch.IndexedFrom.IsZero() || sch.FullyIndexed {
		t.Fatalf("cold: %+v", sch)
	}
	var prev time.Time
	steps := 0
	for {
		got, res := indexPlusResidual(t, s, r, 10*time.Minute)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d: index + residual scan differs from a full scan", steps)
		}
		sch, _ := s.Describe(ctx)
		if !res.IndexedFrom.Equal(sch.IndexedFrom) {
			t.Fatal("count and describe disagree on indexed_from")
		}
		if steps > 0 {
			// Newest first: indexed_from only moves back in time.
			if sch.IndexedFrom.IsZero() || !prev.IsZero() && sch.IndexedFrom.After(prev) {
				t.Fatalf("step %d: indexed_from %v after %v", steps, sch.IndexedFrom, prev)
			}
			if steps == 1 && !sch.IndexedFrom.After(t0.Add(20000*time.Second)) {
				t.Fatalf("first step did not index the newest granule first: %v", sch.IndexedFrom)
			}
		}
		prev = sch.IndexedFrom
		if sch.FullyIndexed {
			if len(res.Residual.Chunks) != 0 {
				t.Fatal("fully indexed but a residual plan remains")
			}
			break
		}
		_, done, err := s.IndexStep(ctx, 1<<20, true) // one granule per step
		if err != nil {
			t.Fatal(err)
		}
		steps++
		if done && steps > 1 {
			sch, _ := s.Describe(ctx)
			if !sch.FullyIndexed {
				t.Fatal("done but not fully indexed")
			}
		}
		if steps > 50 {
			t.Fatal("index never completes")
		}
	}
	if !prev.Equal(t0) {
		t.Fatalf("fully indexed from %v, want %v", prev, t0)
	}
	// The index survives a restart.
	if err := e.store.Flush(); err != nil {
		t.Fatal(err)
	}
	st2, err := index.Open(filepath.Dir(filepath.Join(e.store.Dir(), "x")))
	if err != nil {
		t.Fatal(err)
	}
	s2 := e.source([]string{e.root + "/logs/app.log*"}, func(o *Options) { o.Index = st2 })
	if sch, _ := s2.Describe(ctx); !sch.FullyIndexed {
		t.Fatal("index lost across a restart")
	}
	got, res := indexPlusResidual(t, s2, r, 10*time.Minute)
	if !reflect.DeepEqual(got, want) || len(res.Residual.Chunks) != 0 {
		t.Fatal("reloaded index answers differently")
	}
}

func TestPlanFiltersIndexedGranules(t *testing.T) {
	e := newEnv(t)
	e.write("logs/app.log", genLines(t0, 30000), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	s.IndexStep(ctx, 1<<40, true)
	// The last ~10 minutes are in the last granule only.
	r := source.Range{From: t0.Add(29400 * time.Second), To: t0.Add(30000 * time.Second)}
	plan, _ := s.Plan(ctx, r, source.Selector{})
	if plan.Granules() != 1 {
		t.Fatalf("%d granules for the last 10 minutes", plan.Granules())
	}
	// A selector on an indexed field with no match plans nothing.
	plan, _ = s.Plan(ctx, everything, source.Selector{Terms: []source.Term{{Field: "level", Op: "=", Values: []string{"fatal"}}}})
	if plan.Granules() != 0 {
		t.Fatal("selector on an absent value planned granules")
	}
	// A selector on a field the index does not hold plans everything.
	plan, _ = s.Plan(ctx, everything, source.Selector{Terms: []source.Term{{Field: "host", Op: "=", Values: []string{"a"}}}})
	if plan.Granules() != 4 {
		t.Fatal("selector on an unindexed field filtered granules")
	}
	if _, err := s.IndexCounts(ctx, CountQuery{Range: everything, By: []string{"host"}, Bucket: time.Minute}); !errors.Is(err, ErrNotIndexable) {
		t.Fatalf("count by an unindexed field: %v", err)
	}
}

func TestIndexRedactsAndDropsHighCardinality(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "time=%s level=%s user=u%d@example.com status=%d\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), levels[i%5], i%10, i)
	}
	e.write("logs/app.log", b.String(), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"}, func(o *Options) {
		o.Trusted = []string{"level", "status", "user"}
		o.Sensitive = func(f, v string) bool { return strings.Contains(v, "@") }
	})
	s.IndexStep(ctx, 1<<40, true)
	sch, _ := s.Describe(ctx)
	for _, f := range sch.Fields {
		switch f.Name {
		case "status":
			if f.Values != nil {
				t.Fatal("high-cardinality status still indexed")
			}
		case "user":
			for _, v := range f.Values {
				if strings.Contains(v, "@") {
					t.Fatal("detected value indexed in clear")
				}
			}
		case "level":
			if !slices.Equal(f.Values, []string{"error", "info", "warn"}) {
				t.Fatalf("level values %v", f.Values)
			}
		}
	}
	res, err := s.IndexCounts(ctx, CountQuery{Range: everything, By: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}
	// Redacted values cannot be counted by the index: those granules
	// go to the residual scan (the masker then shows pseudonyms).
	if len(res.Rows) != 0 || res.Residual.Granules() == 0 {
		t.Fatalf("%+v", res)
	}
	// A selector on a redacted value keeps the granule in the plan.
	plan, _ := s.Plan(ctx, everything, source.Selector{Terms: []source.Term{{Field: "user", Op: "=", Values: []string{"u1@example.com"}}}})
	if plan.Granules() == 0 {
		t.Fatal("a granule with redacted values was planned out")
	}
	if _, err := s.IndexCounts(ctx, CountQuery{Range: everything, By: []string{"status"}}); !errors.Is(err, ErrNotIndexable) {
		t.Fatal("count by a dropped field served from the index")
	}
	// Files on disk are private.
	filepath.Walk(e.store.Dir(), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", p, fi.Mode().Perm())
		}
		return nil
	})
	e.store.Flush()
}

func TestRotationAndGrowth(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", "time=2026-10-30T12:00:00Z level=info msg=a\n", time.Time{})
	s := e.source([]string{e.root + "/logs/app.log*"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	id1 := plan.Chunks[0].Stream
	recs := scanPlan(t, s, plan)
	ref := recs[0].Ref
	s.IndexStep(ctx, 1<<40, true)

	// Growth keeps the stream (and its index, re-indexing the tail).
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("time=2026-10-30T12:00:01Z level=error msg=b\n")
	f.Close()
	plan, _ = s.Plan(ctx, everything, source.Selector{})
	if plan.Chunks[0].Stream != id1 || plan.Chunks[0].Granules[0].Indexed {
		t.Fatalf("grown file: %+v", plan.Chunks[0])
	}
	s.IndexStep(ctx, 1<<40, true)
	res, _ := s.IndexCounts(ctx, CountQuery{Range: everything, By: []string{"level"}})
	if len(res.Rows) != 2 || len(res.Residual.Chunks) != 0 {
		t.Fatalf("after growth: %+v", res)
	}

	// Rotation by rename keeps the stream id: old refs still resolve.
	os.Rename(p, p+".1")
	e.write("logs/app.log", "time=2026-10-30T13:00:00Z level=info msg=new\n", time.Time{})
	if rec, err := s.Reread(ctx, ref); err != nil || !strings.Contains(rec.Event.Raw, "msg=a") {
		t.Fatalf("reread after rotation: %v", err)
	}

	// copytruncate-style rewrite: another stream; old refs are stale.
	os.WriteFile(p+".1", []byte("time=2026-10-30T14:00:00Z level=info msg=other content\n"), 0o644)
	if _, err := s.Reread(ctx, ref); !errors.Is(err, source.ErrStale) {
		t.Fatalf("reread of a rewritten file: %v", err)
	}
	plan, _ = s.Plan(ctx, everything, source.Selector{})
	for _, c := range plan.Chunks {
		if c.Stream == id1 {
			t.Fatal("rewritten file kept its stream id")
		}
	}
}

func TestRereadAndAround(t *testing.T) {
	e := newEnv(t)
	e.write("logs/app.log", genLines(t0, 20000), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	recs := scanPlan(t, s, plan)
	// A record at the start of the second granule.
	i := slices.IndexFunc(recs, func(r source.RawRecord) bool { return r.Granule == 1 })
	got, err := s.Reread(ctx, recs[i].Ref)
	if err != nil || got.Event.Raw != recs[i].Event.Raw {
		t.Fatalf("reread: %v", err)
	}
	bad := recs[i].Ref
	bad.Length++
	if _, err := s.Reread(ctx, bad); !errors.Is(err, source.ErrStale) {
		t.Fatalf("reread of a wrong length: %v", err)
	}
	around, err := s.Around(ctx, recs[i].Ref, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(around) != 9 || !reflect.DeepEqual(around[5], recs[i]) || !reflect.DeepEqual(around[0], recs[i-5]) || !reflect.DeepEqual(around[8], recs[i+3]) {
		t.Fatalf("around: %d records", len(around))
	}
	if a, _ := s.Around(ctx, recs[0].Ref, 50, 0); len(a) != 1 {
		t.Fatalf("around the first record: %d", len(a))
	}
}

func TestLeadingUntimedTakeFirstTime(t *testing.T) {
	e := newEnv(t)
	// A granule boundary inside a stack trace: the second granule starts
	// with untimed frames.
	var b strings.Builder
	b.WriteString("2026-10-30T12:00:00Z ERROR first\n")
	for b.Len() < source.GranuleBytes+100 {
		b.WriteString("\tat some.long.frame(File.java:1)\n")
	}
	b.WriteString("2026-10-30T12:05:00Z INFO second\n")
	e.write("logs/app.log", b.String(), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	c := plan.Chunks[0]
	c.Granules = c.Granules[1:]
	recs := scanPlan(t, s, source.Byteplan{Chunks: []source.Chunk{c}})
	if len(recs) < 2 || !recs[0].Event.Inherited || recs[0].Event.Time.Minute() != 5 {
		t.Fatalf("%+v", recs[0].Event)
	}
}

func TestScanRefusesTruncatedStream(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", genLines(t0, 100), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	os.Truncate(p, 10)
	if _, err := s.Scan(ctx, plan.Chunks[0]); !errors.Is(err, source.ErrStale) {
		t.Fatalf("scan of a truncated file: %v", err)
	}
}

func TestPlanSkipsOldFilesByMtime(t *testing.T) {
	e := newEnv(t)
	e.write("logs/old.log", genLines(t0, 10), t0.Add(time.Minute))
	e.write("logs/new.log", genLines(t0.Add(time.Hour), 10), t0.Add(time.Hour+time.Minute))
	s := e.source([]string{e.root + "/logs/*.log"})
	plan, _ := s.Plan(ctx, source.Range{From: t0.Add(time.Hour), To: t0.Add(2 * time.Hour)}, source.Selector{})
	if len(plan.Chunks) != 1 {
		t.Fatalf("%d chunks", len(plan.Chunks))
	}
	// Newest stream first.
	plan, _ = s.Plan(ctx, everything, source.Selector{})
	fi, _ := s.lookup(ctx, plan.Chunks[0].Stream)
	if len(plan.Chunks) != 2 || fi.m.rel != "logs/new.log" {
		t.Fatal("plan not newest first")
	}
}

func TestOpenRefusesNonRegularLastComponent(t *testing.T) {
	e := newEnv(t)
	e.write("logs/real.log", "x\n", time.Time{})
	os.Symlink(filepath.Join(e.root, "logs/real.log"), filepath.Join(e.root, "logs/link.log"))
	syscall.Mkfifo(filepath.Join(e.root, "logs/fifo.log"), 0o644)
	os.Mkdir(filepath.Join(e.root, "logs/dir.log"), 0o755)
	for name, open := range map[string]func(string, string) (*os.File, error){"beneath": openBeneath, "walk": walkOpen} {
		for _, rel := range []string{"logs/link.log", "logs/fifo.log", "logs/dir.log"} {
			done := make(chan error, 1)
			go func() {
				f, err := open(e.root, rel)
				if err == nil {
					f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s opened %s", name, rel)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s blocked on %s", name, rel)
			}
		}
	}
	if f, err := openBeneath("/dev", "null"); err == nil {
		f.Close()
		t.Fatal("a device was opened")
	}
}

func TestOverflowTuplesMayMatch(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	// One minute, 20 x 15 = 300 distinct tuples (> index.MaxTuples).
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "time=2026-10-30T12:00:%02dZ level=l%d status=s%d\n", i%60, i%20, i/20)
	}
	e.write("logs/app.log", b.String(), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	s.IndexStep(ctx, 1<<40, true)
	sel := source.Selector{Terms: []source.Term{{Field: "status", Op: "=", Values: []string{"s14"}}}}
	plan, _ := s.Plan(ctx, everything, sel)
	if plan.Granules() != 1 {
		t.Fatal("a granule with overflowing tuples was planned out")
	}
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	res, err := s.IndexCounts(ctx, CountQuery{Range: r, Selector: sel})
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, row := range res.Rows {
		n += row.N
	}
	for _, rec := range scanPlan(t, s, res.Residual) {
		if v, _ := index.Lookup(rec.Event, "status"); v == "s14" {
			n++
		}
	}
	if n != 20 {
		t.Fatalf("status=s14 counted %d, want 20", n)
	}
}

func TestCopytruncateIsANewStream(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", "", time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	s.Plan(ctx, everything, source.Selector{}) // seen empty
	os.WriteFile(p, []byte("time=2026-10-30T12:00:00Z level=info msg=a\n"), 0o644)
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	id1 := plan.Chunks[0].Stream
	s.IndexStep(ctx, 1<<40, true)
	os.Truncate(p, 0)
	s.Plan(ctx, everything, source.Selector{}) // seen empty again
	os.WriteFile(p, []byte("time=2026-10-30T12:00:00Z level=fail msg=b\n"), 0o644)
	plan, _ = s.Plan(ctx, everything, source.Selector{})
	if plan.Chunks[0].Stream == id1 || plan.Chunks[0].Granules[0].Indexed {
		t.Fatal("the rewritten file kept the old stream or its index")
	}
	res, _ := s.IndexCounts(ctx, CountQuery{Range: source.Range{From: t0, To: t0.Add(time.Hour)}, By: []string{"level"}})
	if len(res.Rows) != 0 || res.Residual.Granules() != 1 {
		t.Fatalf("old index served: %+v", res)
	}
}

func TestPartialLineAcrossBoundaryNotSealed(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	for i := 0; b.Len() < source.GranuleBytes-20; i++ {
		fmt.Fprintf(&b, "time=2026-10-30T12:00:00Z level=info msg=%d\n", i)
	}
	head := b.String()
	partial := "time=2026-10-30T12:01:00Z level=e"
	p := e.write("logs/app.log", head+partial, time.Time{})
	// Grow past the boundary with the line still unfinished.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(strings.Repeat("x", 40))
	f.Close()
	s := e.source([]string{e.root + "/logs/app.log"})
	s.IndexStep(ctx, 1<<40, true)
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(" more\ntime=2026-10-30T12:02:00Z level=error msg=z\n")
	f.Close()
	s.IndexStep(ctx, 1<<40, true)
	r := source.Range{From: t0, To: t0.Add(time.Hour)}
	got, _ := indexPlusResidual(t, s, r, time.Hour)
	want := fullCounts(t, s, r, time.Hour)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("index after completion %v, scan %v", got, want)
	}
}

func TestIndexedFromSurvivesGrowth(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", genLines(t0, 20000), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	s.IndexStep(ctx, 1<<40, true)
	sch, _ := s.Describe(ctx)
	if !sch.IndexedFrom.Equal(t0) || !sch.FullyIndexed {
		t.Fatalf("%+v", sch)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("time=2026-10-30T20:00:00Z level=info msg=x\n")
	f.Close()
	sch, _ = s.Describe(ctx)
	if !sch.IndexedFrom.Equal(t0) || sch.FullyIndexed {
		t.Fatalf("after growth: %+v", sch)
	}
	r := source.Range{From: t0, To: t0.Add(10 * time.Hour)}
	got, res := indexPlusResidual(t, s, r, time.Hour)
	if !reflect.DeepEqual(got, fullCounts(t, s, r, time.Hour)) || res.Residual.Granules() != 1 {
		t.Fatal("grown tail not sent to the residual scan")
	}
}

func TestHardLinkIsOneStream(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/a.log", genLines(t0, 12), time.Time{})
	os.Link(p, filepath.Join(e.root, "logs/b.log"))
	s := e.source([]string{e.root + "/logs/*.log"})
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	if len(plan.Chunks) != 1 {
		t.Fatalf("%d chunks for one inode", len(plan.Chunks))
	}
}

func TestConcurrentIndexAndQueries(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", genLines(t0, 20000), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s.IndexStep(ctx, 1<<20, true)
			e.store.Flush()
			if i%3 == 0 {
				f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
				f.WriteString("time=2026-10-30T20:00:00Z level=info msg=x\n")
				f.Close()
			}
		}
	}()
	r := source.Range{From: t0, To: t0.Add(10 * time.Hour)}
	for i := 0; i < 20; i++ {
		s.Describe(ctx)
		s.IndexCounts(ctx, CountQuery{Range: r, By: []string{"level"}})
		plan, _ := s.Plan(ctx, r, source.Selector{})
		if len(plan.Chunks) > 0 {
			c := plan.Chunks[0]
			c.Granules = c.Granules[:1]
			if it, err := s.Scan(ctx, c); err == nil {
				all(t, it)
			}
		}
	}
	close(stop)
	wg.Wait()
}

func TestCardinalityDropAcrossGranules(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	for i := 0; b.Len() < 4*source.GranuleBytes; i++ {
		fmt.Fprintf(&b, "time=%s level=%s status=s%d msg=\"some padding text for the line\"\n",
			t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), levels[i%5], i/400)
	}
	e.write("logs/app.log", b.String(), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	r := source.Range{From: t0, To: t0.Add(24 * time.Hour)}
	want := fullCounts(t, s, r, time.Hour)
	for i := 0; i < 10; i++ {
		if _, done, err := s.IndexStep(ctx, 1<<20, true); err != nil {
			t.Fatal(err)
		} else if done {
			break
		}
	}
	got, res := indexPlusResidual(t, s, r, time.Hour)
	if !reflect.DeepEqual(got, want) || res.Residual.Granules() != 0 {
		t.Fatal("counts after a cardinality drop differ from a scan")
	}
	if err := e.store.Flush(); err != nil {
		t.Fatal(err)
	}
	st2, err := index.Open(e.store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	s2 := e.source([]string{e.root + "/logs/app.log"}, func(o *Options) { o.Index = st2 })
	got, res = indexPlusResidual(t, s2, r, time.Hour)
	if !reflect.DeepEqual(got, want) || res.Residual.Granules() != 0 {
		t.Fatal("reloaded index differs after a cardinality drop")
	}
}

func TestIndexedFromWithConcurrentFiles(t *testing.T) {
	e := newEnv(t)
	now := t0.Add(30000 * time.Second)
	e.write("logs/a.log", genLines(t0, 20000), now.Add(time.Second))
	e.write("logs/b.log", genLines(t0, 20000), now)
	s := e.source([]string{e.root + "/logs/*.log"}, func(o *Options) { o.Now = func() time.Time { return now.Add(time.Hour) } })
	for i := 0; i < 3; i++ {
		s.IndexStep(ctx, 1<<20, true)
	}
	// The claim holds: every record the index lacks is before
	// indexed_from (b.log, written at the same time, is partly indexed).
	sch, _ := s.Describe(ctx)
	res, _ := s.IndexCounts(ctx, CountQuery{Range: source.Range{From: t0, To: now}, By: []string{"level"}})
	missing := scanPlan(t, s, res.Residual)
	if len(missing) == 0 {
		t.Fatal("test setup: everything indexed already")
	}
	for _, r := range missing {
		if !sch.IndexedFrom.IsZero() && !r.Event.Time.Before(sch.IndexedFrom) {
			t.Fatalf("record at %v not indexed but indexed_from is %v", r.Event.Time, sch.IndexedFrom)
		}
	}
	for i := 0; i < 20; i++ {
		s.IndexStep(ctx, 1<<20, true)
	}
	if sch, _ = s.Describe(ctx); !sch.IndexedFrom.Equal(t0) || !sch.FullyIndexed {
		t.Fatalf("fully indexed: %+v", sch)
	}
}

func TestBackfillOnlyWithoutUpkeep(t *testing.T) {
	e := newEnv(t)
	p := e.write("logs/app.log", genLines(t0, 1000), time.Time{})
	s := e.source([]string{e.root + "/logs/app.log"})
	s.IndexStep(ctx, 1<<40, false) // backfill: the never-indexed granule
	if sch, _ := s.Describe(ctx); !sch.FullyIndexed {
		t.Fatal("backfill did not run without upkeep")
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("time=2026-10-30T20:00:00Z level=info msg=x\n")
	f.Close()
	if n, done, _ := s.IndexStep(ctx, 1<<40, false); n != 0 || !done {
		t.Fatalf("upkeep ran without upkeep: %d bytes", n)
	}
	sch, _ := s.Describe(ctx)
	if sch.FullyIndexed || sch.IndexedUntil.IsZero() {
		t.Fatalf("grown tail: %+v", sch)
	}
	s.IndexStep(ctx, 1<<40, true)
	if sch, _ := s.Describe(ctx); !sch.FullyIndexed || !sch.IndexedUntil.IsZero() {
		t.Fatalf("after upkeep: %+v", sch)
	}
}

func TestCoverageClaimWithJitter(t *testing.T) {
	e := newEnv(t)
	// Ten records per second, timestamps jittered by up to 2 s.
	gen := func(seed int) string {
		var b strings.Builder
		for i := 0; b.Len() < 3*source.GranuleBytes; i++ {
			ts := t0.Add(time.Duration(i)*100*time.Millisecond - time.Duration((i*7919+seed)%20)*100*time.Millisecond)
			fmt.Fprintf(&b, "time=%s level=%s msg=\"record %d with some padding\"\n", ts.Format(time.RFC3339), levels[i%5], i)
		}
		return b.String()
	}
	now := t0.Add(2 * time.Hour)
	e.write("logs/a.log", gen(1), now.Add(time.Second))
	e.write("logs/b.log", gen(5), now)
	s := e.source([]string{e.root + "/logs/*.log"}, func(o *Options) { o.Now = func() time.Time { return now.Add(time.Hour) } })
	for step := 0; step < 12; step++ {
		sch, _ := s.Describe(ctx)
		res, _ := s.IndexCounts(ctx, CountQuery{Range: source.Range{From: t0.Add(-time.Hour), To: now}, By: []string{"level"}})
		for _, r := range scanPlan(t, s, res.Residual) {
			if !sch.IndexedFrom.IsZero() && !r.Event.Time.Before(sch.IndexedFrom) {
				t.Fatalf("step %d: record at %v unindexed, indexed_from %v", step, r.Event.Time, sch.IndexedFrom)
			}
		}
		s.IndexStep(ctx, 1<<20, true)
	}
}

func TestBlankTailAcrossBoundaryNotSealed(t *testing.T) {
	e := newEnv(t)
	var b strings.Builder
	for i := 0; b.Len() < source.GranuleBytes-200; i++ {
		fmt.Fprintf(&b, "2026-10-30T12:00:%02dZ INFO plain record %d\n", i%60, i)
	}
	// The blank line starts 50 bytes before the boundary and runs past it.
	b.WriteString(strings.Repeat("x", source.GranuleBytes-50-1-b.Len()) + "\n")
	head := b.String()
	p := e.write("logs/app.log", head+strings.Repeat(" ", source.GranuleBytes+20-len(head)), time.Time{})
	// Every line its own record, so the completed line is one more record.
	np, _ := parse.New(parse.Options{Multiline: parse.MultilineNone})
	s := e.source([]string{e.root + "/logs/app.log"}, func(o *Options) { o.Parser = np })
	s.IndexStep(ctx, 1<<40, true)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("at frame\n2026-10-30T12:00:59Z ERROR next\n")
	f.Close()
	s.IndexStep(ctx, 1<<40, true)
	fs, _ := s.files(ctx)
	_, _, gs := s.streamIndex(fs[0])
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	c := plan.Chunks[0]
	c.Granules = c.Granules[:1]
	recs := scanPlan(t, s, source.Byteplan{Chunks: []source.Chunk{c}})
	if g := gs[0]; g != nil && usable(g, fs[0].id.size) && g.Records != int64(len(recs)) {
		t.Fatalf("granule 0 indexed with %d records, holds %d", g.Records, len(recs))
	}
}
