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
		if _, _, err := s.IndexStep(ctx, 1<<40); err != nil {
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
	for name, open := range map[string]func(string, string) (*os.File, error){
		"beneath": func(r, p string) (*os.File, error) { return openBeneath(r, p, false) },
		"walk":    func(r, p string) (*os.File, error) { return walkOpen(r, p, false) },
	} {
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
			for _, bad := range []string{"O_CREAT", "O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND", "os.Create", "os.OpenFile", "WriteFile"} {
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
	r := source.Range{From: t0, To: t0.Add(40000 * time.Second)}
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
		_, done, err := s.IndexStep(ctx, 1<<20) // one granule per step
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
	s.IndexStep(ctx, 1<<40)
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
	s.IndexStep(ctx, 1<<40)
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
	if len(res.Rows) != 1 || res.Rows[0].Vals[0] != index.Redacted || res.Rows[0].N != 2000 {
		t.Fatalf("%+v", res.Rows)
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
	s.IndexStep(ctx, 1<<40)

	// Growth keeps the stream (and its index, re-indexing the tail).
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("time=2026-10-30T12:00:01Z level=error msg=b\n")
	f.Close()
	plan, _ = s.Plan(ctx, everything, source.Selector{})
	if plan.Chunks[0].Stream != id1 || plan.Chunks[0].Granules[0].Indexed {
		t.Fatalf("grown file: %+v", plan.Chunks[0])
	}
	s.IndexStep(ctx, 1<<40)
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
	if _, err := s.Reread(ctx, ref); !errors.Is(err, source.ErrStale) && !errors.Is(err, source.ErrNotFound) {
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
	if _, err := s.Scan(ctx, plan.Chunks[0]); !errors.Is(err, source.ErrStale) && !errors.Is(err, source.ErrNotFound) {
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
