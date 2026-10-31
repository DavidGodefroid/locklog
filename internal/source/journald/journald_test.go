//go:build unix

package journald

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

const mid = "0123456789abcdef0123456789abcdef"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// root lays out a journal root: files maps names in <mid>/ to fixtures.
func root(t *testing.T, files map[string]string) string {
	t.Helper()
	r := t.TempDir()
	d := filepath.Join(r, mid)
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, fx := range files {
		if err := os.WriteFile(filepath.Join(d, name), fixture(t, fx), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func newSource(t *testing.T, opts Options) *Source {
	t.Helper()
	p, err := parse.New(parse.Options{Format: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	opts.Parser = p
	if opts.Name == "" {
		opts.Name = "journal"
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var everything = source.Range{From: time.Unix(0, 0), To: time.Unix(1<<40, 0)}

func scanAll(t *testing.T, s *Source, r source.Range) []source.RawRecord {
	t.Helper()
	ctx := context.Background()
	plan, err := s.Plan(ctx, r, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		it, err := s.Scan(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		for {
			rec, err := it.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, rec)
		}
		it.Close()
	}
	return out
}

// refEntries reads journalctl's JSON reference of a fixture.
func refEntries(t *testing.T, name string) []map[string]any {
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(fixture(t, name)))
	for {
		var m map[string]any
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
}

func recordText(rec source.RawRecord) string {
	var b strings.Builder
	b.WriteString(rec.Event.Raw)
	b.WriteString(rec.Event.Message)
	for _, m := range rec.Event.Fields {
		fmt.Fprintf(&b, "|%s=%s", m.Key, m.Value.Str)
	}
	return b.String()
}

func TestRecordsMatchJournalctlThroughTheAllowlist(t *testing.T) {
	for _, set := range []string{"debian-12", "debian-trixie", "ubuntu-24-04", "fedora-41"} {
		for _, kind := range []string{"remote", "native"} {
			t.Run(set+"/"+kind, func(t *testing.T) {
				r := root(t, map[string]string{"system.journal": set + "/" + kind + ".journal.gz"})
				s := newSource(t, Options{Roots: []string{r}})
				recs := scanAll(t, s, everything)
				refs := refEntries(t, set+"/"+kind+".json.gz")
				if len(recs) != len(refs) {
					t.Fatalf("%d records, journalctl %d", len(recs), len(refs))
				}
				for i, rec := range recs {
					ref := refs[i]
					if msg, _ := ref["MESSAGE"].(string); msg != "" && rec.Event.Raw != msg {
						t.Fatalf("entry %d: message differs", i)
					}
					want := map[string]bool{}
					for k := range ref {
						if s.fields[k] {
							if _, ok := ref[k].(string); ok {
								want[k] = true
							}
						}
					}
					got := map[string]bool{}
					for _, m := range rec.Event.Fields {
						if !journalName(m.Key) {
							continue // decoded from the message by the parser
						}
						if !s.fields[m.Key] {
							t.Fatalf("entry %d: field %s served", i, m.Key)
						}
						if ref[m.Key] != m.Value.Str {
							t.Fatalf("entry %d: %s differs", i, m.Key)
						}
						got[m.Key] = true
					}
					if len(got) != len(want) {
						t.Fatalf("entry %d: fields %v, want %v", i, got, want)
					}
					us := rec.Event.Time.UnixMicro()
					if fmt.Sprint(us) != ref["__REALTIME_TIMESTAMP"] {
						t.Fatalf("entry %d: time", i)
					}
				}
			})
		}
	}
}

func TestNeverServedFieldsAndBinaryValues(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "ubuntu-24-04/remote.journal.gz"})
	// Even an allow list naming them cannot serve core dumps, command
	// lines, executables, audit fields or binary values.
	s := newSource(t, Options{Roots: []string{r}, Allow: []string{"COREDUMP_ENVIRON", "COREDUMP", "_CMDLINE", "_EXE", "_AUDIT_SESSION", "BINARY_BLOB", "USER_EMAIL"}})
	recs := scanAll(t, s, everything)
	email := 0
	for _, rec := range recs {
		txt := recordText(rec)
		for _, canary := range []string{"canary-coredump", "hunter2-canary", "canary", "/usr/bin/shop-api"} {
			if strings.Contains(txt, canary) {
				t.Fatalf("canary %q served: %.200s", canary, txt)
			}
		}
		for _, m := range rec.Event.Fields {
			if NeverServed(m.Key) || m.Key == "BINARY_BLOB" {
				t.Fatalf("field %s served", m.Key)
			}
			if m.Key == "USER_EMAIL" {
				email++
			}
		}
	}
	if email == 0 {
		t.Fatal("an allowed text field was not served")
	}
	sch, err := s.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sch.Fields {
		if NeverServed(f.Name) || f.Name == "USER_EMAIL" && f.Trusted {
			t.Fatalf("describe: %+v", f)
		}
	}
	// Without the allow list, the email field is not served either.
	s = newSource(t, Options{Roots: []string{r}})
	for _, rec := range scanAll(t, s, everything) {
		if strings.Contains(recordText(rec), "USER_EMAIL") {
			t.Fatal("USER_EMAIL served without allow")
		}
	}
}

func TestGranulesAreFixedAndNarrowingDropsNothing(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "fedora-41/remote.journal.gz"})
	s := newSource(t, Options{Roots: []string{r}})
	ctx := context.Background()
	all := scanAll(t, s, everything)
	full, err := s.Plan(ctx, everything, source.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	bounds := map[[2]int64]bool{}
	for _, c := range full.Chunks {
		for _, g := range c.Granules {
			if g.Start%GranuleEntries != 0 {
				t.Fatalf("granule %+v not aligned", g)
			}
			bounds[[2]int64{g.Start, g.End}] = true
		}
	}
	first, last := all[0].Event.Time, all[len(all)-1].Event.Time
	span := last.Sub(first)
	for _, frac := range [][2]float64{{0, 0.1}, {0.4, 0.6}, {0.9, 1.01}, {0.85, 0.86}} {
		rg := source.Range{From: first.Add(time.Duration(frac[0] * float64(span))), To: first.Add(time.Duration(frac[1] * float64(span)))}
		plan, err := s.Plan(ctx, rg, source.Selector{})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range plan.Chunks {
			for _, g := range c.Granules {
				if !bounds[[2]int64{g.Start, g.End}] {
					t.Fatalf("granule %+v depends on the range", g)
				}
			}
		}
		want := 0
		for _, rec := range all {
			if rg.Contains(rec.Event.Time) {
				want++
			}
		}
		got := 0
		for _, rec := range scanAll(t, s, rg) {
			if rg.Contains(rec.Event.Time) {
				got++
			}
		}
		if got != want {
			t.Fatalf("range %v: %d records, want %d", frac, got, want)
		}
	}
	// A range after the file plans nothing.
	plan, _ := s.Plan(ctx, source.Range{From: last.Add(time.Hour), To: last.Add(2 * time.Hour)}, source.Selector{})
	if len(plan.Chunks) != 0 {
		t.Fatalf("plan after the file: %+v", plan)
	}
}

func TestChunkByChunkEqualsWhole(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "debian-12/remote.journal.gz"})
	s := newSource(t, Options{Roots: []string{r}})
	ctx := context.Background()
	whole := scanAll(t, s, everything)
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	var parts []source.RawRecord
	for _, c := range plan.Chunks {
		for _, g := range c.Granules {
			one := c
			one.Granules = []source.Granule{g}
			it, err := s.Scan(ctx, one)
			if err != nil {
				t.Fatal(err)
			}
			for {
				rec, err := it.Next()
				if err != nil {
					break
				}
				parts = append(parts, rec)
			}
			it.Close()
		}
	}
	if len(parts) != len(whole) {
		t.Fatalf("%d records by granule, %d whole", len(parts), len(whole))
	}
	for i := range parts {
		if parts[i].Ref != whole[i].Ref {
			t.Fatalf("record %d differs", i)
		}
	}
}

func TestDiscovery(t *testing.T) {
	r := root(t, map[string]string{
		"system.journal":          "debian-12/remote.journal.gz",
		"system@abc-1-2.journal~": "ubuntu-24-04/native.journal.gz",
		"user-1000.journal":       "fedora-41/native.journal.gz",
		"system.journal.bak":      "debian-trixie/native.journal.gz",
		"not-a-journal.journal":   "variants/c0-compact0-keyed0.json.gz",
	})
	d := filepath.Join(r, mid)
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "x.journal"), fixture(t, "debian-trixie/remote.journal.gz"), 0o644)
	if err := os.Symlink(filepath.Join(other, "x.journal"), filepath.Join(d, "system@link.journal")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(r, "fedcba9876543210fedcba9876543210")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(d, "system@fifo.journal"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, Options{Roots: []string{r, filepath.Join(t.TempDir(), "missing")}})
	files, err := s.files(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.name)
	}
	if strings.Join(sorted(names), ",") != "system.journal,system@abc-1-2.journal~" {
		t.Fatalf("files %v", names)
	}
	s = newSource(t, Options{Roots: []string{r}, UserJournals: true})
	files, _ = s.files(context.Background())
	if len(files) != 3 {
		t.Fatalf("with user journals: %d files", len(files))
	}
	// The symlinked file is refused by the opener itself too.
	if _, err := openBeneath(r, mid, "system@link.journal"); err == nil {
		t.Fatal("opened a symbolic link")
	}
	if _, err := openBeneath(r, "fedcba9876543210fedcba9876543210", "x.journal"); err == nil {
		t.Fatal("followed a symlinked directory")
	}
	for _, bad := range [][2]string{{"..", "x"}, {mid, "../x"}, {mid, ""}} {
		if _, err := openBeneath(r, bad[0], bad[1]); err == nil {
			t.Fatalf("opened %v", bad)
		}
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestUnits(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "ubuntu-24-04/remote.journal.gz"})
	s := newSource(t, Options{Roots: []string{r}, Units: []string{"nginx.service", "shop-*"}})
	recs := scanAll(t, s, everything)
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, rec := range recs {
		v, _ := parse.Get(rec.Event.Fields, "_SYSTEMD_UNIT")
		if v.Str != "nginx.service" && !strings.HasPrefix(v.Str, "shop-") {
			t.Fatalf("unit %q served", v.Str)
		}
	}
}

func TestRereadAndAround(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "debian-trixie/remote.journal.gz"})
	s := newSource(t, Options{Roots: []string{r}})
	ctx := context.Background()
	all := scanAll(t, s, everything)
	mid := all[len(all)/2]
	got, err := s.Reread(ctx, mid.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Event.Raw != mid.Event.Raw || got.Ref != mid.Ref {
		t.Fatal("reread differs")
	}
	around, err := s.Around(ctx, mid.Ref, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(around) != 6 || around[3].Ref != mid.Ref || around[0].Ref != all[len(all)/2-3].Ref || around[5].Ref != all[len(all)/2+2].Ref {
		t.Fatalf("around: %d records", len(around))
	}
	if a, _ := s.Around(ctx, all[0].Ref, 999, 0); len(a) != 1 {
		t.Fatalf("around the first record: %d", len(a))
	}
	bad := mid.Ref
	bad.Offset += 8
	if _, err := s.Reread(ctx, bad); !errors.Is(err, source.ErrStale) {
		t.Fatalf("reread at a wrong offset: %v", err)
	}
	gone := mid.Ref
	gone.Stream = "journal:00000000000000000000000000000000"
	if _, err := s.Reread(ctx, gone); !errors.Is(err, source.ErrStale) {
		t.Fatalf("reread of a gone file: %v", err)
	}
}

func TestRotationKeepsTheStream(t *testing.T) {
	r := root(t, map[string]string{"system.journal": "debian-12/remote.journal.gz"})
	s := newSource(t, Options{Roots: []string{r}})
	ctx := context.Background()
	plan, _ := s.Plan(ctx, everything, source.Selector{})
	// journald renames the active file on rotation; the stream follows it.
	if err := os.Rename(filepath.Join(r, mid, "system.journal"), filepath.Join(r, mid, "system@0001-0002-0003.journal")); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.catalog = nil
	s.mu.Unlock()
	it, err := s.Scan(ctx, plan.Chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	if _, err := it.Next(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	p, _ := parse.New(parse.Options{})
	for _, o := range []Options{
		{Parser: p},
		{Parser: p, Roots: []string{"relative"}},
		{Parser: p, Roots: []string{"/"}},
		{Parser: p, Roots: []string{"/var/log/journal"}, Units: []string{"["}},
		{Roots: []string{"/var/log/journal"}},
	} {
		if _, err := New(o); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}

func journalName(k string) bool {
	for _, c := range k {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return k != ""
}

// rootWith lays out a journal root holding one built file.
func rootWith(t *testing.T, raw []byte) string {
	t.Helper()
	r := t.TempDir()
	if err := os.Mkdir(filepath.Join(r, mid), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r, mid, "system.journal"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMessageCannotSpoofJournalFields(t *testing.T) {
	raw := journaltest.Build(journaltest.Options{Compact: true}, []journaltest.Entry{{Realtime: 1761800000000000, Fields: []string{
		`MESSAGE={"_SYSTEMD_UNIT":"spoof.service","PRIORITY":"0","_CMDLINE":"x --password=canary","COREDUMP":"canary","msg":"hi","ok":"1"}`,
		"_SYSTEMD_UNIT=real.service", "PRIORITY=6"}}})
	p, _ := parse.New(parse.Options{Format: "json"})
	s, err := New(Options{Name: "j", Roots: []string{rootWith(t, raw)}, Parser: p})
	if err != nil {
		t.Fatal(err)
	}
	recs := scanAll(t, s, everything)
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	got := map[string][]string{}
	for _, m := range recs[0].Event.Fields {
		got[m.Key] = append(got[m.Key], m.Value.Str)
	}
	if strings.Join(got["_SYSTEMD_UNIT"], ",") != "real.service" || strings.Join(got["PRIORITY"], ",") != "6" {
		t.Fatalf("journal fields spoofed: %v", got)
	}
	for k := range got {
		if NeverServed(k) {
			t.Fatalf("%s served from the message", k)
		}
	}
	if len(got["ok"]) != 1 {
		t.Fatalf("an ordinary message key was dropped: %v", got)
	}
}

// clockStep: 3+ granules whose timestamps step back an hour inside one.
func clockStep() []journaltest.Entry {
	var es []journaltest.Entry
	base := uint64(1761800000000000)
	for i := 0; i < 3*GranuleEntries+40; i++ {
		rt := base + uint64(i)*1_000_000
		if i == GranuleEntries+50 {
			rt = base - 3600_000_000 // the clock stepped back for one entry
		}
		es = append(es, journaltest.Entry{Realtime: rt, Fields: []string{fmt.Sprintf("MESSAGE=entry %d", i), "PRIORITY=6"}})
	}
	return es
}

func TestNarrowingSurvivesClockSteps(t *testing.T) {
	es := clockStep()
	s := newSource(t, Options{Roots: []string{rootWith(t, journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es))}})
	all := scanAll(t, s, everything)
	if len(all) != len(es) {
		t.Fatalf("%d records of %d", len(all), len(es))
	}
	for _, w := range []source.Range{
		{From: usec(es[GranuleEntries+50].Realtime - 1), To: usec(es[GranuleEntries+50].Realtime + 1)},
		{From: usec(es[0].Realtime), To: usec(es[10].Realtime)},
		{From: usec(es[len(es)-5].Realtime), To: usec(es[len(es)-1].Realtime + 1)},
		{From: usec(es[GranuleEntries*2].Realtime), To: usec(es[GranuleEntries*2+200].Realtime)},
	} {
		want := 0
		for _, rec := range all {
			if w.Contains(rec.Event.Time) {
				want++
			}
		}
		got := 0
		for _, rec := range scanAll(t, s, w) {
			if w.Contains(rec.Event.Time) {
				got++
			}
		}
		if got != want || want == 0 {
			t.Fatalf("range %v: %d records in plan, %d in the file", w, got, want)
		}
	}
}

func TestBrokenChainServesItsPrefix(t *testing.T) {
	es := clockStep()[:600]
	raw := journaltest.Build(journaltest.Options{Compact: true, PerArray: 100}, es)
	jf, err := journal.Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	// Break the chain after the third array: its next pointer goes past
	// the end of the file.
	var arrays []uint64
	next := jf.Header().EntryArrayOffset
	for next != 0 {
		arrays = append(arrays, next)
		next = binary.LittleEndian.Uint64(raw[next+16:])
	}
	binary.LittleEndian.PutUint64(raw[arrays[2]+16:], uint64(len(raw))+8)
	s := newSource(t, Options{Roots: []string{rootWith(t, raw)}})
	recs := scanAll(t, s, everything)
	if len(recs) != 300 {
		t.Fatalf("%d records from a file whose chain breaks after 300", len(recs))
	}
}

func TestRereadGranuleIsTheFileGranule(t *testing.T) {
	es := clockStep()
	s := newSource(t, Options{Roots: []string{rootWith(t, journaltest.Build(journaltest.Options{Compact: true}, es))}})
	all := scanAll(t, s, everything)
	for _, i := range []int{0, GranuleEntries - 1, GranuleEntries, 2*GranuleEntries + 7} {
		rec, err := s.Reread(context.Background(), all[i].Ref)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Granule != i/GranuleEntries {
			t.Fatalf("entry %d: granule %d", i, rec.Granule)
		}
	}
}

func TestAllowlistOnEveryFixture(t *testing.T) {
	files, _ := filepath.Glob("testdata/*/*.journal.gz")
	for _, f := range files {
		name := strings.TrimPrefix(f, "testdata/")
		r := root(t, map[string]string{"system.journal": name})
		s := newSource(t, Options{Roots: []string{r}, Allow: []string{"COREDUMP_ENVIRON", "_CMDLINE", "_EXE", "BINARY_BLOB"}})
		for _, rec := range scanAll(t, s, everything) {
			txt := recordText(rec)
			for _, canary := range []string{"canary-coredump", "hunter2-canary", "COREDUMP", "_CMDLINE", "_EXE", "BINARY_BLOB"} {
				if strings.Contains(txt, canary) {
					t.Fatalf("%s: %q served", name, canary)
				}
			}
		}
	}
}
