package index

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
)

func ev(t time.Time, fields ...string) parse.Event {
	e := parse.Event{Time: t, HasTime: !t.IsZero()}
	for i := 0; i+1 < len(fields); i += 2 {
		e.Fields = append(e.Fields, parse.Member{Key: fields[i], Value: parse.Value{Kind: parse.KindString, Str: fields[i+1]}})
	}
	return e
}

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func TestBuilderCountsPerMinute(t *testing.T) {
	b := NewBuilder([]string{"level", "http.status"}, func(f, v string) bool { return v == "secret" })
	nested := ev(t0.Add(30*time.Second), "level", "error")
	nested.Fields = append(nested.Fields, parse.Member{Key: "http", Value: parse.Value{Kind: parse.KindObject,
		Members: []parse.Member{{Key: "status", Value: parse.Value{Kind: parse.KindNumber, Str: "502"}}}}})
	b.Add(nested)
	b.Add(ev(t0.Add(40*time.Second), "level", "error"))
	b.Add(ev(t0.Add(70*time.Second), "level", "secret"))
	b.Add(ev(time.Time{}, "level", "info"))
	g := b.Finish(3, 10, 20, true)
	if g.Records != 4 || g.N != 3 || !g.Sealed || g.From != t0.Add(30*time.Second).UnixNano() || g.To != t0.Add(70*time.Second).UnixNano() {
		t.Fatalf("%+v", g)
	}
	m := t0.Unix() / 60
	want := []Minute{
		{M: m, Counts: []Count{{Vals: []string{"error", ""}, N: 1}, {Vals: []string{"error", "502"}, N: 1}}},
		{M: m + 1, Counts: []Count{{Vals: []string{Redacted, ""}, N: 1}}},
	}
	if !reflect.DeepEqual(g.Minutes, want) {
		t.Fatalf("%+v", g.Minutes)
	}
	if !reflect.DeepEqual(g.Untimed, []Count{{Vals: []string{"info", ""}, N: 1}}) {
		t.Fatalf("%+v", g.Untimed)
	}
}

// TestBuilderMemoizesSensitivity: the masker is asked once per distinct
// (field, value) of a granule, up to memoMax entries; long values are
// always asked; the answers are the same as without the memo.
func TestBuilderMemoizesSensitivity(t *testing.T) {
	asked := map[string]int{}
	b := NewBuilder([]string{"level"}, func(f, v string) bool { asked[v]++; return v == "secret" })
	long := strings.Repeat("x", memoValueMax+1)
	for i := range 8 * memoMax {
		v := []string{"error", "secret", long, fmt.Sprint(i)}[min(i%4, 3)]
		b.Add(ev(t0.Add(time.Duration(i)*time.Millisecond), "level", v))
	}
	if asked["error"] != 1 || asked["secret"] != 1 || asked[long] != 2*memoMax {
		t.Fatalf("asked error %d secret %d long %d", asked["error"], asked["secret"], asked[long])
	}
	if len(b.memo) != memoMax {
		t.Fatalf("memo holds %d entries", len(b.memo))
	}
	g := b.Finish(0, 0, 1, true)
	for _, m := range g.Minutes {
		for _, c := range m.Counts {
			if c.Vals[0] == "secret" {
				t.Fatal("a sensitive value indexed clear")
			}
		}
	}
}

func TestBuilderBoundsTuples(t *testing.T) {
	b := NewBuilder([]string{"k"}, nil)
	for i := 0; i < MaxTuples+50; i++ {
		b.Add(ev(t0, "k", fmt.Sprint(i)))
	}
	g := b.Finish(0, 0, 1, true)
	if n := len(g.Minutes[0].Counts); n != MaxTuples+1 {
		t.Fatalf("%d tuples", n)
	}
	var other int64
	for _, c := range g.Minutes[0].Counts {
		if c.Vals[0] == Other {
			other = c.N
		}
	}
	if other != 50 {
		t.Fatalf("other %d", other)
	}
}

func TestTupleKeyUnambiguous(t *testing.T) {
	if tupleKey([]string{"a\x01b", ""}) == tupleKey([]string{"a", "b\x01"}) || tupleKey([]string{"ab", ""}) == tupleKey([]string{"a", "b"}) {
		t.Fatal("tuple keys collide")
	}
}

func TestStreamDropsHighCardinality(t *testing.T) {
	s := NewStream(1, 2, "g", []string{"a", "b"})
	for n := int64(0); n < 3; n++ {
		b := NewBuilder(s.Fields, nil)
		for i := 0; i < 30; i++ {
			b.Add(ev(t0, "a", fmt.Sprint(int(n)*30+i), "b", "x"))
		}
		s.Put(b.Finish(n, 0, 1, true))
	}
	if !reflect.DeepEqual(s.Fields, []string{"b"}) || !reflect.DeepEqual(s.Dropped, []string{"a"}) {
		t.Fatalf("fields %v dropped %v", s.Fields, s.Dropped)
	}
	for _, g := range s.Granules {
		if len(g.Minutes[0].Counts) != 1 || g.Minutes[0].Counts[0].N != 30 {
			t.Fatalf("not merged: %+v", g.Minutes)
		}
	}
}

func TestStorePersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "idx")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStream(7, 9, "gen1", []string{"level"})
	b := NewBuilder(s.Fields, nil)
	b.Add(ev(t0, "level", "info"))
	s.Put(b.Finish(0, 0, 100, false))
	st.With("app", 7, 9, func(*Stream) *Stream { return s })
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got *Stream
	st2.With("app", 7, 9, func(x *Stream) *Stream { got = x; return nil })
	if got == nil || got.Gen != "gen1" || len(got.Granules) != 1 || got.Granules[0].Records != 1 {
		t.Fatalf("%+v", got)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "app", "7-9.json.gz"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
	// Delete removes the file at the next flush.
	st2.Delete("app", 7, 9)
	st2.Flush()
	if _, err := os.Stat(filepath.Join(dir, "app", "7-9.json.gz")); !os.IsNotExist(err) {
		t.Fatal("deleted index still on disk")
	}
}

func TestStoreIgnoresOtherVersionsAndBadFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "idx")
	os.MkdirAll(filepath.Join(dir, "app"), 0o700)
	f, _ := os.Create(filepath.Join(dir, "app", "1-1.json.gz"))
	zw := gzip.NewWriter(f)
	json.NewEncoder(zw).Encode(map[string]any{"version": 99, "dev": 1, "ino": 1})
	zw.Close()
	f.Close()
	os.WriteFile(filepath.Join(dir, "app", "2-2.json.gz"), []byte("not gzip"), 0o600)
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	st.With("app", 1, 1, func(s *Stream) *Stream {
		if s != nil {
			n++
		}
		return nil
	})
	if n != 0 {
		t.Fatal("index of another version loaded")
	}
}

func TestStoreRefusesOpenDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix modes")
	}
	dir := filepath.Join(t.TempDir(), "idx")
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o755)
	if _, err := Open(dir); err == nil {
		t.Fatal("index directory readable by others accepted")
	}
}

// fakeIndexer has backfill units and upkeep units of unit bytes.
type fakeIndexer struct {
	left   int // backfill
	upkeep int
	unit   int64
}

func (f *fakeIndexer) IndexStep(_ context.Context, max int64, upkeep bool) (int64, bool, error) {
	var n int64
	for f.left > 0 && n < max {
		n += f.unit
		f.left--
	}
	for upkeep && f.upkeep > 0 && n < max {
		n += f.unit
		f.upkeep--
	}
	return n, f.left == 0 && (!upkeep || f.upkeep == 0), nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func TestRunRespectsBudget(t *testing.T) {
	clk := &fakeClock{now: t0}
	src := &fakeIndexer{left: 1000, unit: 1 << 20}
	ctx, cancel := context.WithCancel(context.Background())
	var slept time.Duration
	Run(ctx, []Indexer{src}, RunOptions{
		BytesPerHour: 600 << 20, // 10 MiB per minute
		Now:          clk.Now,
		Sleep: func(_ context.Context, d time.Duration) bool {
			clk.now = clk.now.Add(d)
			slept += d
			if clk.now.Sub(t0) > time.Hour {
				cancel()
				return false
			}
			return true
		},
	})
	done := 1000 - src.left
	// One hour at 600 MiB/h plus the initial one-minute bucket.
	if done < 590 || done > 612 {
		t.Fatalf("indexed %d MiB in an hour at 600 MiB/h", done)
	}
}

func TestRunBusyPausesUpkeepNotBackfill(t *testing.T) {
	clk := &fakeClock{now: t0}
	src := &fakeIndexer{left: 20, upkeep: 5, unit: 1 << 20}
	ctx, cancel := context.WithCancel(context.Background())
	busy := true
	rounds := 0
	Run(ctx, []Indexer{src}, RunOptions{
		BytesPerHour: 1 << 40,
		Busy:         func() bool { return busy },
		Now:          clk.Now,
		Sleep: func(_ context.Context, d time.Duration) bool {
			clk.now = clk.now.Add(d)
			rounds++
			switch rounds {
			case 1:
				// Busy: the backfill ran, the upkeep did not.
				if src.left != 0 || src.upkeep != 5 {
					t.Fatalf("busy: backfill left %d, upkeep left %d", src.left, src.upkeep)
				}
				// A new file appears while still busy: backfilled.
				src.left = 3
			case 2:
				if src.left != 0 || src.upkeep != 5 {
					t.Fatalf("busy again: backfill left %d, upkeep left %d", src.left, src.upkeep)
				}
				busy = false
			case 3:
				if src.upkeep != 0 {
					t.Fatalf("idle: upkeep left %d", src.upkeep)
				}
				cancel()
				return false
			}
			return true
		},
	})
	if rounds < 3 {
		t.Fatal("run ended early")
	}
}

// TestLookupNamespaces: the index reads line fields only; frame attributes
// (labels) are a separate namespace.
func TestLookupNamespaces(t *testing.T) {
	ev := parse.Event{
		Fields: []parse.Member{{Key: "env", Value: parse.Value{Kind: parse.KindString, Str: "field"}}},
		Attrs: []parse.Member{{Key: "env", Value: parse.Value{Kind: parse.KindString, Str: "label"}},
			{Key: "stream", Value: parse.Value{Kind: parse.KindString, Str: "stdout"}}},
	}
	if v, _ := Lookup(ev, "env"); v != "field" {
		t.Fatal(v)
	}
	if v, ok := Lookup(ev, "stream"); ok {
		t.Fatalf("a label read as a field: %q", v)
	}
	if v, _ := LookupAttr(ev, "env"); v != "label" {
		t.Fatal(v)
	}
}

// Values reads a label key (LabelKey) from the frame attributes only and a
// field key from the line fields only: a payload field never stands for the
// trusted container name or the runtime's stream, nor the reverse.
func TestValuesNamespaces(t *testing.T) {
	e := ev(t0, "container", "spoofed", "stream", "spoofed", "level", "warn")
	e.Framed = true
	e.Attrs = []parse.Member{{Key: "container", Value: parse.Value{Kind: parse.KindString, Str: "shop-api-1"}},
		{Key: "attrs", Value: parse.Value{Kind: parse.KindObject,
			Members: []parse.Member{{Key: "team", Value: parse.Value{Kind: parse.KindString, Str: "shop"}}}}}}
	keys := []string{LabelKey("container"), "container", LabelKey("stream"), "stream", LabelKey("attrs.team"), LabelKey("attrs.other"), "level", LabelKey("level")}
	got := Values(e, keys, nil)
	want := []string{"shop-api-1", "spoofed", Absent, "spoofed", "shop", Absent, "warn", Absent}
	if !slices.Equal(got, want) {
		t.Fatalf("Values = %q, want %q", got, want)
	}
	if n, l := SplitKey(LabelKey("attrs.team")); n != "attrs.team" || !l {
		t.Fatal(n, l)
	}
	if n, l := SplitKey("level"); n != "level" || l {
		t.Fatal(n, l)
	}
}
