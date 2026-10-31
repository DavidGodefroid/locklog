package journal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pierrec/lz4/v4"

	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

// The fixtures in ../testdata were written by systemd itself (journald and
// systemd-journal-remote) in the distributions' stock images; each .json.gz
// is journalctl --file F -o json --all from the same image. See
// docs/sources.md (spike S1).

func gunzip(t testing.TB, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
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

// printable is journalctl's test for printing a value as a JSON string
// rather than an array of bytes.
func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if (r < ' ' && r != '\t' && r != '\n') || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

func jsonValue(b []byte) any {
	if printable(b) {
		return string(b)
	}
	a := make([]any, len(b))
	for i, c := range b {
		a[i] = float64(c)
	}
	return a
}

// asJournalctl renders an entry as journalctl -o json does.
func asJournalctl(f *File, e *Entry, withSeq bool) map[string]any {
	m := map[string]any{}
	multi := map[string]bool{}
	for _, fl := range e.Fields {
		v := jsonValue(fl.Value)
		old, ok := m[fl.Name]
		switch {
		case !ok:
			m[fl.Name] = v
		case multi[fl.Name]:
			m[fl.Name] = append(old.([]any), v)
		default:
			m[fl.Name] = []any{old, v}
			multi[fl.Name] = true
		}
	}
	h := f.Header()
	boot := hex.EncodeToString(e.BootID[:])
	seqid := hex.EncodeToString(h.SeqnumID[:])
	m["__CURSOR"] = fmt.Sprintf("s=%s;i=%x;b=%s;m=%x;t=%x;x=%x", seqid, e.Seqnum, boot, e.Monotonic, e.Realtime, e.XorHash)
	m["__REALTIME_TIMESTAMP"] = strconv.FormatUint(e.Realtime, 10)
	m["__MONOTONIC_TIMESTAMP"] = strconv.FormatUint(e.Monotonic, 10)
	m["_BOOT_ID"] = boot
	if withSeq {
		m["__SEQNUM"] = strconv.FormatUint(e.Seqnum, 10)
		m["__SEQNUM_ID"] = seqid
	}
	return m
}

func keepAll(string) bool { return true }

func TestFixturesMatchJournalctl(t *testing.T) {
	files, _ := filepath.Glob("../testdata/*/*.journal.gz")
	if len(files) < 16 {
		t.Fatalf("found %d fixtures", len(files))
	}
	for _, path := range files {
		t.Run(strings.TrimPrefix(path, "../testdata/"), func(t *testing.T) {
			raw := gunzip(t, path)
			var refs []map[string]any
			sc := bufio.NewScanner(bytes.NewReader(gunzip(t, strings.TrimSuffix(path, ".journal.gz")+".json.gz")))
			sc.Buffer(nil, 16<<20)
			for sc.Scan() {
				var m map[string]any
				if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
					t.Fatal(err)
				}
				refs = append(refs, m)
			}
			withSeq := refs[0]["__SEQNUM"] != nil
			f, err := Open(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			n := 0
			err = f.EntryOffsets(func(i, off uint64) bool {
				if i != uint64(n) {
					t.Fatalf("index %d, want %d", i, n)
				}
				e, err := f.Entry(off, keepAll)
				if err != nil {
					t.Fatalf("entry %d: %v", n, err)
				}
				if n >= len(refs) {
					t.Fatalf("more entries than journalctl")
				}
				if got := asJournalctl(f, e, withSeq); !reflect.DeepEqual(got, refs[n]) {
					for k, v := range refs[n] {
						if !reflect.DeepEqual(got[k], v) {
							t.Errorf("entry %d field %s differs", n, k)
						}
					}
					for k := range got {
						if _, ok := refs[n][k]; !ok {
							t.Errorf("entry %d: extra field %s", n, k)
						}
					}
					t.FailNow()
				}
				n++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(refs) {
				t.Fatalf("read %d entries, journalctl %d", n, len(refs))
			}
		})
	}
}

var compressions = []string{"", "zstd", "lz4", "xz"}

func build(compact bool, comp string, es ...journaltest.Entry) []byte {
	return journaltest.Build(journaltest.Options{Compact: compact, Compress: comp}, es)
}

func TestKeepFiltersBeforeReading(t *testing.T) {
	big := "COREDUMP=" + strings.Repeat("canary-core ", 9000) // ~100 KiB
	for _, comp := range compressions {
		raw := build(true, comp, journaltest.Entry{Realtime: 1, Fields: []string{"MESSAGE=hello", "COREDUMP_ENVIRON=SECRET=canary-env", "_CMDLINE=x --password=canary", big}})
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		var seen []string
		var e *Entry
		err = f.EntryOffsets(func(_, off uint64) bool {
			e, err = f.Entry(off, func(n string) bool { seen = append(seen, n); return n == "MESSAGE" })
			return err == nil
		})
		if err != nil {
			t.Fatalf("%s: %v", comp, err)
		}
		if e == nil || len(e.Fields) != 1 || e.Fields[0].Name != "MESSAGE" || string(e.Fields[0].Value) != "hello" {
			t.Fatalf("%s: fields %+v", comp, e)
		}
		if strings.Join(sorted(seen), ",") != "COREDUMP,COREDUMP_ENVIRON,MESSAGE,_CMDLINE" {
			t.Fatalf("%s: names %v", comp, seen)
		}
		for _, v := range f.data {
			if bytes.Contains(v, []byte("canary")) {
				t.Fatalf("%s: a rejected field's value was read", comp)
			}
		}
	}
}

// TestRefusedFieldNotDecompressed: reading the names of an entry costs the
// same whether its refused core dump is 10 KiB or 900 KiB. ZSTD and XZ
// decode only a prefix too, but their decoders allocate the frame's window
// (bounded: 8 MiB for ZSTD, the dictionary cap for XZ), so they are held to
// that bound instead.
func TestRefusedFieldNotDecompressed(t *testing.T) {
	cost := func(comp string, size int) uint64 {
		raw := build(true, comp, journaltest.Entry{Realtime: 1, Fields: []string{"MESSAGE=hello", "COREDUMP=" + strings.Repeat("canary-core ", size/12)}})
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var ms0, ms1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms0)
		f.EntryOffsets(func(_, off uint64) bool {
			f.Entry(off, func(n string) bool { return n == "MESSAGE" })
			return true
		})
		runtime.ReadMemStats(&ms1)
		return ms1.TotalAlloc - ms0.TotalAlloc
	}
	for _, comp := range compressions {
		small, large := cost(comp, 10<<10), cost(comp, 900<<10)
		bound := uint64(64 << 10)
		if comp == "zstd" || comp == "xz" {
			bound = 2 * MaxData
		}
		if large > small+bound {
			t.Errorf("%s: %d bytes allocated with a 900 KiB core dump, %d with 10 KiB", comp, large, small)
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

func TestOverCapDataDropped(t *testing.T) {
	big := "MESSAGE=" + strings.Repeat("a", MaxData)
	for _, comp := range compressions {
		raw := build(false, comp, journaltest.Entry{Realtime: 1, Fields: []string{big, "PRIORITY=3"}})
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		f.EntryOffsets(func(_, off uint64) bool {
			e, err := f.Entry(off, keepAll)
			if err != nil {
				t.Fatalf("%s: %v", comp, err)
			}
			if e.Dropped != 1 || len(e.Fields) != 1 || e.Fields[0].Name != "PRIORITY" {
				t.Fatalf("%s: dropped %d fields %d", comp, e.Dropped, len(e.Fields))
			}
			return true
		})
	}
}

func TestLZ4DeclaredSizeCheckedBeforeAllocation(t *testing.T) {
	// An LZ4 payload declaring 4 GiB: the name still reads from the
	// block's prefix, the value is refused from the size prefix alone,
	// and the entry keeps its other fields.
	raw := build(true, "lz4", journaltest.Entry{Realtime: 1, Fields: []string{"COREDUMP=xxxxxxxxxxxxxxxx", "MESSAGE=hello"}})
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	var core uint64
	for off := range f.dataOffsets(t) {
		if n, _ := f.name(off); n == "COREDUMP" {
			core = off
		}
	}
	putU64(raw[core+72:], 4<<30)
	f, _ = Open(bytes.NewReader(raw), int64(len(raw)))
	if n, err := f.name(core); err != nil || n != "COREDUMP" {
		t.Fatalf("name: %q %v", n, err)
	}
	if _, err := f.value(core, len("COREDUMP")); !errors.Is(err, errTooLarge) {
		t.Fatalf("value: %v", err)
	}
	f.EntryOffsets(func(_, off uint64) bool {
		e, err := f.Entry(off, keepAll)
		if err != nil || e.Dropped != 1 || len(e.Fields) != 1 || e.Fields[0].Name != "MESSAGE" {
			t.Fatalf("entry: %+v %v", e, err)
		}
		return true
	})
}

func TestEntryDataBudget(t *testing.T) {
	// One large allowed object listed many times: read once, and an
	// entry never keeps more than MaxEntryData.
	big := "MESSAGE=" + strings.Repeat("m", MaxData-100)
	raw := build(true, "zstd", journaltest.Entry{Realtime: 1, Fields: []string{big, "A_1=" + strings.Repeat("a", MaxData-100), "A_2=" + strings.Repeat("b", MaxData-100), "PRIORITY=3"}})
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	var off0 uint64
	f.EntryOffsets(func(_, off uint64) bool { off0 = off; return false })
	// Point every item at the MESSAGE object.
	h, _ := f.Head(off0)
	items := raw[off0+entryHeaderSize : off0+h.Size]
	first := append([]byte(nil), items[:4]...)
	for i := 0; i+4 <= len(items); i += 4 {
		copy(items[i:], first)
	}
	f, _ = Open(bytes.NewReader(raw), int64(len(raw)))
	e, err := f.Entry(off0, keepAll)
	if err != nil || len(e.Fields) != 1 {
		t.Fatalf("repeated object: %d fields, %v", len(e.Fields), err)
	}
	raw = build(true, "zstd", journaltest.Entry{Realtime: 1, Fields: []string{big, "A_1=" + strings.Repeat("a", MaxData-100), "A_2=" + strings.Repeat("b", MaxData-100)}})
	f, _ = Open(bytes.NewReader(raw), int64(len(raw)))
	f.EntryOffsets(func(_, off uint64) bool {
		e, err := f.Entry(off, keepAll)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, fl := range e.Fields {
			total += len(fl.Value)
		}
		if total > MaxEntryData || e.Dropped == 0 {
			t.Fatalf("entry kept %d bytes, dropped %d", total, e.Dropped)
		}
		return true
	})
}

func TestLZ4Prefix(t *testing.T) {
	for _, p := range []string{"MESSAGE=hello", "MESSAGE=" + strings.Repeat("ab", 500), strings.Repeat("Z", 70)} {
		out := make([]byte, lz4.CompressBlockBound(len(p)))
		n, _ := lz4.CompressBlock([]byte(p), out, nil)
		if n == 0 {
			continue
		}
		got := lz4Prefix(out[:n], 65)
		want := p[:min(65, len(p))]
		if string(got) != want {
			t.Fatalf("prefix %q, want %q", got, want)
		}
	}
	for _, junk := range [][]byte{nil, {0xff}, {0xf0, 255, 255}, {0x1f, 'a', 9, 0}} {
		lz4Prefix(junk, 65) // never panics
	}
}

func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// dataOffsets lists the DATA objects of a compact file.
func (f *File) dataOffsets(t *testing.T) map[uint64]bool {
	out := map[uint64]bool{}
	f.EntryOffsets(func(_, off uint64) bool {
		h, _ := f.Head(off)
		items := make([]byte, h.Size-entryHeaderSize)
		f.read(items, off+entryHeaderSize)
		for i := 0; i+4 <= len(items); i += 4 {
			out[uint64(items[i])|uint64(items[i+1])<<8|uint64(items[i+2])<<16|uint64(items[i+3])<<24] = true
		}
		return true
	})
	return out
}

func readAll(raw []byte) (n int) {
	f, err := Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return 0
	}
	defer f.Close()
	f.EntryOffsets(func(_, off uint64) bool {
		f.Head(off)
		if e, err := f.Entry(off, keepAll); err == nil {
			n += len(e.Fields)
		}
		return true
	})
	return n
}

func seeds() [][]byte {
	es := []journaltest.Entry{
		{Realtime: 10, Fields: []string{"MESSAGE=one", "PRIORITY=3", "_SYSTEMD_UNIT=api.service"}},
		{Realtime: 20, Fields: []string{"MESSAGE=two\nlines", "PRIORITY=6", "COREDUMP=\x00\x01\x02"}},
		{Realtime: 30, Fields: []string{"MESSAGE=" + strings.Repeat("z", 700), "PRIORITY=6"}},
	}
	var out [][]byte
	for _, c := range []bool{false, true} {
		for _, comp := range compressions {
			out = append(out, journaltest.Build(journaltest.Options{Compact: c, Compress: comp, PerArray: 2}, es))
		}
	}
	return out
}

func TestCorruptFilesNeverPanic(t *testing.T) {
	for _, raw := range seeds() {
		want := readAll(raw)
		if want != 8 {
			t.Fatalf("seed reads %d fields", want)
		}
		for cut := 0; cut < len(raw); cut += 7 {
			readAll(raw[:cut])
		}
		for i := 0; i < len(raw); i++ {
			b := bytes.Clone(raw)
			b[i] ^= 0xff
			readAll(b)
		}
	}
}

func TestEntryArrayLoopRefused(t *testing.T) {
	raw := seeds()[0]
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	arr := f.Header().EntryArrayOffset
	putU64(raw[arr+16:], arr) // next points at itself
	f, _ = Open(bytes.NewReader(raw), int64(len(raw)))
	if err := f.EntryOffsets(func(_, _ uint64) bool { return true }); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loop: %v", err)
	}
}

func TestNotJournal(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("LPKSHHRH"), bytes.Repeat([]byte{0}, 4096)} {
		if _, err := Open(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrNotJournal) {
			t.Fatalf("%q: %v", b[:min(len(b), 8)], err)
		}
	}
	raw := seeds()[0]
	raw[12] |= 1 << 6 // an unknown incompatible flag
	if _, err := Open(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown flag: %v", err)
	}
}

func FuzzJournal(f *testing.F) {
	for _, s := range seeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		readAll(b)
	})
}

// xzDataObject returns the offset of the XZ DATA object holding name.
func xzObject(t *testing.T, raw []byte, name string) uint64 {
	t.Helper()
	f, err := Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for off := range f.dataOffsets(t) {
		if n, _ := f.name(off); n == name {
			return off
		}
	}
	t.Fatalf("no %s object", name)
	return 0
}

func TestXZDictionaryCapped(t *testing.T) {
	for _, dictByte := range []byte{0x20, 40} { // 128 MiB, 4 GiB
		raw := build(true, "xz", journaltest.Entry{Realtime: 1, Fields: []string{"MESSAGE=hello", "PRIORITY=3"}})
		off := xzObject(t, raw, "MESSAGE")
		// Stream header (12 bytes), then the block header: size, flags,
		// filter id 0x21, property size 1, the dictionary byte.
		p := raw[off+72:]
		i := 12 + 2
		if p[13]&0x40 != 0 || p[13]&0x80 != 0 {
			t.Skip("builder wrote sizes in the block header")
		}
		if p[i] != 0x21 || p[i+1] != 1 {
			t.Fatalf("unexpected block header % x", p[12:20])
		}
		p[i+2] = dictByte // the block header CRC is not checked
		f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
		var ms0, ms1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms0)
		if n, err := f.name(off); err != nil || n != "MESSAGE" {
			t.Fatalf("dict %#x: name %q %v", dictByte, n, err)
		}
		if _, err := f.value(off, len("MESSAGE")); !errors.Is(err, errTooLarge) {
			t.Fatalf("dict %#x: value %v", dictByte, err)
		}
		runtime.ReadMemStats(&ms1)
		if a := ms1.TotalAlloc - ms0.TotalAlloc; a > 4*MaxXZDict {
			t.Fatalf("dict %#x: %d bytes allocated", dictByte, a)
		}
	}
}

func TestEntryDecodeWorkBounded(t *testing.T) {
	// 64 distinct over-cap XZ fields: each would be decoded whole to find
	// it is over the cap; the entry stops decoding after maxEntryWork.
	var fields []string
	for i := 0; i < 64; i++ {
		fields = append(fields, fmt.Sprintf("F_%d=%s", i, strings.Repeat(string(rune('a'+i%26)), MaxData+10)))
	}
	raw := build(true, "xz", journaltest.Entry{Realtime: 1, Fields: append(fields, "PRIORITY=3")})
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	f.EntryOffsets(func(_, off uint64) bool {
		e, err := f.Entry(off, keepAll)
		if err != nil || e.Dropped < 64 {
			t.Fatalf("entry: %v, dropped %d", err, e.Dropped)
		}
		return true
	})
	runtime.ReadMemStats(&ms1)
	if a := ms1.TotalAlloc - ms0.TotalAlloc; a > 64*MaxData {
		t.Fatalf("%d bytes allocated for one entry", a)
	}
}

func TestNameDecodingChargedToTheEntry(t *testing.T) {
	// Thousands of compressed fields the reader refuses: each name costs a
	// block decode, so after the budget the rest are dropped undecoded.
	var fields []string
	for i := 0; i < 2000; i++ {
		fields = append(fields, fmt.Sprintf("F_%d=%s", i, strings.Repeat("a", 128<<10)))
	}
	raw := build(true, "zstd", journaltest.Entry{Realtime: 1, Fields: fields})
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	f.EntryOffsets(func(_, off uint64) bool {
		e, err := f.Entry(off, func(string) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if decoded := 2000 - e.Dropped; decoded > maxEntryWork/nameCompressedCost+1 {
			t.Fatalf("%d compressed names decoded", decoded)
		}
		return true
	})
}

func TestXZSecondBlockDropped(t *testing.T) {
	raw := journaltest.Build(journaltest.Options{Compact: true, Compress: "xz", XZBlockSize: 1024},
		[]journaltest.Entry{{Realtime: 1, Fields: []string{"MESSAGE=" + strings.Repeat("x", 5000), "PRIORITY=3"}}})
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	f.EntryOffsets(func(_, off uint64) bool {
		e, err := f.Entry(off, keepAll)
		if err != nil || e.Dropped != 1 || len(e.Fields) != 1 || e.Fields[0].Name != "PRIORITY" {
			t.Fatalf("entry %+v %v", e, err)
		}
		return true
	})
}

type countingReaderAt struct {
	r io.ReaderAt
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

func TestCompressedNameReadIsBounded(t *testing.T) {
	// A ZSTD payload whose name sits behind 300,000 empty raw blocks.
	raw := build(true, "", journaltest.Entry{Realtime: 1, Fields: []string{"F=" + strings.Repeat("p", 1<<20)}})
	off := xzObjectAny(t, raw)
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00} // magic, no content size, 1 KiB window
	for i := 0; i < 300000; i++ {
		frame = append(frame, 0, 0, 0) // an empty raw block, not the last
	}
	name := "F=" + strings.Repeat("a", 80)
	frame = append(frame, byte(len(name)<<3|1), byte(len(name)>>5), 0)
	frame = append(frame, name...)
	raw[off+1] = objCompressedZSTD
	copy(raw[off+72:], frame)
	cr := &countingReaderAt{r: bytes.NewReader(raw)}
	f, err := Open(cr, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	cr.n = 0
	f.name(off) // corrupt or not, it must stop early
	if cr.n > 2*nameCompressedCost {
		t.Fatalf("decoding one name read %d bytes", cr.n)
	}
}

// xzObjectAny returns the offset of the only DATA object of a compact file.
func xzObjectAny(t *testing.T, raw []byte) uint64 {
	f, _ := Open(bytes.NewReader(raw), int64(len(raw)))
	for off := range f.dataOffsets(t) {
		return off
	}
	t.Fatal("no data object")
	return 0
}
