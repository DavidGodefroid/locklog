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
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestKeepFiltersBeforeReading(t *testing.T) {
	for _, z := range []bool{false, true} {
		raw := buildJournal(true, z, []testEntry{{realtime: 1, fields: []string{"MESSAGE=hello", "COREDUMP_ENVIRON=SECRET=canary-env", "_CMDLINE=x --password=canary"}}})
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		var seen []string
		err = f.EntryOffsets(func(_, off uint64) bool {
			e, err := f.Entry(off, func(n string) bool { seen = append(seen, n); return n == "MESSAGE" })
			if err != nil {
				t.Fatal(err)
			}
			if len(e.Fields) != 1 || e.Fields[0].Name != "MESSAGE" || string(e.Fields[0].Value) != "hello" {
				t.Fatalf("fields %+v", e.Fields)
			}
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(seen, ",") != "MESSAGE,COREDUMP_ENVIRON,_CMDLINE" {
			t.Fatalf("names %v", seen)
		}
		// Rejected values were never decoded: nothing of them is cached.
		for _, v := range f.data {
			if bytes.Contains(v, []byte("canary")) {
				t.Fatalf("a rejected field's value was read (zstd=%v)", z)
			}
		}
	}
}

func TestOverCapDataDropped(t *testing.T) {
	big := "MESSAGE=" + strings.Repeat("a", MaxData)
	for _, z := range []bool{false, true} {
		raw := buildJournal(false, z, []testEntry{{realtime: 1, fields: []string{big, "PRIORITY=3"}}})
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		f.EntryOffsets(func(_, off uint64) bool {
			e, err := f.Entry(off, keepAll)
			if err != nil {
				t.Fatal(err)
			}
			if e.Dropped != 1 || len(e.Fields) != 1 || e.Fields[0].Name != "PRIORITY" {
				t.Fatalf("zstd=%v: dropped %d fields %d", z, e.Dropped, len(e.Fields))
			}
			return true
		})
	}
}

func TestDeclaredSizeCheckedBeforeAllocation(t *testing.T) {
	// An LZ4 object declaring a 4 GiB payload is refused from its prefix.
	raw := buildJournal(true, false, []testEntry{{realtime: 1, fields: []string{"MESSAGE=xxxxxxxxxxxxxxxx"}}})
	f, err := Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var data uint64
	for off := range f.dataOffsets(t) {
		data = off
	}
	raw[data+1] = objCompressedLZ4
	putU64(raw[data+72:], 4<<30)
	f, _ = Open(bytes.NewReader(raw), int64(len(raw)))
	if _, err := f.name(data); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("name: %v", err)
	}
	if _, err := f.value(data, 7); !errors.Is(err, errTooLarge) {
		t.Fatalf("value: %v", err)
	}
}

func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// dataOffsets lists the DATA objects of a file built by buildJournal.
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
	es := []testEntry{
		{realtime: 10, fields: []string{"MESSAGE=one", "PRIORITY=3", "_SYSTEMD_UNIT=api.service"}},
		{realtime: 20, fields: []string{"MESSAGE=two\nlines", "PRIORITY=6", "COREDUMP=\x00\x01\x02"}},
		{realtime: 30, fields: []string{"MESSAGE=" + strings.Repeat("z", 700), "PRIORITY=6"}},
	}
	var out [][]byte
	for _, c := range []bool{false, true} {
		for _, z := range []bool{false, true} {
			out = append(out, buildJournal(c, z, es))
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
