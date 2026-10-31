package parse

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// lineStart returns the first line start at or after s.
func lineStart(in string, s int) int {
	if s == 0 {
		return 0
	}
	i := strings.IndexByte(in[s-1:], '\n')
	if i < 0 {
		return len(in)
	}
	return s + i
}

func drain(t testing.TB, r *Reader) []Event {
	t.Helper()
	var out []Event
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
}

// sectionsAgree checks that reading fixed sections of unit bytes one after
// the other on a shared LineReader gives, section by section, the same
// events as reading each section on its own.
func sectionsAgree(t testing.TB, p *Parser, in string, unit int) {
	t.Helper()
	shared := NewLineReader(strings.NewReader(in), 0)
	for s := 0; s < len(in); s += unit {
		e := min(s+unit, len(in))
		seq := drain(t, p.NewSectionReader(shared, int64(e)))
		st := lineStart(in, s)
		alone := drain(t, p.NewSectionReader(NewLineReader(strings.NewReader(in[st:]), int64(st)), int64(e)))
		if !reflect.DeepEqual(seq, alone) {
			t.Fatalf("section [%d,%d): sequential %+v != alone %+v", s, e, seq, alone)
		}
		for _, ev := range seq {
			if ev.Offset < int64(s) || ev.Offset >= int64(e) {
				t.Fatalf("event at %d outside section [%d,%d)", ev.Offset, s, e)
			}
		}
	}
	if _, err := shared.Next(); !errors.Is(err, io.EOF) {
		t.Fatal("shared reader not exhausted")
	}
}

func TestSectionsIndependent(t *testing.T) {
	for _, o := range []Options{{}, {Multiline: MultilineNone}, {Multiline: MultilinePattern, Start: `^\d{4}-`}, {Format: "testframe"}} {
		p := mustParser(t, o)
		for _, unit := range []int{1, 7, 64, 100, 1 << 20} {
			sectionsAgree(t, p, trace+trace, unit)
		}
	}
}

func TestSectionCutsEvents(t *testing.T) {
	p := mustParser(t, Options{})
	in := "head\n\tat a\n\tat b\n"
	lr := NewLineReader(strings.NewReader(in), 0)
	first := drain(t, p.NewSectionReader(lr, 8)) // "head\n" and "\tat a\n" start before 8
	second := drain(t, p.NewSectionReader(lr, int64(len(in))))
	if len(first) != 1 || first[0].Lines != 2 || len(second) != 1 || second[0].Raw != "\tat b" {
		t.Fatalf("%+v / %+v", first, second)
	}
}

func FuzzSections(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s, uint16(13))
	}
	ps := []*Parser{mustParser(f, Options{}), mustParser(f, Options{Format: "testframe"}),
		mustParser(f, Options{Multiline: MultilinePattern, Start: `^\[?\d{4}-`})}
	f.Fuzz(func(t *testing.T, in string, unit uint16) {
		u := int(unit%512) + 1
		for _, p := range ps {
			sectionsAgree(t, p, in, u)
		}
	})
}
