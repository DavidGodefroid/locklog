package parse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

var fuzzSeeds = []string{
	trace,
	`{"ts":"2026-10-30T14:02:11Z","msg":"x","n":1e400,"a":{"b":[{"c":null}]}}` + "\n",
	`level=error msg="a \"b\" c" status=502 k` + "\n",
	"\xff\xfe\r\n\r\n\t at x\n",
	`{"a":` + strings.Repeat("[", 70) + "\n",
	"2026-10-30T14:00:00Z P part\n2026-10-30T14:00:00Z F end\n",
	"[2026-10-30 14:02:11] [error] x\n  y\nCaused by: z\n",
}

// checkEvents asserts the reader's invariants on any input: events ordered,
// non-overlapping, inside the input, separated only by blank bytes; caps
// held; valid UTF-8 everywhere.
func checkEvents(t *testing.T, in string, evs []Event) {
	t.Helper()
	checkEventsGaps(t, in, evs, true)
}

func checkEventsGaps(t *testing.T, in string, evs []Event, blankGaps bool) {
	t.Helper()
	checkCoverageGaps(t, in, evs, blankGaps)
	for _, e := range evs {
		if len(e.Raw) > MaxEventBytes || e.Lines > MaxEventLines || e.Lines < 1 {
			t.Fatalf("caps: %d bytes, %d lines", len(e.Raw), e.Lines)
		}
		if !utf8.ValidString(e.Raw) || !utf8.ValidString(e.Message) {
			t.Fatal("invalid UTF-8 in event")
		}
		walk(t, e.Fields, 0)
	}
}

func walk(t *testing.T, ms []Member, depth int) {
	if depth > MaxDepth+1 {
		t.Fatalf("depth %d", depth)
	}
	for _, m := range ms {
		if len(m.Key) > MaxKeyBytes || !utf8.ValidString(m.Key) || !utf8.ValidString(m.Value.Str) {
			t.Fatalf("bad member %q", m.Key)
		}
		walkValue(t, m.Value, depth+1)
	}
}

func walkValue(t *testing.T, v Value, depth int) {
	switch v.Kind {
	case KindObject:
		walk(t, v.Members, depth)
	case KindArray:
		for _, it := range v.Items {
			walkValue(t, it, depth+1)
		}
	case KindNumber:
		if !isNumber(v.Str) {
			t.Fatalf("number literal %q", v.Str)
		}
	}
}

func fuzzRead(t *testing.T, p *Parser, in string) []Event {
	r := p.NewReader(strings.NewReader(in), 0)
	var evs []Event
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return evs
		}
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
	}
}

func FuzzParseAuto(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{})
	f.Fuzz(func(t *testing.T, in string) {
		checkEvents(t, in, fuzzRead(t, p, in))
	})
}

func FuzzParseJSON(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: "json", Multiline: MultilineNone})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEvents(t, in, evs)
		for _, e := range evs {
			if e.Format == "json" {
				// A decoded line re-decodes identically.
				v, err := DecodeJSON(e.Raw)
				if err != nil || v.Kind != KindObject {
					t.Fatalf("json event does not re-decode: %v", err)
				}
			}
		}
	})
}

func FuzzParseLogfmt(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: "logfmt"})
	f.Fuzz(func(t *testing.T, in string) {
		checkEvents(t, in, fuzzRead(t, p, in))
	})
}

func FuzzParseMultilinePattern(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: "plain", Multiline: MultilinePattern, Start: `^\[?\d{4}-`})
	f.Fuzz(func(t *testing.T, in string) {
		checkEvents(t, in, fuzzRead(t, p, in))
	})
}

func FuzzParseFramed(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: "testframe"})
	f.Fuzz(func(t *testing.T, in string) {
		// Frames with a blank payload are skipped like blank lines.
		checkEventsGaps(t, in, fuzzRead(t, p, in), false)
	})
}

func FuzzParseTime(f *testing.F) {
	for _, s := range []string{"1730297000", "2026-10-30T14:02:11.204Z", "2026-10-30 14:02:11,5", "1730297000.123456789123"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if tm, ok := ParseTime(s, nil); ok && (tm.Before(minTime) || !tm.Before(maxTime)) {
			t.Fatalf("out of range %v", tm)
		}
	})
}
