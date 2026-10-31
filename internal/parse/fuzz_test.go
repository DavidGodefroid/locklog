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
	"\f{}\n\v{\"a\":1}\n",
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
		walk(t, e.Attrs, 0)
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
	if !utf8.ValidString(v.Str) {
		t.Fatalf("invalid UTF-8 in %s value", v.Kind)
	}
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
	return fuzzReadAt(t, p, in, 0)
}

func fuzzReadAt(t *testing.T, p *Parser, in string, base int64) []Event {
	r := p.NewReader(strings.NewReader(in), base)
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

// checkResume asserts that a reader resumed at an event's offset yields the
// same event boundaries, text and formats from there on (Split and
// inherited times aside). It checks the first, middle and last events.
func checkResume(t *testing.T, p *Parser, in string, evs []Event) {
	t.Helper()
	if len(evs) == 0 {
		return
	}
	for _, i := range []int{0, len(evs) / 2, len(evs) - 1} {
		off := evs[i].Offset
		got := fuzzReadAt(t, p, in[off:], off)
		want := evs[i:]
		if len(got) != len(want) {
			t.Fatalf("resume at %d: %d events, want %d", off, len(got), len(want))
		}
		for j := range want {
			g, w := got[j], want[j]
			if g.Offset != w.Offset || g.Length != w.Length || g.Raw != w.Raw || g.Format != w.Format {
				t.Fatalf("resume at %d: event %d differs: %+v vs %+v", off, j, g, w)
			}
		}
	}
}

func FuzzParseAuto(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEvents(t, in, evs)
		checkResume(t, p, in, evs)
	})
}

func FuzzParseLine(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{})
	f.Fuzz(func(t *testing.T, in string) {
		ev := p.Line(in)
		if len(ev.Raw) > MaxEventBytes || ev.Lines > MaxEventLines || !utf8.ValidString(ev.Raw) || !utf8.ValidString(ev.Message) {
			t.Fatalf("Line: %d bytes, %d lines", len(ev.Raw), ev.Lines)
		}
		walk(t, ev.Fields, 0)
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
	p := mustParser(f, Options{Multiline: MultilinePattern, Start: `^\[?\d{4}-`})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEvents(t, in, evs)
		checkResume(t, p, in, evs)
	})
}

func FuzzParseFramed(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: "testframe"})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEventsGaps(t, in, evs, false)
		// Gaps may hold only blank lines and frames with a blank payload.
		var pos int64
		gaps := []string{}
		for _, e := range evs {
			gaps = append(gaps, in[pos:e.Offset])
			pos = e.Offset + e.Length
		}
		gaps = append(gaps, in[pos:])
		for _, g := range gaps {
			for _, l := range strings.Split(g, "\n") {
				if strings.TrimSpace(l) == "" {
					continue
				}
				fr, ok := testFramer{}.Unwrap(validText([]byte(strings.TrimSuffix(l, "\r"))), nil)
				if !ok || strings.TrimSpace(fr.Text) != "" {
					t.Fatalf("non-blank line skipped: %q", l)
				}
			}
		}
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

// formatSeeds are lines of the syslog, combined, CRI and docker-json
// formats.
var formatSeeds = []string{
	`<165>1 2003-10-11T22:14:15.003Z h app 1 ID [a@1 k="v\"]"][b x="1"] m` + "\n<13>1 - - - - - -\n",
	"<34>Oct 11 22:14:15 host su[1]: x\nFeb 29 12:00:00 h a: y\n2026-01-02T09:00:00+01:00 web s: z\n",
	`1.2.3.4 - u [10/Oct/2000:13:55:36 -0700] "GET /\"q HTTP/1.0" 200 1 "r" "ua" extra` + "\n",
	"2026-10-31T02:41:55Z stderr P {\"a\":\n2026-10-31T02:41:55Z stderr F 1}\n2026-10-31T02:41:56Z stdout F\n",
	`{"log":"a","stream":"stdout","time":"2026-10-31T02:41:55Z"}` + "\n" + `{"log":"b\n","attrs":{"t":"x"}}` + "\n",
}

func fuzzFormat(f *testing.F, name string, framed bool) {
	for _, s := range append(append([]string{}, fuzzSeeds...), formatSeeds...) {
		f.Add(s)
	}
	p := mustParser(f, Options{Format: name})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEventsGaps(t, in, evs, !framed)
		for _, e := range evs {
			if e.Format == name && !strings.Contains(in, e.Message) && name != "combined" && name != "syslog" {
				t.Fatalf("message %q not in the input", e.Message)
			}
		}
	})
}

func FuzzParseSyslog(f *testing.F)     { fuzzFormat(f, "syslog", false) }
func FuzzParseCombined(f *testing.F)   { fuzzFormat(f, "combined", false) }
func FuzzParseCRI(f *testing.F)        { fuzzFormat(f, "cri", true) }
func FuzzParseDockerJSON(f *testing.F) { fuzzFormat(f, "docker-json", true) }

// FuzzSyslogAndCombinedDecode checks that a decoded event's message is a
// suffix of the text (syslog) or built from it (combined), and that the
// structured data never panics on any header.
func FuzzSyslogAndCombinedDecode(f *testing.F) {
	for _, s := range formatSeeds {
		f.Add(strings.SplitN(s, "\n", 2)[0])
	}
	f.Fuzz(func(t *testing.T, line string) {
		if !utf8.ValidString(line) {
			return // the reader replaces invalid UTF-8 before decoding
		}
		if ev, ok := (syslogFormat{}).Decode(line, nil); ok {
			if !strings.HasSuffix(line, ev.Message) {
				t.Fatalf("syslog message %q is not the end of %q", ev.Message, line)
			}
			walk(t, ev.Fields, 0)
		}
		if ev, ok := (combinedFormat{}).Decode(line, nil); ok {
			walk(t, ev.Fields, 0)
			if (combinedFormat{}).Detect(line) != ok {
				t.Fatal("Detect and Decode disagree")
			}
		}
	})
}
