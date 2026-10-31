package parse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func mustParser(t testing.TB, o Options) *Parser {
	t.Helper()
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func readAll(t testing.TB, p *Parser, in string) []Event {
	t.Helper()
	r := p.NewReader(strings.NewReader(in), 0)
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

func TestJSONExactNumbersOrderDuplicates(t *testing.T) {
	p := mustParser(t, Options{Format: "json"})
	in := `{"ts":"2026-10-30T14:02:11.204Z","level":"error","msg":"boom","order_id":12345678901234567890,"amount":0.1000000000000000055511,"a":1,"a":2,"nested":{"k":[1,"x",null,true]}}` + "\n"
	evs := readAll(t, p, in)
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	ev := evs[0]
	if ev.Format != "json" || ev.Fallback {
		t.Fatalf("format %q fallback %v", ev.Format, ev.Fallback)
	}
	want := time.Date(2026, 10, 30, 14, 2, 11, 204e6, time.UTC)
	if !ev.HasTime || !ev.Time.Equal(want) || ev.TimeKey != "ts" {
		t.Fatalf("time %v %v %q", ev.Time, ev.HasTime, ev.TimeKey)
	}
	if ev.Message != "boom" || ev.MessageKey != "msg" {
		t.Fatalf("message %q %q", ev.Message, ev.MessageKey)
	}
	keys := []string{}
	for _, m := range ev.Fields {
		keys = append(keys, m.Key)
	}
	if got := strings.Join(keys, ","); got != "level,order_id,amount,a,a,nested" {
		t.Fatalf("keys %s", got)
	}
	if v, _ := Get(ev.Fields, "order_id"); v.Kind != KindNumber || v.Str != "12345678901234567890" {
		t.Fatalf("order_id %+v", v)
	}
	if v, _ := Get(ev.Fields, "amount"); v.Str != "0.1000000000000000055511" {
		t.Fatalf("amount %+v", v)
	}
	n, _ := Get(ev.Fields, "nested")
	k, _ := Get(n.Members, "k")
	if len(k.Items) != 4 || k.Items[2].Kind != KindNull || k.Items[3].Str != "true" {
		t.Fatalf("nested %+v", k)
	}
	if ev.Offset != 0 || ev.Length != int64(len(in)) || ev.Lines != 1 {
		t.Fatalf("position %d %d %d", ev.Offset, ev.Length, ev.Lines)
	}
}

func TestJSONLimitsFallBackToText(t *testing.T) {
	p := mustParser(t, Options{Format: "json"})
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	longKey := `{"` + strings.Repeat("k", MaxKeyBytes+1) + `":1}`
	okDepth := `{"a":` + strings.Repeat("[", MaxDepth-1) + strings.Repeat("]", MaxDepth-1) + `}`
	for name, tc := range map[string]struct {
		line     string
		fallback bool
	}{
		"deep":      {`{"a":` + deep + `}`, true},
		"long key":  {longKey, true},
		"trailing":  {`{"a":1} x`, true},
		"two":       {`{"a":1}{"b":2}`, true},
		"not obj":   {`[1,2]`, true},
		"max depth": {okDepth, false},
	} {
		evs := readAll(t, p, tc.line+"\n")
		if len(evs) != 1 || evs[0].Fallback != tc.fallback {
			t.Fatalf("%s: %+v", name, evs)
		}
		if tc.fallback && (evs[0].Format != "plain" || evs[0].Message != tc.line || evs[0].Fields != nil) {
			t.Fatalf("%s: fallback event %+v", name, evs[0])
		}
	}
}

func TestLogfmt(t *testing.T) {
	p := mustParser(t, Options{})
	evs := readAll(t, p, `time=2026-10-30T14:02:11Z level=error msg="upstream \"timed\" out" status=502 dur=1.5e3 ok debug path=/a?b=c empty=`+"\n")
	if len(evs) != 1 {
		t.Fatal(len(evs))
	}
	ev := evs[0]
	if ev.Format != "logfmt" || ev.Message != `upstream "timed" out` || ev.TimeKey != "time" {
		t.Fatalf("%+v", ev)
	}
	for k, want := range map[string]Value{
		"status": {Kind: KindNumber, Str: "502"},
		"dur":    {Kind: KindNumber, Str: "1.5e3"},
		"debug":  {Kind: KindBool, Str: "true"},
		"path":   {Kind: KindString, Str: "/a?b=c"},
		"empty":  {Kind: KindString, Str: ""},
		"level":  {Kind: KindString, Str: "error"},
	} {
		got, ok := Get(ev.Fields, k)
		if !ok || got.Kind != want.Kind || got.Str != want.Str {
			t.Fatalf("%s: %+v", k, got)
		}
	}
}

func TestAutoDetection(t *testing.T) {
	p := mustParser(t, Options{})
	in := strings.Join([]string{
		`{"msg":"j"}`,
		`level=info msg=l`,
		`2026-10-30 14:02:11.123 ERROR plain text here`,
		`just words = not logfmt`,
	}, "\n")
	evs := readAll(t, p, in)
	got := []string{}
	for _, e := range evs {
		got = append(got, e.Format)
	}
	if strings.Join(got, ",") != "json,logfmt,plain,plain" {
		t.Fatalf("formats %v", got)
	}
	if evs[2].Message != "ERROR plain text here" || !evs[2].HasTime {
		t.Fatalf("plain %+v", evs[2])
	}
	if lvl, _ := Get(evs[2].Fields, "level"); lvl.Str != "error" {
		t.Fatalf("level %+v", evs[2].Fields)
	}
	if evs[3].Fallback {
		t.Fatal("auto never falls back")
	}
}

func TestPlainTimestampsAndLevels(t *testing.T) {
	p := mustParser(t, Options{Format: "plain"})
	for line, want := range map[string]struct {
		t   string
		lvl string
	}{
		"2026-10-30T14:02:11Z [warn] x":            {"2026-10-30T14:02:11Z", "warn"},
		"[2026-10-30 14:02:11] error: x":           {"2026-10-30T14:02:11Z", "error"},
		"2026-10-30 14:02:11,500 INFO x":           {"2026-10-30T14:02:11.5Z", "info"},
		"2026-10-30 16:02:11.000 +0200 FATAL x":    {"2026-10-30T14:02:11Z", "fatal"},
		"2026/10/30 14:02:11 hello":                {"2026-10-30T14:02:11Z", ""},
		"no time here ERROR":                       {"", ""},
		"1730297000 seconds is not a leading time": {"", ""},
	} {
		ev := p.Line(line)
		if want.t == "" {
			if ev.HasTime {
				t.Fatalf("%q: unexpected time %v", line, ev.Time)
			}
		} else {
			wt, _ := time.Parse(time.RFC3339Nano, want.t)
			if !ev.HasTime || !ev.Time.Equal(wt) {
				t.Fatalf("%q: time %v %v", line, ev.Time, ev.HasTime)
			}
		}
		lvl, _ := Get(ev.Fields, "level")
		if lvl.Str != want.lvl {
			t.Fatalf("%q: level %q", line, lvl.Str)
		}
	}
}

func TestParseTimeEpochs(t *testing.T) {
	want := time.Date(2024, 10, 30, 14, 3, 20, 0, time.UTC)
	for _, s := range []string{"1730297000", "1730297000000", "1730297000000000", "1730297000000000000", "1730297000.0"} {
		got, ok := ParseTime(s, nil)
		if !ok || !got.Equal(want) {
			t.Fatalf("%s: %v %v", s, got, ok)
		}
	}
	for _, s := range []string{"12", "1730297000000.5", "1e9", "-1730297000", "99999999999999999999", "", "1730297000."} {
		if got, ok := ParseTime(s, nil); ok {
			t.Fatalf("%s: unexpected %v", s, got)
		}
	}
	if got, ok := ParseTime("1730297000.25", nil); !ok || got.Nanosecond() != 250e6 {
		t.Fatalf("fraction %v", got)
	}
	loc := time.FixedZone("x", 3600)
	if got, _ := ParseTime("2026-10-30 15:00:00", loc); got.Hour() != 14 {
		t.Fatalf("location %v", got)
	}
}

func TestJSONNumericTime(t *testing.T) {
	p := mustParser(t, Options{})
	ev := p.Line(`{"time":1730297000123,"msg":"x"}`)
	if !ev.HasTime || ev.Time.UnixMilli() != 1730297000123 {
		t.Fatalf("%+v", ev)
	}
	// An implausible time stays a field.
	ev = p.Line(`{"time":5,"msg":"x"}`)
	if ev.HasTime {
		t.Fatal("5 is not a time")
	}
	if v, ok := Get(ev.Fields, "time"); !ok || v.Str != "5" {
		t.Fatalf("%+v", ev.Fields)
	}
}

const trace = `2026-10-30T14:02:11Z ERROR request failed
java.lang.IllegalStateException: boom
	at a.b.C.d(C.java:10)
	at a.b.C.e(C.java:20)
Caused by: java.io.IOException: io
	... 3 more
2026-10-30T14:02:12Z INFO next
`

func TestMultilineIndent(t *testing.T) {
	p := mustParser(t, Options{})
	evs := readAll(t, p, trace)
	if len(evs) != 3 {
		t.Fatalf("got %d events: %+v", len(evs), evs)
	}
	// The exception line is not indented: it is its own event, which
	// absorbs the indented frames and the Caused by.
	if evs[0].Lines != 1 || evs[1].Lines != 5 || evs[2].Lines != 1 {
		t.Fatalf("lines %d %d %d", evs[0].Lines, evs[1].Lines, evs[2].Lines)
	}
	if !evs[1].Inherited || !evs[1].Time.Equal(evs[0].Time) {
		t.Fatal("continuation event inherits the time")
	}
	checkCoverage(t, trace, evs)
}

func TestMultilinePattern(t *testing.T) {
	p := mustParser(t, Options{Multiline: MultilinePattern, Start: `^\d{4}-\d{2}-\d{2}T`})
	evs := readAll(t, p, trace)
	if len(evs) != 2 || evs[0].Lines != 6 || evs[1].Lines != 1 {
		t.Fatalf("%+v", evs)
	}
	if !strings.HasPrefix(evs[0].Raw, "2026-10-30T14:02:11Z ERROR") || !strings.HasSuffix(evs[0].Raw, "... 3 more") {
		t.Fatalf("raw %q", evs[0].Raw)
	}
	if evs[0].Message != strings.TrimPrefix(evs[0].Raw, "2026-10-30T14:02:11Z ") {
		t.Fatalf("message %q", evs[0].Message)
	}
	checkCoverage(t, trace, evs)
}

func TestMultilineNone(t *testing.T) {
	p := mustParser(t, Options{Multiline: MultilineNone})
	if evs := readAll(t, p, trace); len(evs) != 7 {
		t.Fatalf("got %d", len(evs))
	}
}

func TestStructuredNeverAbsorbsContinuation(t *testing.T) {
	p := mustParser(t, Options{})
	evs := readAll(t, p, "{\"msg\":\"a\"}\n  indented\n")
	if len(evs) != 2 || evs[0].Format != "json" || evs[1].Format != "plain" {
		t.Fatalf("%+v", evs)
	}
}

func TestEventLineCapSplits(t *testing.T) {
	p := mustParser(t, Options{})
	var b strings.Builder
	b.WriteString("2026-10-30T14:02:11Z start\n")
	for i := 0; i < MaxEventLines+10; i++ {
		b.WriteString("\tat frame\n")
	}
	in := b.String()
	evs := readAll(t, p, in)
	if len(evs) != 2 || evs[0].Lines != MaxEventLines || evs[1].Lines != 11 || !evs[1].Split || evs[0].Split {
		t.Fatalf("%d events, lines %d", len(evs), evs[0].Lines)
	}
	if !evs[1].Inherited {
		t.Fatal("split part inherits time")
	}
	checkCoverage(t, in, evs)
}

func TestEventByteCapSplits(t *testing.T) {
	p := mustParser(t, Options{})
	line := "\t" + strings.Repeat("x", 100<<10) + "\n"
	in := "head\n" + line + line + line
	evs := readAll(t, p, in)
	for _, e := range evs {
		if len(e.Raw) > MaxEventBytes {
			t.Fatalf("event of %d bytes", len(e.Raw))
		}
	}
	if len(evs) != 2 || evs[0].Lines != 3 || evs[1].Lines != 1 {
		t.Fatalf("%d events", len(evs))
	}
	checkCoverage(t, in, evs)
}

func TestLongLineTruncated(t *testing.T) {
	p := mustParser(t, Options{})
	long := strings.Repeat("é", MaxLineBytes) // 2 bytes each: twice the cap
	in := long + "\nnext\n"
	evs := readAll(t, p, in)
	if len(evs) != 2 {
		t.Fatalf("%d", len(evs))
	}
	if !evs[0].Truncated || len(evs[0].Raw) > MaxLineBytes || !strings.HasSuffix(evs[0].Raw, "é") {
		t.Fatalf("truncated %v len %d", evs[0].Truncated, len(evs[0].Raw))
	}
	if evs[0].Length != int64(len(long)+1) || evs[1].Offset != int64(len(long)+1) {
		t.Fatalf("offsets %d %d", evs[0].Length, evs[1].Offset)
	}
}

func TestLineReaderTerminators(t *testing.T) {
	lr := NewLineReader(strings.NewReader("a\r\nb\n\nc"), 100)
	var got []Line
	for {
		l, err := lr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		got = append(got, l)
	}
	want := []Line{{Text: "a", Offset: 100, Length: 3}, {Text: "b", Offset: 103, Length: 2}, {Text: "", Offset: 105, Length: 1}, {Text: "c", Offset: 106, Length: 1, Unterminated: true}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %+v != %+v", i, got[i], want[i])
		}
	}
	if lr.Offset() != 107 {
		t.Fatal(lr.Offset())
	}
}

func TestLineCapExactlyAtCRLF(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes)
	lr := NewLineReader(strings.NewReader(line+"\r\n"), 0)
	l, err := lr.Next()
	if err != nil || l.Truncated || l.Text != line || l.Length != int64(MaxLineBytes+2) {
		t.Fatalf("%v truncated=%v len=%d", err, l.Truncated, len(l.Text))
	}
}

func TestInvalidUTF8Replaced(t *testing.T) {
	p := mustParser(t, Options{})
	ev := p.Line("bad \xff\xfe bytes")
	if ev.Raw != "bad � bytes" && ev.Raw != "bad �� bytes" {
		t.Fatalf("%q", ev.Raw)
	}
}

func TestResumeAtOffset(t *testing.T) {
	p := mustParser(t, Options{})
	all := readAll(t, p, trace)
	r := p.NewReader(strings.NewReader(trace), 0)
	first, _ := r.Next()
	off := r.Offset()
	if off != first.Offset+first.Length {
		t.Fatalf("offset %d", off)
	}
	r2 := p.NewReader(strings.NewReader(trace[off:]), off)
	rest := []Event{}
	for {
		ev, err := r2.Next()
		if err != nil {
			break
		}
		rest = append(rest, ev)
	}
	if len(rest) != len(all)-1 || rest[0].Offset != all[1].Offset || rest[0].Raw != all[1].Raw {
		t.Fatalf("resume %+v", rest)
	}
}

func TestOptionsValidation(t *testing.T) {
	for _, o := range []Options{
		{Format: "nope"},
		{Multiline: "weird"},
		{Multiline: MultilinePattern},
		{Multiline: MultilinePattern, Start: "("},
		{Multiline: MultilinePattern, Start: strings.Repeat("a", MaxPatternBytes+1)},
		{Start: "^x"},
	} {
		if _, err := New(o); err == nil {
			t.Fatalf("%+v accepted", o)
		}
	}
	p := mustParser(t, Options{})
	if o := p.Options(); o.Format != "auto" || o.Multiline != MultilineIndent {
		t.Fatalf("%+v", o)
	}
}

func TestLineCapsLongRecord(t *testing.T) {
	p := mustParser(t, Options{})
	ev := p.Line(strings.Repeat("x", MaxEventBytes+5))
	if !ev.Truncated || len(ev.Raw) != MaxEventBytes || ev.Length != MaxEventBytes+5 {
		t.Fatalf("%v %d", ev.Truncated, len(ev.Raw))
	}
}

// testFramer frames lines as "<ts> <P|F> <payload>", like CRI.
type testFramer struct{}

func (testFramer) Name() string                          { return "testframe" }
func (testFramer) Detect(string) bool                    { return false }
func (testFramer) Decode(string, *Options) (Event, bool) { return Event{}, false }
func (testFramer) Unwrap(line string, o *Options) (Frame, bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || (parts[1] != "P" && parts[1] != "F") {
		return Frame{}, false
	}
	t, ok := ParseTime(parts[0], nil)
	return Frame{Text: parts[2], Time: t, HasTime: ok, Partial: parts[1] == "P",
		Attrs: []Member{{Key: "stream", Value: Value{Kind: KindString, Str: "stdout"}}}}, true
}

func init() { Register(testFramer{}, -1) }

func TestFramerJoinsPartials(t *testing.T) {
	p := mustParser(t, Options{Format: "testframe"})
	in := "2026-10-30T14:00:00Z P {\"msg\":\"he\n2026-10-30T14:00:00Z F llo\",\"ts\":\"2020-01-01T00:00:00Z\"}\n2026-10-30T14:00:01Z F plain\nnot a frame\n"
	evs := readAll(t, p, in)
	if len(evs) != 3 {
		t.Fatalf("%d %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Format != "json" || e.Message != "hello" || e.Time.Hour() != 14 || len(e.Attrs) != 1 {
		t.Fatalf("%+v", e)
	}
	// The payload's own timestamp is kept as a field.
	if v, ok := Get(e.Fields, "ts"); !ok || v.Str != "2020-01-01T00:00:00Z" {
		t.Fatalf("payload ts lost: %+v", e.Fields)
	}
	if e.Length != int64(len("2026-10-30T14:00:00Z P {\"msg\":\"he\n2026-10-30T14:00:00Z F llo\",\"ts\":\"2020-01-01T00:00:00Z\"}\n")) {
		t.Fatalf("length %d", e.Length)
	}
	if evs[2].Format != "plain" || evs[2].Attrs != nil {
		t.Fatalf("%+v", evs[2])
	}
	checkCoverage(t, in, evs)
}

// checkCoverage asserts events are ordered, non-overlapping, within the input,
// and that the bytes between them are blank.
func checkCoverage(t testing.TB, in string, evs []Event) {
	t.Helper()
	checkCoverageGaps(t, in, evs, true)
}

// checkCoverageGaps is checkCoverage; blankGaps false allows skipped frames
// whose payload is blank.
func checkCoverageGaps(t testing.TB, in string, evs []Event, blankGaps bool) {
	t.Helper()
	var pos int64
	for i, e := range evs {
		if e.Offset < pos || e.Length <= 0 || e.Offset+e.Length > int64(len(in)) {
			t.Fatalf("event %d at %d+%d after %d (input %d)", i, e.Offset, e.Length, pos, len(in))
		}
		if gap := in[pos:e.Offset]; blankGaps && strings.TrimSpace(gap) != "" {
			t.Fatalf("event %d: non-blank gap %q", i, gap)
		}
		pos = e.Offset + e.Length
	}
	if tail := in[pos:]; blankGaps && strings.TrimSpace(tail) != "" {
		t.Fatalf("non-blank tail %q", tail)
	}
}

func TestCapsHoldWithInvalidUTF8(t *testing.T) {
	bad := strings.Repeat("\xffa", MaxLineBytes/2)
	p := mustParser(t, Options{})
	for _, ev := range readAll(t, p, bad+"\n") {
		if len(ev.Raw) > MaxEventBytes || !ev.Truncated {
			t.Fatalf("reader: %d bytes, truncated %v", len(ev.Raw), ev.Truncated)
		}
	}
	if ev := p.Line(bad); len(ev.Raw) > MaxEventBytes || !ev.Truncated {
		t.Fatalf("Line: %d bytes", len(ev.Raw))
	}
	fp := mustParser(t, Options{Format: "testframe"})
	in := "2026-10-30T14:00:00Z P " + bad + "\n2026-10-30T14:00:00Z F " + bad + "\n"
	for _, ev := range readAll(t, fp, in) {
		if len(ev.Raw) > MaxEventBytes {
			t.Fatalf("framed: %d bytes", len(ev.Raw))
		}
	}
}

func TestLineCapsLines(t *testing.T) {
	p := mustParser(t, Options{})
	ev := p.Line(strings.Repeat("a\n", 2000))
	if ev.Lines != MaxEventLines || !ev.Truncated {
		t.Fatalf("lines %d", ev.Lines)
	}
}

func TestOffsetHoldsUnterminatedTail(t *testing.T) {
	p := mustParser(t, Options{})
	in := "one\ntwo passw"
	r := p.NewReader(strings.NewReader(in), 0)
	a, _ := r.Next()
	b, _ := r.Next()
	if a.Unterminated || !b.Unterminated || b.Raw != "two passw" {
		t.Fatalf("%+v %+v", a, b)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if r.Offset() != 4 {
		t.Fatalf("offset %d, want the unterminated event's 4", r.Offset())
	}
}

func TestResumeMidSplitIndent(t *testing.T) {
	p := mustParser(t, Options{})
	var b strings.Builder
	b.WriteString("head\n")
	for i := 0; i < MaxEventLines; i++ {
		b.WriteString("\tat x\n")
	}
	b.WriteString("\t{\"a\":1}\n\tat y\n")
	in := b.String()
	all := readAll(t, p, in)
	if len(all) != 2 || !all[1].Split || all[1].Format != "plain" {
		t.Fatalf("%+v", all)
	}
	rest := readAll(t, p, in[all[1].Offset:])
	if len(rest) != 1 || rest[0].Raw != all[1].Raw || rest[0].Format != "plain" || rest[0].Lines != all[1].Lines {
		t.Fatalf("resumed %+v vs %+v", rest, all[1])
	}
}

func TestPatternBlankWhenFullSplits(t *testing.T) {
	p := mustParser(t, Options{Multiline: MultilinePattern, Start: `^START`})
	var b strings.Builder
	b.WriteString("START\n")
	for i := 1; i < MaxEventLines; i++ {
		b.WriteString("x\n")
	}
	b.WriteString("\n{\"cont\":\"v\"}\n")
	evs := readAll(t, p, b.String())
	if len(evs) != 2 || !evs[1].Split || evs[1].Format != "plain" {
		t.Fatalf("%d %+v", len(evs), evs[len(evs)-1])
	}
}

func TestFramedPlainKeepsPayloadTime(t *testing.T) {
	p := mustParser(t, Options{Format: "testframe"})
	evs := readAll(t, p, "2026-10-30T14:00:00Z F 2020-01-01T00:00:00Z secret here\n")
	if len(evs) != 1 || evs[0].Message != "2020-01-01T00:00:00Z secret here" || evs[0].Time.Year() != 2026 {
		t.Fatalf("%+v", evs)
	}
}

type failAfter struct {
	data string
	done bool
}

func (f *failAfter) Read(b []byte) (int, error) {
	if f.done {
		return 0, errors.New("disk error")
	}
	f.done = true
	return copy(b, f.data), nil
}

func TestReadErrorKeepsOffset(t *testing.T) {
	lr := NewLineReader(&failAfter{data: "ok\npart"}, 0)
	if l, err := lr.Next(); err != nil || l.Text != "ok" {
		t.Fatal(l, err)
	}
	if _, err := lr.Next(); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("want the read error, got %v", err)
	}
	if lr.Offset() != 3 {
		t.Fatalf("offset %d, want 3", lr.Offset())
	}
}

func TestPartialFrameAtEOFHeld(t *testing.T) {
	p := mustParser(t, Options{Format: "testframe"})
	r := p.NewReader(strings.NewReader("2026-10-30T14:00:00Z P {\"msg\":\"he\n"), 0)
	ev, err := r.Next()
	if err != nil || !ev.Unterminated {
		t.Fatalf("%+v %v", ev, err)
	}
	r.Next()
	if r.Offset() != 0 {
		t.Fatalf("offset %d, want 0", r.Offset())
	}
}

func TestResumeMidSplitPattern(t *testing.T) {
	p := mustParser(t, Options{Multiline: MultilinePattern, Start: `^START`})
	var b strings.Builder
	b.WriteString("START\n")
	for i := 1; i < MaxEventLines; i++ {
		b.WriteString("x\n")
	}
	b.WriteString("{\"a\":1}\nmore\n")
	in := b.String()
	all := readAll(t, p, in)
	if len(all) != 2 || !all[1].Split || all[1].Lines != 2 {
		t.Fatalf("%+v", all)
	}
	rest := readAll(t, p, in[all[1].Offset:])
	if len(rest) != 1 || rest[0].Raw != all[1].Raw || rest[0].Format != "plain" {
		t.Fatalf("resumed %+v", rest)
	}
}

func TestFramedJSONKeepsMemberOrder(t *testing.T) {
	p := mustParser(t, Options{Format: "testframe"})
	evs := readAll(t, p, "2026-10-30T14:00:00Z F {\"a\":1,\"ts\":\"2020-01-01T00:00:00Z\",\"b\":2}\n")
	var keys []string
	for _, m := range evs[0].Fields {
		keys = append(keys, m.Key)
	}
	if strings.Join(keys, ",") != "a,ts,b" {
		t.Fatalf("order %v", keys)
	}
}

func TestUnterminatedBlankTailHeld(t *testing.T) {
	p := mustParser(t, Options{})
	r := p.NewReader(strings.NewReader("ERROR x\n   "), 0)
	r.Next()
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if r.Offset() != 8 {
		t.Fatalf("offset %d, want 8", r.Offset())
	}
}

func TestCapTextKeepsRuneCutByReader(t *testing.T) {
	b := append([]byte(strings.Repeat("a", MaxLineBytes-1)), "é"...) // é straddles the cap
	s, cut := capText(b, MaxLineBytes)
	if !cut || strings.ContainsRune(s, '�') || len(s) != MaxLineBytes-1 {
		t.Fatalf("cut=%v len=%d", cut, len(s))
	}
}
