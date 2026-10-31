package parse

import (
	"strings"
	"testing"
)

// attr returns an attribute, "attrs.<key>" reaching into the attrs object.
func attr(ev Event, key string) (string, bool) {
	head, rest, nested := strings.Cut(key, ".")
	v, ok := Get(ev.Attrs, head)
	if ok && nested {
		v, ok = Get(v.Members, rest)
	}
	return v.Str, ok
}

// The docker-json frame with the source's options: FrameAttrs filters the
// attrs object, StaticAttrs comes first on every event.
func TestDockerJSONFrameAttrs(t *testing.T) {
	p := mustParser(t, Options{Format: "docker-json", FrameAttrs: []string{"team"},
		StaticAttrs: []Member{{Key: "container", Value: Value{Kind: KindString, Str: "shop-api-1"}}}})
	in := `{"log":"{\"msg\":\"he","stream":"stdout","time":"2026-10-31T01:20:40.732446205Z"}` + "\n" +
		`{"log":"llo\",\"level\":\"error\"}\n","stream":"stdout","attrs":{"team":"shop","secret":"s3cr3t"},"time":"2026-10-31T01:20:41Z"}` + "\n" +
		`{"log":"plain text\r\n","stream":"stderr","attrs":{"team":"shop","env":"X=1"},"time":"2026-10-31T01:20:42Z"}` + "\n" +
		"not a frame\n" +
		`{"log":"\n","stream":"stdout","time":"2026-10-31T01:20:43Z"}` + "\n" +
		`{"log":"no time\n"}` + "\n"
	evs := readAll(t, p, in)
	if len(evs) != 4 {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	e := evs[0]
	// Partial frames joined; the first frame's time is the record time.
	if e.Format != "json" || e.Message != "hello" || e.Time.Second() != 40 || e.Time.Nanosecond() != 732446205 {
		t.Fatalf("joined: %+v", e)
	}
	if v, _ := attr(e, "stream"); v != "stdout" {
		t.Errorf("stream: %+v", e.Attrs)
	}
	if v, _ := attr(e, "container"); v != "shop-api-1" || e.Attrs[0].Key != "container" {
		t.Errorf("static attr: %+v", e.Attrs)
	}
	// The first frame of the run carries the attrs: none here.
	if _, ok := attr(e, "attrs.team"); ok {
		t.Errorf("attrs of a later frame kept: %+v", e.Attrs)
	}
	e = evs[1]
	if e.Format != "plain" || e.Message != "plain text" || e.Raw != "plain text" {
		t.Fatalf("crlf: %+v", e)
	}
	if v, _ := attr(e, "stream"); v != "stderr" {
		t.Errorf("stream: %+v", e.Attrs)
	}
	if v, _ := attr(e, "attrs.team"); v != "shop" {
		t.Errorf("allowed attr: %+v", e.Attrs)
	}
	if a, _ := Get(e.Attrs, "attrs"); len(a.Members) != 1 {
		t.Errorf("attrs outside the allowlist kept: %+v", e.Attrs)
	}
	if !e.Framed || evs[2].Framed {
		t.Errorf("Framed: %v %v", e.Framed, evs[2].Framed)
	}
	// A non-frame line is free text, with the static attrs only.
	if e := evs[2]; e.Raw != "not a frame" || len(e.Attrs) != 1 || e.Attrs[0].Key != "container" {
		t.Fatalf("non-frame: %+v", e)
	}
	// The empty frame is a blank line: skipped. A frame without time
	// inherits the previous one.
	if e := evs[3]; e.Message != "no time" || !e.Inherited || e.Time.Second() != 42 {
		t.Fatalf("untimed: %+v", e)
	}
	checkCoverageGaps(t, in, evs, false)
}

func TestDockerJSONDropsAttrsByDefault(t *testing.T) {
	p := mustParser(t, Options{Format: "docker-json"})
	evs := readAll(t, p, `{"log":"x\n","stream":"stdout","attrs":{"team":"shop"},"time":"2026-10-31T01:20:41Z"}`+"\n")
	if len(evs) != 1 || len(evs[0].Attrs) != 1 || evs[0].Attrs[0].Key != "stream" {
		t.Fatalf("%+v", evs)
	}
	// Non-string attrs, malformed JSON and a bad time.
	p = mustParser(t, Options{Format: "docker-json", FrameAttrs: []string{"n"}})
	evs = readAll(t, p, `{"log":"y\n","attrs":{"n":1},"time":"yesterday"}`+"\n"+`{"log":"z\n"`+"\n")
	if len(evs) != 2 || len(evs[0].Attrs) != 0 || evs[0].HasTime || evs[0].Message != "y" {
		t.Fatalf("%+v", evs[0])
	}
	if evs[1].Raw != `{"log":"z\n"` {
		t.Fatalf("malformed frame: %+v", evs[1])
	}
}

func TestDockerJSONPartialAtEOFHeld(t *testing.T) {
	p := mustParser(t, Options{Format: "docker-json"})
	in := `{"log":"start of a long ","time":"2026-10-31T01:20:41Z"}` + "\n"
	r := p.NewReader(strings.NewReader(in), 0)
	ev, err := r.Next()
	if err != nil || !ev.Unterminated || ev.Message != "start of a long " || r.Offset() != 0 {
		t.Fatalf("%+v %v offset %d", ev, err, r.Offset())
	}
}

func FuzzParseDockerJSONFrameAttrs(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add(`{"log":"a","stream":"stdout","time":"2026-10-31T01:20:40Z"}` + "\n" + `{"log":"b\n","stream":"stdout","attrs":{"k":"v"},"time":"2026-10-31T01:20:40Z"}` + "\n")
	f.Add(`{"log":"\u0000\ud800\n","stream":"\xff","attrs":{"k":["x"]}}` + "\n" + `{"log":` + "\n")
	p := mustParser(f, Options{Format: "docker-json", FrameAttrs: []string{"k"},
		StaticAttrs: []Member{{Key: "container", Value: Value{Kind: KindString, Str: "c"}}}})
	f.Fuzz(func(t *testing.T, in string) {
		evs := fuzzRead(t, p, in)
		checkEventsGaps(t, in, evs, false)
		for _, e := range evs {
			if len(e.Attrs) == 0 || e.Attrs[0].Key != "container" {
				t.Fatalf("static attr missing: %+v", e.Attrs)
			}
			for _, m := range e.Attrs[1:] {
				if m.Key == "attrs" && (len(m.Value.Members) != 1 || m.Value.Members[0].Key != "k") {
					t.Fatalf("attrs not filtered: %+v", m.Value)
				}
				if m.Key != "stream" && m.Key != "attrs" {
					t.Fatalf("unexpected attr %q", m.Key)
				}
			}
		}
	})
}
