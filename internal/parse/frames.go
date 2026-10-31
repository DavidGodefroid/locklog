package parse

import (
	"strings"
	"time"
)

// criFormat unwraps CRI log frames (containerd, CRI-O, Podman's k8s-file):
//
//	2026-10-31T02:41:55.123456789Z stderr F payload
//
// The runtime's timestamp is the frame's time, the stream an attribute,
// and a "P" tag marks a line the runtime split (the reader joins the run).
// The payload is decoded with "auto".
type criFormat struct{}

func (criFormat) Name() string                          { return "cri" }
func (criFormat) Detect(string) bool                    { return false }
func (criFormat) Decode(string, *Options) (Event, bool) { return Event{}, false }

func (criFormat) Unwrap(line string, _ *Options) (Frame, bool) {
	ts, rest, ok := strings.Cut(line, " ")
	if !ok {
		return Frame{}, false
	}
	stream, rest, ok := strings.Cut(rest, " ")
	if !ok || stream != "stdout" && stream != "stderr" {
		return Frame{}, false
	}
	tag, text, ok := strings.Cut(rest, " ")
	if !ok {
		tag, text = rest, "" // "F" with an empty payload
	}
	// The tag is "P" or "F", possibly followed by ":"-separated flags.
	tag, _, _ = strings.Cut(tag, ":")
	if tag != "P" && tag != "F" {
		return Frame{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return Frame{}, false
	}
	fr := Frame{Text: text, Partial: tag == "P", Attrs: []Member{strMember("stream", stream)}}
	if t, ok := checkRange(t.UTC()); ok {
		fr.Time, fr.HasTime = t, true
	}
	return fr, true
}

// dockerJSONFormat unwraps Docker's json-file frames:
//
//	{"log":"payload\n","stream":"stderr","attrs":{"tag":"api"},"time":"2026-10-31T02:41:55.1Z"}
//
// A "log" that does not end in a newline is a line Docker split at 16 KiB
// (the reader joins the run). "stream" and the "attrs" object (labels and
// env named by the log driver's options) are attributes; which of them a
// source exposes is its own allowlist.
type dockerJSONFormat struct{}

func (dockerJSONFormat) Name() string                          { return "docker-json" }
func (dockerJSONFormat) Detect(string) bool                    { return false }
func (dockerJSONFormat) Decode(string, *Options) (Event, bool) { return Event{}, false }

func (dockerJSONFormat) Unwrap(line string, _ *Options) (Frame, bool) {
	if !strings.HasPrefix(line, "{") {
		return Frame{}, false
	}
	v, err := DecodeJSON(line)
	if err != nil || v.Kind != KindObject {
		return Frame{}, false
	}
	logv, ok := Get(v.Members, "log")
	if !ok || logv.Kind != KindString {
		return Frame{}, false
	}
	fr := Frame{Text: logv.Str}
	if strings.HasSuffix(fr.Text, "\n") {
		fr.Text = strings.TrimSuffix(strings.TrimSuffix(fr.Text, "\n"), "\r")
	} else {
		fr.Partial = true
	}
	if s, ok := Get(v.Members, "stream"); ok && s.Kind == KindString {
		fr.Attrs = append(fr.Attrs, strMember("stream", s.Str))
	}
	if a, ok := Get(v.Members, "attrs"); ok && a.Kind == KindObject {
		fr.Attrs = append(fr.Attrs, Member{Key: "attrs", Value: a})
	}
	if ts, ok := Get(v.Members, "time"); ok && ts.Kind == KindString {
		if t, err := time.Parse(time.RFC3339Nano, ts.Str); err == nil {
			if t, ok := checkRange(t.UTC()); ok {
				fr.Time, fr.HasTime = t, true
			}
		}
	}
	return fr, true
}
