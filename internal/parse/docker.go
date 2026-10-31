package parse

import (
	"encoding/json"
	"slices"
	"strings"
)

// dockerJSON is Docker's json-file log driver frame: one JSON object per
// line, {"log":"<text>\n","stream":"stdout","time":"<RFC 3339>","attrs":{...}}.
// A "log" without a trailing "\n" is a partial line (the runtime split a long
// line at 16 KiB): the reader joins it with the frames that follow. The frame
// time is the record time. "stream" is kept as a frame attribute; "attrs"
// (the log-opt labels and env) are dropped, except the keys Options.FrameAttrs
// names, kept as "attrs.<key>".
type dockerJSON struct{}

func (dockerJSON) Name() string { return "docker-json" }

// Detect is never used: docker-json is not in "auto".
func (dockerJSON) Detect(string) bool { return false }

// Decode is never used: a framer's payload is decoded by "auto".
func (dockerJSON) Decode(string, *Options) (Event, bool) { return Event{}, false }

func (dockerJSON) Unwrap(line string, o *Options) (Frame, bool) {
	if !strings.HasPrefix(line, "{") {
		return Frame{}, false
	}
	var raw struct {
		Log    *string                    `json:"log"`
		Stream string                     `json:"stream"`
		Time   string                     `json:"time"`
		Attrs  map[string]json.RawMessage `json:"attrs"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Frame{}, false
	}
	fr := Frame{}
	if raw.Log != nil {
		text := *raw.Log
		if t, ok := strings.CutSuffix(text, "\n"); ok {
			fr.Text = strings.TrimSuffix(t, "\r")
		} else {
			fr.Text, fr.Partial = text, true
		}
	}
	if raw.Time != "" {
		fr.Time, fr.HasTime = ParseTime(raw.Time, nil)
	}
	if raw.Stream != "" {
		fr.Attrs = append(fr.Attrs, Member{Key: "stream", Value: Value{Kind: KindString, Str: validText([]byte(raw.Stream))}})
	}
	if o != nil && len(raw.Attrs) > 0 {
		keys := slices.Clone(o.FrameAttrs)
		slices.Sort(keys)
		for _, k := range slices.Compact(keys) {
			m, ok := raw.Attrs[k]
			if !ok {
				continue
			}
			var s string
			if json.Unmarshal(m, &s) != nil {
				continue // attrs are strings; anything else is dropped
			}
			fr.Attrs = append(fr.Attrs, Member{Key: "attrs." + k, Value: Value{Kind: KindString, Str: validText([]byte(s))}})
		}
	}
	return fr, true
}

func init() { Register(dockerJSON{}, -1) }
