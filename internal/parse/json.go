package parse

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var errStructure = errors.New("parse: structure over limits")

// DecodeJSON decodes text as exactly one JSON value (surrounding whitespace
// allowed). Numbers keep their literal; object member order and duplicate keys
// are kept. Nesting deeper than MaxDepth or a key longer than MaxKeyBytes is
// an error: the caller treats the text as free text, which is masked in text
// mode.
func DecodeJSON(text string) (Value, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Value{}, errors.New("parse: trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return Value{}, err
	}
	return decodeFrom(dec, tok, depth)
}

func decodeFrom(dec *json.Decoder, tok json.Token, depth int) (Value, error) {
	switch t := tok.(type) {
	case nil:
		return Value{Kind: KindNull}, nil
	case bool:
		if t {
			return Value{Kind: KindBool, Str: "true"}, nil
		}
		return Value{Kind: KindBool, Str: "false"}, nil
	case json.Number:
		return Value{Kind: KindNumber, Str: string(t)}, nil
	case string:
		return Value{Kind: KindString, Str: t}, nil
	case json.Delim:
		if depth >= MaxDepth {
			return Value{}, errStructure
		}
		switch t {
		case '{':
			v := Value{Kind: KindObject, Members: []Member{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return Value{}, err
				}
				key, ok := kt.(string)
				if !ok {
					return Value{}, errors.New("parse: object key is not a string")
				}
				if len(key) > MaxKeyBytes {
					return Value{}, errStructure
				}
				mv, err := decodeValue(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				v.Members = append(v.Members, Member{Key: key, Value: mv})
			}
			if _, err := dec.Token(); err != nil { // '}'
				return Value{}, err
			}
			return v, nil
		case '[':
			v := Value{Kind: KindArray, Items: []Value{}}
			for dec.More() {
				iv, err := decodeValue(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				v.Items = append(v.Items, iv)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return Value{}, err
			}
			return v, nil
		}
	}
	return Value{}, errors.New("parse: unexpected JSON token")
}

// jsonFormat decodes one JSON object per event.
type jsonFormat struct{}

func (jsonFormat) Name() string { return "json" }

// Starts reports whether a line begins a JSON event. JSON events are single
// lines, so every line starts one.
func (jsonFormat) Starts(string) bool { return true }

// Detect reports whether a line looks like a JSON object (used by "auto").
func (jsonFormat) Detect(line string) bool {
	s := strings.TrimSpace(line)
	return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}'
}

func (jsonFormat) Decode(text string, o *Options) (Event, bool) {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "{") {
		return Event{}, false
	}
	v, err := DecodeJSON(s)
	if err != nil || v.Kind != KindObject {
		return Event{}, false
	}
	ev := Event{Format: "json"}
	ev.Fields = liftTimeAndMessage(&ev, v.Members, o)
	return ev, true
}

// liftTimeAndMessage moves the first timestamp key and the first string
// message key out of members into ev, returning the remaining members.
func liftTimeAndMessage(ev *Event, members []Member, o *Options) []Member {
	timeIdx, msgIdx := -1, -1
	for _, k := range timeKeys {
		if timeIdx >= 0 {
			break
		}
		for i, m := range members {
			if m.Key != k || (m.Value.Kind != KindString && m.Value.Kind != KindNumber) {
				continue
			}
			if t, ok := ParseTime(m.Value.Str, o.location()); ok {
				ev.Time, ev.HasTime, ev.TimeKey = t, true, k
				ev.timeMember = &members[i]
				timeIdx = i
			}
			break
		}
	}
	for _, k := range messageKeys {
		if msgIdx >= 0 {
			break
		}
		for i, m := range members {
			if i == timeIdx || m.Key != k {
				continue
			}
			if m.Value.Kind == KindString {
				ev.Message, ev.MessageKey = m.Value.Str, k
				msgIdx = i
			}
			break
		}
	}
	if timeIdx < 0 && msgIdx < 0 {
		return members
	}
	out := make([]Member, 0, len(members))
	for i, m := range members {
		if i != timeIdx && i != msgIdx {
			out = append(out, m)
		}
	}
	return out
}
