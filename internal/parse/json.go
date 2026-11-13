package parse

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// jsonSpace is the whitespace JSON allows around a value.
const jsonSpace = " \t\r\n"

var errStructure = errors.New("parse: structure over limits")

// DecodeJSON decodes text as exactly one JSON value (surrounding whitespace
// allowed). Numbers keep their literal; object member order and duplicate keys
// are kept. Nesting deeper than MaxDepth or a key longer than MaxKeyBytes is
// an error: the caller treats the text as free text, which is masked in text
// mode.
//
// It reads as encoding/json does (strings unquoted alike, an invalid UTF-8
// byte or a lone surrogate read as U+FFFD), with a scanner of its own: every
// line of a JSON source is decoded, and encoding/json's token reader was a
// quarter of an approved scan's time (#150).
func DecodeJSON(text string) (Value, error) {
	d := jsonDecoder{s: text}
	v, err := d.value(0)
	if err != nil {
		return Value{}, err
	}
	if d.skipSpace(); d.i < len(d.s) {
		return Value{}, errors.New("parse: trailing data after JSON value")
	}
	return v, nil
}

var errSyntax = errors.New("parse: invalid JSON")

type jsonDecoder struct {
	s string
	i int
}

func (d *jsonDecoder) skipSpace() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\r', '\n':
			d.i++
		default:
			return
		}
	}
}

func (d *jsonDecoder) value(depth int) (Value, error) {
	d.skipSpace()
	if d.i >= len(d.s) {
		return Value{}, errSyntax
	}
	switch c := d.s[d.i]; {
	case c == '"':
		str, err := d.str()
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindString, Str: str}, nil
	case c == '{':
		if depth >= MaxDepth {
			return Value{}, errStructure
		}
		return d.object(depth)
	case c == '[':
		if depth >= MaxDepth {
			return Value{}, errStructure
		}
		return d.array(depth)
	case c == '-' || c >= '0' && c <= '9':
		n, err := d.number()
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindNumber, Str: n}, nil
	case strings.HasPrefix(d.s[d.i:], "true"):
		d.i += 4
		return Value{Kind: KindBool, Str: "true"}, nil
	case strings.HasPrefix(d.s[d.i:], "false"):
		d.i += 5
		return Value{Kind: KindBool, Str: "false"}, nil
	case strings.HasPrefix(d.s[d.i:], "null"):
		d.i += 4
		return Value{Kind: KindNull}, nil
	}
	return Value{}, errSyntax
}

func (d *jsonDecoder) object(depth int) (Value, error) {
	d.i++ // '{'
	v := Value{Kind: KindObject, Members: []Member{}}
	if d.skipSpace(); d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return v, nil
	}
	for {
		if d.skipSpace(); d.i >= len(d.s) || d.s[d.i] != '"' {
			return Value{}, errors.New("parse: object key is not a string")
		}
		key, err := d.str()
		if err != nil {
			return Value{}, err
		}
		if len(key) > MaxKeyBytes {
			return Value{}, errStructure
		}
		if d.skipSpace(); d.i >= len(d.s) || d.s[d.i] != ':' {
			return Value{}, errSyntax
		}
		d.i++
		mv, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.Members = append(v.Members, Member{Key: key, Value: mv})
		if d.skipSpace(); d.i >= len(d.s) {
			return Value{}, errSyntax
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case '}':
			d.i++
			return v, nil
		default:
			return Value{}, errSyntax
		}
	}
}

func (d *jsonDecoder) array(depth int) (Value, error) {
	d.i++ // '['
	v := Value{Kind: KindArray, Items: []Value{}}
	if d.skipSpace(); d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return v, nil
	}
	for {
		iv, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.Items = append(v.Items, iv)
		if d.skipSpace(); d.i >= len(d.s) {
			return Value{}, errSyntax
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case ']':
			d.i++
			return v, nil
		default:
			return Value{}, errSyntax
		}
	}
}

// number reads a number's literal: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
func (d *jsonDecoder) number() (string, error) {
	start := d.i
	if d.s[d.i] == '-' {
		d.i++
	}
	switch {
	case d.i < len(d.s) && d.s[d.i] == '0':
		d.i++
	case d.i < len(d.s) && d.s[d.i] >= '1' && d.s[d.i] <= '9':
		d.digits()
	default:
		return "", errSyntax
	}
	if d.i < len(d.s) && d.s[d.i] == '.' {
		d.i++
		if d.digits() == 0 {
			return "", errSyntax
		}
	}
	if d.i < len(d.s) && (d.s[d.i] == 'e' || d.s[d.i] == 'E') {
		d.i++
		if d.i < len(d.s) && (d.s[d.i] == '+' || d.s[d.i] == '-') {
			d.i++
		}
		if d.digits() == 0 {
			return "", errSyntax
		}
	}
	return d.s[start:d.i], nil
}

func (d *jsonDecoder) digits() int {
	start := d.i
	for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
		d.i++
	}
	return d.i - start
}

// str reads a string at d.i (its opening quote) and returns it unquoted:
// the text itself when it has no escape and is valid UTF-8, else decoded
// as encoding/json does.
func (d *jsonDecoder) str() (string, error) {
	start := d.i + 1
	escaped, ascii := false, true
	for i := start; i < len(d.s); i++ {
		switch c := d.s[i]; {
		case c == '"':
			d.i = i + 1
			if body := d.s[start:i]; !escaped && (ascii || utf8.ValidString(body)) {
				return body, nil
			}
			return unquoteJSON(d.s[start:i]), nil
		case c == '\\':
			escaped = true
			i++
			if i >= len(d.s) {
				return "", errSyntax
			}
			switch d.s[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if i+4 >= len(d.s) || !isHex4(d.s[i+1:i+5]) {
					return "", errSyntax
				}
				i += 4
			default:
				return "", errSyntax
			}
		case c < 0x20:
			return "", errSyntax
		case c >= utf8.RuneSelf:
			ascii = false
		}
	}
	return "", errSyntax
}

func isHex4(s string) bool {
	for i := 0; i < 4; i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// unquoteJSON decodes the body of a string str validated: its escapes, a
// surrogate pair as one rune, a lone surrogate and an invalid UTF-8 byte
// as U+FFFD (encoding/json's unquote).
func unquoteJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			if c < utf8.RuneSelf {
				b.WriteByte(c)
				i++
				continue
			}
			r, n := utf8.DecodeRuneInString(s[i:])
			b.WriteRune(r) // RuneError for an invalid byte
			i += n
			continue
		}
		switch e := s[i+1]; e {
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r := hex4(s[i+2 : i+6])
			i += 6
			if utf16.IsSurrogate(r) {
				if i+6 <= len(s) && s[i] == '\\' && s[i+1] == 'u' {
					if dec := utf16.DecodeRune(r, hex4(s[i+2:i+6])); dec != unicode.ReplacementChar {
						b.WriteRune(dec)
						i += 6
						continue
					}
				}
				r = unicode.ReplacementChar
			}
			b.WriteRune(r)
			continue
		default: // '"', '\\', '/'
			b.WriteByte(e)
		}
		i += 2
	}
	return b.String()
}

func hex4(s string) rune {
	var r rune
	for i := 0; i < 4; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c -= 'a' - 10
		default:
			c -= 'A' - 10
		}
		r = r<<4 | rune(c)
	}
	return r
}

// jsonFormat decodes one JSON object per event.
type jsonFormat struct{}

func (jsonFormat) Name() string { return "json" }

// Starts reports whether a line begins a JSON event. JSON events are single
// lines, so every line starts one.
func (jsonFormat) Starts(string) bool { return true }

// Detect reports whether a line looks like a JSON object (used by "auto").
func (jsonFormat) Detect(line string) bool {
	s := strings.Trim(line, jsonSpace)
	return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}'
}

func (jsonFormat) Decode(text string, o *Options) (Event, bool) {
	s := strings.Trim(text, jsonSpace)
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
		if i == timeIdx {
			ev.timePos = len(out)
		}
		if i != timeIdx && i != msgIdx {
			out = append(out, m)
		}
	}
	return out
}
