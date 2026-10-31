// Package mask turns raw events into masked records, the only form of log
// content that leaves the console (design §4). Every string of an event
// passes the same fixed order: secrets first, and final; then rules,
// personal field names, value detectors and the structured/text mode
// defaults, all on the string step 1 produced.
//
// A Record has no exported field and refuses to be encoded unless the
// masker built it: typed responses that hold Records cannot carry raw
// content by mistake.
package mask

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Placeholders written in place of masked content. Source text never
// contains the brackets: they are replaced by U+FFFD before masking, so a
// placeholder in a record was always written by the masker.
const (
	Open  = "⟦" // ⟦
	Close = "⟧" // ⟧
	// Secret replaces a secret: never unmaskable, never pseudonymised.
	Secret = Open + "secret" + Close
	// Redacted replaces a value withheld whole (redact-unknown, a redact
	// rule, a forgotten epoch).
	Redacted = Open + "redacted" + Close
)

// Token is the placeholder of a pseudonym: ⟦kind:ID⟧.
func Token(kind, id string) string { return Open + kind + ":" + id + Close }

// KeyKind is the kind of a field name that was masked (⟦key:ID⟧).
const KeyKind = "key"

// ErrUnmasked is the error of encoding a Record the masker did not build.
var ErrUnmasked = errors.New("mask: record not built by the masker")

// Kind is the kind of a masked value.
type Kind uint8

// Value kinds. A masked number or bool becomes a string.
const (
	Null Kind = iota
	Bool
	Number
	String
	Object
	Array
)

// Value is one masked node of a structured record.
type Value struct {
	kind    Kind
	text    string
	members []Field
	items   []Value
}

// Kind returns the value's kind.
func (v Value) Kind() Kind { return v.kind }

// Text returns a scalar's masked text ("true", an exact number literal, a
// masked string).
func (v Value) Text() string { return v.text }

// Members returns an object's masked members, in order, duplicates kept.
func (v Value) Members() []Field { return slices.Clone(v.members) }

// Items returns an array's masked items.
func (v Value) Items() []Value { return slices.Clone(v.items) }

// Field is one masked member: its name as shown (clear, or ⟦key:ID⟧ when
// the name itself was masked) and its value.
type Field struct {
	name  string
	value Value
}

// Name returns the name as shown to the agent.
func (f Field) Name() string { return f.name }

// Value returns the masked value.
func (f Field) Value() Value { return f.value }

// Record is one masked event. The zero value is invalid: only the masker
// builds valid records.
type Record struct {
	ok bool

	ts      time.Time
	hasTime bool
	format  string

	fields []Field
	attrs  []Field
	msg    string

	// kinds masked in this record (sorted, distinct): detector kinds,
	// "secret", "redacted", "key".
	kinds []string
	// secretPaths are the shown paths of values that held a secret (or
	// were masked whole for their secret name): HadSecret reports them,
	// and callers refuse lookup on them.
	secretPaths []string
	// failed: the masker failed on this record and withheld all of it.
	failed bool

	offset, length int64
}

// Valid reports whether the masker built r.
func (r Record) Valid() bool { return r.ok }

// Failed reports whether masking failed on the record, which then holds
// nothing but its position (masked_failure).
func (r Record) Failed() bool { return r.failed }

// Time returns the record's timestamp and whether it has one.
func (r Record) Time() (time.Time, bool) { return r.ts, r.hasTime }

// Format returns the format that decoded the event.
func (r Record) Format() string { return r.format }

// Fields returns the masked structured part.
func (r Record) Fields() []Field { return slices.Clone(r.fields) }

// Attrs returns the masked container-frame fields.
func (r Record) Attrs() []Field { return slices.Clone(r.attrs) }

// Message returns the masked free text.
func (r Record) Message() string { return r.msg }

// Kinds returns the kinds of what was masked.
func (r Record) Kinds() []string { return slices.Clone(r.kinds) }

// HadSecret reports whether the leaf at the shown path held a secret.
func (r Record) HadSecret(path string) bool { return slices.Contains(r.secretPaths, path) }

// Position returns the event's place in its stream (byte offset, bytes
// consumed): plan metadata, not content.
func (r Record) Position() (offset, length int64) { return r.offset, r.length }

// Lookup returns the first leaf or object at a shown path ("user.email",
// "⟦key:ID⟧.city"); arrays are crossed without an index.
func (r Record) Lookup(path string) (Value, bool) {
	if r.failed {
		return Value{}, false
	}
	return lookup(r.fields, splitPath(path))
}

func lookup(fields []Field, parts []string) (Value, bool) {
	if len(parts) == 0 {
		return Value{}, false
	}
	for _, f := range fields {
		if f.name != parts[0] {
			continue
		}
		if v, ok := descend(f.value, parts[1:]); ok {
			return v, true
		}
	}
	return Value{}, false
}

func descend(v Value, parts []string) (Value, bool) {
	if len(parts) == 0 {
		return v, true
	}
	switch v.kind {
	case Object:
		return lookup(v.members, parts)
	case Array:
		for _, it := range v.items {
			if got, ok := descend(it, parts); ok {
				return got, true
			}
		}
	}
	return Value{}, false
}

// splitPath splits a shown path at the dots outside placeholders.
func splitPath(p string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(p); {
		switch {
		case hasAt(p, i, Open):
			depth++
			i += len(Open)
		case hasAt(p, i, Close):
			depth--
			i += len(Close)
		case p[i] == '.' && depth == 0:
			out = append(out, p[start:i])
			i++
			start = i
		default:
			i++
		}
	}
	return append(out, p[start:])
}

func hasAt(s string, i int, sub string) bool { return len(s)-i >= len(sub) && s[i:i+len(sub)] == sub }

// MarshalJSON writes the masked record: {"ts", "fields", "attrs", "msg"},
// or {"masked_failure": true}. A record the masker did not build is
// refused.
func (r Record) MarshalJSON() ([]byte, error) {
	if !r.ok {
		return nil, ErrUnmasked
	}
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	key := func(k string) {
		if !first {
			b.WriteByte(',')
		}
		first = false
		writeString(&b, k)
		b.WriteByte(':')
	}
	if r.hasTime {
		key("ts")
		writeString(&b, r.ts.UTC().Format(time.RFC3339Nano))
	}
	if r.failed {
		key("masked_failure")
		b.WriteString("true")
		b.WriteByte('}')
		return b.Bytes(), nil
	}
	if len(r.fields) > 0 {
		key("fields")
		writeMembers(&b, r.fields)
	}
	if len(r.attrs) > 0 {
		key("attrs")
		writeMembers(&b, r.attrs)
	}
	if r.msg != "" {
		key("msg")
		writeString(&b, r.msg)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// MarshalJSON writes the masked value.
func (v Value) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	writeValue(&b, v)
	return b.Bytes(), nil
}

func writeMembers(b *bytes.Buffer, fs []Field) {
	b.WriteByte('{')
	for i, f := range fs {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, f.name)
		b.WriteByte(':')
		writeValue(b, f.value)
	}
	b.WriteByte('}')
}

func writeValue(b *bytes.Buffer, v Value) {
	switch v.kind {
	case Null:
		b.WriteString("null")
	case Bool, Number:
		b.WriteString(v.text) // checked literals: "true"/"false", a JSON number
	case String:
		writeString(b, v.text)
	case Object:
		writeMembers(b, v.members)
	case Array:
		b.WriteByte('[')
		for i, it := range v.items {
			if i > 0 {
				b.WriteByte(',')
			}
			writeValue(b, it)
		}
		b.WriteByte(']')
	}
}

func writeString(b *bytes.Buffer, s string) {
	enc, _ := json.Marshal(s) // a string always encodes
	b.Write(enc)
}
