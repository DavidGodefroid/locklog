// Package parse turns raw log bytes into events: it reads bounded lines,
// assembles multi-line events (stack traces) under the event caps, and
// decodes each event's format into a structured tree with exact numbers.
//
// Everything produced here is raw, unmasked log content. It is consumed only
// by internal/source, internal/mask and internal/engine; nothing in this
// package may be returned to an agent.
package parse

import (
	"time"
)

// Caps (design §2.3, §4.5). They bound memory and per-event masking cost and
// are inputs of the engine's worst-case cost model, so they are constants.
const (
	// MaxEventBytes is the largest assembled event, in bytes of text.
	MaxEventBytes = 256 << 10
	// MaxEventLines is the largest number of lines in one assembled event.
	MaxEventLines = 500
	// MaxLineBytes is the longest line kept; the rest of a longer line is
	// consumed (it counts towards offsets and budgets) but dropped.
	MaxLineBytes = MaxEventBytes
	// MaxDepth is the deepest JSON nesting decoded as structure.
	MaxDepth = 64
	// MaxKeyBytes is the longest JSON or logfmt key decoded as structure.
	MaxKeyBytes = 256
)

// Kind is the kind of a structured value.
type Kind uint8

// Value kinds. Numbers keep their exact literal text.
const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindObject
	KindArray
)

func (k Kind) String() string {
	switch k {
	case KindNull:
		return "null"
	case KindBool:
		return "bool"
	case KindNumber:
		return "number"
	case KindString:
		return "string"
	case KindObject:
		return "object"
	case KindArray:
		return "array"
	}
	return "unknown"
}

// Value is one node of a structured event. Scalars carry their text in Str:
// "true"/"false" for bools, the exact literal for numbers (never rounded
// through float64), the decoded string for strings. Objects keep member order
// and duplicate keys, so nothing a source wrote is hidden from the masker.
type Value struct {
	Kind    Kind
	Str     string
	Members []Member // KindObject
	Items   []Value  // KindArray
}

// Member is one key of an object.
type Member struct {
	Key   string
	Value Value
}

// Get returns the first member named key.
func Get(members []Member, key string) (Value, bool) {
	for _, m := range members {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Value{}, false
}

// Event is one assembled, decoded log event.
type Event struct {
	// Format is the format that decoded the event ("json", "logfmt",
	// "plain", ...). When a structured format fails on a line, the event
	// falls back to "plain" and Fallback is set.
	Format   string
	Fallback bool

	// Time is the event's timestamp. HasTime is false when the event
	// carries none; Inherited is set when the reader filled Time from the
	// previous timed event of the same stream.
	Time      time.Time
	HasTime   bool
	Inherited bool

	// Fields is the structured part (top-level members), without the keys
	// that became Time and Message. Nil for free text.
	Fields []Member
	// TimeKey and MessageKey name the keys Time and Message came from.
	TimeKey    string
	MessageKey string
	// Message is the free-text part, masked in text mode.
	Message string

	// Raw is the assembled text of the event (lines joined by "\n", line
	// terminators removed, invalid UTF-8 replaced). Callers must not
	// modify it.
	Raw string

	// Offset and Length locate the event in the stream: the byte offset of
	// its first line and the number of stream bytes it consumed, including
	// line terminators and any dropped tail of a truncated line.
	Offset int64
	Length int64
	// Lines is the number of lines in the event.
	Lines int
	// Truncated is set when a line was cut at MaxLineBytes.
	Truncated bool
	// Split is set when this event continues a previous one that hit
	// MaxEventBytes or MaxEventLines.
	Split bool

	// Attrs are the container frame's fields (stream, ...) for framed
	// formats; nil otherwise.
	Attrs []Member

	timeMember *Member // the member Time was lifted from
}
