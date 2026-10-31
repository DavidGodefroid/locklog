// Package index is the local index of file streams: for each plan granule
// of a stream, its record count, its time span, and per-minute counts of the
// tuples of the source's trusted low-cardinality fields.
//
// The index holds raw values of trusted fields (masked by the engine when an
// answer is built) and lives in the console's home volume (directory 0700,
// files 0600). A value a detector flags is stored as Redacted, never in
// clear; a field with more than MaxDistinct values in a stream is dropped
// from that stream's index.
package index

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
)

const (
	// Version of the on-disk format; another version is rebuilt.
	Version = 1
	// MaxDistinct is the most distinct values a field may have in one
	// stream and stay indexed.
	MaxDistinct = 64
	// MaxTuples bounds the distinct tuples of one minute of a granule;
	// beyond it the remaining records count under Other values.
	MaxTuples = 256
)

// Special tuple values. They cannot collide with field values: parsed text
// never holds NUL.
const (
	// Absent is the value of a field the record does not have.
	Absent = ""
	// Redacted replaces a value a detector flagged.
	Redacted = "\x00redacted"
	// Other replaces values beyond MaxTuples in a minute.
	Other = "\x00other"
)

// Count is the number of records with one tuple of values.
type Count struct {
	Vals []string `json:"v"`
	N    int64    `json:"n"`
}

// Minute holds the counts of one minute (Unix minutes).
type Minute struct {
	M      int64   `json:"m"`
	Counts []Count `json:"c"`
}

// Granule is the index of one plan granule.
type Granule struct {
	// N is the granule number: the granule covers stream offsets
	// [N*size, (N+1)*size), clipped to the stream.
	N     int64 `json:"g"`
	Start int64 `json:"s"`
	End   int64 `json:"e"`
	// Sealed is false for the tail granule of a stream that may grow;
	// it is indexed again once the stream has grown past it.
	Sealed  bool  `json:"sealed,omitempty"`
	Records int64 `json:"r"`
	// From and To bound the timed records (Unix ns); zero when none.
	From int64 `json:"from,omitempty"`
	To   int64 `json:"to,omitempty"`
	// Minutes are sorted by minute. Untimed counts records without a
	// time.
	Minutes []Minute `json:"min,omitempty"`
	Untimed []Count  `json:"untimed,omitempty"`
}

// Span returns the time span of the granule's timed records.
func (g *Granule) Span() (from, to time.Time, ok bool) {
	if g.From == 0 && g.To == 0 {
		return time.Time{}, time.Time{}, false
	}
	return time.Unix(0, g.From).UTC(), time.Unix(0, g.To).UTC(), true
}

// Builder accumulates the records of one granule.
type Builder struct {
	fields    []string
	sensitive func(field, value string) bool
	g         Granule
	minutes   map[int64]map[string]*Count
	untimed   map[string]*Count
}

// NewBuilder indexes the given fields; sensitive reports values a detector
// flags (nil: none).
func NewBuilder(fields []string, sensitive func(field, value string) bool) *Builder {
	return &Builder{fields: fields, sensitive: sensitive, minutes: map[int64]map[string]*Count{}, untimed: map[string]*Count{}}
}

// Add counts one record.
func (b *Builder) Add(ev parse.Event) {
	b.g.Records++
	vals := Values(ev, b.fields, b.sensitive)
	key := tupleKey(vals)
	var bucket map[string]*Count
	if ev.HasTime || ev.Inherited {
		ns := ev.Time.UnixNano()
		if b.g.From == 0 || ns < b.g.From {
			b.g.From = ns
		}
		if ns > b.g.To {
			b.g.To = ns
		}
		m := ev.Time.Unix() / 60 // times are after 1990: no negative floor
		if bucket = b.minutes[m]; bucket == nil {
			bucket = map[string]*Count{}
			b.minutes[m] = bucket
		}
	} else {
		bucket = b.untimed
	}
	c := bucket[key]
	if c == nil {
		if len(bucket) >= MaxTuples {
			other := make([]string, len(vals))
			for i := range other {
				other[i] = Other
			}
			vals, key = other, tupleKey(other)
			if c = bucket[key]; c == nil {
				c = &Count{Vals: vals}
				bucket[key] = c
			}
		} else {
			c = &Count{Vals: vals}
			bucket[key] = c
		}
	}
	c.N++
}

// Finish returns the granule.
func (b *Builder) Finish(n, start, end int64, sealed bool) Granule {
	g := b.g
	g.N, g.Start, g.End, g.Sealed = n, start, end, sealed
	ms := make([]int64, 0, len(b.minutes))
	for m := range b.minutes {
		ms = append(ms, m)
	}
	slices.Sort(ms)
	for _, m := range ms {
		g.Minutes = append(g.Minutes, Minute{M: m, Counts: sortedCounts(b.minutes[m])})
	}
	g.Untimed = sortedCounts(b.untimed)
	return g
}

// tupleKey is an unambiguous key of a tuple (length-prefixed values).
func tupleKey(vals []string) string {
	var b strings.Builder
	for _, v := range vals {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

func sortedCounts(m map[string]*Count) []Count {
	if len(m) == 0 {
		return nil
	}
	out := make([]Count, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return slices.Compare(out[i].Vals, out[j].Vals) < 0 })
	return out
}

// Values returns the record's values of fields, in order: the scalar text of
// the field (dotted paths reach nested objects), Absent when missing or not
// a scalar, Redacted when sensitive flags it.
func Values(ev parse.Event, fields []string, sensitive func(field, value string) bool) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		v, ok := Lookup(ev, f)
		switch {
		case !ok:
			out[i] = Absent
		case sensitive != nil && sensitive(f, v):
			out[i] = Redacted
		default:
			out[i] = v
		}
	}
	return out
}

// Lookup returns the scalar text of a field of ev: a frame attribute (the
// runtime's stream, the source's container name) first, so that a payload
// field of the same name cannot stand for it; else a top-level member named
// name, else a dotted path through nested objects.
func Lookup(ev parse.Event, name string) (string, bool) {
	if v, ok := parse.Get(ev.Attrs, name); ok {
		return scalar(v)
	}
	return lookupMembers(ev.Fields, name)
}

func lookupMembers(ms []parse.Member, name string) (string, bool) {
	if v, ok := parse.Get(ms, name); ok {
		return scalar(v)
	}
	head, rest, ok := strings.Cut(name, ".")
	for ok {
		if v, found := parse.Get(ms, head); found && v.Kind == parse.KindObject {
			if s, ok := lookupMembers(v.Members, rest); ok {
				return s, true
			}
		}
		var more string
		more, rest, ok = strings.Cut(rest, ".")
		head = head + "." + more
	}
	return "", false
}

func scalar(v parse.Value) (string, bool) {
	switch v.Kind {
	case parse.KindString, parse.KindNumber, parse.KindBool:
		if strings.ContainsRune(v.Str, 0) {
			return "", false // never collides with the special values
		}
		return v.Str, true
	}
	return "", false
}
