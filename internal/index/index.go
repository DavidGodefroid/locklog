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
	// Version of the on-disk format; another version is rebuilt. 2:
	// line fields and labels (LabelKey) are separate namespaces (1 fell
	// back from a field to a frame attribute).
	Version = 2
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
	// memo holds sensitive's answers: trusted fields are low-cardinality
	// (status, method, level), and asking the masker for every record
	// dominated the backfill (R6-P1: backfill at full speed). Bounded by
	// memoMax entries of values up to memoValueMax bytes.
	memo    map[memoKey]bool
	g       Granule
	minutes map[int64]map[string]*Count
	untimed map[string]*Count
}

// NewBuilder indexes the given fields; sensitive reports values a detector
// flags (nil: none).
func NewBuilder(fields []string, sensitive func(field, value string) bool) *Builder {
	b := &Builder{fields: fields, minutes: map[int64]map[string]*Count{}, untimed: map[string]*Count{}}
	if sensitive != nil {
		b.memo = map[memoKey]bool{}
		b.sensitive = func(f, v string) bool {
			if len(v) > memoValueMax {
				return sensitive(f, v)
			}
			k := memoKey{f, v}
			if r, ok := b.memo[k]; ok {
				return r
			}
			r := sensitive(f, v)
			if len(b.memo) < memoMax {
				b.memo[k] = r
			}
			return r
		}
	}
	return b
}

type memoKey struct{ field, value string }

const (
	memoMax      = 4096
	memoValueMax = 256
)

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

// labelPrefix marks an indexed name as a label (a frame attribute): a
// configured field name never holds a colon.
const labelPrefix = "label:"

// LabelKey is the indexed name of the label name: the index holds line
// fields and labels side by side, each in its own namespace.
func LabelKey(name string) string { return labelPrefix + name }

// SplitKey returns the field or label an indexed name stands for.
func SplitKey(key string) (name string, label bool) {
	if n, ok := strings.CutPrefix(key, labelPrefix); ok {
		return n, true
	}
	return key, false
}

// TermKey is the indexed name a field (label unset) or label stands for.
func TermKey(name string, label bool) string {
	if label {
		return LabelKey(name)
	}
	return name
}

// Values returns the record's values of keys (line fields, and labels as
// LabelKey), in order: the scalar text of the field or label (dotted paths
// reach nested objects), Absent when missing or not a scalar, Redacted when
// sensitive flags it.
func Values(ev parse.Event, keys []string, sensitive func(field, value string) bool) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		f, _ := SplitKey(k)
		v := Value(ev, k)
		switch {
		case v == Absent || v == Redacted:
			out[i] = v
		case sensitive != nil && sensitive(f, v):
			out[i] = Redacted
		default:
			out[i] = v
		}
	}
	return out
}

// Lookup returns the scalar text of a line field of ev: a top-level member
// named name, else a dotted path through nested objects. Frame attributes
// (labels) are another namespace (LookupAttr): the engine's scan reads a
// field predicate on the line's fields only, and so does the index.
func Lookup(ev parse.Event, name string) (string, bool) {
	return lookupMembers(ev.Fields, name)
}

// LookupAttr returns the scalar text of a frame attribute (label) of ev.
func LookupAttr(ev parse.Event, name string) (string, bool) {
	return lookupMembers(ev.Attrs, name)
}

// Value returns the indexed value of key (a line field, or a label as
// LabelKey) on ev: its scalar text, Absent when nothing is at the path, or
// Redacted (unknown) when the path is ambiguous: several leaves (a repeated
// key, an array, a dotted name also stored as one key) or an object or
// other non-scalar. The scan matches a predicate on any leaf at the path,
// so an ambiguous value must never prune a granule nor be counted by one.
func Value(ev parse.Event, key string) string {
	name, label := SplitKey(key)
	ms := ev.Fields
	if label {
		ms = ev.Attrs
	}
	var c leafCount
	c.walk(ms, name)
	switch {
	case c.n == 0:
		return Absent
	case c.n > 1:
		return Redacted
	}
	if s, ok := scalar(c.first); ok {
		return s
	}
	return Redacted
}

// leafCount counts the leaves at a dotted path, every reading of its dots
// (nested objects, a key holding dots), arrays crossed, as the scan does.
type leafCount struct {
	n     int
	first parse.Value
}

func (c *leafCount) walk(ms []parse.Member, path string) {
	for _, m := range ms {
		switch {
		case m.Key == path:
			c.leaf(m.Value)
		case strings.HasPrefix(path, m.Key+"."):
			c.down(m.Value, path[len(m.Key)+1:])
		}
	}
}

func (c *leafCount) down(v parse.Value, rest string) {
	switch v.Kind {
	case parse.KindObject:
		c.walk(v.Members, rest)
	case parse.KindArray:
		for _, it := range v.Items {
			c.down(it, rest)
		}
	}
}

func (c *leafCount) leaf(v parse.Value) {
	if v.Kind == parse.KindArray {
		if len(v.Items) == 0 {
			c.n += 2 // an empty array: present, no scalar (unknown)
		}
		for _, it := range v.Items {
			c.leaf(it)
		}
		return
	}
	if c.n == 0 {
		c.first = v
	}
	c.n++
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
