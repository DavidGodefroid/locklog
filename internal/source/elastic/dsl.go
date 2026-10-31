package elastic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Caps of what locklog asks a backend.
const (
	// MaxSize is the most hits of one search page.
	MaxSize = 1000
	// MaxHistogramBuckets is the most date_histogram buckets of a count.
	MaxHistogramBuckets = 1000
	// MaxTermsSize is the most buckets of one terms aggregation.
	MaxTermsSize = 100
	// SearchTimeout is the server-side timeout of a search.
	SearchTimeout = "30s"
)

// The request bodies are typed: every key is a constant of this file or a
// validated field name, every value a JSON string, number or bool written
// by encoding/json. There is no script, query_string or text query to fill:
// text is matched locally, after masking.

// RangeSpec is a range on the time field, [GTE, LT).
type RangeSpec struct {
	GTE    string `json:"gte"`
	LT     string `json:"lt"`
	Format string `json:"format"`
}

// Clause is one filter clause: exactly one of its members is set.
type Clause struct {
	Range map[string]RangeSpec `json:"range,omitempty"`
	Term  map[string]string    `json:"term,omitempty"`
	Terms map[string][]string  `json:"terms,omitempty"`
}

// BoolQuery is a conjunction of filters and negated filters.
type BoolQuery struct {
	Filter  []Clause `json:"filter,omitempty"`
	MustNot []Clause `json:"must_not,omitempty"`
}

// Query is the query of a search or a count.
type Query struct {
	Bool BoolQuery `json:"bool"`
}

// SortSpec is the sort of one field.
type SortSpec struct {
	Order        string `json:"order"`
	NumericType  string `json:"numeric_type,omitempty"`
	UnmappedType string `json:"unmapped_type,omitempty"`
}

// DateHistogram is a date_histogram aggregation.
type DateHistogram struct {
	Field         string `json:"field"`
	FixedInterval string `json:"fixed_interval"`
	Offset        string `json:"offset,omitempty"`
	MinDocCount   int    `json:"min_doc_count"`
}

// TermsAgg is a terms aggregation. Missing puts the documents without the
// field in the "" bucket (the absent value of a count).
type TermsAgg struct {
	Field   string  `json:"field"`
	Size    int     `json:"size"`
	Missing *string `json:"missing,omitempty"`
}

// Agg is one aggregation: exactly one of DateHistogram and Terms, with
// sub-aggregations.
type Agg struct {
	DateHistogram *DateHistogram `json:"date_histogram,omitempty"`
	Terms         *TermsAgg      `json:"terms,omitempty"`
	Aggs          map[string]Agg `json:"aggs,omitempty"`
}

// SearchBody is the body of a _search.
type SearchBody struct {
	Size           int                   `json:"size"`
	Timeout        string                `json:"timeout"`
	TrackTotalHits bool                  `json:"track_total_hits"`
	Source         bool                  `json:"_source"`
	Fields         []string              `json:"fields,omitempty"`
	Query          Query                 `json:"query"`
	Sort           []map[string]SortSpec `json:"sort,omitempty"`
	SearchAfter    []any                 `json:"search_after,omitempty"`
	Aggs           map[string]Agg        `json:"aggs,omitempty"`
}

// CountBody is the body of a _count.
type CountBody struct {
	Query Query `json:"query"`
}

// IndexPrivileges are the privileges asked on the source's indices.
type IndexPrivileges struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

// PrivilegesBody is the body of Elasticsearch's _has_privileges.
type PrivilegesBody struct {
	Cluster []string          `json:"cluster"`
	Index   []IndexPrivileges `json:"index"`
}

// fieldRe is a field name locklog names in a body: no wildcard, no space,
// no quote.
var fieldRe = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@-]{0,127}$`)

func checkField(f string) error {
	if !fieldRe.MatchString(f) || strings.Contains(f, "..") || strings.HasSuffix(f, ".") {
		return fmt.Errorf("invalid field name %q", f)
	}
	return nil
}

func checkValue(v string) error {
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("control character in a field value")
	}
	if len(v) > 4096 {
		return errors.New("field value longer than 4096 bytes")
	}
	return nil
}

// FieldValues is one term of a filter: the field equals one of Values.
type FieldValues struct {
	Field  string   `json:"f"`
	Values []string `json:"v"`
}

// Filter is the server-side selection of a plan, without its time range:
// the profile's selector and the trusted terms. Its canonical JSON is the
// chunk's stream, so that a reread selects as the scan did.
type Filter struct {
	In    []FieldValues `json:"in,omitempty"`
	NotIn []FieldValues `json:"not_in,omitempty"`
}

func (f Filter) normalise() Filter {
	norm := func(fs []FieldValues) []FieldValues {
		var out []FieldValues
		for _, x := range fs {
			v := slices.Clone(x.Values)
			sort.Strings(v)
			out = append(out, FieldValues{Field: x.Field, Values: slices.Compact(v)})
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Field != out[j].Field {
				return out[i].Field < out[j].Field
			}
			return slices.Compare(out[i].Values, out[j].Values) < 0
		})
		return out
	}
	return Filter{In: norm(f.In), NotIn: norm(f.NotIn)}
}

func (f Filter) check() error {
	for _, x := range append(slices.Clone(f.In), f.NotIn...) {
		if err := checkField(x.Field); err != nil {
			return err
		}
		if len(x.Values) == 0 {
			return errors.New("a term without values")
		}
		if len(x.Values) > 1024 {
			return errors.New("a term with more than 1024 values")
		}
		for _, v := range x.Values {
			if err := checkValue(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// Encode returns the canonical JSON of f.
func (f Filter) Encode() (string, error) {
	f = f.normalise()
	if err := f.check(); err != nil {
		return "", err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeFilter parses a stream back into its filter; only a canonical
// encoding is accepted.
func DecodeFilter(s string) (Filter, error) {
	var f Filter
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Filter{}, errors.New("invalid stream")
	}
	if back, err := f.Encode(); err != nil || back != s {
		return Filter{}, errors.New("invalid stream")
	}
	return f, nil
}

func clause(x FieldValues) Clause {
	if len(x.Values) == 1 {
		return Clause{Term: map[string]string{x.Field: x.Values[0]}}
	}
	return Clause{Terms: map[string][]string{x.Field: slices.Clone(x.Values)}}
}

// timeText writes t for a range on a date or date_nanos field.
func timeText(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

const timeFormat = "strict_date_optional_time_nanos"

// query builds the query of f over [from, to) on timeField. The bounds are
// widened to whole milliseconds (a date field holds milliseconds and
// truncates finer bounds); callers drop what falls outside [from, to).
func (f Filter) query(timeField string, from, to time.Time) (Query, error) {
	if err := checkField(timeField); err != nil {
		return Query{}, err
	}
	f = f.normalise()
	if err := f.check(); err != nil {
		return Query{}, err
	}
	lo := from.Truncate(time.Millisecond)
	hi := to.Truncate(time.Millisecond)
	if hi.Before(to) {
		hi = hi.Add(time.Millisecond)
	}
	q := Query{Bool: BoolQuery{Filter: []Clause{{Range: map[string]RangeSpec{timeField: {GTE: timeText(lo), LT: timeText(hi), Format: timeFormat}}}}}}
	for _, x := range f.In {
		q.Bool.Filter = append(q.Bool.Filter, clause(x))
	}
	for _, x := range f.NotIn {
		q.Bool.MustNot = append(q.Bool.MustNot, clause(x))
	}
	return q, nil
}

// checkClause reports a clause that is not exactly one well-formed filter.
func checkClause(c Clause) error {
	n := 0
	for k := range c.Range {
		n++
		if checkField(k) != nil {
			return errors.New("range on an invalid field")
		}
	}
	for k, v := range c.Term {
		n++
		if checkField(k) != nil || checkValue(v) != nil {
			return errors.New("invalid term")
		}
	}
	for k, vs := range c.Terms {
		n++
		if checkField(k) != nil || len(vs) == 0 || slices.ContainsFunc(vs, func(v string) bool { return checkValue(v) != nil }) {
			return errors.New("invalid terms")
		}
	}
	if n != 1 {
		return errors.New("a clause must hold exactly one filter")
	}
	return nil
}

func checkQuery(q Query) error {
	for _, c := range append(slices.Clone(q.Bool.Filter), q.Bool.MustNot...) {
		if err := checkClause(c); err != nil {
			return err
		}
	}
	return nil
}

func checkAggs(aggs map[string]Agg, depth int) error {
	if depth > 4 {
		return errors.New("aggregations nested too deep")
	}
	for name, a := range aggs {
		if checkField(name) != nil {
			return errors.New("invalid aggregation name")
		}
		switch {
		case a.DateHistogram != nil && a.Terms == nil:
			if checkField(a.DateHistogram.Field) != nil {
				return errors.New("date_histogram on an invalid field")
			}
		case a.Terms != nil && a.DateHistogram == nil:
			if checkField(a.Terms.Field) != nil || a.Terms.Size < 1 || a.Terms.Size > MaxTermsSize {
				return errors.New("invalid terms aggregation")
			}
		default:
			return errors.New("an aggregation must be one date_histogram or terms")
		}
		if err := checkAggs(a.Aggs, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// check validates a search body against the caps.
func (b SearchBody) check() error {
	if b.Size < 0 || b.Size > MaxSize {
		return fmt.Errorf("size %d outside [0, %d]", b.Size, MaxSize)
	}
	if b.Timeout == "" {
		return errors.New("a search needs a timeout")
	}
	for _, f := range b.Fields {
		if checkField(f) != nil {
			return errors.New("invalid field")
		}
	}
	for _, s := range b.Sort {
		for k := range s {
			if checkField(k) != nil {
				return errors.New("invalid sort field")
			}
		}
	}
	for _, v := range b.SearchAfter {
		switch v.(type) {
		case json.Number, string, int64:
		default:
			return errors.New("search_after holds a value that is not a number or a string")
		}
	}
	if err := checkQuery(b.Query); err != nil {
		return err
	}
	return checkAggs(b.Aggs, 0)
}

// marshalChecked writes v and parses it back into a fresh value of its
// type, refusing unknown keys: the body sent has exactly the typed shape,
// whatever the values hold.
func marshalChecked[T any](v T) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var back T
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&back); err != nil {
		return nil, fmt.Errorf("query builder: the body does not parse back: %w", err)
	}
	again, err := json.Marshal(back)
	if err != nil || !bytes.Equal(again, b) {
		return nil, errors.New("query builder: the body does not parse back to itself")
	}
	return b, nil
}

// searchJSON validates and writes a search body.
func searchJSON(b SearchBody) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, fmt.Errorf("query builder: %w", err)
	}
	return marshalChecked(b)
}

// countJSON validates and writes a count body.
func countJSON(b CountBody) ([]byte, error) {
	if err := checkQuery(b.Query); err != nil {
		return nil, fmt.Errorf("query builder: %w", err)
	}
	return marshalChecked(b)
}
