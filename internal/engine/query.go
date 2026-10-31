package engine

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Refusal codes (stable, documented for agents).
const (
	EBadQuery     = "E_BAD_QUERY"
	EUnknownField = "E_UNKNOWN_FIELD"
	EPIIInQuery   = "E_PII_IN_QUERY"
	EOverBudget   = "E_OVER_BUDGET"
	ESource       = "E_SOURCE"
	// EMask is reserved: a record masking fails on is withheld and
	// counted in masked_failures, never refused (see run).
	EMask          = "E_MASK"
	EPolicyChanged = "E_POLICY_CHANGED"
	EStale         = "E_STALE"
)

// Error is a structured refusal. Its text never holds log content: query
// values are echoed only through the masker's text path by the caller.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Span is the JSON path of the offending part of the query.
	Span string `json:"span,omitempty"`
	// Estimate is the plan estimate of an over-budget call.
	Estimate *Estimate `json:"estimate,omitempty"`
}

func (e *Error) Error() string {
	if e.Span != "" {
		return e.Code + ": " + e.Message + " (at " + e.Span + ")"
	}
	return e.Code + ": " + e.Message
}

func refuse(code, span, format string, a ...any) *Error {
	return &Error{Code: code, Span: span, Message: fmt.Sprintf(format, a...)}
}

// Estimate is what a plan would cost.
type Estimate struct {
	Bytes    int64         `json:"bytes"`
	Granules int           `json:"granules"`
	Range    time.Duration `json:"range_ns"`
}

// Operators.
const (
	OpEq       = "="
	OpNe       = "!="
	OpIn       = "in"
	OpExists   = "exists"
	OpLt       = "<"
	OpLe       = "<="
	OpGt       = ">"
	OpGe       = ">="
	OpContains = "contains"
	OpMatches  = "matches"
)

var ops = []string{OpEq, OpNe, OpIn, OpExists, OpLt, OpLe, OpGt, OpGe, OpContains, OpMatches}

// Limits of a query.
const (
	MaxPattern    = 256 // bytes of a regex
	MaxNeedle     = 256 // bytes of a contains/text needle
	MaxPredicates = 32
	MaxFields     = 64
	MaxInValues   = 64
	MaxSources    = 32
	DefaultLimit  = 100
)

// Pred is one predicate of where. Field addresses a field by its shown
// path (clear, or with ⟦key:ID⟧ segments); Label a source label (Loki
// labels, container-frame attributes).
type Pred struct {
	Field string          `json:"field,omitempty"`
	Label string          `json:"label,omitempty"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value,omitempty"`

	// Validated forms.
	vals   []string // = != in: the values as text (numbers canonical)
	nums   []*big.Rat
	re     *regexp.Regexp
	needle string
}

// name is the field or label the predicate is about; label tells which
// namespace (a Loki stream label or structured metadata, a docker container
// or stream are labels).
func (p *Pred) name() string {
	if p.Label != "" {
		return p.Label
	}
	return p.Field
}

// label reports whether the predicate is about a label.
func (p *Pred) label() bool { return p.Label != "" }

// Query is a search or count query (design §3.2).
type Query struct {
	Sources []string  `json:"sources,omitempty"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	// Last, when set, resolves the range at validation: [now-Last, now).
	Last   string   `json:"last,omitempty"`
	Where  []Pred   `json:"where,omitempty"`
	Text   string   `json:"text,omitempty"`
	Regex  string   `json:"regex,omitempty"`
	Fields []string `json:"fields,omitempty"`
	Limit  int      `json:"limit,omitempty"`
	// Order is "asc" (default) or "desc".
	Order  string `json:"order,omitempty"`
	Cursor string `json:"cursor,omitempty"`

	textRe *regexp.Regexp
}

// numeric reports whether a value of the predicate is a number. The
// evaluator compares numbers by exact value (200 = 200.0 = 2e2), while the
// index and source selectors hold raw literals compared as text, so a
// numeric term is never pushed down to a source nor answered from the index:
// it is evaluated on the masked records only. It reads the raw value, so it
// holds before validation too (Count sizes its range from it).
func (p *Pred) numeric() bool {
	d := json.NewDecoder(strings.NewReader(string(p.Value)))
	d.UseNumber()
	var x any
	if d.Decode(&x) != nil {
		return false
	}
	switch t := x.(type) {
	case json.Number:
		return true
	case []any:
		for _, it := range t {
			if _, ok := it.(json.Number); ok {
				return true
			}
		}
	}
	return false
}

// trustedOnly reports whether the query uses only trusted-field selection:
// no text, no regex, every predicate an equality on a trusted field with
// non-numeric values (see numeric).
func (q *Query) trustedOnly(trusted func(src, name string, label bool) bool) bool {
	if q.Text != "" || q.Regex != "" {
		return false
	}
	for _, p := range q.Where {
		if !slices.Contains([]string{OpEq, OpNe, OpIn}, p.Op) || p.numeric() {
			return false
		}
		for _, s := range q.Sources {
			if !trusted(s, p.name(), p.label()) {
				return false
			}
		}
	}
	return true
}

// selector returns the trusted-field terms of the query, used for planning;
// numeric terms are left out (see numeric).
func (q *Query) selector(src string, trusted func(src, name string, label bool) bool) source.Selector {
	var sel source.Selector
	for _, p := range q.Where {
		if !trusted(src, p.name(), p.label()) || p.numeric() {
			continue
		}
		// A label predicate is pushed as a label term, a field one
		// as a field term: a source applies each in its namespace.
		switch p.Op {
		case OpEq, OpIn:
			sel.Terms = append(sel.Terms, source.Term{Field: p.name(), Label: p.label(), Op: OpIn, Values: p.vals})
		case OpNe:
			sel.Terms = append(sel.Terms, source.Term{Field: p.name(), Label: p.label(), Op: OpNe, Values: p.vals})
		}
	}
	return sel
}

// validator holds what validation needs from the console.
type validator struct {
	now     time.Time
	sources []string
	trusted func(src, name string, label bool) bool
	// detect reports a value a detector flags (personal data, secret).
	detect func(string) bool
	// nameMasked reports a clear path whose name the masker shows masked.
	nameMasked func(src, path string) bool
	maxRange   time.Duration
	limitMax   int
}

// validate checks q totally and fills the validated forms. Refusals name
// the span of the query they are about.
func (v *validator) validate(q *Query) *Error {
	if len(q.Sources) == 0 {
		q.Sources = slices.Clone(v.sources)
	}
	if len(q.Sources) > MaxSources {
		return refuse(EBadQuery, "sources", "at most %d sources", MaxSources)
	}
	for i, s := range q.Sources {
		if !slices.Contains(v.sources, s) {
			return refuse(EBadQuery, fmt.Sprintf("sources[%d]", i), "unknown source (see locklog_sources)")
		}
	}
	slices.Sort(q.Sources)
	q.Sources = slices.Compact(q.Sources)
	if q.Last != "" {
		if !q.From.IsZero() || !q.To.IsZero() {
			return refuse(EBadQuery, "last", "give either last or from/to")
		}
		d, err := time.ParseDuration(q.Last)
		if err != nil || d <= 0 {
			return refuse(EBadQuery, "last", "want a positive duration such as 90m or 24h")
		}
		q.To = v.now.Truncate(time.Second)
		q.From = q.To.Add(-d)
		q.Last = ""
	}
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return refuse(EBadQuery, "from", "want an absolute range with from before to")
	}
	q.From, q.To = q.From.UTC(), q.To.UTC()
	if q.To.Sub(q.From) > v.maxRange {
		return &Error{Code: EOverBudget, Span: "to", Message: fmt.Sprintf("range over the %s budget of this query (locklog_scan goes past it)", v.maxRange),
			Estimate: &Estimate{Range: q.To.Sub(q.From)}}
	}
	if len(q.Where) > MaxPredicates {
		return refuse(EBadQuery, "where", "at most %d predicates", MaxPredicates)
	}
	for i := range q.Where {
		if err := v.pred(q, &q.Where[i], fmt.Sprintf("where[%d]", i)); err != nil {
			return err
		}
	}
	if q.Text != "" {
		if err := v.needle(q.Text, "text"); err != nil {
			return err
		}
	}
	if q.Regex != "" {
		re, err := v.regex(q.Regex, "regex")
		if err != nil {
			return err
		}
		q.textRe = re
	}
	if len(q.Fields) > MaxFields {
		return refuse(EBadQuery, "fields", "at most %d fields", MaxFields)
	}
	for i, f := range q.Fields {
		if err := v.path(q, f, fmt.Sprintf("fields[%d]", i)); err != nil {
			return err
		}
	}
	switch {
	case q.Limit == 0:
		q.Limit = DefaultLimit
	case q.Limit < 0 || q.Limit > v.limitMax:
		return refuse(EBadQuery, "limit", "want 1 to %d", v.limitMax)
	}
	switch q.Order {
	case "":
		q.Order = "asc"
	case "asc", "desc":
	default:
		return refuse(EBadQuery, "order", "want asc or desc")
	}
	return nil
}

// path checks a field path: a clear path the masker would show masked is
// refused as unknown (no existence oracle: an unknown field and a masked
// one look the same).
func (v *validator) path(q *Query, p, span string) *Error {
	if p == "" || len(p) > 512 || !utf8.ValidString(p) || strings.ContainsFunc(p, unicode.IsControl) {
		return refuse(EBadQuery, span, "invalid field path")
	}
	if strings.Contains(p, mask.Open) {
		return nil // addressed by its masked name
	}
	for _, s := range q.Sources {
		if v.nameMasked != nil && v.nameMasked(s, p) {
			return refuse(EUnknownField, span, "unknown field (fields shown masked are addressed as ⟦key:ID⟧)")
		}
	}
	return nil
}

func (v *validator) pred(q *Query, p *Pred, span string) *Error {
	if (p.Field == "") == (p.Label == "") {
		return refuse(EBadQuery, span, "give one of field or label")
	}
	if p.Field != "" {
		if err := v.path(q, p.Field, span+".field"); err != nil {
			return err
		}
	}
	if !slices.Contains(ops, p.Op) {
		return refuse(EBadQuery, span+".op", "unknown operator (want one of %s)", strings.Join(ops, " "))
	}
	if p.Op == OpExists {
		if len(p.Value) != 0 {
			return refuse(EBadQuery, span+".value", "exists takes no value")
		}
		return nil
	}
	if len(p.Value) == 0 {
		return refuse(EBadQuery, span+".value", "missing value")
	}
	switch p.Op {
	case OpContains:
		s, err := stringValue(p.Value)
		if err != nil {
			return refuse(EBadQuery, span+".value", "contains takes a string")
		}
		if e := v.needle(s, span+".value"); e != nil {
			return e
		}
		p.needle = s
		return nil
	case OpMatches:
		s, err := stringValue(p.Value)
		if err != nil {
			return refuse(EBadQuery, span+".value", "matches takes a string")
		}
		re, e := v.regex(s, span+".value")
		if e != nil {
			return e
		}
		p.re = re
		return nil
	case OpLt, OpLe, OpGt, OpGe:
		// Ordering on a masked field is an oracle (as MIN/MAX would be).
		for _, s := range q.Sources {
			if !v.trusted(s, p.name(), p.label()) {
				return refuse(EBadQuery, span+".op", "ordering operators apply to trusted fields and labels only")
			}
		}
	}
	var raw []json.RawMessage
	if p.Op == OpIn {
		if json.Unmarshal(p.Value, &raw) != nil || len(raw) == 0 || len(raw) > MaxInValues {
			return refuse(EBadQuery, span+".value", "in takes a list of 1 to %d values", MaxInValues)
		}
	} else {
		raw = []json.RawMessage{p.Value}
	}
	for i, r := range raw {
		s, num, err := scalarValue(r)
		if err != nil {
			return refuse(EBadQuery, fmt.Sprintf("%s.value[%d]", span, i), "want a string, number or bool")
		}
		if len(s) > MaxNeedle || strings.ContainsFunc(s, unicode.IsControl) {
			return refuse(EBadQuery, fmt.Sprintf("%s.value[%d]", span, i), "value too long or with control characters")
		}
		if !isToken(s) && v.detect != nil && v.detect(s) {
			return refuse(EPIIInQuery, fmt.Sprintf("%s.value[%d]", span, i), "the value looks like personal data or a secret: use locklog_lookup to get its pseudonym")
		}
		p.vals = append(p.vals, s)
		p.nums = append(p.nums, num)
	}
	if (p.Op == OpLt || p.Op == OpLe || p.Op == OpGt || p.Op == OpGe) && p.nums[0] == nil && isToken(p.vals[0]) {
		return refuse(EBadQuery, span+".value", "ordering on a pseudonym")
	}
	return nil
}

func (v *validator) needle(s, span string) *Error {
	if s == "" || len(s) > MaxNeedle || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) || strings.ContainsRune(s, utf8.RuneError) {
		return refuse(EBadQuery, span, "want 1 to %d bytes of printable text", MaxNeedle)
	}
	if strings.Contains(s, mask.Open) || strings.Contains(s, mask.Close) {
		return refuse(EBadQuery, span, "text never matches inside a placeholder; compare a field with = ⟦kind:ID⟧")
	}
	if v.detect != nil && v.detect(s) {
		return refuse(EPIIInQuery, span, "the text holds personal data or a secret: use locklog_lookup to get its pseudonym")
	}
	return nil
}

func (v *validator) regex(s, span string) (*regexp.Regexp, *Error) {
	if s == "" || len(s) > MaxPattern || !utf8.ValidString(s) {
		return nil, refuse(EBadQuery, span, "want an RE2 pattern of 1 to %d bytes", MaxPattern)
	}
	if strings.Contains(s, mask.Open) || strings.Contains(s, mask.Close) {
		return nil, refuse(EBadQuery, span, "patterns never match inside a placeholder")
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, refuse(EBadQuery, span, "invalid RE2 pattern")
	}
	// Literal parts of a pattern are checked like text.
	if v.detect != nil && v.detect(s) {
		return nil, refuse(EPIIInQuery, span, "the pattern holds personal data or a secret: use locklog_lookup")
	}
	return re, nil
}

func stringValue(r json.RawMessage) (string, error) {
	var s string
	err := json.Unmarshal(r, &s)
	return s, err
}

// scalarValue returns a JSON scalar as text (numbers as their literal) and,
// for a number, its exact value.
func scalarValue(r json.RawMessage) (string, *big.Rat, error) {
	var x any
	d := json.NewDecoder(strings.NewReader(string(r)))
	d.UseNumber()
	if err := d.Decode(&x); err != nil {
		return "", nil, err
	}
	switch t := x.(type) {
	case string:
		return t, nil, nil
	case json.Number:
		n, ok := parseNumber(string(t))
		if !ok {
			return "", nil, fmt.Errorf("number (at most %d characters, exponent within ±%d)", maxNumberLen, maxNumberExponent)
		}
		return string(t), n, nil
	case bool:
		if t {
			return "true", nil, nil
		}
		return "false", nil, nil
	}
	return "", nil, fmt.Errorf("not a scalar")
}

// isToken reports whether s is one pseudonym placeholder ⟦kind:ID⟧.
func isToken(s string) bool {
	if !strings.HasPrefix(s, mask.Open) || !strings.HasSuffix(s, mask.Close) {
		return false
	}
	inner := s[len(mask.Open) : len(s)-len(mask.Close)]
	kind, id, ok := strings.Cut(inner, ":")
	return ok && kind != "" && id != "" && !strings.ContainsAny(inner, mask.Open+mask.Close)
}
