package engine

import (
	"math/big"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// Masked-view semantics (design §4.4 rule 1): every predicate is evaluated
// on the masked record only. contains and matches see the evaluation string
// E: the masked text with every placeholder replaced by a NUL, which no
// needle or pattern literal can contain, so nothing ever matches inside a
// placeholder; = compares masked text, so a pseudonym is matched by its
// token.

// evalString returns E for a masked text.
func evalString(s string) string {
	if !strings.Contains(s, mask.Open) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, mask.Open)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteByte(0)
		j := strings.Index(s[i:], mask.Close)
		if j < 0 {
			return b.String() // unterminated: the rest is placeholder
		}
		s = s[i+j+len(mask.Close):]
	}
}

// msgPaths are the paths that address the free-text message.
var msgPaths = map[string]bool{"msg": true, "message": true}

// val is a masked scalar seen by a predicate.
type val struct {
	kind mask.Kind
	text string
}

// lookup returns the masked scalar values at a shown path (several when the
// path crosses arrays or duplicate keys), for a field or a label.
func lookup(rec mask.Record, p *Pred) []val {
	if p.Label != "" {
		return leaves(rec.Attrs(), p.Label)
	}
	if msgPaths[p.Field] {
		if _, ok := rec.Lookup(p.Field); !ok {
			if m := rec.Message(); m != "" {
				return []val{{kind: mask.String, text: m}}
			}
		}
	}
	return leaves(rec.Fields(), p.Field)
}

// leaves collects every value at a dotted shown path, under every reading
// of its dots (nested objects, a key holding dots at any level, as docker's
// attrs "com.docker.compose.service"), arrays crossed: the same readings as
// the local index (index.Value), so that index and scan agree.
func leaves(fields []mask.Field, path string) []val {
	var out []val
	var walk func(fs []mask.Field, rest string)
	var down func(v mask.Value, rest string)
	var leaf func(v mask.Value)
	leaf = func(v mask.Value) {
		switch v.Kind() {
		case mask.Array:
			for _, it := range v.Items() {
				leaf(it)
			}
		case mask.Object:
			out = append(out, val{kind: mask.Object})
		default:
			out = append(out, val{kind: v.Kind(), text: v.Text()})
		}
	}
	walk = func(fs []mask.Field, rest string) {
		for _, f := range fs {
			switch n := f.Name(); {
			case n == rest:
				leaf(f.Value())
			case strings.HasPrefix(rest, n+"."):
				down(f.Value(), rest[len(n)+1:])
			}
		}
	}
	down = func(v mask.Value, rest string) {
		switch v.Kind() {
		case mask.Object:
			walk(v.Members(), rest)
		case mask.Array:
			for _, it := range v.Items() {
				down(it, rest)
			}
		}
	}
	if path != "" {
		walk(fields, path)
	}
	return out
}

// budget bounds the evaluation of one group of records: work is charged
// as bytes of evaluated text (a fixed cost per leaf, the text's length,
// weighted by the regex program for matches) and the clock is checked every
// budgetStep bytes, across predicates and leaves, so a single large record
// cannot run past the deadline. A nil budget never stops.
type budget struct {
	stop    func() bool
	pending int64
	over    bool
}

const (
	budgetStep = 64 << 10
	leafCost   = 16
)

// charge adds n bytes of work and reports whether evaluation must stop.
func (b *budget) charge(n int64) bool {
	if b == nil {
		return false
	}
	if b.over {
		return true
	}
	if b.pending += n; b.pending >= budgetStep {
		b.pending = 0
		b.over = b.stop()
	}
	return b.over
}

// check consults the clock now and reports whether evaluation must stop.
func (b *budget) check() bool {
	if b == nil {
		return false
	}
	if !b.over {
		b.pending = 0
		b.over = b.stop()
	}
	return b.over
}

// exceeded reports whether evaluation was stopped (its results are void).
func (b *budget) exceeded() bool { return b != nil && b.over }

// match evaluates the query's predicates, text and regex on a masked record
// under b. Once b is exceeded it returns false, and the caller refuses the
// call.
func (q *Query) match(rec mask.Record, b *budget) bool {
	if !rec.Valid() || rec.Failed() {
		return false
	}
	for i := range q.Where {
		p := &q.Where[i]
		vs := lookup(rec, p)
		if b.charge(int64(len(vs)) * leafCost) {
			return false
		}
		if !predMatch(p, vs, b) || b.exceeded() {
			return false
		}
	}
	if q.Text != "" && !anyText(rec, b, 1, func(e string) bool { return strings.Contains(e, q.Text) }) {
		return false
	}
	if q.textRe != nil && !anyText(rec, b, regexWeight(q.textReCost), q.textRe.MatchString) {
		return false
	}
	if q.trace != nil && !q.trace.match(rec, b) {
		return false
	}
	return !b.exceeded()
}

// textPreds is how many text predicates (contains, matches, text, regex)
// the query evaluates on every leaf: the cost model sizes groups by it.
func (q *Query) textPreds() int64 {
	var n int64
	for i := range q.Where {
		if q.Where[i].Op == OpContains || q.Where[i].Op == OpMatches {
			n++
		}
	}
	if q.Text != "" {
		n++
	}
	if q.trace != nil {
		n++
	}
	if q.textRe != nil {
		n++
	}
	return n
}

// evalFactor is the multiplier the cost model applies to a group's bytes
// for the evaluation of the query's text predicates (a function of the
// query only, never of the data).
func (q *Query) evalFactor() int64 { return 1 + q.textPreds()/4 }

// regexWeight is the charge per byte of a regex of expanded size cost (see
// regexCost): a match costs up to bytes × program size.
func regexWeight(cost int) int64 { return 1 + int64(cost)/32 }

// anyText applies fn to E of the message and of every string leaf, charging
// b weight per byte.
func anyText(rec mask.Record, b *budget, weight int64, fn func(string) bool) bool {
	if m := rec.Message(); m != "" {
		if b.charge(leafCost + int64(len(m))*weight) {
			return false
		}
		if fn(evalString(m)) {
			return true
		}
	}
	found := false
	var walk func(v mask.Value)
	walk = func(v mask.Value) {
		if found || b.exceeded() {
			return
		}
		switch v.Kind() {
		case mask.String:
			if b.charge(leafCost + int64(len(v.Text()))*weight) {
				return
			}
			found = fn(evalString(v.Text()))
		case mask.Object:
			for _, f := range v.Members() {
				walk(f.Value())
			}
		case mask.Array:
			for _, it := range v.Items() {
				walk(it)
			}
		}
	}
	for _, f := range rec.Fields() {
		walk(f.Value())
	}
	return found && !b.exceeded()
}

// predMatch evaluates a predicate on the values at its path, charging b per
// leaf; once b is exceeded its result is void.
func predMatch(p *Pred, vs []val, b *budget) bool {
	weight := int64(1)
	if p.Op == OpMatches {
		weight = regexWeight(p.reCost)
	}
	switch p.Op {
	case OpExists:
		return len(vs) > 0
	case OpNe:
		for _, v := range vs {
			if b.charge(leafCost + int64(len(v.text))) {
				return false
			}
			if equal(p, 0, v) {
				return false
			}
		}
		return true
	}
	for _, v := range vs {
		if b.charge(leafCost + int64(len(v.text))*weight) {
			return false
		}
		switch p.Op {
		case OpEq:
			if equal(p, 0, v) {
				return true
			}
		case OpIn:
			if p.inMatch(v) {
				return true
			}
		case OpContains:
			if v.kind != mask.Object && strings.Contains(evalString(v.text), p.needle) {
				return true
			}
		case OpMatches:
			if v.kind != mask.Object && p.re.MatchString(evalString(v.text)) {
				return true
			}
		case OpLt, OpLe, OpGt, OpGe:
			if c, ok := compare(p, v); ok {
				switch p.Op {
				case OpLt:
					if c < 0 {
						return true
					}
				case OpLe:
					if c <= 0 {
						return true
					}
				case OpGt:
					if c > 0 {
						return true
					}
				case OpGe:
					if c >= 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// equal compares a masked scalar to value i: numbers by exact value,
// everything else by its masked text (a pseudonym by its token).
func equal(p *Pred, i int, v val) bool {
	if v.kind == mask.Object {
		return false
	}
	if p.nums[i] != nil && v.kind == mask.Number {
		if n, ok := parseNumber(v.text); ok {
			return n.Cmp(p.nums[i]) == 0
		}
	}
	return v.text == p.vals[i]
}

// compare orders a trusted value against the predicate's value: numerically
// when both are numbers, else as text.
func compare(p *Pred, v val) (int, bool) {
	if v.kind == mask.Object || v.kind == mask.Null {
		return 0, false
	}
	t := v.text
	if p.nums[0] != nil {
		n, ok := parseNumber(t)
		if !ok {
			return 0, false
		}
		return n.Cmp(p.nums[0]), true
	}
	if isToken(t) {
		return 0, false
	}
	return strings.Compare(t, p.vals[0]), true
}

var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// Number literal bounds: big.Rat's cost grows with the exponent (1e999999
// takes milliseconds), and log content chooses it.
const (
	maxNumberLen      = 400
	maxNumberExponent = 400
)

// numberParses counts parseNumber calls (tests bound the work of numeric
// predicates by it, not by wall-clock time).
var numberParses atomic.Int64

// parseNumber returns the exact value of a number literal within the
// bounds; a literal beyond them is not a number to compare (equality falls
// back to its text).
func parseNumber(s string) (*big.Rat, bool) {
	numberParses.Add(1)
	// The JSON number grammar only: big.Rat also takes hex, octal and
	// binary mantissas, p exponents (0x1p9999999), fractions and
	// underscores.
	if len(s) > maxNumberLen || !jsonNumber.MatchString(s) {
		return nil, false
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil || e > maxNumberExponent || e < -maxNumberExponent {
			return nil, false
		}
	}
	return new(big.Rat).SetString(s)
}

// inSet is an in predicate's values, precomputed once: a leaf is parsed at
// most once and looked up, never compared value by value (numbers in a
// long array would cost leaves × values parses).
type inSet struct {
	nums    map[string]bool // canonical exact values of the numeric ones
	text    map[string]bool // every value's text
	nonNums map[string]bool // the text of the non-numeric ones
}

func (p *Pred) inSet() *inSet {
	if p.in != nil {
		return p.in
	}
	s := &inSet{nums: map[string]bool{}, text: map[string]bool{}, nonNums: map[string]bool{}}
	for i, v := range p.vals {
		s.text[v] = true
		if p.nums[i] != nil {
			s.nums[p.nums[i].RatString()] = true
		} else {
			s.nonNums[v] = true
		}
	}
	p.in = s
	return s
}

// inMatch is equal(p, i, v) for some i: a number leaf by its exact value
// against the numeric values and by text against the others, any other
// leaf by text.
func (p *Pred) inMatch(v val) bool {
	if v.kind == mask.Object {
		return false
	}
	s := p.inSet()
	if v.kind == mask.Number && len(s.nums) > 0 {
		if n, ok := parseNumber(v.text); ok {
			return s.nums[n.RatString()] || s.nonNums[v.text]
		}
	}
	return s.text[v.text]
}

// Regex size bounds: a repetition count above maxRepeat, or an expanded size
// (repetitions multiplied out) above maxRegexCost, is refused. RE2 matches
// in time bytes × program size, and the program of [ab ]{1,250} alone is
// hundreds of instructions.
const (
	maxRepeat    = 100
	maxRegexCost = 1000
)

// regexCost returns the expanded size of a parsed regex, saturating past
// maxRegexCost, and whether every repetition count is within maxRepeat.
func regexCost(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return max(len(re.Rune), 1), true
	case syntax.OpRepeat:
		if re.Min > maxRepeat || re.Max > maxRepeat {
			return 0, false
		}
		sub, ok := regexCost(re.Sub[0])
		if !ok {
			return 0, false
		}
		n := max(re.Max, re.Min, 1)
		return min(n*sub, maxRegexCost+1), true
	}
	c := 1
	for _, sub := range re.Sub {
		sc, ok := regexCost(sub)
		if !ok {
			return 0, false
		}
		c = min(c+sc, maxRegexCost+1)
	}
	return c, true
}
