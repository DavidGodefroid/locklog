package engine

import (
	"math/big"
	"strings"

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

// leaves collects every value at a dotted shown path.
func leaves(fields []mask.Field, path string) []val {
	parts := splitShown(path)
	var out []val
	var walk func(fs []mask.Field, parts []string)
	var down func(v mask.Value, parts []string)
	walk = func(fs []mask.Field, parts []string) {
		for _, f := range fs {
			if f.Name() == parts[0] {
				down(f.Value(), parts[1:])
			}
		}
	}
	down = func(v mask.Value, parts []string) {
		switch {
		case len(parts) == 0:
			if v.Kind() == mask.Array {
				for _, it := range v.Items() {
					down(it, parts)
				}
				return
			}
			if v.Kind() != mask.Object {
				out = append(out, val{kind: v.Kind(), text: v.Text()})
			} else {
				out = append(out, val{kind: mask.Object})
			}
		case v.Kind() == mask.Object:
			walk(v.Members(), parts)
		case v.Kind() == mask.Array:
			for _, it := range v.Items() {
				down(it, parts)
			}
		}
	}
	if len(parts) > 0 {
		walk(fields, parts)
		// A clear dotted name stored as one key ("http.status").
		if len(parts) > 1 {
			walk(fields, []string{path})
		}
	}
	return out
}

// splitShown splits a shown path at the dots outside placeholders.
func splitShown(p string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(p); {
		switch {
		case strings.HasPrefix(p[i:], mask.Open):
			depth++
			i += len(mask.Open)
		case strings.HasPrefix(p[i:], mask.Close):
			depth--
			i += len(mask.Close)
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

// match evaluates the query's predicates, text and regex on a masked record.
func (q *Query) match(rec mask.Record) bool {
	if !rec.Valid() || rec.Failed() {
		return false
	}
	for i := range q.Where {
		if !predMatch(&q.Where[i], lookup(rec, &q.Where[i])) {
			return false
		}
	}
	if q.Text != "" && !anyText(rec, func(e string) bool { return strings.Contains(e, q.Text) }) {
		return false
	}
	if q.textRe != nil && !anyText(rec, q.textRe.MatchString) {
		return false
	}
	return true
}

// anyText applies fn to E of the message and of every string leaf.
func anyText(rec mask.Record, fn func(string) bool) bool {
	if m := rec.Message(); m != "" && fn(evalString(m)) {
		return true
	}
	found := false
	var walk func(v mask.Value)
	walk = func(v mask.Value) {
		if found {
			return
		}
		switch v.Kind() {
		case mask.String:
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
	return found
}

func predMatch(p *Pred, vs []val) bool {
	switch p.Op {
	case OpExists:
		return len(vs) > 0
	case OpNe:
		for _, v := range vs {
			if equal(p, 0, v) {
				return false
			}
		}
		return true
	}
	for _, v := range vs {
		switch p.Op {
		case OpEq:
			if equal(p, 0, v) {
				return true
			}
		case OpIn:
			for i := range p.vals {
				if equal(p, i, v) {
					return true
				}
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
		if n, ok := new(big.Rat).SetString(v.text); ok {
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
		n, ok := new(big.Rat).SetString(t)
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
