package loki

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Matcher is one label matcher or structured-metadata filter of a query.
type Matcher struct {
	Name string
	Op   string // "=", "!=", "=~", "!~"
	// Values: one for = and !=; the alternatives of =~ and !~ (literal
	// values, quoted into an anchored alternation).
	Values []string
}

// Selector is what locklog sends Loki: stream matchers (the profile's
// selector ANDed with trusted-label terms) and filters on trusted structured
// metadata. Text never goes to Loki.
type Selector struct {
	Stream []Matcher
	Meta   []Matcher
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// quote writes a LogQL double-quoted string.
func quote(s string) string { return strconv.Quote(s) }

func (m Matcher) value() string {
	if m.Op == "=~" || m.Op == "!~" {
		alts := make([]string, len(m.Values))
		for i, v := range m.Values {
			alts[i] = regexp.QuoteMeta(v)
		}
		return strings.Join(alts, "|")
	}
	return m.Values[0]
}

func (m Matcher) check() error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("invalid label name %q", m.Name)
	}
	switch m.Op {
	case "=", "!=":
		if len(m.Values) != 1 {
			return errors.New("= and != take one value")
		}
	case "=~", "!~":
		if len(m.Values) == 0 {
			return errors.New("regex matcher without values")
		}
	default:
		return fmt.Errorf("invalid operator %q", m.Op)
	}
	for _, v := range m.Values {
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return errors.New("control character in a label value")
		}
	}
	return nil
}

// normalise sorts matchers and values so equal selectors render equally.
func (s Selector) normalise() Selector {
	norm := func(ms []Matcher) []Matcher {
		out := make([]Matcher, len(ms))
		for i, m := range ms {
			m.Values = slices.Clone(m.Values)
			sort.Strings(m.Values)
			m.Values = slices.Compact(m.Values)
			out[i] = m
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Name != out[j].Name {
				return out[i].Name < out[j].Name
			}
			return out[i].Op < out[j].Op
		})
		return out
	}
	return Selector{Stream: norm(s.Stream), Meta: norm(s.Meta)}
}

// Render builds the LogQL log query of s and checks it by parsing it back:
// the query sent is exactly the selector built, whatever the values hold.
func (s Selector) Render() (string, error) {
	s = s.normalise()
	if len(s.Stream) == 0 {
		return "", errors.New("a Loki query needs at least one stream matcher")
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range s.Stream {
		if err := m.check(); err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(m.Name + m.Op + quote(m.value()))
	}
	b.WriteByte('}')
	for _, m := range s.Meta {
		if err := m.check(); err != nil {
			return "", err
		}
		b.WriteString(" | " + m.Name + m.Op + quote(m.value()))
	}
	q := b.String()
	back, err := parseQuery(q)
	if err != nil {
		return "", fmt.Errorf("logql builder: %w", err)
	}
	if !equalRendered(back, s) {
		return "", errors.New("logql builder: the query does not parse back to its selector")
	}
	return q, nil
}

// rendered is a parsed query: names, operators and raw (unquoted) values.
type rendered struct {
	stream, meta [][3]string
}

func equalRendered(r rendered, s Selector) bool {
	want := func(ms []Matcher) [][3]string {
		var out [][3]string
		for _, m := range ms {
			out = append(out, [3]string{m.Name, m.Op, m.value()})
		}
		return out
	}
	return slices.Equal(r.stream, want(s.Stream)) && slices.Equal(r.meta, want(s.Meta))
}

// parseQuery parses the grammar Render writes:
// '{' name op string (', ' name op string)* '}' (' | ' name op string)*.
func parseQuery(q string) (rendered, error) {
	var r rendered
	if !strings.HasPrefix(q, "{") {
		return r, errors.New("no stream selector")
	}
	rest := q[1:]
	matcher := func() ([3]string, error) {
		i := 0
		for i < len(rest) && (rest[i] == '_' || rest[i] >= 'a' && rest[i] <= 'z' || rest[i] >= 'A' && rest[i] <= 'Z' || i > 0 && rest[i] >= '0' && rest[i] <= '9') {
			i++
		}
		name := rest[:i]
		rest = rest[i:]
		var op string
		for _, o := range []string{"=~", "!~", "!=", "="} {
			if strings.HasPrefix(rest, o) {
				op = o
				break
			}
		}
		if name == "" || op == "" {
			return [3]string{}, errors.New("bad matcher")
		}
		rest = rest[len(op):]
		lit, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return [3]string{}, err
		}
		rest = rest[len(lit):]
		v, err := strconv.Unquote(lit)
		if err != nil {
			return [3]string{}, err
		}
		return [3]string{name, op, v}, nil
	}
	for {
		m, err := matcher()
		if err != nil {
			return r, err
		}
		r.stream = append(r.stream, m)
		if strings.HasPrefix(rest, ", ") {
			rest = rest[2:]
			continue
		}
		if !strings.HasPrefix(rest, "}") {
			return r, errors.New("unterminated stream selector")
		}
		rest = rest[1:]
		break
	}
	for rest != "" {
		if !strings.HasPrefix(rest, " | ") {
			return r, errors.New("unexpected text after the selector")
		}
		rest = rest[3:]
		m, err := matcher()
		if err != nil {
			return r, err
		}
		r.meta = append(r.meta, m)
	}
	return r, nil
}
