package mask

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockkit/pii"
)

// Rule modes.
const (
	// ModeRedact withholds the value whole (⟦redacted⟧).
	ModeRedact = "redact"
	// ModePseudonym replaces the value whole by its pseudonym.
	ModePseudonym = "pseudonym"
	// ModeAllow shows the value after the secret step and the detectors,
	// also under redact-unknown.
	ModeAllow = "allow"
)

// Rule is a human rule of .locklog/pii.toml: field names and modes only.
// Field is a clear dotted path; "*" matches one segment (in a mask rule,
// also a key holding dots: one or more segments, so a mask rule covers
// more, never less).
type Rule struct {
	Sources []string // source names; empty: every source
	Field   string
	Mode    string
	Kind    string // pseudonym rules: the pseudonym kind ("customer")
}

// ValueRule is a human rule of the console's PII directory: a regular
// expression whose matches are pseudonymised as Kind.
type ValueRule struct {
	Kind  string
	Regex string
	re    *regexp.Regexp
}

// Rules are the masking rules in force: the project's (names and modes),
// the console's value rules, and the agent's (tighten-only, keyed
// digests in the PII directory).
type Rules struct {
	Mask   []Rule
	Allow  []Rule
	Values []ValueRule
	Agent  *AgentRules
}

type rawRule struct {
	Sources []string `toml:"sources"`
	Field   string   `toml:"field"`
	Label   string   `toml:"label"`
	Mode    string   `toml:"mode"`
	Kind    string   `toml:"kind"`
}

type rawRules struct {
	Mask  []rawRule `toml:"mask"`
	Allow []rawRule `toml:"allow"`
}

type rawValues struct {
	Value []struct {
		Kind  string `toml:"kind"`
		Regex string `toml:"regex"`
	} `toml:"value"`
}

// MaxRegex bounds a value rule's expression (RE2).
const MaxRegex = 256

// LoadProjectRules reads .locklog/pii.toml. A missing file is no rules.
// Only field (or label) names and modes may appear: value lists and
// expressions belong to the console's PII directory.
func LoadProjectRules(file string) (Rules, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return Rules{}, nil
	}
	if err != nil {
		return Rules{}, fmt.Errorf("pii rules: %w", err)
	}
	return ParseProjectRules(data)
}

// ParseProjectRules parses the content of a pii.toml.
func ParseProjectRules(data []byte) (Rules, error) {
	var raw rawRules
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return Rules{}, fmt.Errorf("pii rules: %v", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Rules{}, fmt.Errorf("pii rules: unknown key %s (rules name fields and modes only)", und[0])
	}
	var out Rules
	seen := map[string]bool{}
	for i, r := range raw.Mask {
		rule, err := buildRule(r, true)
		if err != nil {
			return Rules{}, fmt.Errorf("pii rules: mask rule %d: %w", i+1, err)
		}
		k := strings.Join(rule.Sources, ",") + "\x00" + rule.Field + "\x00" + rule.Mode
		if seen[k] {
			return Rules{}, fmt.Errorf("pii rules: mask rule %d: a rule with the same field, sources and mode comes earlier", i+1)
		}
		seen[k] = true
		out.Mask = append(out.Mask, rule)
	}
	for i, r := range raw.Allow {
		rule, err := buildRule(r, false)
		if err != nil {
			return Rules{}, fmt.Errorf("pii rules: allow rule %d: %w", i+1, err)
		}
		out.Allow = append(out.Allow, rule)
	}
	return out, nil
}

func buildRule(r rawRule, mask bool) (Rule, error) {
	field := r.Field
	if (r.Field == "") == (r.Label == "") {
		return Rule{}, errors.New("set exactly one of field and label")
	}
	if field == "" {
		field = r.Label
	}
	if err := checkPath(field, true); err != nil {
		return Rule{}, err
	}
	for _, s := range r.Sources {
		if !validName(s) {
			return Rule{}, fmt.Errorf("source %q: want a source name", s)
		}
	}
	rule := Rule{Sources: slices.Sorted(slices.Values(r.Sources)), Field: field, Mode: r.Mode, Kind: r.Kind}
	if !mask {
		if r.Mode != "" || r.Kind != "" {
			return Rule{}, errors.New("an allow rule has no mode or kind")
		}
		rule.Mode = ModeAllow
		return rule, nil
	}
	switch rule.Mode {
	case "":
		rule.Mode = ModeRedact
	case ModeRedact, ModePseudonym:
	default:
		return Rule{}, fmt.Errorf("mode %q: want redact or pseudonym", r.Mode)
	}
	if rule.Kind != "" && (rule.Mode != ModePseudonym || !pii.ValidKind(rule.Kind)) {
		return Rule{}, fmt.Errorf("kind %q: only on a pseudonym rule, 1 to 32 of a-z, 0-9, _", r.Kind)
	}
	return rule, nil
}

// checkPath refuses a path a rule cannot name: empty segments, controls,
// placeholders, or a glob where none is allowed.
func checkPath(p string, glob bool) error {
	if p == "" || len(p) > 512 {
		return errors.New("a field path is 1 to 512 bytes")
	}
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			return fmt.Errorf("field %q: empty segment", p)
		}
		if !glob && strings.ContainsAny(seg, "*?[]") {
			return fmt.Errorf("field %q: no glob", p)
		}
		if glob && seg != "*" && strings.ContainsAny(seg, "*?[]") {
			return fmt.Errorf("field %q: a glob is a whole segment (*)", p)
		}
	}
	if strings.Contains(p, Open) || strings.Contains(p, Close) {
		return fmt.Errorf("field %q: a rule names clear fields", p)
	}
	for _, r := range p {
		if unsafeRune(r) || r == '\n' || r == '\t' {
			return fmt.Errorf("field %q: control character", p)
		}
	}
	return nil
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// LoadValueRules reads values.toml in the console's PII directory: value
// expressions are human rules, never the project's.
func LoadValueRules(dir string) ([]ValueRule, error) {
	data, err := os.ReadFile(path.Join(dir, "values.toml"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pii value rules: %w", err)
	}
	var raw rawValues
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("pii value rules: %v", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("pii value rules: unknown key %s", und[0])
	}
	var out []ValueRule
	for i, v := range raw.Value {
		if !pii.ValidKind(v.Kind) {
			return nil, fmt.Errorf("pii value rule %d: kind %q: 1 to 32 of a-z, 0-9, _", i+1, v.Kind)
		}
		if v.Regex == "" || len(v.Regex) > MaxRegex {
			return nil, fmt.Errorf("pii value rule %d: regex of 1 to %d bytes", i+1, MaxRegex)
		}
		re, err := regexp.Compile(v.Regex)
		if err != nil {
			return nil, fmt.Errorf("pii value rule %d: %v", i+1, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("pii value rule %d: the regex matches the empty string", i+1)
		}
		out = append(out, ValueRule{Kind: v.Kind, Regex: v.Regex, re: re})
	}
	return out, nil
}

// Find implements Finder for the value rules: their matches, as ranges.
func (r *Rules) Find(s string) []pii.Match {
	var out []pii.Match
	for _, v := range r.Values {
		if v.re == nil {
			continue
		}
		for _, loc := range v.re.FindAllStringIndex(s, -1) {
			if loc[1] > loc[0] {
				out = append(out, pii.Match{Start: loc[0], End: loc[1], Kind: v.Kind})
			}
		}
	}
	return out
}

// maskRuleMatches is ruleMatches for a mask rule, where "*" also covers
// a key holding dots ("hosts.*.owner" on hosts → "10.0.0.1" → owner): a
// mask rule may cover more, never less (an allow rule matches exactly).
func maskRuleMatches(r Rule, source, clearPath string) bool {
	if ruleMatches(r, source, clearPath) {
		return true
	}
	if len(r.Sources) > 0 && !slices.Contains(r.Sources, source) || !strings.Contains(r.Field, "*") {
		return false
	}
	ps, fs := strings.Split(clearPath, "."), strings.Split(r.Field, ".")
	if len(ps) < len(fs) {
		return false
	}
	// Wildcard matching, "*" taking one or more segments: the classic
	// two-pointer walk with one backtrack point, no allocation.
	i, j, star, mark := 0, 0, -1, 0
	for j < len(ps) {
		switch {
		case i < len(fs) && fs[i] == "*":
			star, mark = i, j // "*" takes ps[j] (through ps[mark])
			i, j = i+1, j+1
		case i < len(fs) && fs[i] == ps[j]:
			i, j = i+1, j+1
		case star >= 0:
			mark++ // "*" takes one more segment
			i, j = star+1, mark+1
		default:
			return false
		}
	}
	return i == len(fs)
}

func ruleMatches(r Rule, source, clearPath string) bool {
	if len(r.Sources) > 0 && !slices.Contains(r.Sources, source) {
		return false
	}
	ps, fs := strings.Split(clearPath, "."), strings.Split(r.Field, ".")
	if len(ps) != len(fs) {
		return r.Field == clearPath // a flat key holding dots
	}
	for i := range ps {
		if fs[i] != "*" && fs[i] != ps[i] {
			return r.Field == clearPath
		}
	}
	return true
}

// human returns the mask rule for a field: the first redact rule, else
// the first pseudonym rule (the strongest wins), else an allow rule.
func (r *Rules) human(source, clearPath string) (Rule, bool) {
	var pseudo *Rule
	for i, m := range r.Mask {
		if maskRuleMatches(m, source, clearPath) {
			if m.Mode == ModeRedact {
				return m, true
			}
			if pseudo == nil {
				pseudo = &r.Mask[i]
			}
		}
	}
	if pseudo != nil {
		return *pseudo, true
	}
	for _, a := range r.Allow {
		if ruleMatches(a, source, clearPath) {
			return a, true
		}
	}
	return Rule{}, false
}

func (r *Rules) allowed(source, clearPath string) bool {
	for _, a := range r.Allow {
		if ruleMatches(a, source, clearPath) {
			return true
		}
	}
	return false
}

func (r *Rules) agent(source, clearPath string) (string, bool) {
	if r.Agent == nil {
		return "", false
	}
	return r.Agent.lookup(source, clearPath)
}

// Texts returns the canonical form of each rule, sorted.
func (r *Rules) Texts() []string {
	var out []string
	for _, m := range append(slices.Clone(r.Mask), r.Allow...) {
		out = append(out, m.text())
	}
	for _, v := range r.Values {
		out = append(out, "value kind="+v.Kind+" regex="+v.Regex)
	}
	slices.Sort(out)
	return out
}

func (r Rule) text() string {
	t := r.Mode + " field=" + r.Field
	if len(r.Sources) > 0 {
		t += " sources=" + strings.Join(r.Sources, ",")
	}
	if r.Kind != "" {
		t += " kind=" + r.Kind
	}
	return t
}

// Fingerprint identifies the rules in force (part of the policy
// fingerprint): human rules by their text, agent rules by their keyed
// digests.
func (r *Rules) Fingerprint() string {
	h := sha256.New()
	for _, t := range r.Texts() {
		h.Write([]byte(t))
		h.Write([]byte{0})
	}
	if r.Agent != nil {
		for _, d := range r.Agent.digests() {
			h.Write([]byte("agent " + d))
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Change classifies a change of the project rules (design §4.4 rule 7):
// the loosenings, which go to the human's review; a change without any
// only tightens and may apply at once. A new pseudonym rule is a
// loosening: under redact-unknown it turns ⟦redacted⟧ into a linkable
// pseudonym (and, with a detector kind, opens lookup).
func Change(old, new Rules) (loosenings []string) {
	key := func(r Rule) string { return strings.Join(r.Sources, ",") + "\x00" + r.Field }
	before := map[string]Rule{}
	for _, m := range append(slices.Clone(old.Mask), old.Allow...) {
		before[key(m)+"\x00"+m.Mode] = m
	}
	after := map[string]Rule{}
	for _, m := range append(slices.Clone(new.Mask), new.Allow...) {
		after[key(m)+"\x00"+m.Mode] = m
	}
	for k, m := range before {
		if _, kept := after[k]; kept {
			continue
		}
		if m.Mode == ModeAllow {
			continue // an allow rule removed: tighter
		}
		// A mask rule removed or weakened.
		loosenings = append(loosenings, "removes: "+m.text())
	}
	for k, m := range after {
		if _, had := before[k]; had {
			if m.Mode == ModePseudonym && before[k].Kind != m.Kind {
				loosenings = append(loosenings, "changes the kind: "+m.text())
			}
			continue
		}
		if m.Mode == ModeAllow {
			loosenings = append(loosenings, "adds: "+m.text())
			continue
		}
		if m.Mode == ModePseudonym {
			loosenings = append(loosenings, "adds: "+m.text())
		}
		// A new redact rule only tightens.
	}
	// The first matching pseudonym rule gives the kind: reordering or
	// removing one can change a field's kind (and open lookup).
	var oldP, newP []string
	inOld := map[string]bool{}
	for _, m := range old.Mask {
		if m.Mode == ModePseudonym {
			oldP = append(oldP, m.text())
			inOld[m.text()] = true
		}
	}
	for _, m := range new.Mask {
		if m.Mode == ModePseudonym && inOld[m.text()] {
			newP = append(newP, m.text())
		}
	}
	if !slices.Equal(oldP, newP) {
		loosenings = append(loosenings, "reorders or removes pseudonym rules")
	}
	slices.Sort(loosenings)
	return loosenings
}
