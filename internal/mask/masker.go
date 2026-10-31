package mask

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/parse"
)

// Structured modes (design §4.2), as the profile names them.
const (
	StructuredRedactUnknown = "redact-unknown"
	StructuredDetect        = "detect"
)

// PersonalKind is the kind of a value pseudonymised because of its field
// name (LooksPersonal, LooksQuasi) or a rule, when no detector recognises
// it whole.
const PersonalKind = "personal"

// Finder finds values in a text, as byte ranges of it.
type Finder interface {
	Find(s string) []pii.Match
}

// Detectors finds what lockkit detectors find, in the text and in its
// detection views (encodings, look-alikes, invisible characters).
type Detectors []pii.Detector

// Find implements Finder.
func (ds Detectors) Find(s string) []pii.Match { return pii.FindInViews(s, ds) }

// Options configure a Masker.
type Options struct {
	// Structured is StructuredRedactUnknown (default) or StructuredDetect.
	Structured string
	// Values are the value detectors of step 4 (personal data).
	Values Finder
	// Secrets finds secret values (step 1); SecretName reports a field
	// name whose value is a secret whole.
	Secrets    Finder
	SecretName func(name string) bool
	// Trusted are the clear paths of trusted fields: shown after the
	// secret step and the detectors, never redacted by redact-unknown nor
	// pseudonymised for their name.
	Trusted []string
	// Rules are the human and agent rules (step 2).
	Rules *Rules
	// Pseudonyms is the current epoch.
	Pseudonyms *pii.Pseudonymizer
}

// Masker masks events. It is safe for concurrent use.
type Masker struct {
	o       Options
	trusted map[string]bool

	mu    sync.Mutex
	names nameBook
}

// New returns a masker; Pseudonyms is required.
func New(o Options) (*Masker, error) {
	if o.Pseudonyms == nil {
		return nil, fmt.Errorf("mask: no pseudonym epoch")
	}
	switch o.Structured {
	case "":
		o.Structured = StructuredRedactUnknown
	case StructuredRedactUnknown, StructuredDetect:
	default:
		return nil, fmt.Errorf("mask: unknown structured mode %q", o.Structured)
	}
	if o.Rules == nil {
		o.Rules = &Rules{}
	}
	m := &Masker{o: o, trusted: map[string]bool{}, names: newNameBook()}
	for _, t := range o.Trusted {
		m.trusted[t] = true
	}
	return m, nil
}

// Epoch returns the pseudonym epoch records are masked under.
func (m *Masker) Epoch() string { return m.o.Pseudonyms.Epoch() }

// Mask masks one event of source. A panic in masking withholds the whole
// record (Failed), never part of it.
func (m *Masker) Mask(source string, ev parse.Event) (rec Record) {
	defer func() {
		if recover() != nil {
			rec = Record{ok: true, failed: true, ts: ev.Time, hasTime: ev.HasTime, offset: ev.Offset, length: ev.Length}
		}
	}()
	w := &walk{m: m, source: source, kinds: map[string]bool{}}
	rec = Record{ok: true, ts: ev.Time, hasTime: ev.HasTime, format: ev.Format, offset: ev.Offset, length: ev.Length}
	rec.fields = w.members(ev.Fields, "", "", false)
	rec.attrs = w.members(ev.Attrs, "", "", true)
	if ev.Message != "" || ev.Fields == nil {
		rec.msg = w.text(ev.Message)
	}
	rec.kinds = sortedKeys(w.kinds)
	rec.secretPaths = w.secretPaths
	return rec
}

// Text masks a string that leaves the console other than as a record
// (names in `sources`, bucket keys, refusal echoes, errors, audit
// causes): secrets, then personal values.
func (m *Masker) Text(s string) string {
	w := &walk{m: m, kinds: map[string]bool{}}
	return w.text(s)
}

// walk masks one record.
type walk struct {
	m           *Masker
	source      string
	kinds       map[string]bool
	secretPaths []string
}

func (w *walk) members(ms []parse.Member, clearPath, shownPath string, trusted bool) []Field {
	if ms == nil {
		return nil
	}
	out := make([]Field, 0, len(ms))
	for _, mem := range ms {
		name, shownName := w.key(mem.Key)
		cp, sp := join(clearPath, name), join(shownPath, shownName)
		out = append(out, Field{name: shownName, value: w.value(mem.Value, name, cp, sp, trusted)})
	}
	return out
}

// key masks a field name: a name holding a secret or a personal value is
// shown as ⟦key:ID⟧, kept (clear) in the console's name book only. It
// returns the clear name (after U+FFFD replacement) and the shown name.
func (w *walk) key(k string) (string, string) {
	k = cleanSource(k)
	secrets := w.find(w.m.o.Secrets, k)
	values := w.values(k)
	if len(secrets) == 0 && len(values) == 0 {
		w.m.noteClear(w.source, k)
		return k, outputSafe(k)
	}
	step1 := replace(k, secrets, func(string, pii.Match) string { return Secret })
	id, err := w.m.o.Pseudonyms.ID(KeyKind, step1)
	if err != nil {
		w.kinds["redacted"] = true
		return k, Redacted
	}
	w.kinds[KeyKind] = true
	w.m.noteMasked(id, k)
	return k, Token(KeyKind, id)
}

func (w *walk) value(v parse.Value, name, clearPath, shownPath string, trusted bool) Value {
	trusted = trusted || w.m.trusted[clearPath]
	switch v.Kind {
	case parse.KindObject:
		return Value{kind: Object, members: w.members(v.Members, clearPath, shownPath, trusted)}
	case parse.KindArray:
		items := make([]Value, len(v.Items))
		for i, it := range v.Items {
			items[i] = w.value(it, name, clearPath, shownPath, trusted)
		}
		return Value{kind: Array, items: items}
	case parse.KindNull:
		if !trusted && w.m.o.Structured == StructuredRedactUnknown && !w.m.o.Rules.allowed(w.source, clearPath) {
			w.kinds["redacted"] = true
			return Value{kind: String, text: Redacted}
		}
		return Value{kind: Null}
	}
	return w.leaf(v, name, clearPath, shownPath, trusted)
}

// leaf masks a scalar in the fixed order (design §4.2).
func (w *walk) leaf(v parse.Value, name, clearPath, shownPath string, trusted bool) Value {
	s := cleanSource(v.Str)
	if len(s) > pii.DetectLimit {
		s = pii.CutAt(s, pii.DetectLimit)
	}
	// (1) Secrets, first and final.
	if w.m.o.SecretName != nil && w.m.o.SecretName(name) {
		w.kinds["secret"] = true
		w.secretPaths = append(w.secretPaths, shownPath)
		return Value{kind: String, text: Secret}
	}
	secrets := w.find(w.m.o.Secrets, s)
	if len(secrets) > 0 {
		w.kinds["secret"] = true
		w.secretPaths = append(w.secretPaths, shownPath)
		s = replace(s, secrets, func(string, pii.Match) string { return Secret })
	}
	// Steps 2-5 work on s, the string step 1 produced.
	rule, hasRule := w.m.o.Rules.human(w.source, clearPath)
	switch {
	case hasRule && rule.Mode == ModeAllow:
		return w.detected(v.Kind, s, len(secrets) > 0)
	case hasRule && rule.Mode == ModeRedact:
		w.kinds["redacted"] = true
		return Value{kind: String, text: Redacted}
	case hasRule && rule.Mode == ModePseudonym:
		return w.whole(s, rule.Kind)
	case !trusted && (pii.LooksPersonal(name) || pii.LooksQuasi(name)):
		return w.whole(s, "")
	}
	out := w.detected(v.Kind, s, len(secrets) > 0)
	if !trusted && w.m.o.Structured == StructuredRedactUnknown && !w.m.o.Rules.allowed(w.source, clearPath) {
		w.kinds["redacted"] = true
		return Value{kind: String, text: Redacted}
	}
	// An agent rule only tightens: it masks a value nothing masked whole.
	if mode, ok := w.m.o.Rules.agent(w.source, clearPath); ok && !wholeMasked(out.text) {
		if mode == ModeRedact {
			w.kinds["redacted"] = true
			return Value{kind: String, text: Redacted}
		}
		return w.whole(s, "")
	}
	return out
}

// detected masks the personal values the detectors find in s (step 4).
func (w *walk) detected(k parse.Kind, s string, hadSecret bool) Value {
	ms := w.values(s)
	if len(ms) == 0 && !hadSecret {
		return Value{kind: kindOf(k), text: outputSafeScalar(k, s)}
	}
	return Value{kind: String, text: outputSafe(w.pseudonymise(s, ms))}
}

// whole pseudonymises s whole: of the kind a detector finds it to be
// whole, else kind (or PersonalKind).
func (w *walk) whole(s, kind string) Value {
	if s == Secret {
		return Value{kind: String, text: Secret}
	}
	if kind == "" {
		kind = PersonalKind
		if ms := w.find(w.m.o.Values, strings.TrimSpace(s)); len(ms) == 1 && ms[0].Start == 0 && ms[0].End == len(strings.TrimSpace(s)) && pii.ValidKind(ms[0].Kind) {
			kind = ms[0].Kind
			s = strings.TrimSpace(s)
		}
	}
	return Value{kind: String, text: w.token(kind, s)}
}

func (w *walk) token(kind, s string) string {
	id, err := w.m.o.Pseudonyms.ID(kind, s)
	if err != nil {
		w.kinds["redacted"] = true
		return Redacted
	}
	w.kinds[kind] = true
	return Token(kind, id)
}

// text masks free text: secrets, then the values detectors find.
func (w *walk) text(s string) string {
	s = cleanSource(s)
	if len(s) > pii.DetectLimit {
		s = pii.CutAt(s, pii.DetectLimit)
	}
	if secrets := w.find(w.m.o.Secrets, s); len(secrets) > 0 {
		w.kinds["secret"] = true
		s = replace(s, secrets, func(string, pii.Match) string { return Secret })
	}
	return outputSafe(w.pseudonymise(s, w.values(s)))
}

// pseudonymise replaces the matches of s, then masks again what the
// detectors find once those are replaced (a value glued to a neighbour is
// one only when the neighbour is gone): no detectable value is left.
func (w *walk) pseudonymise(s string, ms []pii.Match) string {
	out := w.replaceValues(s, ms)
	for round := 0; round < 3 && len(ms) > 0; round++ {
		ms = w.values(blankLen(out))
		if len(ms) == 0 {
			break
		}
		out = w.replaceValues(out, ms)
	}
	return out
}

// blankLen replaces every placeholder of s by spaces of its length, so
// that offsets hold and a placeholder's ID is never read as a value.
func blankLen(s string) string {
	if !strings.Contains(s, Open) {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], Open)
		if j < 0 {
			break
		}
		k := strings.Index(s[i+j:], Close)
		if k < 0 {
			break
		}
		for x := i + j; x < i+j+k+len(Close); x++ {
			b[x] = ' '
		}
		i += j + k + len(Close)
	}
	return string(b)
}

func (w *walk) replaceValues(s string, ms []pii.Match) string {
	return replace(s, ms, func(s string, m pii.Match) string {
		v := s[m.Start:m.End]
		if v == Secret || !pii.ValidKind(m.Kind) || m.Kind == pii.CutKind {
			w.kinds["redacted"] = true
			return Redacted
		}
		return w.token(m.Kind, v)
	})
}

// values finds the personal values of s: the human value rules (step 2)
// and the detectors (step 4); where they overlap, the rule names the kind.
func (w *walk) values(s string) []pii.Match {
	ms := w.find(w.m.o.Rules, s)
	for _, d := range w.find(w.m.o.Values, s) {
		if !overlapsAny(d, ms) {
			ms = append(ms, d)
		}
	}
	return mergeOverlaps(ms)
}

func overlapsAny(m pii.Match, ms []pii.Match) bool {
	for _, o := range ms {
		if m.Start < o.End && o.Start < m.End {
			return true
		}
	}
	return false
}

func (w *walk) find(f Finder, s string) []pii.Match {
	if f == nil || s == "" {
		return nil
	}
	ms := f.Find(s)
	// A match must never cut a placeholder: widen it to whole ones.
	for i := range ms {
		ms[i].Start, ms[i].End = widenToPlaceholders(s, ms[i].Start, ms[i].End)
	}
	return mergeOverlaps(ms)
}

// replace writes s with each match replaced by with(s, match).
func replace(s string, ms []pii.Match, with func(string, pii.Match) string) string {
	if len(ms) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		if m.Start < last || m.End > len(s) || m.Start >= m.End {
			continue
		}
		b.WriteString(s[last:m.Start])
		b.WriteString(with(s, m))
		last = m.End
	}
	b.WriteString(s[last:])
	return b.String()
}

func mergeOverlaps(ms []pii.Match) []pii.Match {
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	out := ms[:0]
	for _, m := range ms {
		if n := len(out); n > 0 && m.Start < out[n-1].End {
			out[n-1].End = max(out[n-1].End, m.End)
			continue
		}
		out = append(out, m)
	}
	return out
}

// widenToPlaceholders extends [a, b) to cover any placeholder it cuts.
func widenToPlaceholders(s string, a, b int) (int, int) {
	if i := strings.LastIndex(s[:a], Open); i >= 0 && !strings.Contains(s[i:a], Close) {
		a = i
	}
	if i := strings.Index(s[b:], Close); i >= 0 && !strings.Contains(s[b:b+i], Open) {
		b += i + len(Close)
	}
	return a, b
}

// wholeMasked reports whether a value is one placeholder.
func wholeMasked(s string) bool {
	return strings.HasPrefix(s, Open) && strings.HasSuffix(s, Close) && strings.Count(s, Open) == 1
}

func kindOf(k parse.Kind) Kind {
	switch k {
	case parse.KindBool:
		return Bool
	case parse.KindNumber:
		return Number
	case parse.KindNull:
		return Null
	}
	return String
}

// outputSafeScalar keeps a bool or number literal; strings are cleaned.
func outputSafeScalar(k parse.Kind, s string) string {
	if k == parse.KindBool || k == parse.KindNumber {
		if validLiteral(k, s) {
			return s
		}
	}
	return outputSafe(s)
}

func validLiteral(k parse.Kind, s string) bool {
	if k == parse.KindBool {
		return s == "true" || s == "false"
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune("0123456789+-.eE", rune(s[i])) {
			return false
		}
	}
	return true
}

// cleanSource prepares source text for masking: the placeholder brackets
// become U+FFFD (design §4.4 rule 6: only the masker writes them), and
// controls (but tab and newline) and invisible characters are dropped
// (§5.4), before detection, so that the detectors see exactly the text
// that will be shown.
func cleanSource(s string) string {
	dirty := false
	for _, r := range s {
		if unsafeRune(r) || r == '\u27e6' || r == '\u27e7' {
			dirty = true
			break
		}
	}
	if !dirty {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\u27e6' || r == '\u27e7':
			return utf8.RuneError
		case unsafeRune(r):
			return -1
		}
		return r
	}, s)
}

// outputSafe replaces control characters (but tab and newline), format
// characters and other invisible ones by U+FFFD: log content cannot drive
// a terminal or hide text from a reader (design §5.4).
func outputSafe(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return utf8.RuneError
		}
		return r
	}, s)
}

func unsafeRune(r rune) bool {
	if r == '\t' || r == '\n' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

func join(p, name string) string {
	if p == "" {
		return name
	}
	return p + "." + name
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
