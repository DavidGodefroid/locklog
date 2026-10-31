package mask

import (
	"fmt"
	"math/big"
	"regexp"
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

// SecretDetectorName is lockkit's secret detector: step 1, always on,
// never a value detector a profile names.
const SecretDetectorName = "secret"

// SecretDetectors finds secrets with lockkit's secret detector
// (credentials, token shapes, private keys, URL userinfo), in the text and
// in its detection views. Every masker runs it in step 1, whatever
// Options.Secrets adds.
func SecretDetectors() Detectors {
	ds, err := pii.Detectors([]string{SecretDetectorName})
	if err != nil || len(ds) != 1 {
		panic(fmt.Sprintf("mask: lockkit has no secret detector: %v", err))
	}
	return Detectors(ds)
}

// DefaultValueDetectors names the value detectors of a profile that sets
// none, and of a masker given no Values: lockkit's default set
// (pii.AllDetectors) and ip (public addresses; private and loopback ones
// are infrastructure, never found).
func DefaultValueDetectors() []string {
	ds := pii.AllDetectors()
	out := make([]string, 0, len(ds)+1)
	for _, d := range ds {
		out = append(out, d.Name())
	}
	return append(out, "ip")
}

// ValueDetectors returns the value detectors a profile names (step 4).
// The secret detector is refused: secrets are step 1, always on.
func ValueDetectors(names []string) (Detectors, error) {
	if slices.Contains(names, SecretDetectorName) {
		return nil, fmt.Errorf("mask: %q is not a value detector (secret detection is always on)", SecretDetectorName)
	}
	ds, err := pii.Detectors(names)
	if err != nil {
		return nil, fmt.Errorf("mask: %w", err)
	}
	return Detectors(ds), nil
}

// Options configure a Masker.
type Options struct {
	// Structured is StructuredRedactUnknown (default) or StructuredDetect.
	Structured string
	// Values are the value detectors of step 4 (personal data); left
	// nil, DefaultValueDetectors.
	Values Finder
	// Secrets finds secret values (step 1); SecretName reports a field
	// name whose value is a secret whole. Both add to lockkit's secret
	// detector (SecretDetectors) and pii.LooksSecret, which every masker
	// runs: they can widen step 1, never replace it.
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

	// withoutLockkitSecrets drops lockkit's secret step: for the tests
	// that prove the leak harness sees an unmasked secret, never settable
	// outside this package.
	withoutLockkitSecrets bool
}

// finders runs several finders; find merges their overlapping matches.
type finders []Finder

func (fs finders) Find(s string) []pii.Match {
	var out []pii.Match
	for _, f := range fs {
		if f != nil {
			out = append(out, f.Find(s)...)
		}
	}
	return out
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
	if o.Values == nil {
		ds, err := ValueDetectors(DefaultValueDetectors())
		if err != nil {
			return nil, err
		}
		o.Values = ds
	}
	if !o.withoutLockkitSecrets {
		if o.Secrets == nil {
			o.Secrets = SecretDetectors()
		} else {
			o.Secrets = finders{SecretDetectors(), o.Secrets}
		}
		if extra := o.SecretName; extra == nil {
			o.SecretName = pii.LooksSecret
		} else {
			o.SecretName = func(n string) bool { return pii.LooksSecret(n) || extra(n) }
		}
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
			rec = Record{ok: true, failed: true, ts: ev.Time, hasTime: ev.HasTime || ev.Inherited, offset: ev.Offset, length: ev.Length}
		}
	}()
	w := &walk{m: m, source: source, kinds: map[string]bool{}}
	rec = Record{ok: true, ts: ev.Time, hasTime: ev.HasTime || ev.Inherited, format: ev.Format, offset: ev.Offset, length: ev.Length}
	rec.fields = w.members(ev.Fields, "", "", false, inherited{})
	// Attrs come from the source's own frame (journald, docker), never
	// from the line: only allowlisted ones reach here (LL-11 `attrs`,
	// default none), so they skip the personal-name and redact-unknown
	// steps; secrets and detectors still run.
	rec.attrs = w.members(ev.Attrs, "", "", true, inherited{})
	if ev.Message != "" || ev.Fields == nil {
		w.scoped(func() bool {
			rec.msg = w.message(ev.Message, ev.MessageKey)
			return rec.msg == Redacted
		})
	}
	rec.kinds = sortedKeys(w.kinds)
	rec.secretPaths = w.secretPaths
	return rec
}

// Text masks a string read from the logs that leaves the console other
// than as a record (names in `sources`, bucket keys, errors, audit
// causes): secrets, then personal values as pseudonyms. Never pass it
// text the agent wrote: the pseudonym of a guessed value would answer
// whether that value is in the logs (design §4.4); use RedactText.
func (m *Masker) Text(s string) (out string) {
	defer func() {
		if recover() != nil {
			out = Redacted // a failure withholds it all
		}
	}()
	w := &walk{m: m, kinds: map[string]bool{}}
	return w.text(s)
}

// RedactText masks text the agent wrote before it is echoed back (refusal
// echoes): secrets as ⟦secret⟧, personal values as ⟦redacted⟧, never as a
// pseudonym (no oracle, design §4.4).
func (m *Masker) RedactText(s string) (out string) {
	defer func() {
		if recover() != nil {
			out = Redacted // a failure withholds it all
		}
	}()
	w := &walk{m: m, kinds: map[string]bool{}}
	s = cleanSource(s)
	if len(s) > pii.DetectLimit {
		s = pii.CutAt(s, pii.DetectLimit)
	}
	for round := 0; ; round++ {
		s, _ = w.redactSecrets(s)
		ms := w.values(blankLen(s))
		if len(ms) == 0 {
			break
		}
		if round == 4 {
			return Redacted // still glued values: withhold it all
		}
		s = replace(s, ms, func(string, pii.Match) string { return Redacted })
	}
	return outputSafe(s)
}

// walk masks one record.
type walk struct {
	m           *Masker
	source      string
	kinds       map[string]bool
	secretPaths []string
	lateSecret  bool // pseudonymise found a secret (see value)
}

// inherited is what a container's name and rules impose on everything
// under it: a rule or a name on "user" covers "user.first".
type inherited struct {
	pseudo    *Rule  // a human pseudonym rule on an ancestor
	personal  bool   // an ancestor's name looks personal or quasi-identifying
	agentMode string // an agent rule on an ancestor ("" for none)
}

func (w *walk) members(ms []parse.Member, clearPath, shownPath string, trusted bool, inh inherited) []Field {
	if ms == nil {
		return nil
	}
	out := make([]Field, 0, len(ms))
	for _, mem := range ms {
		name, shownName := w.key(mem.Key)
		cp, sp := join(clearPath, name), join(shownPath, shownName)
		out = append(out, Field{name: shownName, value: w.value(mem.Value, name, cp, sp, trusted, inh)})
	}
	return out
}

// key masks a field name: a name holding a secret or a personal value is
// shown as ⟦key:ID⟧, kept (clear) in the console's name book only. It
// returns the clear name (after U+FFFD replacement) and the shown name.
func (w *walk) key(k string) (string, string) {
	k = cleanSource(k)
	step1, hadSecret := w.redactSecrets(k)
	values := w.values(k)
	if !hadSecret && len(values) == 0 {
		w.m.noteClear(w.source, k)
		return k, outputSafe(k)
	}
	id, err := w.m.o.Pseudonyms.ID(KeyKind, step1)
	if err != nil {
		w.kinds["redacted"] = true
		return k, Redacted
	}
	w.kinds[KeyKind] = true
	w.m.noteMasked(id, k)
	return k, Token(KeyKind, id)
}

func (w *walk) value(v parse.Value, name, clearPath, shownPath string, trusted bool, inh inherited) Value {
	trusted = trusted || w.m.trusted[clearPath]
	if v.Kind == parse.KindObject || v.Kind == parse.KindArray {
		// A container's name and rules decide for all it holds (design
		// §4.2): secrets first and whole, then a human redact rule; a
		// pseudonym rule, a personal name or an agent rule is handed down
		// to every value under it.
		if w.m.o.SecretName != nil && w.m.o.SecretName(name) {
			w.kinds["secret"] = true
			w.secretPaths = append(w.secretPaths, shownPath)
			return Value{kind: String, text: Secret}
		}
		if rule, ok := w.m.o.Rules.human(w.source, clearPath); ok && rule.Mode != ModeAllow {
			if rule.Mode == ModeRedact {
				w.kinds["redacted"] = true
				return Value{kind: String, text: Redacted}
			}
			inh.pseudo = &rule
		}
		if !trusted && (pii.LooksPersonal(name) || pii.LooksQuasi(name)) {
			inh.personal = true
		}
		if mode, ok := w.m.o.Rules.agent(w.source, clearPath); ok && (inh.agentMode == "" || mode == ModeRedact) {
			inh.agentMode = mode
		}
		if v.Kind == parse.KindObject {
			return Value{kind: Object, members: w.members(v.Members, clearPath, shownPath, trusted, inh)}
		}
		items := make([]Value, len(v.Items))
		for i, it := range v.Items {
			items[i] = w.value(it, name, clearPath, shownPath, trusted, inh)
		}
		return Value{kind: Array, items: items}
	}
	switch v.Kind {
	case parse.KindNull:
		rule, ok := w.m.o.Rules.human(w.source, clearPath)
		am, aok := w.m.o.Rules.agent(w.source, clearPath)
		if ok && rule.Mode == ModeRedact || aok && am == ModeRedact || inh.agentMode == ModeRedact {
			w.kinds["redacted"] = true
			return Value{kind: String, text: Redacted}
		}
		if !trusted && w.m.o.Structured == StructuredRedactUnknown && !w.m.o.Rules.allowed(w.source, clearPath) {
			w.kinds["redacted"] = true
			return Value{kind: String, text: Redacted}
		}
		return Value{kind: Null}
	}
	return w.leaf(v, name, clearPath, shownPath, trusted, inh)
}

// leaf masks a scalar in the fixed order (design §4.2). A secret is
// recorded (Kinds, HadSecret) only when the value is not withheld: a
// redaction tells nothing of what it held.
func (w *walk) leaf(v parse.Value, name, clearPath, shownPath string, trusted bool, inh inherited) Value {
	hadSecret := false
	var out Value
	w.scoped(func() bool {
		out = w.leafMasked(v, name, clearPath, trusted, inh, &hadSecret)
		return out.text == Redacted
	})
	if hadSecret && out.text != Redacted {
		w.kinds["secret"] = true
		w.secretPaths = append(w.secretPaths, shownPath)
	}
	return out
}

// scoped runs f with a kinds set of its own, merged into the record's
// only when f's value was not withheld (f returns true): a redaction
// tells nothing of what it held.
func (w *walk) scoped(f func() (withheld bool)) {
	outer := w.kinds
	w.kinds = map[string]bool{}
	withheld := f()
	inner := w.kinds
	w.kinds = outer
	if withheld {
		outer["redacted"] = true
		return
	}
	for k := range inner {
		outer[k] = true
	}
}

func (w *walk) leafMasked(v parse.Value, name, clearPath string, trusted bool, inh inherited, hadSecret *bool) Value {
	s := cleanSource(v.Str)
	if len(s) > pii.DetectLimit {
		s = pii.CutAt(s, pii.DetectLimit)
	}
	// (1) Secrets, first and final.
	if w.m.o.SecretName != nil && w.m.o.SecretName(name) {
		*hadSecret = true
		return Value{kind: String, text: Secret}
	}
	s, stepSecret := w.redactSecrets(s)
	if stepSecret {
		*hadSecret = true
	}
	w.lateSecret = false
	defer func() {
		if w.lateSecret {
			*hadSecret = true // a secret step 4's replacements uncovered
		}
	}()
	// Steps 2-5 work on s, the string step 1 produced.
	rule, hasRule := w.m.o.Rules.human(w.source, clearPath)
	// The strongest of the field's own rule and an inherited one wins
	// (redact, then pseudonym, then allow).
	if inh.pseudo != nil && (!hasRule || rule.Mode == ModeAllow) {
		rule, hasRule = *inh.pseudo, true
	}
	var out Value
	switch {
	case hasRule && rule.Mode == ModeAllow:
		out = w.detected(v.Kind, s, stepSecret)
	case hasRule && rule.Mode == ModeRedact:
		w.kinds["redacted"] = true
		return Value{kind: String, text: Redacted}
	case hasRule && rule.Mode == ModePseudonym:
		out = w.whole(s, rule.Kind)
	case !trusted && (inh.personal || pii.LooksPersonal(name) || pii.LooksQuasi(name)):
		out = w.whole(s, "")
	case !trusted && w.m.o.Structured == StructuredRedactUnknown && !w.m.o.Rules.allowed(w.source, clearPath):
		// Withheld before detection: Kinds must not tell what it held.
		w.kinds["redacted"] = true
		return Value{kind: String, text: Redacted}
	default:
		out = w.detected(v.Kind, s, stepSecret)
	}
	// An agent rule only tightens: redact always wins; a pseudonym masks a
	// value nothing masked whole.
	mode, ok := w.m.o.Rules.agent(w.source, clearPath)
	if inh.agentMode != "" && (!ok || inh.agentMode == ModeRedact) {
		mode, ok = inh.agentMode, true
	}
	switch {
	case ok && mode == ModeRedact:
		w.kinds["redacted"] = true
		return Value{kind: String, text: Redacted}
	case ok && !wholeMasked(out.text):
		return w.whole(s, "")
	}
	return out
}

// message masks the record's message, lifted from key (empty for a plain
// line): the key's secret name, human rule and agent rule decide first, as
// for a field; otherwise it is free text.
func (w *walk) message(s, key string) string {
	if key == "" {
		return w.text(s)
	}
	w.m.noteClear(w.source, key)
	if w.m.o.SecretName != nil && w.m.o.SecretName(key) {
		w.kinds["secret"] = true
		w.secretPaths = append(w.secretPaths, key)
		return Secret
	}
	mode, kind := "", ""
	if rule, ok := w.m.o.Rules.human(w.source, key); ok && rule.Mode != ModeAllow {
		mode, kind = rule.Mode, rule.Kind
	}
	if am, ok := w.m.o.Rules.agent(w.source, key); ok && (mode == "" || am == ModeRedact) {
		mode, kind = am, ""
	}
	switch mode {
	case ModeRedact:
		w.kinds["redacted"] = true
		return Redacted
	case ModePseudonym:
		t := cleanSource(s)
		if len(t) > pii.DetectLimit {
			t = pii.CutAt(t, pii.DetectLimit)
		}
		if r, found := w.redactSecrets(t); found {
			w.kinds["secret"] = true
			w.secretPaths = append(w.secretPaths, key)
			t = r
		}
		return w.whole(t, kind).text
	}
	return w.text(s)
}

// detected masks the personal values the detectors find in s (step 4).
func (w *walk) detected(k parse.Kind, s string, hadSecret bool) Value {
	if k == parse.KindNumber {
		// A number in exponent or decimal form ("4.111111111111111E15",
		// Jackson's doubles) is read as the integer it is.
		if it, ok := integralText(s); ok && it != s {
			if ms := w.values(it); len(ms) > 0 {
				return Value{kind: String, text: outputSafe(w.pseudonymise(it, ms))}
			}
		}
	}
	ms := w.values(s)
	if len(ms) == 0 && !hadSecret {
		if (k == parse.KindBool || k == parse.KindNumber) && !validLiteral(k, s) {
			return Value{kind: String, text: outputSafe(s)} // never written raw
		}
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
		if ms := w.find(w.m.o.Values, strings.TrimSpace(s)); len(ms) == 1 && ms[0].Start == 0 && ms[0].End == len(strings.TrimSpace(s)) && pii.ValidKind(ms[0].Kind) && ms[0].Kind != pii.CutKind {
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
	if r, found := w.redactSecrets(s); found {
		w.kinds["secret"] = true
		s = r
	}
	return outputSafe(w.pseudonymise(s, w.values(s)))
}

// pseudonymise replaces the matches of s, then masks again what the
// secret finders and the detectors find once those are replaced (a value
// glued to a neighbour is one only when the neighbour is gone; a secret
// name before a pseudonym may make the rest read as a secret): no
// detectable value or secret is left. A secret found so sets lateSecret.
func (w *walk) pseudonymise(s string, ms []pii.Match) string {
	out := w.replaceValues(s, ms)
	for round := 0; len(ms) > 0; round++ {
		if r, found := w.redactSecrets(out); found {
			w.kinds["secret"] = true
			w.lateSecret = true
			out = r
		}
		ms = w.values(blankLen(out))
		if len(ms) == 0 {
			break
		}
		if round == 3 {
			// Still glued values after the last round: withhold it all.
			w.kinds["redacted"] = true
			return Redacted
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

// redactSecrets is step 1: every secret of s as Secret, until the
// secret finders find nothing more in the result with its placeholders
// blanked (a secret name before a replaced value may make the rest of the
// text read as a value: "pass:⟦secret⟧\":\""); a match of placeholders and
// blanks alone is what was already replaced. Past four rounds, the whole
// string is withheld.
func (w *walk) redactSecrets(s string) (string, bool) {
	found := false
	for round := 0; ; round++ {
		plain := blankLen(s) // the same length as s
		var ms []pii.Match
		for _, m := range w.find(w.m.o.Secrets, plain) {
			if !blankOnly(plain, m) {
				m.Start, m.End = widenToPlaceholders(s, m.Start, m.End)
				ms = append(ms, m)
			}
		}
		if len(ms) == 0 {
			return s, found
		}
		found = true
		if round == 4 {
			return Secret, true
		}
		s = replace(s, mergeOverlaps(ms), func(string, pii.Match) string { return Secret })
	}
}

// blankOnly reports a match of plain that covers blanks alone.
func blankOnly(plain string, m pii.Match) bool {
	for i := m.Start; i < m.End; i++ {
		if c := plain[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
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
	return jsonNumber.MatchString(s)
}

// integralText is the integer a number literal denotes exactly, written
// in full, when it has one below 1e20.
func integralText(s string) (string, bool) {
	if !strings.ContainsAny(s, ".eE") || len(s) > 64 {
		return "", false
	}
	f, _, err := big.ParseFloat(s, 10, 256, big.ToNearestEven)
	if err != nil || !f.IsInt() || new(big.Float).Abs(f).Cmp(big.NewFloat(1e20)) >= 0 {
		return "", false
	}
	i, _ := f.Int(nil)
	return i.String(), true
}

// jsonNumber is a JSON number literal (RFC 8259 §6).
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// cleanSource prepares source text for masking: the placeholder brackets
// become U+FFFD (design §4.4 rule 6: only the masker writes them), and
// controls (but tab and newline) and invisible characters are dropped
// (§5.4), as are invalid bytes and U+FFFD, before detection, so that the detectors see exactly the text
// that will be shown.
func cleanSource(s string) string {
	dirty := !utf8.ValidString(s)
	for _, r := range s {
		if dirty || unsafeRune(r) || r == '\u27e6' || r == '\u27e7' || r == utf8.RuneError {
			dirty = true
			break
		}
	}
	if !dirty {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError:
			// An invalid byte, or the U+FFFD a parser put for one: dropped,
			// so the detectors see the value it splits
			// ("andr\xe9@example.com") as it will be read.
		case r == '\u27e6' || r == '\u27e7':
			b.WriteRune(utf8.RuneError)
		case unsafeRune(r):
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
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
