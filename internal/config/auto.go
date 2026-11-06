package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// The auto mode of a profile (#126): for each action that becomes a
// ticket, what `lox run` does with it while it runs in auto mode. Manual
// mode asks every ticket whatever the profile says; deny holds in both.
//
//	[profiles.local]
//	auto = "full-auto"
//
//	[profiles.prod.auto]
//	read   = "auto"
//	unmask = "deny"
//
// The lock enforces its side: an action whose rule is deny is refused
// before any ticket; the ticket of an action whose rule is ask is signed
// never-auto (ticket.Flags.NeverAuto), so that the lock refuses an auto
// rule's approval of it (ticket.ErrAuto); auto leaves the ticket to lox
// run's auto mode. The rules are part of the approved policy: moving one
// toward auto is a loosening the human reviews at start or at :review,
// with the typed profile name on production.
//
// Free calls (search, count, patterns, context, trace, tail, a free
// lookup) take no ticket: their rules do not apply, except that lookup =
// "deny" refuses every lookup.

// AutoValue is what auto mode does with one action.
type AutoValue string

// The values of an action, from the strictest.
const (
	// AutoDeny refuses the action, even when a human would approve it.
	AutoDeny AutoValue = "deny"
	// AutoAsk asks the human every time.
	AutoAsk AutoValue = "ask"
	// AutoAuto leaves the ticket to lox run's auto mode.
	AutoAuto AutoValue = "auto"
)

// rank orders the values from the strictest: a higher rank loosens.
func (v AutoValue) rank() int {
	switch v {
	case AutoDeny:
		return 0
	case AutoAsk:
		return 1
	case AutoAuto:
		return 2
	}
	return -1
}

// ParseAutoValue parses "auto", "ask" or "deny". Its error never quotes s.
func ParseAutoValue(s string) (AutoValue, error) {
	if v := AutoValue(s); v.rank() >= 0 {
		return v, nil
	}
	return "", errors.New("want auto, ask or deny")
}

// AutoAction is what a rule applies to.
type AutoAction string

// The actions of an auto rule.
const (
	// ActionRead is an approved scan (locklog_scan): the masked records
	// of a whole plan, one ticket for all its continuations (risk read).
	ActionRead AutoAction = "read"
	// ActionUnmask is an unmask (locklog_unmask): clear values to the
	// agent (risk read-pii).
	ActionUnmask AutoAction = "unmask"
	// ActionLookup is a lookup: with lookup = "approved", its ticket
	// (risk read-pii); deny refuses free lookups too.
	ActionLookup AutoAction = "lookup"
)

// AutoActions lists the actions in the order they are shown.
var AutoActions = []AutoAction{ActionRead, ActionUnmask, ActionLookup}

// The presets: PresetFullAuto sets every action to auto, PresetDefault is
// DefaultAutoRules.
const (
	PresetFullAuto = "full-auto"
	PresetDefault  = "default"
)

// AutoRules is the auto mode of a profile, one value per action. The
// zero value of a field is its default (DefaultAutoRules): a profile
// stores only what differs from it, so that a policy approved before auto
// rules existed keeps its fingerprint.
type AutoRules struct {
	Read   AutoValue `json:"read,omitempty"`
	Unmask AutoValue `json:"unmask,omitempty"`
	Lookup AutoValue `json:"lookup,omitempty"`
}

// DefaultAutoRules is the auto mode of a profile that sets none: every
// ticket asked, as before auto rules existed (an approved scan covers a
// whole plan, an unmask and an approved lookup are read-pii). Making any
// of them auto is the human's explicit, reviewed loosening.
var DefaultAutoRules = AutoRules{Read: AutoAsk, Unmask: AutoAsk, Lookup: AutoAsk}

// FullAutoRules is the full-auto preset: every action auto.
var FullAutoRules = AutoRules{Read: AutoAuto, Unmask: AutoAuto, Lookup: AutoAuto}

func (r *AutoRules) field(a AutoAction) *AutoValue {
	switch a {
	case ActionRead:
		return &r.Read
	case ActionUnmask:
		return &r.Unmask
	case ActionLookup:
		return &r.Lookup
	}
	return nil
}

// Get is the value of action a, its default when r does not set it; an
// unknown action, or a value that is not one, is deny (fail closed).
func (r AutoRules) Get(a AutoAction) AutoValue {
	if f := r.field(a); f != nil && *f != "" {
		if f.rank() < 0 {
			return AutoDeny
		}
		return *f
	}
	if f := DefaultAutoRules.field(a); f != nil {
		return *f
	}
	return AutoDeny
}

// Effective is r with every action set (defaults filled in).
func (r AutoRules) Effective() AutoRules {
	var out AutoRules
	for _, a := range AutoActions {
		*out.field(a) = r.Get(a)
	}
	return out
}

// sparse is r without its defaults, nil when every action is its
// default: what a Profile stores.
func (r AutoRules) sparse() *AutoRules {
	var out AutoRules
	set := false
	for _, a := range AutoActions {
		if v := r.Get(a); v != *DefaultAutoRules.field(a) {
			*out.field(a), set = v, true
		}
	}
	if !set {
		return nil
	}
	return &out
}

// Preset names the preset r is, "" for none.
func (r AutoRules) Preset() string {
	switch r.Effective() {
	case FullAutoRules:
		return PresetFullAuto
	case DefaultAutoRules:
		return PresetDefault
	}
	return ""
}

// Map is r's effective rules by action name: what `locklog profile rules
// --json` prints for lox run.
func (r AutoRules) Map() map[string]AutoValue {
	out := make(map[string]AutoValue, len(AutoActions))
	for _, a := range AutoActions {
		out[string(a)] = r.Get(a)
	}
	return out
}

// RuleText is the rule of action a as the audit records it:
// "auto.read = ask".
func (r AutoRules) RuleText(a AutoAction) string {
	return fmt.Sprintf("auto.%s = %s", a, r.Get(a))
}

// String is r in one line: "read ask · unmask ask · lookup ask", with the
// preset it is when it is one.
func (r AutoRules) String() string {
	parts := make([]string, 0, len(AutoActions))
	for _, a := range AutoActions {
		parts = append(parts, string(a)+" "+string(r.Get(a)))
	}
	s := strings.Join(parts, " · ")
	if p := r.Preset(); p != "" {
		s += " (" + p + ")"
	}
	return s
}

// AutoRules is the effective auto mode of p.
func (p Profile) AutoRules() AutoRules {
	if p.Auto == nil {
		return DefaultAutoRules
	}
	return p.Auto.Effective()
}

// rawAuto is the auto key of a profile as written: a preset name
// (`auto = "full-auto"`), or a table of actions with an optional preset
// that the actions override.
type rawAuto struct {
	Preset string
	Read   string
	Unmask string
	Lookup string
	// bad is what UnmarshalTOML refused, reported by rules with the
	// profile's name.
	bad error
}

func (r *rawAuto) fields() map[string]*string {
	return map[string]*string{"preset": &r.Preset, "read": &r.Read, "unmask": &r.Unmask, "lookup": &r.Lookup}
}

// UnmarshalTOML reads `auto = "<preset>"` or an [auto] table of strings;
// an unknown key is refused. Errors name the key, never quote a value.
func (r *rawAuto) UnmarshalTOML(v any) error {
	r.bad = r.decode(v)
	return nil
}

func (r *rawAuto) decode(v any) error {
	switch t := v.(type) {
	case string:
		*r = rawAuto{Preset: t}
		if t == "" {
			return errors.New("auto: unknown preset (empty)")
		}
		return nil
	case map[string]any:
		*r = rawAuto{}
		f := r.fields()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dst, ok := f[k]
			if !ok {
				return fmt.Errorf("auto: unknown key %s (want preset, %s)", safeKey(k), actionNames())
			}
			s, isStr := t[k].(string)
			if !isStr || s == "" {
				if k == "preset" {
					return fmt.Errorf("auto.preset: want %q or %q", PresetFullAuto, PresetDefault)
				}
				return fmt.Errorf("auto.%s: want auto, ask or deny", k)
			}
			*dst = s
		}
		return nil
	}
	return fmt.Errorf("auto: want a preset (%q) or a table of %s", PresetFullAuto, actionNames())
}

// rules checks r and returns the rules it sets: the preset (the defaults
// without one), then each action set.
func (r rawAuto) rules() (AutoRules, error) {
	if r.bad != nil {
		return AutoRules{}, r.bad
	}
	out := DefaultAutoRules
	switch r.Preset {
	case "":
	case PresetFullAuto:
		out = FullAutoRules
	case PresetDefault:
	default:
		return AutoRules{}, fmt.Errorf("auto: unknown preset (want %q or %q)", PresetFullAuto, PresetDefault)
	}
	for _, a := range AutoActions {
		s := *r.fields()[string(a)]
		if s == "" {
			continue
		}
		v, err := ParseAutoValue(s)
		if err != nil {
			return AutoRules{}, fmt.Errorf("auto.%s: %v", a, err)
		}
		*out.field(a) = v
	}
	return out, nil
}

func actionNames() string {
	n := make([]string, len(AutoActions))
	for i, a := range AutoActions {
		n[i] = string(a)
	}
	return strings.Join(n, ", ")
}

// safeKey is a key fit for an error message: quoted, printable ASCII,
// cut short.
func safeKey(k string) string {
	var b strings.Builder
	for _, c := range k {
		if b.Len() >= 32 {
			b.WriteString("…")
			break
		}
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteRune(c)
	}
	return fmt.Sprintf("%q", b.String())
}

// autoDiff lists the changes of the auto rules: a value that moves toward
// auto (deny → ask → auto) loosens.
func autoDiff(a, c AutoRules) []kconfig.Change {
	var out []kconfig.Change
	for _, act := range AutoActions {
		o, n := a.Get(act), c.Get(act)
		if o != n {
			out = append(out, kconfig.Change{Field: "auto." + string(act), Old: string(o), New: string(n), Loosens: n.rank() > o.rank()})
		}
	}
	return out
}
