package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/managed"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// ManagedTool is locklog's section of the company's managed file
// ([locklog.bounds], [locklog.defaults], [locklog.profiles.<name>]).
const ManagedTool = "locklog"

// Managed is locklog's part of the company's managed file (lockkit
// managed): its defaults, its profiles and its bounds. A nil *Managed is
// no managed file.
type Managed struct {
	File *managed.File
	// Defaults is [locklog.defaults] as the file holds it (nil: none):
	// the keys a profile leaves unset take it.
	Defaults map[string]any
	// Profiles are [locklog.profiles.<name>], built with the defaults.
	Profiles map[string]Profile
	// Bounds are [locklog.bounds] and the [family] rules locklog
	// enforces (nil: none).
	Bounds *Bounds
}

// LoadManaged reads the machine's managed file: nil and no error when
// there is none. A file lockkit refuses (badly owned, invalid, badly
// signed) or a locklog section that is invalid or beyond its own bounds
// is an error: the caller refuses to start.
func LoadManaged() (*Managed, error) {
	f, err := managed.Load(context.Background())
	if err != nil || f == nil {
		return nil, err
	}
	return ParseManaged(f)
}

// ParseManaged reads locklog's part of f. A managed default or a managed
// profile beyond the bounds is an error.
func ParseManaged(f *managed.File) (*Managed, error) {
	if f == nil {
		return nil, nil
	}
	m := &Managed{File: f, Profiles: map[string]Profile{}}
	where := func(kind string, err error) error {
		return fmt.Errorf("managed: %s: [%s.%s]: %w", f.Path, ManagedTool, kind, err)
	}
	b, err := parseBounds(f)
	if err != nil {
		return nil, where(managed.KindBounds, err)
	}
	m.Bounds = b
	if ok, err := f.Decode(&rawProfile{}, ManagedTool, managed.KindDefaults); err != nil {
		return nil, err
	} else if ok {
		var t rawTable
		if _, err := f.Decode(&t, ManagedTool, managed.KindDefaults); err != nil {
			return nil, err
		}
		if _, ok := t.v["sources"]; ok {
			return nil, where(managed.KindDefaults, errors.New("sources: a default holds no source (put it in a managed profile)"))
		}
		m.Defaults = t.v
		if err := m.checkDefaults(); err != nil {
			return nil, where(managed.KindDefaults, err)
		}
	}
	for _, name := range f.Profiles(ManagedTool) {
		key := managed.KindProfiles + "." + name
		if _, err := f.Decode(&rawProfile{}, ManagedTool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		var t rawTable
		if _, err := f.Decode(&t, ManagedTool, managed.KindProfiles, name); err != nil {
			return nil, err
		}
		p, err := profileFromTable(name, t.v, m.Defaults)
		if err != nil {
			return nil, where(key, err)
		}
		p.Managed = true
		m.Bounds.require(&p)
		if lines, err := m.Bounds.Violations(m.Bounds.policyOf(p)); err != nil {
			return nil, where(key, err)
		} else if len(lines) > 0 {
			return nil, where(key, fmt.Errorf("the managed profile is beyond the managed bounds: %s", lines[0]))
		}
		m.Profiles[name] = p
	}
	return m, nil
}

// rawTable is a table as the file holds it (the keys it sets). Its
// UnmarshalTOML takes the table whole: decoded into a map[string]any, the
// keys of a nested table would read as unknown to File.Decode's strict
// check.
type rawTable struct{ v map[string]any }

// UnmarshalTOML implements toml.Unmarshaler.
func (r *rawTable) UnmarshalTOML(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("want a table")
	}
	r.v = m
	return nil
}

// defaultsProbe is the source a profile made of the defaults alone is
// checked with: a profile needs one, and the defaults hold none.
var defaultsProbe = map[string]any{"managed-defaults": map[string]any{"kind": KindFile, "paths": []any{"/var/log/managed-defaults.log"}}}

// checkDefaults refuses a managed default beyond the bounds: the
// defaults make a profile of their own, and a violation of a key they set
// is an error.
func (m *Managed) checkDefaults() error {
	t := maps.Clone(m.Defaults)
	t["sources"] = defaultsProbe
	p, err := profileFromTable("managed-defaults", t, nil)
	if err != nil {
		return err
	}
	m.Bounds.require(&p)
	pol := m.Bounds.policyOf(p)
	set := flatKeys(m.Defaults, "")
	for _, v := range managed.Check(pol, m.Bounds.Ceiling(pol)) {
		for _, k := range set {
			if v.Field == k || strings.HasPrefix(v.Field, k+".") {
				return fmt.Errorf("the managed default is beyond the managed bounds: %s", strings.Replace(v.String(), "(profile managed-defaults: ", "(defaults: ", 1))
			}
		}
	}
	return nil
}

// flatKeys lists the keys of t, those of its limits and auto tables as
// "limits.max_records", "limits.local.range", "auto.read".
func flatKeys(t map[string]any, prefix string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(t)) {
		out = append(out, prefix+k)
		if sub, ok := t[k].(map[string]any); ok {
			out = append(out, flatKeys(sub, prefix+k+".")...)
		}
	}
	return out
}

// DescribeDefaults is [locklog.defaults] as lines for `locklog managed
// show` ("locklog.defaults.limits.max_records = 50").
func (m *Managed) DescribeDefaults() []string {
	if m == nil {
		return nil
	}
	var out []string
	var walk func(t map[string]any, prefix string)
	walk = func(t map[string]any, prefix string) {
		for _, k := range slices.Sorted(maps.Keys(t)) {
			if sub, ok := t[k].(map[string]any); ok {
				walk(sub, prefix+k+".")
				continue
			}
			var buf bytes.Buffer
			if err := toml.NewEncoder(&buf).Encode(map[string]any{"v": t[k]}); err != nil {
				continue
			}
			v := strings.TrimSpace(strings.TrimPrefix(buf.String(), "v = "))
			v = strings.Join(strings.Fields(v), " ")
			out = append(out, ManagedTool+"."+managed.KindDefaults+"."+prefix+k+" = "+v)
		}
	}
	walk(m.Defaults, "")
	return out
}

// defaults is the managed defaults (nil for a nil m).
func (m *Managed) defaults() map[string]any {
	if m == nil {
		return nil
	}
	return m.Defaults
}

// profiles is the managed profiles (nil for a nil m).
func (m *Managed) profiles() map[string]Profile {
	if m == nil {
		return nil
	}
	return m.Profiles
}

// BoundsOf is m's bounds, nil for a nil m.
func (m *Managed) BoundsOf() *Bounds {
	if m == nil {
		return nil
	}
	return m.Bounds
}

// merge merges the profiles by precedence (managed.MergeProfiles) and
// adds the detectors the managed bounds require to every one.
func (m *Managed) merge(project, user map[string]Profile) (map[string]Profile, error) {
	out, err := managed.MergeProfiles(m.profiles(), project, user)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if out == nil {
		out = map[string]Profile{}
	}
	for n, p := range out {
		m.BoundsOf().require(&p)
		out[n] = p
	}
	return out, nil
}

// withDefaults is the profile table t with the keys it does not set taken
// from the defaults d; the limits table (and its local and remote tables)
// is merged key by key, the auto key is taken whole.
func withDefaults(t, d map[string]any) map[string]any {
	out := maps.Clone(t)
	if out == nil {
		out = map[string]any{}
	}
	for k, v := range d {
		cur, ok := out[k]
		if !ok {
			out[k] = v
			continue
		}
		cl, ok1 := cur.(map[string]any)
		dl, ok2 := v.(map[string]any)
		if (k == "limits" || k == "local" || k == "remote") && ok1 && ok2 {
			out[k] = withDefaults(cl, dl)
		}
	}
	return out
}

// profileFromTable builds the profile name from its table t and the
// defaults d, through the same checks as a profile of a config file.
func profileFromTable(name string, t, d map[string]any) (Profile, error) {
	t = withDefaults(t, d)
	var r rawProfile
	if err := decodeTable(t, &r); err != nil {
		return Profile{}, fmt.Errorf("profile %q: %w", name, err)
	}
	_, detectorsSet := t["detectors"]
	return buildProfile(name, r, detectorsSet)
}

// decodeTable decodes the table m into into, strictly.
func decodeTable(m map[string]any, into any) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	md, err := toml.NewDecoder(&buf).Decode(into)
	if err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "toml: "))
	}
	if und := md.Undecoded(); len(und) > 0 {
		return fmt.Errorf("unknown key %q", und[0].String())
	}
	return nil
}

// Bounds are [locklog.bounds] and the [family] rules locklog enforces:
// the loosest policy the company allows. A nil *Bounds bounds nothing.
type Bounds struct {
	// desc are the bounds as `locklog managed show` prints them.
	desc []string
	// ceil sets the bounded fields of a profile to their bound.
	ceil []func(*Profile)
	// The allowlists: nil bounds nothing (network and extra_roots: an
	// empty list allows none).
	kinds, hosts, paths, auth, credentials, network, extraRoots []string
	networkSet, rootsSet                                        bool
	tls                                                         string
	detectors                                                   []string
	masks                                                       []mask.Rule
	vaultRequired                                               bool
}

type rawBoundBudgets struct {
	Range                string `toml:"range"`
	CountRange           string `toml:"count_range"`
	MaxBytes             string `toml:"max_bytes"`
	BytesPerHour         string `toml:"bytes_per_hour"`
	MetricQueriesPerHour *int   `toml:"metric_queries_per_hour"`
	RequestsPerMinute    *int   `toml:"requests_per_minute"`
}

type rawBoundLimits struct {
	Local                rawBoundBudgets `toml:"local"`
	Remote               rawBoundBudgets `toml:"remote"`
	MaxRecords           *int            `toml:"max_records"`
	MaxOutput            string          `toml:"max_output"`
	LookupsPerHour       *int            `toml:"lookups_per_hour"`
	LookupsPerHourPerUID *int            `toml:"lookups_per_hour_per_uid"`
	PIIAddsPerHour       *int            `toml:"pii_adds_per_hour"`
	PIIRulesMax          *int            `toml:"pii_rules_max"`
	MaxCalls             *int            `toml:"max_calls"`
	IdleTimeout          string          `toml:"idle_timeout"`
	MaxSession           string          `toml:"max_session"`
}

type rawBounds struct {
	Production        *bool           `toml:"production"`
	Structured        string          `toml:"structured"`
	Text              string          `toml:"text"`
	Unmask            string          `toml:"unmask"`
	Lookup            string          `toml:"lookup"`
	Strict            *bool           `toml:"strict"`
	Prefilter         *bool           `toml:"prefilter"`
	UserJournals      *bool           `toml:"user_journals"`
	PseudonymRotation string          `toml:"pseudonym_rotation"`
	PseudonymMaxAge   string          `toml:"pseudonym_max_age"`
	Auto              any             `toml:"auto"`
	Limits            rawBoundLimits  `toml:"limits"`
	Kinds             *[]string       `toml:"kinds"`
	Hosts             *[]string       `toml:"hosts"`
	Paths             *[]string       `toml:"paths"`
	Auth              *[]string       `toml:"auth"`
	Credentials       *[]string       `toml:"credentials"`
	TLS               string          `toml:"tls"`
	Network           *[]string       `toml:"network"`
	ExtraRoots        *[]string       `toml:"extra_roots"`
	Detectors         []string        `toml:"detectors"`
	PIIMask           []mask.RuleSpec `toml:"pii_mask"`
}

// boundKey is the managed key of a bound ("locklog.bounds.unmask").
func boundKey(k string) string { return ManagedTool + "." + managed.KindBounds + "." + k }

// parseBounds reads [locklog.bounds] and the [family] vault rule: nil
// when f has neither. Its errors name the key, never quote a value.
func parseBounds(f *managed.File) (*Bounds, error) {
	var r rawBounds
	ok, err := f.Decode(&r, ManagedTool, managed.KindBounds)
	if err != nil {
		return nil, err
	}
	vault := f.Family.Vault != nil && f.Family.Vault.Required
	if !ok && !vault {
		return nil, nil
	}
	b := &Bounds{vaultRequired: vault}
	add := func(key, val string, set func(*Profile)) {
		b.desc = append(b.desc, boundKey(key)+" = "+val)
		b.ceil = append(b.ceil, set)
	}
	only := func(key string, v *bool, want bool, set func(*Profile)) error {
		if v == nil {
			return nil
		}
		if *v != want {
			return fmt.Errorf("%s: only %t bounds anything", key, want)
		}
		add(key, strconv.FormatBool(want), set)
		return nil
	}
	if err := only("production", r.Production, true, func(p *Profile) { p.Production = true }); err != nil {
		return nil, err
	}
	if err := only("strict", r.Strict, true, func(p *Profile) { p.Strict = true }); err != nil {
		return nil, err
	}
	if err := only("prefilter", r.Prefilter, false, func(p *Profile) { p.Prefilter = false }); err != nil {
		return nil, err
	}
	if err := only("user_journals", r.UserJournals, false, func(p *Profile) { p.UserJournals = false }); err != nil {
		return nil, err
	}
	for _, s := range []struct {
		key, val, want string
		set            func(*Profile)
	}{
		{"structured", r.Structured, StructuredRedactUnknown, func(p *Profile) { p.Structured = StructuredRedactUnknown }},
		{"text", r.Text, TextTemplate, func(p *Profile) { p.Text = TextTemplate }},
		{"unmask", r.Unmask, UnmaskNever, func(p *Profile) { p.Unmask = UnmaskNever }},
		{"lookup", r.Lookup, LookupApproved, func(p *Profile) { p.Lookup = LookupApproved }},
	} {
		switch s.val {
		case "":
		case s.want:
			add(s.key, s.want, s.set)
		default:
			return nil, fmt.Errorf("%s: only %q bounds anything", s.key, s.want)
		}
	}
	if rot := r.PseudonymRotation; rot != "" {
		if rot != RotationSession && rot != RotationNever {
			d, err := ParseDuration(rot)
			if err != nil {
				return nil, errors.New("pseudonym_rotation: want \"session\", \"never\" or a duration such as \"7d\"")
			}
			rot = FormatDuration(d)
		}
		add("pseudonym_rotation", rot, func(p *Profile) { p.PseudonymRotation = rot })
	}
	if r.PseudonymMaxAge != "" {
		d, err := ParseDuration(r.PseudonymMaxAge)
		if err != nil {
			return nil, fmt.Errorf("pseudonym_max_age: %v", err)
		}
		add("pseudonym_max_age", FormatDuration(d), func(p *Profile) { p.PseudonymMaxAge = d })
	}
	if err := b.parseAuto(r.Auto, add); err != nil {
		return nil, err
	}
	if err := parseBoundLimits(r.Limits, add); err != nil {
		return nil, err
	}
	if err := b.parseLists(r); err != nil {
		return nil, err
	}
	if _, err := mask.ValueDetectors(r.Detectors); err != nil {
		return nil, fmt.Errorf("detectors: %v", err)
	}
	b.detectors = kconfig.SortedSet(r.Detectors)
	if len(b.detectors) > 0 {
		b.desc = append(b.desc, boundKey("detectors")+" = "+strings.Join(b.detectors, ", "))
	}
	for i, s := range r.PIIMask {
		rule, err := mask.BuildManagedRule(s)
		if err != nil {
			return nil, fmt.Errorf("pii_mask %d: %w", i+1, err)
		}
		b.masks = append(b.masks, rule)
		b.desc = append(b.desc, boundKey("pii_mask")+" = "+rule.Text())
	}
	if vault {
		b.desc = append(b.desc, "family.vault.required = true")
	}
	return b, nil
}

// parseAuto reads auto = { <action> = "deny" | "ask" | "auto" }: a
// ceiling per action. A preset is refused: a bound names its actions.
func (b *Bounds) parseAuto(v any, add func(string, string, func(*Profile))) error {
	if v == nil {
		return nil
	}
	t, ok := v.(map[string]any)
	if !ok {
		return errors.New("auto: a preset is refused in a bound; name the actions (auto = { unmask = \"ask\" })")
	}
	for _, act := range AutoActions {
		raw, ok := t[string(act)]
		if !ok {
			continue
		}
		s, _ := raw.(string)
		val, err := ParseAutoValue(s)
		if err != nil {
			return fmt.Errorf("auto.%s: %v", act, err)
		}
		add("auto."+string(act), string(val), func(p *Profile) {
			rules := p.AutoRules()
			*rules.field(act) = val
			p.Auto = &rules
		})
	}
	for _, k := range slices.Sorted(maps.Keys(t)) {
		if !slices.Contains(AutoActions, AutoAction(k)) {
			return fmt.Errorf("auto: unknown key %s (want %s)", safeKey(k), actionNames())
		}
	}
	return nil
}

// parseBoundLimits reads the limits bounds, each a ceiling.
func parseBoundLimits(r rawBoundLimits, add func(string, string, func(*Profile))) error {
	dur := func(key, v string, set func(*Profile, time.Duration)) error {
		if v == "" {
			return nil
		}
		d, err := ParseDuration(v)
		if err != nil {
			return fmt.Errorf("limits.%s: %v", key, err)
		}
		add("limits."+key, FormatDuration(d), func(p *Profile) { set(p, d) })
		return nil
	}
	size := func(key, v string, set func(*Profile, int64)) error {
		if v == "" {
			return nil
		}
		n, err := ParseSize(v)
		if err != nil {
			return fmt.Errorf("limits.%s: %v", key, err)
		}
		add("limits."+key, FormatSize(n), func(p *Profile) { set(p, n) })
		return nil
	}
	num := func(key string, v *int, set func(*Profile, int)) error {
		if v == nil {
			return nil
		}
		if *v < 1 {
			return fmt.Errorf("limits.%s: want at least 1", key)
		}
		n := *v
		add("limits."+key, strconv.Itoa(n), func(p *Profile) { set(p, n) })
		return nil
	}
	if r.Local.MetricQueriesPerHour != nil || r.Local.RequestsPerMinute != nil {
		return errors.New("limits.local: metric_queries_per_hour and requests_per_minute apply only to limits.remote")
	}
	for _, s := range []struct {
		name string
		raw  rawBoundBudgets
		get  func(*Profile) *Budgets
	}{{"local", r.Local, func(p *Profile) *Budgets { return &p.Limits.Local }}, {"remote", r.Remote, func(p *Profile) *Budgets { return &p.Limits.Remote }}} {
		get := s.get
		for _, err := range []error{
			dur(s.name+".range", s.raw.Range, func(p *Profile, d time.Duration) { get(p).Range = d }),
			dur(s.name+".count_range", s.raw.CountRange, func(p *Profile, d time.Duration) { get(p).CountRange = d }),
			size(s.name+".max_bytes", s.raw.MaxBytes, func(p *Profile, n int64) { get(p).MaxBytes = n }),
			size(s.name+".bytes_per_hour", s.raw.BytesPerHour, func(p *Profile, n int64) { get(p).BytesPerHour = n }),
			num(s.name+".metric_queries_per_hour", s.raw.MetricQueriesPerHour, func(p *Profile, n int) { get(p).MetricQueriesPerHour = n }),
			num(s.name+".requests_per_minute", s.raw.RequestsPerMinute, func(p *Profile, n int) { get(p).RequestsPerMinute = n }),
		} {
			if err != nil {
				return err
			}
		}
	}
	for _, err := range []error{
		num("max_records", r.MaxRecords, func(p *Profile, n int) { p.Limits.MaxRecords = n }),
		size("max_output", r.MaxOutput, func(p *Profile, n int64) { p.Limits.MaxOutputBytes = n }),
		num("lookups_per_hour", r.LookupsPerHour, func(p *Profile, n int) { p.Limits.LookupsPerHour = n }),
		num("lookups_per_hour_per_uid", r.LookupsPerHourPerUID, func(p *Profile, n int) { p.Limits.LookupsPerHourPerUID = n }),
		num("pii_adds_per_hour", r.PIIAddsPerHour, func(p *Profile, n int) { p.Limits.PIIAddsPerHour = n }),
		num("pii_rules_max", r.PIIRulesMax, func(p *Profile, n int) { p.Limits.PIIRulesMax = n }),
		num("max_calls", r.MaxCalls, func(p *Profile, n int) { p.Limits.MaxCalls = n }),
		dur("idle_timeout", r.IdleTimeout, func(p *Profile, d time.Duration) { p.IdleTimeout = d }),
		dur("max_session", r.MaxSession, func(p *Profile, d time.Duration) { p.MaxSession = d }),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// parseLists reads the allowlist bounds, which Diff cannot express as one
// ceiling value: Check refuses a value outside them itself.
func (b *Bounds) parseLists(r rawBounds) error {
	list := func(key string, v *[]string, allowed []string, emptyOK bool) ([]string, error) {
		if v == nil {
			return nil, nil
		}
		if len(*v) == 0 && !emptyOK {
			return nil, fmt.Errorf("%s: list at least one value", key)
		}
		for i, s := range *v {
			if allowed != nil && !slices.Contains(allowed, s) {
				return nil, fmt.Errorf("%s entry %d: want one of %s", key, i+1, strings.Join(allowed, ", "))
			}
		}
		out := kconfig.SortedSet(*v)
		if out == nil {
			out = []string{}
		}
		return out, nil
	}
	var err error
	if b.kinds, err = list("kinds", r.Kinds, Kinds, false); err != nil {
		return err
	}
	if b.auth, err = list("auth", r.Auth, []string{AuthNone, AuthBasic, AuthBearer, AuthMTLS, AuthAPIKey}, false); err != nil {
		return err
	}
	if b.credentials, err = list("credentials", r.Credentials, []string{kconfig.CredentialsAsk, kconfig.CredentialsVault}, false); err != nil {
		return err
	}
	if b.hosts, err = list("hosts", r.Hosts, nil, false); err != nil {
		return err
	}
	for i, h := range b.hosts {
		if _, err := path.Match(h, ""); err != nil || strings.ContainsAny(h, "/:@ ") {
			return fmt.Errorf("hosts entry %d: want a host pattern such as \"*.logs.example.com\"", i+1)
		}
	}
	if b.paths, err = list("paths", r.Paths, nil, false); err != nil {
		return err
	}
	for i, p := range b.paths {
		if !path.IsAbs(p) || strings.ContainsAny(p, "*?[") {
			return fmt.Errorf("paths entry %d: want an absolute directory such as \"/var/log\"", i+1)
		}
	}
	if b.network, err = list("network", r.Network, nil, true); err != nil {
		return err
	}
	b.networkSet = r.Network != nil
	if b.extraRoots, err = list("extra_roots", r.ExtraRoots, nil, true); err != nil {
		return err
	}
	b.rootsSet = r.ExtraRoots != nil
	for i, p := range b.extraRoots {
		if !path.IsAbs(p) {
			return fmt.Errorf("extra_roots entry %d: want an absolute directory", i+1)
		}
	}
	if r.TLS != "" {
		if kconfig.TLSRank(r.TLS) < 0 {
			return errors.New("tls: unknown tls mode (want disable, prefer, require, verify-ca or verify-full)")
		}
		b.tls = r.TLS
	}
	for _, l := range []struct {
		key string
		v   []string
		set bool
	}{{"kinds", b.kinds, b.kinds != nil}, {"hosts", b.hosts, b.hosts != nil}, {"paths", b.paths, b.paths != nil},
		{"auth", b.auth, b.auth != nil}, {"credentials", b.credentials, b.credentials != nil}, {"tls", []string{b.tls}, b.tls != ""},
		{"network", b.network, b.networkSet}, {"extra_roots", b.extraRoots, b.rootsSet}} {
		if l.set {
			b.desc = append(b.desc, boundKey(l.key)+" = "+orNone(l.v))
		}
	}
	return nil
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}

// Describe is the bounds as lines for `locklog managed show`.
func (b *Bounds) Describe() []string {
	if b == nil {
		return nil
	}
	return slices.Clone(b.desc)
}

// Masks are the managed mask rules ([[locklog.bounds.pii_mask]]).
func (b *Bounds) Masks() []mask.Rule {
	if b == nil {
		return nil
	}
	return slices.Clone(b.masks)
}

// require adds the required detectors to p.
func (b *Bounds) require(p *Profile) {
	if b == nil || len(b.detectors) == 0 {
		return
	}
	p.Detectors = kconfig.SortedSet(append(slices.Clone(p.Detectors), b.detectors...))
}

// policyOf is p's policy as the console would load it, with the managed
// mask rules and no launch environment.
func (b *Bounds) policyOf(p Profile) Policy {
	return Canonical(Policy{Profile: p, PIIMask: b.Masks()})
}

// CheckAllow refuses an allow rule of pii.toml that could show what a
// managed mask rule masks: the user can add rules, never weaken a
// managed one.
func (b *Bounds) CheckAllow(allow []mask.Rule) error {
	if b == nil {
		return nil
	}
	for i, a := range allow {
		for _, m := range b.masks {
			if mask.Overlaps(a, m) {
				return fmt.Errorf("pii rules: allow rule %d would show what the company's managed configuration masks (%s: %s): remove it", i+1, boundKey("pii_mask"), m.Text())
			}
		}
	}
	return nil
}

// Ceiling is pol with each bounded field set to its bound: what
// managed.Check compares pol with through Policy.Diff. A nil b bounds
// nothing (a nil Ceiling).
func (b *Bounds) Ceiling(pol Policy) managed.Bounds {
	if b == nil {
		return managed.Bounds{}
	}
	c := Canonical(pol)
	cp := &c.Profile
	for _, set := range b.ceil {
		set(cp)
	}
	cp.Detectors = kconfig.SortedSet(append(slices.Clone(cp.Detectors), b.detectors...))
	if len(b.masks) > 0 {
		c.PIIMask = append(slices.Clone(c.PIIMask), b.masks...)
	}
	return managed.Bounds{Tool: ManagedTool, Profile: pol.Profile.Name, Ceiling: Canonical(c), Keys: map[string]string{"pii.mask": "pii_mask"}}
}

// AllowViolation is a value outside an allowlist bound (kinds, hosts,
// paths, auth, credentials, tls, network, extra_roots) or the [family]
// vault rule.
type AllowViolation struct {
	// Key is the managed key ("locklog.bounds.kinds").
	Key string
	// Profile, Field and Value are the policy's; Allowed is the bound.
	Profile, Field, Value, Allowed string
}

// Text is the violation without the "blocked by company policy: "
// prefix, which the console adds.
func (v AllowViolation) Text() string {
	return fmt.Sprintf("%s does not allow %s = %s (profile %s; allowed: %s)", v.Key, v.Field, v.Value, v.Profile, v.Allowed)
}

// String cites the managed key, as managed.Violation does.
func (v AllowViolation) String() string { return "blocked by company policy: " + v.Text() }

// BoundsError is a policy outside an allowlist bound. The console
// refuses it as a violation, citing its first line.
type BoundsError struct {
	Violations []AllowViolation
}

func (e *BoundsError) Error() string {
	lines := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		lines[i] = v.Text()
	}
	return strings.Join(lines, "; ")
}

// Check returns the managed bounds of pol (Ceiling) and, as a
// *BoundsError naming the managed key, every value outside an allowlist
// Diff cannot express. A nil b bounds nothing.
func (b *Bounds) Check(pol Policy) (managed.Bounds, error) {
	if b == nil {
		return managed.Bounds{}, nil
	}
	mb := b.Ceiling(pol)
	if vs := b.allowViolations(Canonical(pol)); len(vs) > 0 {
		return mb, &BoundsError{Violations: vs}
	}
	return mb, nil
}

// Violations are the lines that refuse pol: its allowlist violations and
// managed.Check's, each "blocked by company policy: …".
func (b *Bounds) Violations(pol Policy) ([]string, error) {
	mb, err := b.Check(pol)
	var lines []string
	var be *BoundsError
	switch {
	case errors.As(err, &be):
		for _, v := range be.Violations {
			lines = append(lines, v.String())
		}
	case err != nil:
		return nil, err
	}
	for _, v := range managed.Check(pol, mb) {
		lines = append(lines, v.String())
	}
	return lines, nil
}

func (b *Bounds) allowViolations(pol Policy) []AllowViolation {
	pr := pol.Profile
	var vs []AllowViolation
	add := func(key, field, value string, allowed []string) {
		vs = append(vs, AllowViolation{Key: key, Profile: pr.Name, Field: field, Value: value, Allowed: orNone(allowed)})
	}
	for _, s := range pr.Sources {
		pre := "sources." + s.Name + "."
		if b.kinds != nil && !slices.Contains(b.kinds, s.Kind) {
			add(boundKey("kinds"), pre+"kind", s.Kind, b.kinds)
		}
		if b.paths != nil && s.Kind == KindFile {
			for _, p := range s.Paths {
				if !underAny(p, b.paths) {
					add(boundKey("paths"), pre+"paths", p, b.paths)
				}
			}
		}
		r := s.Remote
		if r == nil {
			continue
		}
		if b.hosts != nil {
			host := "(invalid)"
			if u, err := url.Parse(r.URL); err == nil {
				host = u.Hostname()
			}
			if !hostAllowed(host, b.hosts) {
				add(boundKey("hosts"), pre+"url", host, b.hosts)
			}
		}
		if b.auth != nil && !slices.Contains(b.auth, r.Auth) {
			add(boundKey("auth"), pre+"auth", r.Auth, b.auth)
		}
		if b.credentials != nil && r.Credentials != "" && !slices.Contains(b.credentials, r.Credentials) {
			add(boundKey("credentials"), pre+"credentials", r.Credentials, b.credentials)
		}
		if b.vaultRequired && r.Auth != AuthNone && r.Auth != AuthMTLS && r.Credentials != kconfig.CredentialsVault {
			add("family.vault.required", pre+"credentials", orNone([]string{r.Credentials}), []string{kconfig.CredentialsVault})
		}
		if b.tls != "" && kconfig.TLSRank(r.TLS) < kconfig.TLSRank(b.tls) {
			add(boundKey("tls"), pre+"tls", orNone([]string{r.TLS}), []string{b.tls + " or stronger"})
		}
	}
	if b.networkSet && pol.Network != "" && !slices.Contains(b.network, pol.Network) {
		add(boundKey("network"), "network", pol.Network, b.network)
	}
	if b.rootsSet {
		for _, r := range pol.ExtraRoots {
			if !underAny(r, b.extraRoots) {
				add(boundKey("extra_roots"), "extra_roots", r, b.extraRoots)
			}
		}
	}
	return vs
}

// underAny reports whether the path (or glob) p lies under one of the
// directories dirs.
func underAny(p string, dirs []string) bool {
	p = path.Clean(p)
	for _, d := range dirs {
		d = path.Clean(d)
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

func hostAllowed(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range patterns {
		if ok, _ := path.Match(strings.ToLower(pat), host); ok {
			return true
		}
	}
	return false
}
