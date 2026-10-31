// Package config loads locklog profiles from the project and user config
// files (`.locklog/config.toml`, then the user's), applies the defaults,
// refuses anything that looks like a secret or that the production rules
// forbid, and computes the security-relevant policy of a profile. The file
// lookup, the secret-safe decoding, the shared profile base and the diff
// helpers are lockkit's.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// Version is the config file format this binary reads. A file with a
// later version is refused: it was written for a newer locklog.
const Version = 1

// Profile is one named set of log sources with its masking and budget
// policy. It never holds a secret.
type Profile struct {
	Name string `json:"name"`
	// Base carries production and the session limits; its connection
	// fields are unused (each remote source has its own).
	kconfig.Base
	Structured string   `json:"structured"`
	Text       string   `json:"text"`
	Detectors  []string `json:"detectors"`
	Unmask     string   `json:"unmask"`
	Lookup     string   `json:"lookup"`
	// Strict makes every search and count a ticket the human approves.
	Strict bool `json:"strict"`
	// Prefilter matches clear text before masking (non-production only):
	// faster, but latency then reveals how many records hold a substring.
	Prefilter bool `json:"prefilter"`
	// UserJournals also serves user-*.journal files.
	UserJournals bool `json:"user_journals"`
	// PseudonymRotation is "session", "never" or a duration ("7d");
	// PseudonymMaxAge is when an unrotated key shows red.
	PseudonymRotation string        `json:"pseudonym_rotation"`
	PseudonymMaxAge   time.Duration `json:"pseudonym_max_age"`
	Limits            Limits        `json:"limits"`
	// Sources are sorted by name.
	Sources []Source `json:"sources"`
}

// Source returns the source named n.
func (p Profile) Source(n string) (Source, bool) {
	i := slices.IndexFunc(p.Sources, func(s Source) bool { return s.Name == n })
	if i < 0 {
		return Source{}, false
	}
	return p.Sources[i], true
}

// RotationEvery is the rotation interval: 0 for "session" (a new key per
// console session) and for "never".
func (p Profile) RotationEvery() time.Duration {
	if p.PseudonymRotation == RotationSession || p.PseudonymRotation == RotationNever {
		return 0
	}
	d, _ := ParseDuration(p.PseudonymRotation)
	return d
}

type rawBudgets struct {
	Range                string `toml:"range"`
	CountRange           string `toml:"count_range"`
	MaxBytes             string `toml:"max_bytes"`
	BytesPerHour         string `toml:"bytes_per_hour"`
	MetricQueriesPerHour int    `toml:"metric_queries_per_hour"`
	RequestsPerMinute    int    `toml:"requests_per_minute"`
}

type rawLimits struct {
	Local                rawBudgets `toml:"local"`
	Remote               rawBudgets `toml:"remote"`
	MaxRecords           int        `toml:"max_records"`
	MaxOutput            string     `toml:"max_output"`
	LookupsPerHour       int        `toml:"lookups_per_hour"`
	LookupsPerHourPerUID int        `toml:"lookups_per_hour_per_uid"`
	PIIAddsPerHour       int        `toml:"pii_adds_per_hour"`
	PIIRulesMax          int        `toml:"pii_rules_max"`
	IdleTimeout          string     `toml:"idle_timeout"`
	MaxSession           string     `toml:"max_session"`
}

type rawProfile struct {
	Production        bool                 `toml:"production"`
	Structured        string               `toml:"structured"`
	Text              string               `toml:"text"`
	Detectors         []string             `toml:"detectors"`
	Unmask            string               `toml:"unmask"`
	Lookup            string               `toml:"lookup"`
	Strict            bool                 `toml:"strict"`
	Prefilter         bool                 `toml:"prefilter"`
	UserJournals      bool                 `toml:"user_journals"`
	PseudonymRotation string               `toml:"pseudonym_rotation"`
	PseudonymMaxAge   string               `toml:"pseudonym_max_age"`
	Limits            rawLimits            `toml:"limits"`
	Sources           map[string]rawSource `toml:"sources"`
}

type rawFile struct {
	Version  *int                  `toml:"version"`
	Profiles map[string]rawProfile `toml:"profiles"`
}

// Load reads the user config and the project config (found by walking up
// from cwd). On a profile name present in both, the project profile wins
// as a whole. It also returns the project root ("" when none).
func Load(cwd string) (map[string]Profile, string, error) {
	userPath, _ := kconfig.UserConfigPath(product.P)
	return LoadFrom(cwd, userPath)
}

// LoadFrom is Load with an explicit user config path ("" for none). A
// missing user config file is not an error.
func LoadFrom(cwd, userConfigPath string) (map[string]Profile, string, error) {
	out := map[string]Profile{}
	if userConfigPath != "" {
		ps, err := LoadFile(userConfigPath)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, "", err
		}
		for n, p := range ps {
			out[n] = p
		}
	}
	root, ok := kconfig.FindProjectRoot(product.P, cwd)
	if !ok {
		return out, "", nil
	}
	ps, err := LoadFile(kconfig.ProjectConfigPath(product.P, root))
	if err != nil {
		return nil, "", err
	}
	for n, p := range ps {
		out[n] = p
	}
	return out, root, nil
}

// LoadFile reads the profiles of one config file.
func LoadFile(path string) (map[string]Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return ParseProfiles(data, filepath.Clean(path))
}

// ParseProfiles decodes and validates config data; name labels errors.
// Errors never quote a value that could hold a secret.
func ParseProfiles(data []byte, name string) (map[string]Profile, error) {
	var raw rawFile
	md, err := kconfig.Decode(product.P, data, name, &raw)
	if err != nil {
		return nil, err
	}
	switch {
	case raw.Version == nil:
		return nil, fmt.Errorf("config: %s: version is required (version = %d at the top of the file)", name, Version)
	case *raw.Version > Version:
		return nil, fmt.Errorf("config: %s: version %d was written for a newer locklog (this one reads version %d): update locklog", name, *raw.Version, Version)
	case *raw.Version != Version:
		return nil, fmt.Errorf("config: %s: unknown version %d (want %d)", name, *raw.Version, Version)
	}
	names := make([]string, 0, len(raw.Profiles))
	for pn := range raw.Profiles {
		names = append(names, pn)
	}
	sort.Strings(names)
	out := make(map[string]Profile, len(names))
	for _, pn := range names {
		p, err := buildProfile(pn, raw.Profiles[pn], md.IsDefined("profiles", pn, "detectors"))
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", name, err)
		}
		out[pn] = p
	}
	return out, nil
}

func buildProfile(name string, r rawProfile, detectorsSet bool) (Profile, error) {
	if err := kconfig.CheckProfileName(name, r.Production); err != nil {
		return Profile{}, err
	}
	errf := func(format string, a ...any) error {
		return fmt.Errorf("profile %q: "+format, append([]any{name}, a...)...)
	}
	prod := r.Production
	p := Profile{
		Name: name, Base: kconfig.Base{Production: prod},
		Structured: r.Structured, Text: r.Text, Detectors: r.Detectors, Unmask: r.Unmask, Lookup: r.Lookup,
		Strict: r.Strict, Prefilter: r.Prefilter, UserJournals: r.UserJournals,
	}
	if !detectorsSet {
		p.Detectors = DefaultDetectors()
	}
	if slices.Contains(p.Detectors, SecretDetector) {
		return Profile{}, errf("detectors: %q is not a value detector (secret detection is always on)", SecretDetector)
	}
	if _, err := pii.Detectors(p.Detectors); err != nil {
		return Profile{}, errf("detectors: %v", err)
	}
	p.Detectors = kconfig.SortedSet(p.Detectors)
	if p.Structured == "" {
		p.Structured = DefaultStructured(prod)
	}
	if p.Structured != StructuredRedactUnknown && p.Structured != StructuredDetect {
		return Profile{}, errf("unknown structured mode (want redact-unknown or detect)")
	}
	if p.Text == "" {
		p.Text = TextDetect
	}
	if p.Text != TextDetect && p.Text != TextTemplate {
		return Profile{}, errf("unknown text mode (want detect or template)")
	}
	if p.Unmask == "" {
		p.Unmask = DefaultUnmask(prod)
	}
	if p.Unmask != UnmaskNever && p.Unmask != UnmaskApproved {
		return Profile{}, errf("unknown unmask mode (want never or approved)")
	}
	if p.Lookup == "" {
		p.Lookup = LookupFree
	}
	if p.Lookup != LookupFree && p.Lookup != LookupApproved {
		return Profile{}, errf("unknown lookup mode (want free or approved)")
	}
	if prod && p.Prefilter {
		return Profile{}, errf("prefilter = true is refused on a production profile: with it, latency reveals how many records hold a clear substring")
	}

	switch rot := r.PseudonymRotation; rot {
	case "":
		p.PseudonymRotation = FormatDuration(DefaultRotation)
	case RotationSession:
		p.PseudonymRotation = rot
	case RotationNever:
		if prod {
			return Profile{}, errf("pseudonym_rotation = \"never\" is refused on a production profile")
		}
		p.PseudonymRotation = rot
	default:
		d, err := ParseDuration(rot)
		if err != nil || d < MinRotation || d > MaxPseudonymAge {
			return Profile{}, errf("pseudonym_rotation: want \"session\", \"never\" or a duration between %s and %s, such as \"7d\"",
				FormatDuration(MinRotation), FormatDuration(MaxPseudonymAge))
		}
		p.PseudonymRotation = FormatDuration(d)
	}
	p.PseudonymMaxAge = DefaultMaxAge
	if r.PseudonymMaxAge != "" {
		d, err := ParseDuration(r.PseudonymMaxAge)
		if err != nil || d < MinRotation || d > MaxPseudonymAge {
			return Profile{}, errf("pseudonym_max_age: want a duration between %s and %s, such as \"30d\"",
				FormatDuration(MinRotation), FormatDuration(MaxPseudonymAge))
		}
		p.PseudonymMaxAge = d
	}
	if e := p.RotationEvery(); e > p.PseudonymMaxAge {
		return Profile{}, errf("pseudonym_rotation (%s) is above pseudonym_max_age (%s)", FormatDuration(e), FormatDuration(p.PseudonymMaxAge))
	}

	l, err := buildLimits(r.Limits, prod)
	if err != nil {
		return Profile{}, errf("%v", err)
	}
	p.Limits = l
	p.IdleTimeout, p.MaxSession = DefaultIdle, DefaultMaxSession
	for _, f := range []struct {
		key, val string
		dst      *time.Duration
	}{{"idle_timeout", r.Limits.IdleTimeout, &p.IdleTimeout}, {"max_session", r.Limits.MaxSession, &p.MaxSession}} {
		if f.val == "" {
			continue
		}
		d, err := ParseDuration(f.val)
		if err != nil {
			return Profile{}, errf("limits.%s: %v", f.key, err)
		}
		*f.dst = d
	}
	if r.Limits.IdleTimeout == "" {
		// A defaulted idle timeout never exceeds an explicit max_session.
		p.IdleTimeout = min(DefaultIdle, p.MaxSession)
	}
	switch {
	case p.MaxSession < MinIdleTimeout || p.MaxSession > MaxMaxSession:
		return Profile{}, errf("limits.max_session (%s) must be between %s and %s", p.MaxSession, MinIdleTimeout, FormatDuration(MaxMaxSession))
	case p.IdleTimeout < MinIdleTimeout:
		return Profile{}, errf("limits.idle_timeout (%s) is below %s", p.IdleTimeout, MinIdleTimeout)
	case p.IdleTimeout > p.MaxSession:
		return Profile{}, errf("limits.idle_timeout (%s) is above limits.max_session (%s)", p.IdleTimeout, p.MaxSession)
	}

	if len(r.Sources) == 0 {
		return Profile{}, errf("no sources: add at least one [profiles.%s.sources.<name>] table", name)
	}
	snames := make([]string, 0, len(r.Sources))
	for sn := range r.Sources {
		snames = append(snames, sn)
	}
	sort.Strings(snames)
	for _, sn := range snames {
		s, err := buildSource(sn, r.Sources[sn], prod)
		if err != nil {
			return Profile{}, errf("%v", err)
		}
		if s.Kind == KindJournald && !p.UserJournals && slices.ContainsFunc(s.Units, func(u string) bool { return canMatchPrefix(u, "user@") }) {
			return Profile{}, errf("source %q: units that can match user sessions (user@..., so also globs such as *.service) need user_journals = true; name the system units instead", sn)
		}
		p.Sources = append(p.Sources, s)
	}
	return p, nil
}

// CheckDockerAlone refuses a docker source beside a file or journald source
// (the mount plan applies it: a profile may still describe both, e.g. for
// review, but no console mounts them together).
// Reading the containers root needs gid 0, and a supplementary group applies
// to the whole console process: beside other bound log directories it would
// open every file of theirs readable by group root. Remote sources stay
// allowed.
func CheckDockerAlone(sources []Source) error {
	docker, local := "", ""
	for _, s := range sources {
		switch s.Kind {
		case KindDocker:
			docker = s.Name
		case KindFile, KindJournald:
			local = s.Name
		}
	}
	if docker != "" && local != "" {
		return fmt.Errorf("source %q (docker) cannot share a profile with source %q (%s logs): the console reads the containers root with group 0, which would apply to every bound log directory; put the container logs in a profile of their own and run a separate console for them",
			docker, local, kindOf(sources, local))
	}
	return nil
}

func kindOf(sources []Source, name string) string {
	for _, s := range sources {
		if s.Name == name {
			return s.Kind
		}
	}
	return ""
}

func buildLimits(r rawLimits, production bool) (Limits, error) {
	l := DefaultLimits(production)
	for _, b := range []struct {
		name string
		raw  rawBudgets
		dst  *Budgets
	}{{"local", r.Local, &l.Local}, {"remote", r.Remote, &l.Remote}} {
		for _, f := range []struct {
			key, val string
			dst      *time.Duration
		}{{"range", b.raw.Range, &b.dst.Range}, {"count_range", b.raw.CountRange, &b.dst.CountRange}} {
			if f.val == "" {
				continue
			}
			d, err := ParseDuration(f.val)
			if err != nil {
				return Limits{}, fmt.Errorf("limits.%s.%s: %v", b.name, f.key, err)
			}
			if d > RangeCeiling {
				return Limits{}, fmt.Errorf("limits.%s.%s (%s) is above its ceiling %s", b.name, f.key, FormatDuration(d), FormatDuration(RangeCeiling))
			}
			*f.dst = d
		}
		for _, f := range []struct {
			key, val string
			ceiling  int64
			dst      *int64
		}{{"max_bytes", b.raw.MaxBytes, BytesCeiling, &b.dst.MaxBytes}, {"bytes_per_hour", b.raw.BytesPerHour, BytesPerHourCeiling, &b.dst.BytesPerHour}} {
			if f.val == "" {
				continue
			}
			n, err := ParseSize(f.val)
			if err != nil {
				return Limits{}, fmt.Errorf("limits.%s.%s: %v", b.name, f.key, err)
			}
			if f.ceiling > 0 && n > f.ceiling {
				return Limits{}, fmt.Errorf("limits.%s.%s (%s) is above its ceiling %s", b.name, f.key, FormatSize(n), FormatSize(f.ceiling))
			}
			*f.dst = n
		}
		if b.name == "local" && (b.raw.MetricQueriesPerHour != 0 || b.raw.RequestsPerMinute != 0) {
			return Limits{}, fmt.Errorf("limits.local: metric_queries_per_hour and requests_per_minute apply only to limits.remote")
		}
		for _, f := range []struct {
			key string
			val int
			dst *int
		}{{"metric_queries_per_hour", b.raw.MetricQueriesPerHour, &b.dst.MetricQueriesPerHour}, {"requests_per_minute", b.raw.RequestsPerMinute, &b.dst.RequestsPerMinute}} {
			if f.val < 0 {
				return Limits{}, fmt.Errorf("limits.%s.%s must be positive", b.name, f.key)
			}
			if f.val > RateCeiling {
				return Limits{}, fmt.Errorf("limits.%s.%s (%d) is above its ceiling %d", b.name, f.key, f.val, RateCeiling)
			}
			if f.val > 0 {
				*f.dst = f.val
			}
		}
		if b.dst.MaxBytes > b.dst.BytesPerHour {
			return Limits{}, fmt.Errorf("limits.%s.max_bytes (%s) is above limits.%s.bytes_per_hour (%s)", b.name, FormatSize(b.dst.MaxBytes), b.name, FormatSize(b.dst.BytesPerHour))
		}
	}
	if r.MaxOutput != "" {
		n, err := ParseSize(r.MaxOutput)
		if err != nil {
			return Limits{}, fmt.Errorf("limits.max_output: %v", err)
		}
		if n > OutputCeiling {
			return Limits{}, fmt.Errorf("limits.max_output (%s) is above its ceiling %s", FormatSize(n), FormatSize(OutputCeiling))
		}
		l.MaxOutputBytes = n
	}
	for _, f := range []struct {
		key          string
		val, ceiling int
		dst          *int
	}{
		{"max_records", r.MaxRecords, RecordsCeiling, &l.MaxRecords},
		{"lookups_per_hour", r.LookupsPerHour, LookupsCeiling, &l.LookupsPerHour},
		{"lookups_per_hour_per_uid", r.LookupsPerHourPerUID, LookupsCeiling, &l.LookupsPerHourPerUID},
		{"pii_adds_per_hour", r.PIIAddsPerHour, PIIAddsCeiling, &l.PIIAddsPerHour},
		{"pii_rules_max", r.PIIRulesMax, PIIRulesCeiling, &l.PIIRulesMax},
	} {
		switch {
		case f.val < 0:
			return Limits{}, fmt.Errorf("limits.%s must be positive", f.key)
		case f.ceiling > 0 && f.val > f.ceiling:
			return Limits{}, fmt.Errorf("limits.%s (%d) is above its ceiling %d", f.key, f.val, f.ceiling)
		case f.val > 0:
			*f.dst = f.val
		}
	}
	if l.LookupsPerHourPerUID > l.LookupsPerHour {
		if r.LookupsPerHourPerUID > 0 {
			return Limits{}, fmt.Errorf("limits.lookups_per_hour_per_uid (%d) is above limits.lookups_per_hour (%d)", l.LookupsPerHourPerUID, l.LookupsPerHour)
		}
		// The default per-uid cap never exceeds an explicit console cap.
		l.LookupsPerHourPerUID = l.LookupsPerHour
	}
	return l, nil
}
