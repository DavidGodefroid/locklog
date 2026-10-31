package config

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
)

// Policy is the security-relevant view of one profile plus the launch
// environment the human chose (the network the console joins, the extra
// mount roots): what the console fingerprints, compares with the last
// approved one and asks the human about before applying any loosening.
type Policy struct {
	Profile Profile `json:"profile"`
	// Network is LOCKLOG_NETWORK: a Docker network the console joins to
	// reach a backend ("" for none).
	Network string `json:"network"`
	// ExtraRoots is LOCKLOG_EXTRA_ROOTS: mount roots beyond the built-in
	// allowlist, sorted.
	ExtraRoots []string `json:"extra_roots"`
}

var _ kconfig.Policy = Policy{}

// NewPolicy builds the canonical policy of p started with network and
// extraRoots.
func NewPolicy(p Profile, network string, extraRoots []string) (Policy, error) {
	if network != "" && !networkRe.MatchString(network) {
		return Policy{}, fmt.Errorf("LOCKLOG_NETWORK: invalid Docker network name")
	}
	switch network {
	case "host", "bridge", "none":
		return Policy{}, fmt.Errorf("LOCKLOG_NETWORK: name a network of your own, not %s", network)
	}
	for _, r := range extraRoots {
		if !path.IsAbs(r) || path.Clean(r) == "/" || strings.IndexFunc(r, kconfig.UnsafeRune) >= 0 || strings.ContainsAny(r, ",=:\"'`\\\n") {
			return Policy{}, fmt.Errorf("LOCKLOG_EXTRA_ROOTS: %q is not an absolute directory other than /, without the characters a mount cannot carry", r)
		}
	}
	return Canonical(Policy{Profile: p, Network: network, ExtraRoots: extraRoots}), nil
}

var networkRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Canonical sorts and de-duplicates the lists of p: its JSON is the
// fingerprinted form.
func Canonical(p Policy) Policy {
	pr := p.Profile
	pr.Detectors = kconfig.SortedSet(pr.Detectors)
	srcs := make([]Source, len(pr.Sources))
	for i, s := range pr.Sources {
		s.Trusted = kconfig.SortedSet(s.Trusted)
		s.Paths = sortedOrNil(s.Paths)
		s.Units = sortedOrNil(s.Units)
		s.Allow = sortedOrNil(s.Allow)
		s.Containers = sortedOrNil(s.Containers)
		s.Attrs = sortedOrNil(s.Attrs)
		if s.Remote != nil {
			r := *s.Remote
			r.TrustedLabels = kconfig.SortedSet(r.TrustedLabels)
			r.TrustedMetadata = kconfig.SortedSet(r.TrustedMetadata)
			r.Selector = maps.Clone(r.Selector)
			if r.Selector == nil {
				r.Selector = map[string]string{}
			}
			s.Remote = &r
		}
		srcs[i] = s
	}
	slices.SortFunc(srcs, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })
	pr.Sources = srcs
	p.Profile = pr
	roots := make([]string, len(p.ExtraRoots))
	for i, r := range p.ExtraRoots {
		roots[i] = path.Clean(r)
	}
	p.ExtraRoots = kconfig.SortedSet(roots)
	return p
}

func sortedOrNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return kconfig.SortedSet(s)
}

// Fingerprint is the policy's fingerprint (policy_fp): it binds refs,
// cursors and approvals to the policy they were made under.
func (p Policy) Fingerprint() string { return kconfig.Fingerprint(Canonical(p)) }

// LooseningKeys are the profile keys whose loosening is a policy-loosen
// change request when the agent proposes it, and a confirmation at the
// console when the human edits it. Every other loosening (a new source,
// path, container, unit, trusted field or label, a larger limit) is
// reviewed the same way; these are the keys named for the agent.
var LooseningKeys = []string{"production", "prefilter", "unmask", "lookup", "network", "user_journals", "allow", "extra_roots"}

// rotationRank orders rotation settings from the tightest: session, then
// durations, then never.
func rotationRank(s string) int64 {
	switch s {
	case RotationSession:
		return 0
	case RotationNever:
		return 1 << 62
	}
	d, err := ParseDuration(s)
	if err != nil {
		return 1 << 62
	}
	return int64(d)
}

// Diff lists the changes from approved to p and marks each loosening:
// production true → false (and the session limits, through
// kconfig.DiffBase), structured redact-unknown → detect, text template →
// detect, a removed detector, unmask never → approved, lookup approved →
// free, strict on → off, prefilter or user_journals off → on, a longer
// pseudonym rotation or max age, any larger limit, another network, an
// added extra root, and for sources: a new source, another kind, format or
// multiline mode, an added path, unit (or every unit), container, allowed
// field, attr, trusted field or label, recursive off → on, and for a remote
// source any change of url, selector, auth, org_id or connection
// (kconfig.DiffBase).
func (p Policy) Diff(approved kconfig.Policy) []kconfig.Change {
	a, ok := approved.(Policy)
	if !ok {
		return []kconfig.Change{{Field: "policy", Old: fmt.Sprintf("%T", approved), New: "locklog", Loosens: true}}
	}
	a, c := Canonical(a), Canonical(p)
	ap, cp := a.Profile, c.Profile
	out := kconfig.DiffBase(ap.Base, cp.Base)
	add := func(field, o, n string, loosens bool) {
		if o != n {
			out = append(out, kconfig.Change{Field: field, Old: o, New: n, Loosens: loosens})
		}
	}
	add("structured", ap.Structured, cp.Structured, cp.Structured != StructuredRedactUnknown)
	add("text", ap.Text, cp.Text, cp.Text != TextTemplate)
	out = append(out, kconfig.SetDiff("detectors", ap.Detectors, cp.Detectors, true)...)
	add("unmask", ap.Unmask, cp.Unmask, cp.Unmask != UnmaskNever)
	add("lookup", ap.Lookup, cp.Lookup, cp.Lookup != LookupApproved)
	b := strconv.FormatBool
	add("strict", b(ap.Strict), b(cp.Strict), !cp.Strict)
	add("prefilter", b(ap.Prefilter), b(cp.Prefilter), cp.Prefilter)
	add("user_journals", b(ap.UserJournals), b(cp.UserJournals), cp.UserJournals)
	add("pseudonym_rotation", ap.PseudonymRotation, cp.PseudonymRotation, rotationRank(cp.PseudonymRotation) > rotationRank(ap.PseudonymRotation))
	add("pseudonym_max_age", FormatDuration(ap.PseudonymMaxAge), FormatDuration(cp.PseudonymMaxAge), cp.PseudonymMaxAge > ap.PseudonymMaxAge)
	out = append(out, diffLimits(ap.Limits, cp.Limits)...)
	add("network", a.Network, c.Network, c.Network != "")
	out = append(out, kconfig.SetDiff("extra_roots", a.ExtraRoots, c.ExtraRoots, false)...)

	for _, cs := range cp.Sources {
		as, found := ap.Source(cs.Name)
		if !found {
			out = append(out, kconfig.Change{Field: "sources", New: cs.Name + " (" + cs.Kind + ")", Loosens: true})
			continue
		}
		out = append(out, diffSource(as, cs)...)
	}
	for _, as := range ap.Sources {
		if _, found := cp.Source(as.Name); !found {
			out = append(out, kconfig.Change{Field: "sources", Old: as.Name + " (" + as.Kind + ")"})
		}
	}
	return out
}

func diffLimits(a, c Limits) []kconfig.Change {
	var out []kconfig.Change
	num := func(field string, o, n int64, format func(int64) string) {
		if o != n {
			out = append(out, kconfig.Change{Field: "limits." + field, Old: format(o), New: format(n), Loosens: kconfig.LooserLimit(o, n)})
		}
	}
	dur := func(v int64) string { return FormatDuration(time.Duration(v)) }
	itoa := func(v int64) string { return strconv.FormatInt(v, 10) }
	for _, b := range []struct {
		name string
		a, c Budgets
	}{{"local", a.Local, c.Local}, {"remote", a.Remote, c.Remote}} {
		num(b.name+".range", int64(b.a.Range), int64(b.c.Range), dur)
		num(b.name+".count_range", int64(b.a.CountRange), int64(b.c.CountRange), dur)
		num(b.name+".max_bytes", b.a.MaxBytes, b.c.MaxBytes, FormatSize)
		num(b.name+".bytes_per_hour", b.a.BytesPerHour, b.c.BytesPerHour, FormatSize)
		num(b.name+".metric_queries_per_hour", int64(b.a.MetricQueriesPerHour), int64(b.c.MetricQueriesPerHour), itoa)
		num(b.name+".requests_per_minute", int64(b.a.RequestsPerMinute), int64(b.c.RequestsPerMinute), itoa)
	}
	num("max_records", int64(a.MaxRecords), int64(c.MaxRecords), itoa)
	num("max_output", a.MaxOutputBytes, c.MaxOutputBytes, FormatSize)
	num("lookups_per_hour", int64(a.LookupsPerHour), int64(c.LookupsPerHour), itoa)
	num("lookups_per_hour_per_uid", int64(a.LookupsPerHourPerUID), int64(c.LookupsPerHourPerUID), itoa)
	num("pii_adds_per_hour", int64(a.PIIAddsPerHour), int64(c.PIIAddsPerHour), itoa)
	num("pii_rules_max", int64(a.PIIRulesMax), int64(c.PIIRulesMax), itoa)
	return out
}

func diffSource(a, c Source) []kconfig.Change {
	pre := "sources." + c.Name + "."
	var out []kconfig.Change
	// Another kind, format or line assembly reads the same bytes another
	// way: every change is reviewed.
	same := func(field, o, n string) {
		if o != n {
			out = append(out, kconfig.Change{Field: pre + field, Old: o, New: n, Loosens: true})
		}
	}
	same("kind", a.Kind, c.Kind)
	same("format", a.Format, c.Format)
	same("multiline", a.Multiline, c.Multiline)
	out = append(out, kconfig.SetDiff(pre+"trusted", a.Trusted, c.Trusted, false)...)
	out = append(out, kconfig.SetDiff(pre+"paths", kconfig.SortedSet(a.Paths), kconfig.SortedSet(c.Paths), false)...)
	if a.Recursive != c.Recursive {
		out = append(out, kconfig.Change{Field: pre + "recursive", Old: strconv.FormatBool(a.Recursive), New: strconv.FormatBool(c.Recursive), Loosens: c.Recursive})
	}
	switch au, cu := kconfig.SortedSet(a.Units), kconfig.SortedSet(c.Units); {
	case len(au) > 0 && len(cu) == 0:
		out = append(out, kconfig.Change{Field: pre + "units", Old: strings.Join(au, ", "), New: "(every unit)", Loosens: true})
	case len(au) == 0 && len(cu) > 0:
		if a.Kind == KindJournald {
			out = append(out, kconfig.Change{Field: pre + "units", Old: "(every unit)", New: strings.Join(cu, ", ")})
		} else {
			out = append(out, kconfig.SetDiff(pre+"units", au, cu, false)...)
		}
	default:
		out = append(out, kconfig.SetDiff(pre+"units", au, cu, false)...)
	}
	out = append(out, kconfig.SetDiff(pre+"allow", kconfig.SortedSet(a.Allow), kconfig.SortedSet(c.Allow), false)...)
	out = append(out, kconfig.SetDiff(pre+"containers", kconfig.SortedSet(a.Containers), kconfig.SortedSet(c.Containers), false)...)
	out = append(out, kconfig.SetDiff(pre+"attrs", kconfig.SortedSet(a.Attrs), kconfig.SortedSet(c.Attrs), false)...)

	ar, cr := a.Remote, c.Remote
	switch {
	case ar == nil && cr == nil:
	case ar == nil || cr == nil:
		out = append(out, kconfig.Change{Field: pre + "remote", Old: remoteString(ar), New: remoteString(cr), Loosens: cr != nil})
	default:
		same("url", ar.URL, cr.URL)
		same("selector", selectorString(ar.Selector), selectorString(cr.Selector))
		same("auth", ar.Auth, cr.Auth)
		same("org_id", ar.OrgID, cr.OrgID)
		out = append(out, kconfig.SetDiff(pre+"trusted_labels", ar.TrustedLabels, cr.TrustedLabels, false)...)
		out = append(out, kconfig.SetDiff(pre+"trusted_metadata", ar.TrustedMetadata, cr.TrustedMetadata, false)...)
		for _, ch := range kconfig.DiffBase(ar.Base, cr.Base) {
			ch.Field = pre + ch.Field
			out = append(out, ch)
		}
	}
	return out
}

func selectorString(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + strconv.Quote(m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func remoteString(r *Remote) string {
	if r == nil {
		return "(none)"
	}
	return r.URL + " " + selectorString(r.Selector)
}

// Describe is the policy as lines for the console's status and review
// screens.
func (p Policy) Describe() []string {
	c := Canonical(p)
	pr := c.Profile
	l := pr.Limits
	lines := []string{
		fmt.Sprintf("production: %t · structured: %s · text: %s · unmask: %s · lookup: %s · strict: %t",
			pr.Production, pr.Structured, pr.Text, pr.Unmask, pr.Lookup, pr.Strict),
		"detectors: " + strings.Join(pr.Detectors, ", ") + " (secrets: always)",
		fmt.Sprintf("pseudonyms: rotation %s · max age %s", pr.PseudonymRotation, FormatDuration(pr.PseudonymMaxAge)),
		fmt.Sprintf("local budgets: range %s · count range %s · %s per call · %s per hour",
			FormatDuration(l.Local.Range), FormatDuration(l.Local.CountRange), FormatSize(l.Local.MaxBytes), FormatSize(l.Local.BytesPerHour)),
		fmt.Sprintf("remote budgets: range %s · count range %s · %s per call · %s per hour · %d metric queries per hour · %d requests per minute",
			FormatDuration(l.Remote.Range), FormatDuration(l.Remote.CountRange), FormatSize(l.Remote.MaxBytes), FormatSize(l.Remote.BytesPerHour),
			l.Remote.MetricQueriesPerHour, l.Remote.RequestsPerMinute),
		fmt.Sprintf("output: %d records · %s · lookups %d/h (%d/h per uid) · agent rules %d/h, %d at most",
			l.MaxRecords, FormatSize(l.MaxOutputBytes), l.LookupsPerHour, l.LookupsPerHourPerUID, l.PIIAddsPerHour, l.PIIRulesMax),
		fmt.Sprintf("session: idle %s · max %s", pr.IdleTimeout, pr.MaxSession),
	}
	if pr.Prefilter {
		lines = append(lines, "prefilter: ON (latency reveals how many records hold a clear substring)")
	}
	if pr.UserJournals {
		lines = append(lines, "user journals: served")
	}
	if c.Network != "" {
		lines = append(lines, "network: "+c.Network)
	}
	for _, r := range c.ExtraRoots {
		lines = append(lines, "extra root: "+r)
	}
	for _, s := range pr.Sources {
		lines = append(lines, describeSource(s)...)
	}
	return lines
}

func describeSource(s Source) []string {
	head := fmt.Sprintf("source %s (%s, format %s, multiline %s)", s.Name, s.Kind, s.Format, s.Multiline)
	lines := []string{head}
	item := func(label string, v []string) {
		if len(v) > 0 {
			lines = append(lines, "  "+label+": "+strings.Join(v, ", "))
		}
	}
	switch s.Kind {
	case KindFile:
		item("paths", s.Paths)
		if s.Recursive {
			lines = append(lines, "  recursive")
		}
	case KindJournald:
		if len(s.Units) == 0 {
			lines = append(lines, "  units: every unit")
		}
		item("units", s.Units)
		item("allow", s.Allow)
	case KindDocker:
		item("containers", s.Containers)
		item("attrs", s.Attrs)
	case KindLoki:
		r := s.Remote
		lines = append(lines, "  url: "+r.URL, "  selector: "+selectorString(r.Selector),
			fmt.Sprintf("  auth: %s · tls: %s · credentials: %s", r.Auth, r.TLS, r.Credentials))
		if r.OrgID != "" {
			lines = append(lines, "  org_id: "+r.OrgID)
		}
		item("trusted labels", r.TrustedLabels)
		item("trusted metadata", r.TrustedMetadata)
	}
	item("trusted", s.TrustedFields())
	return lines
}
