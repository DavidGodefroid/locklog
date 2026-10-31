package config

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// Source kinds.
const (
	KindFile     = "file"
	KindJournald = "journald"
	KindDocker   = "docker"
	KindLoki     = "loki"
)

// Kinds lists the source kinds in a fixed order.
var Kinds = []string{KindFile, KindJournald, KindDocker, KindLoki}

// Formats of log lines. "auto" detects the format per line.
var Formats = []string{"auto", "json", "logfmt", "syslog", "cri", "docker-json", "combined", "plain"}

// Multiline modes: how lines are assembled into events. "indent" joins a
// line that starts with whitespace to the event before it (stack traces).
var Multilines = []string{"none", "indent"}

// Auth modes of a remote source.
const (
	AuthNone   = "none"
	AuthBasic  = "basic"
	AuthBearer = "bearer"
	AuthMTLS   = "mtls"
)

// JournaldTrusted are the journald fields locklog trusts: shown in clear
// (after the detectors) and selectable. MESSAGE is text, masked.
var JournaldTrusted = []string{"CODE_FILE", "CODE_FUNC", "CODE_LINE", "CONTAINER_NAME", "PRIORITY",
	"SYSLOG_IDENTIFIER", "_HOSTNAME", "_PID", "_SYSTEMD_UNIT", "_TRANSPORT"}

// parserTrusted are the fields a parser knows and trusts, per format:
// they are never redacted by redact-unknown.
var parserTrusted = map[string][]string{
	"combined":    {"method", "status"},
	"cri":         {"stream"},
	"docker-json": {"stream"},
}

// Source is one approved log source of a profile. It never holds a secret.
type Source struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Format is the format of a line (of the message, for journald,
	// containers and Loki); Multiline how lines become events.
	Format    string `json:"format"`
	Multiline string `json:"multiline"`
	// Trusted are the fields the human trusts beyond the parser's own:
	// shown in clear after the detectors, selectable and countable.
	Trusted []string `json:"trusted"`

	// File: absolute path globs; ** (one per glob) only when Recursive.
	Paths     []string `json:"paths,omitempty"`
	Recursive bool     `json:"recursive,omitempty"`

	// journald: the units served (empty: every unit), extra fields
	// allowed besides the trusted ones and MESSAGE.
	Units []string `json:"units,omitempty"`
	Allow []string `json:"allow,omitempty"`

	// Docker: container name globs, and the json-file attrs allowed.
	Containers []string `json:"containers,omitempty"`
	Attrs      []string `json:"attrs,omitempty"`

	// Loki.
	Remote *Remote `json:"remote,omitempty"`
}

// Remote is the connection and server-side scope of a remote source.
type Remote struct {
	URL string `json:"url"`
	// Selector is ANDed into every query: label = value.
	Selector map[string]string `json:"selector"`
	// TrustedLabels and TrustedMetadata are shown (after the detectors)
	// and selectable; every other label and field is dropped.
	TrustedLabels   []string `json:"trusted_labels"`
	TrustedMetadata []string `json:"trusted_metadata"`
	Auth            string   `json:"auth"`
	OrgID           string   `json:"org_id,omitempty"`
	// Base holds user, credentials, vault_path and the TLS settings.
	kconfig.Base
}

// TrustedFields is every field of s locklog trusts: the parser's known
// fields (and journald's) plus the human's, sorted.
func (s Source) TrustedFields() []string {
	out := slices.Clone(s.Trusted)
	out = append(out, parserTrusted[s.Format]...)
	if s.Kind == KindJournald {
		out = append(out, JournaldTrusted...)
	}
	return kconfig.SortedSet(out)
}

type rawSource struct {
	Kind            string            `toml:"kind"`
	Format          string            `toml:"format"`
	Multiline       string            `toml:"multiline"`
	Trusted         []string          `toml:"trusted"`
	Paths           []string          `toml:"paths"`
	Recursive       bool              `toml:"recursive"`
	Units           []string          `toml:"units"`
	Allow           []string          `toml:"allow"`
	Containers      []string          `toml:"containers"`
	Attrs           []string          `toml:"attrs"`
	URL             string            `toml:"url"`
	Selector        map[string]string `toml:"selector"`
	TrustedLabels   []string          `toml:"trusted_labels"`
	TrustedMetadata []string          `toml:"trusted_metadata"`
	Auth            string            `toml:"auth"`
	OrgID           string            `toml:"org_id"`
	User            string            `toml:"user"`
	Credentials     string            `toml:"credentials"`
	VaultPath       string            `toml:"vault_path"`
	TLS             string            `toml:"tls"`
	TLSCA           string            `toml:"tls_ca"`
	TLSCert         string            `toml:"tls_cert"`
	TLSKey          string            `toml:"tls_key"`
}

var (
	sourceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	fieldNameRe  = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@-]{0,127}$`)
	journalRe    = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)
	unitRe       = regexp.MustCompile(`^[A-Za-z0-9@._:*?-]{1,255}$`)
	containerRe  = regexp.MustCompile(`^[A-Za-z0-9*?][A-Za-z0-9_.*?-]{0,127}$`)
	labelRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	orgIDRe      = regexp.MustCompile(`^[A-Za-z0-9_.!*'()-]{1,150}$`)
)

// ConsolePrefix starts the name of every locklog console container. A
// container glob that can match any name with this prefix is refused; the
// docker source also skips console containers by label and id when it
// reads, whatever the glob.
const ConsolePrefix = "locklog-console"

// canMatchPrefix reports whether the container glob g (literals, '*' and
// '?' only, as containerRe allows) matches at least one name that starts
// with prefix. It runs the glob as an automaton over the prefix: once the
// prefix is consumed, any remaining pattern still matches some suffix.
func canMatchPrefix(g, prefix string) bool {
	states := closure(g, map[int]bool{0: true})
	for i := 0; i < len(prefix) && len(states) > 0; i++ {
		next := map[int]bool{}
		for st := range states {
			if st >= len(g) {
				continue
			}
			switch g[st] {
			case '*':
				next[st] = true // '*' absorbs the character
			case '?':
				next[st+1] = true
			default:
				if g[st] == prefix[i] {
					next[st+1] = true
				}
			}
		}
		states = closure(g, next)
	}
	return len(states) > 0
}

// closure adds, for every state on a '*', the state after it ('*' matching
// the empty string).
func closure(g string, states map[int]bool) map[int]bool {
	for changed := true; changed; {
		changed = false
		for st := range states {
			if st < len(g) && g[st] == '*' && !states[st+1] {
				states[st+1] = true
				changed = true
			}
		}
	}
	return states
}

// neverAllowed reports a journald field no allow or trusted rule can name:
// core dumps, command lines, executables, audit records, and every OBJECT_
// field (the process a core dump or a log record is about).
func neverAllowed(f string) bool {
	for _, p := range []string{"COREDUMP", "_COREDUMP", "_AUDIT_", "AUDIT_", "OBJECT_"} {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	return strings.HasSuffix(f, "CMDLINE") || strings.HasSuffix(f, "_EXE") || f == "EXE"
}

// messageFields are the names parsers give the message text of a line
// (JSON, logfmt, docker-json, cri, syslog): never trusted.
var messageFields = []string{"msg", "message", "log", "line", "text", "body", "content", "error", "err", "exception", "stack", "stacktrace", "stack_trace"}

func messageField(f string) bool {
	lf := strings.ToLower(f)
	if i := strings.LastIndexByte(lf, '.'); i >= 0 {
		lf = lf[i+1:]
	}
	return slices.Contains(messageFields, lf) || lf == "syslog_raw"
}

// checkJournaldField validates a journald field name an allow or trusted
// list names.
func checkJournaldField(key, f string) error {
	switch {
	case !journalRe.MatchString(f):
		return fmt.Errorf("%s: invalid journald field name %q (upper-case letters, digits and '_')", key, f)
	case neverAllowed(f):
		return fmt.Errorf("%s: %s can never be served (core dumps, command lines, executables, audit records and OBJECT_ fields stay dropped)", key, f)
	case f == "MESSAGE" || f == "SYSLOG_RAW":
		return fmt.Errorf("%s: %s holds the message text, always served masked; it cannot be listed", key, f)
	}
	return nil
}

func buildSource(name string, r rawSource, production bool) (Source, error) {
	errf := func(format string, a ...any) error {
		return fmt.Errorf("source %q: "+format, append([]any{name}, a...)...)
	}
	if !sourceNameRe.MatchString(name) {
		return Source{}, fmt.Errorf("invalid source name %q: use 1 to 48 lower-case letters, digits, '_' or '-', starting with a letter or digit", name)
	}
	s := Source{Name: name, Kind: r.Kind, Format: r.Format, Multiline: r.Multiline, Recursive: r.Recursive}
	if !slices.Contains(Kinds, s.Kind) {
		return Source{}, errf("kind: want one of %s", strings.Join(Kinds, ", "))
	}
	if s.Format == "" {
		s.Format = "auto"
	}
	if !slices.Contains(Formats, s.Format) {
		return Source{}, errf("format: want one of %s", strings.Join(Formats, ", "))
	}
	if s.Multiline == "" {
		s.Multiline = "none"
	}
	if !slices.Contains(Multilines, s.Multiline) {
		return Source{}, errf("multiline: want one of %s", strings.Join(Multilines, ", "))
	}
	for _, f := range r.Trusted {
		if s.Kind == KindJournald {
			if err := checkJournaldField("trusted", f); err != nil {
				return Source{}, errf("%v", err)
			}
		}
		if !fieldNameRe.MatchString(f) {
			return Source{}, errf("trusted: invalid field name %q", f)
		}
		if messageField(f) {
			return Source{}, errf("trusted: %s is the message text of a parsed line, always served masked; it cannot be trusted", f)
		}
		if pii.LooksPersonal(f) || pii.LooksQuasi(f) {
			return Source{}, errf("trusted: %q looks like personal data and cannot be trusted (its values would reach the agent in clear)", f)
		}
	}
	s.Trusted = kconfig.SortedSet(r.Trusted)

	// Keys of another kind are refused rather than ignored.
	type keyed struct {
		key string
		set bool
	}
	only := func(kind string, keys ...keyed) error {
		if s.Kind == kind {
			return nil
		}
		for _, k := range keys {
			if k.set {
				return errf("%s applies only to kind = %q", k.key, kind)
			}
		}
		return nil
	}
	remoteSet := r.URL != "" || r.Selector != nil || r.TrustedLabels != nil || r.TrustedMetadata != nil || r.Auth != "" ||
		r.OrgID != "" || r.User != "" || r.Credentials != "" || r.VaultPath != "" || r.TLS != "" || r.TLSCA != "" || r.TLSCert != "" || r.TLSKey != ""
	for _, err := range []error{
		only(KindFile, keyed{"paths", r.Paths != nil}, keyed{"recursive", r.Recursive}),
		only(KindJournald, keyed{"units", r.Units != nil}, keyed{"allow", r.Allow != nil}),
		only(KindDocker, keyed{"containers", r.Containers != nil}, keyed{"attrs", r.Attrs != nil}),
		only(KindLoki, keyed{"url, selector, auth and the connection keys", remoteSet}),
	} {
		if err != nil {
			return Source{}, err
		}
	}

	switch s.Kind {
	case KindFile:
		if len(r.Paths) == 0 {
			return Source{}, errf("paths: a file source needs at least one absolute path glob")
		}
		for _, p := range r.Paths {
			if err := checkPathGlob(p, r.Recursive); err != nil {
				return Source{}, errf("paths: %v", err)
			}
		}
		s.Paths = kconfig.SortedSet(r.Paths)
	case KindJournald:
		for _, u := range r.Units {
			if !unitRe.MatchString(u) {
				return Source{}, errf("units: invalid unit name or glob %q", u)
			}
			if _, err := path.Match(u, ""); err != nil {
				return Source{}, errf("units: invalid glob %q", u)
			}
		}
		for _, f := range r.Allow {
			if err := checkJournaldField("allow", f); err != nil {
				return Source{}, errf("%v", err)
			}
			if slices.Contains(JournaldTrusted, f) {
				return Source{}, errf("allow: %s is always served; remove it", f)
			}
		}
		s.Units = kconfig.SortedSet(r.Units)
		s.Allow = kconfig.SortedSet(r.Allow)
	case KindDocker:
		if len(r.Containers) == 0 {
			return Source{}, errf("containers: a docker source needs at least one container name or glob")
		}
		for _, c := range r.Containers {
			if !containerRe.MatchString(c) {
				return Source{}, errf("containers: invalid container name or glob %q", c)
			}
			if canMatchPrefix(c, ConsolePrefix) {
				return Source{}, errf("containers: %q can match a locklog console container (%s*), whose logs are never served", c, ConsolePrefix)
			}
		}
		for _, a := range r.Attrs {
			if !fieldNameRe.MatchString(a) {
				return Source{}, errf("attrs: invalid attribute name %q", a)
			}
		}
		s.Containers = kconfig.SortedSet(r.Containers)
		s.Attrs = kconfig.SortedSet(r.Attrs)
	case KindLoki:
		rem, err := buildRemote(r, production, errf)
		if err != nil {
			return Source{}, err
		}
		s.Remote = rem
	}
	return s, nil
}

// checkPathGlob validates one file glob: absolute, clean, no character
// the launcher's mount plan refuses, a valid pattern, and ** only as a
// whole component, once, when recursive.
func checkPathGlob(p string, recursive bool) error {
	if strings.ContainsAny(p, ",=\"'`\\") || strings.IndexFunc(p, kconfig.UnsafeRune) >= 0 || strings.ContainsAny(p, "\n\r\t") {
		return fmt.Errorf("%q holds a character the mount plan refuses (comma, '=', quote, backslash or control)", p)
	}
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("%q: want an absolute, clean path (no '..', '.', '//' or trailing '/')", p)
	}
	if p == "/" {
		return fmt.Errorf("the root directory cannot be a source")
	}
	n := 0
	for _, c := range strings.Split(p[1:], "/") {
		if c == "**" {
			n++
			continue
		}
		if strings.Contains(c, "**") {
			return fmt.Errorf("%q: ** must be a whole path component", p)
		}
		if _, err := path.Match(c, ""); err != nil {
			return fmt.Errorf("%q: invalid glob", p)
		}
	}
	switch {
	case n > 0 && !recursive:
		return fmt.Errorf("%q: ** needs recursive = true", p)
	case n > 1:
		return fmt.Errorf("%q: at most one ** per glob", p)
	case strings.HasSuffix(p, "/**"):
		return fmt.Errorf("%q: ** must be followed by a file name pattern", p)
	}
	if first := strings.Split(p[1:], "/")[0]; strings.ContainsAny(first, "*?[") {
		return fmt.Errorf("%q: the first path component must not be a glob", p)
	}
	return nil
}

func buildRemote(r rawSource, production bool, errf func(string, ...any) error) (*Remote, error) {
	for _, f := range []struct{ key, val string }{{"url", r.URL}, {"user", r.User}, {"vault_path", r.VaultPath},
		{"tls_ca", r.TLSCA}, {"tls_cert", r.TLSCert}, {"tls_key", r.TLSKey}, {"org_id", r.OrgID}} {
		if err := kconfig.CheckValue(product.P, f.key, f.val); err != nil {
			return nil, errf("%v", err)
		}
	}
	rem := &Remote{
		URL: r.URL, Auth: r.Auth, OrgID: r.OrgID,
		Selector:        map[string]string{},
		TrustedLabels:   kconfig.SortedSet(r.TrustedLabels),
		TrustedMetadata: kconfig.SortedSet(r.TrustedMetadata),
		Base: kconfig.Base{User: r.User, Credentials: r.Credentials, VaultPath: r.VaultPath,
			TLS: r.TLS, TLSCA: r.TLSCA, TLSCert: r.TLSCert, TLSKey: r.TLSKey},
	}
	if strings.ContainsAny(rem.User, ":@") || strings.IndexFunc(rem.User, unicode.IsSpace) >= 0 {
		return nil, errf("user: a login name without ':', '@' or spaces (the console asks for the secret)")
	}
	if rem.URL == "" {
		return nil, errf("url is required")
	}
	if strings.Contains(rem.URL, "@") || kconfig.EmbedsPassword(rem.URL) {
		return nil, errf("url must not hold a user or password (set user and auth; the console asks for the secret)")
	}
	u, err := url.Parse(rem.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, errf("url is not a valid http:// or https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errf("url: want http:// or https://")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errf("url must not have a query or a fragment")
	}
	for k, v := range r.Selector {
		if !labelRe.MatchString(k) {
			return nil, errf("selector: invalid label name %q", k)
		}
		if v == "" || strings.IndexFunc(v, kconfig.UnsafeRune) >= 0 || strings.ContainsAny(v, "\"\\`") || len(v) > 1024 {
			return nil, errf("selector: label %s needs a non-empty value without quotes, backslashes or control characters", k)
		}
		rem.Selector[k] = v
	}
	if len(rem.Selector) == 0 {
		return nil, errf("selector: a Loki source needs at least one label matcher, such as selector = { app = \"api\" }")
	}
	for _, l := range append(slices.Clone(r.TrustedLabels), r.TrustedMetadata...) {
		if !labelRe.MatchString(l) {
			return nil, errf("trusted_labels / trusted_metadata: invalid name %q", l)
		}
		if pii.LooksPersonal(l) || pii.LooksQuasi(l) {
			return nil, errf("trusted_labels / trusted_metadata: %q looks like personal data and cannot be trusted", l)
		}
	}
	if rem.OrgID != "" && !orgIDRe.MatchString(rem.OrgID) {
		return nil, errf("org_id: invalid tenant id (one tenant: letters, digits and _.!*'()-; no '|' federation)")
	}

	if rem.Auth == "" {
		return nil, errf("auth is required: none, basic, bearer or mtls")
	}
	switch rem.Auth {
	case AuthNone:
		if production {
			hint := ""
			if rem.OrgID != "" {
				hint = " (an org_id alone is not authentication)"
			}
			return nil, errf("auth = \"none\" is refused on a production profile%s: put the backend behind an authenticating proxy (locklog setup prints one)", hint)
		}
		if rem.User != "" || rem.Credentials != "" || rem.VaultPath != "" {
			return nil, errf("auth = \"none\" takes no user, credentials or vault_path")
		}
	case AuthBasic:
		if rem.User == "" {
			return nil, errf("auth = \"basic\" needs user")
		}
	case AuthBearer:
		if rem.User != "" {
			return nil, errf("auth = \"bearer\" takes no user")
		}
	case AuthMTLS:
		if rem.TLSCert == "" || rem.TLSKey == "" {
			return nil, errf("auth = \"mtls\" needs tls_cert and tls_key")
		}
	default:
		return nil, errf("unknown auth mode (want none, basic, bearer or mtls)")
	}
	needsSecret := rem.Auth == AuthBasic || rem.Auth == AuthBearer
	switch rem.Credentials {
	case "":
		if needsSecret {
			rem.Credentials = kconfig.CredentialsAsk
		}
	case kconfig.CredentialsAsk:
		if !needsSecret {
			return nil, errf("credentials applies only to auth = \"basic\" or \"bearer\"")
		}
	case kconfig.CredentialsVault:
		if !needsSecret {
			return nil, errf("credentials applies only to auth = \"basic\" or \"bearer\"")
		}
		if rem.VaultPath == "" || strings.HasPrefix(rem.VaultPath, "-") || strings.HasPrefix(rem.VaultPath, "/") || strings.ContainsAny(rem.VaultPath, " \t") {
			return nil, errf("credentials = \"vault\" needs vault_path, such as \"secret/data/loki-reader\", without spaces and not starting with '-' or '/'")
		}
	default:
		return nil, errf("unknown credentials mode (want ask or vault; the console runs in a container without a keychain, and never reads a secret from a config file)")
	}
	if rem.Credentials != kconfig.CredentialsVault && rem.VaultPath != "" {
		return nil, errf("vault_path is only used with credentials = \"vault\"")
	}
	if (rem.TLSCert == "") != (rem.TLSKey == "") {
		return nil, errf("tls_cert and tls_key go together: set both, or neither")
	}

	tls := scheme == "https"
	if rem.TLS == "" {
		rem.TLS = kconfig.TLSVerifyFull
		if !tls {
			rem.TLS = kconfig.TLSDisable
		}
	}
	if kconfig.TLSRank(rem.TLS) < 0 {
		return nil, errf("unknown tls mode (want disable, require, verify-ca or verify-full)")
	}
	switch {
	case tls && rem.TLS == kconfig.TLSDisable:
		return nil, errf("tls = \"disable\" with an https:// URL")
	case !tls && rem.TLS != kconfig.TLSDisable:
		return nil, errf("tls = \"%s\" needs an https:// URL", rem.TLS)
	case tls && rem.TLS == kconfig.TLSPrefer:
		return nil, errf("tls = \"prefer\" does not apply to https://; use require, verify-ca or verify-full")
	case !tls && (rem.TLSCA != "" || rem.TLSCert != ""):
		return nil, errf("tls_ca, tls_cert and tls_key need an https:// URL")
	case production && !tls:
		return nil, errf("a production profile needs an https:// URL")
	case production && rem.TLS != kconfig.TLSVerifyFull:
		return nil, errf("a production profile needs tls = \"verify-full\"")
	case !tls && rem.Auth != AuthNone && !kconfig.IsLoopback(u.Hostname()):
		return nil, errf("credentials over plain http:// are refused except on a loopback host; use https://")
	}
	return rem, nil
}
