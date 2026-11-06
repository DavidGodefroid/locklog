package mask

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Refusals of an agent rule (design §4.4 rule 7). The engine maps them to
// E_UNKNOWN_FIELD, E_PII_IN_QUERY and E_OVER_BUDGET.
var (
	ErrUnknownField = errors.New("mask: unknown field")
	ErrPIIInQuery   = errors.New("mask: the rule holds a personal value or a secret (use locklog_lookup)")
	ErrRuleCap      = errors.New("mask: agent rule cap reached")
	ErrRuleExists   = errors.New("mask: a rule already decides this field")
	ErrRuleMode     = errors.New("mask: an agent rule is redact or pseudonym")
)

// AgentLimits cap the agent's rules: per hour and in total. Both must be
// positive: a zero limit refuses every rule (it never means unlimited).
type AgentLimits struct {
	PerHour int
	Total   int
}

// AgentRules are the rules the agent added: they only tighten. They live
// only in the console's PII directory, each field named by a keyed digest
// of (source, clear path), never by its name: neither the project's
// pii.toml nor this directory holds a name that was shown masked
// (round-6 amendment). The key is the directory's rules.key (0600).
type AgentRules struct {
	dir string
	key []byte

	mu      sync.Mutex
	entries []agentEntry

	// digestMemo memoizes digest (keyed, pure): every leaf of every
	// record asks for its path's rule. Bounded (at most maxDigests,
	// then it starts over).
	digestMemo sync.Map // source + "\x00" + clear path -> digest
	nDigests   atomic.Int64
	// generation counts the rules added since the rules were opened.
	generation atomic.Uint64
}

const maxDigests = 4096

type agentEntry struct {
	Digest string    `json:"digest"`
	Mode   string    `json:"mode"`
	Added  time.Time `json:"added"`
}

const (
	agentFile    = "agent-rules.json"
	agentKeyFile = "rules.key"
	digestLabel  = "locklog-agent-rule-v1\x00"
)

// OpenAgentRules opens (creating if needed) the agent rules of a PII
// directory, which must be private to the console (0700).
func OpenAgentRules(dir string) (*AgentRules, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent rules: %w", err)
	}
	// Windows has no Unix modes (the console runs on Linux).
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("agent rules: %s must be a private directory (0700)", dir)
	}
	a := &AgentRules{dir: dir}
	key, err := os.ReadFile(filepath.Join(dir, agentKeyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := writePrivate(dir, agentKeyFile, key); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("agent rules: %w", err)
	case len(key) != 32:
		return nil, errors.New("agent rules: rules.key is corrupt")
	}
	a.key = key
	data, err := os.ReadFile(filepath.Join(dir, agentFile))
	if err == nil {
		if err := json.Unmarshal(data, &a.entries); err != nil {
			return nil, errors.New("agent rules: agent-rules.json is corrupt")
		}
		for _, e := range a.entries {
			if len(e.Digest) != 64 || (e.Mode != ModeRedact && e.Mode != ModePseudonym) {
				return nil, errors.New("agent rules: agent-rules.json is corrupt")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent rules: %w", err)
	}
	return a, nil
}

func (a *AgentRules) digest(source, clearPath string) string {
	k := source + "\x00" + clearPath
	if d, ok := a.digestMemo.Load(k); ok {
		return d.(string)
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(digestLabel + k))
	d := hex.EncodeToString(m.Sum(nil))
	if len(k) <= 512 {
		if a.nDigests.Add(1) > maxDigests {
			a.digestMemo.Clear()
			a.nDigests.Store(1)
		}
		a.digestMemo.Store(k, d)
	}
	return d
}

func (a *AgentRules) lookup(source, clearPath string) (string, bool) {
	a.mu.Lock()
	none := len(a.entries) == 0
	a.mu.Unlock()
	if none {
		return "", false // no rule: no digest to compute (every leaf asks)
	}
	d := a.digest(source, clearPath)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Digest == d {
			return e.Mode, true
		}
	}
	return "", false
}

func (a *AgentRules) digests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		out = append(out, e.Digest+" "+e.Mode)
	}
	slices.Sort(out)
	return out
}

// Len returns the number of agent rules.
func (a *AgentRules) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

func (a *AgentRules) add(source, clearPath, mode string, now time.Time, lim AgentLimits) error {
	return a.Add(AgentRule{Digest: a.digest(source, clearPath), Mode: mode}, now, lim)
}

// AgentRule is an agent rule as CheckAgentRule returns it: the keyed
// digest of its (source, clear path) and its mode, nothing else. Its
// String form is the canonical pattern the console records, prints and
// audits: it never holds a name, clear or as shown.
type AgentRule struct {
	Digest string
	Mode   string
}

// agentRulePrefix starts the canonical form of an agent rule.
const agentRulePrefix = "agent "

// String is the canonical form: "agent <mode> <digest>".
func (r AgentRule) String() string { return agentRulePrefix + r.Mode + " " + r.Digest }

// ParseAgentRule parses the canonical form of an agent rule.
func ParseAgentRule(s string) (AgentRule, error) {
	bad := errors.New("mask: not an agent rule")
	rest, ok := strings.CutPrefix(s, agentRulePrefix)
	if !ok {
		return AgentRule{}, bad
	}
	mode, digest, ok := strings.Cut(rest, " ")
	if !ok || (mode != ModeRedact && mode != ModePseudonym) || !validDigest(digest) {
		return AgentRule{}, bad
	}
	return AgentRule{Digest: digest, Mode: mode}, nil
}

// validDigest is 64 lower-case hex digits.
func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	for i := 0; i < len(d); i++ {
		if c := d[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// allows reports why entries refuse a rule of digest d at now: one
// already there, or a cap reached. a.mu is held.
func (a *AgentRules) allows(d string, now time.Time, lim AgentLimits) error {
	recent := 0
	for _, e := range a.entries {
		if e.Digest == d {
			return ErrRuleExists
		}
		if now.Sub(e.Added) < time.Hour {
			recent++
		}
	}
	if lim.Total <= 0 || lim.PerHour <= 0 || len(a.entries) >= lim.Total || recent >= lim.PerHour {
		return ErrRuleCap
	}
	return nil
}

// Add stores a rule CheckAgentRule returned, checking again, under the
// lock, that no rule has its digest and that the caps allow it.
func (a *AgentRules) Add(r AgentRule, now time.Time, lim AgentLimits) error {
	if (r.Mode != ModeRedact && r.Mode != ModePseudonym) || !validDigest(r.Digest) {
		return errors.New("mask: not an agent rule")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.allows(r.Digest, now, lim); err != nil {
		return err
	}
	entries := append(slices.Clone(a.entries), agentEntry{Digest: r.Digest, Mode: r.Mode, Added: now.UTC()})
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := writePrivate(a.dir, agentFile, data); err != nil {
		return err
	}
	a.entries = entries
	a.generation.Add(1) // after the entries: a reader seeing it sees them
	return nil
}

// AgentStats count the agent's rules: in all, added within the hour
// before now, and the last one's time (zero for none).
type AgentStats struct {
	Rules    int
	LastHour int
	Last     time.Time
}

// Stats returns the counts of the rules at now.
func (a *AgentRules) Stats(now time.Time) AgentStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := AgentStats{Rules: len(a.entries)}
	for _, e := range a.entries {
		if now.Sub(e.Added) < time.Hour {
			st.LastHour++
		}
		if e.Added.After(st.Last) {
			st.Last = e.Added
		}
	}
	return st
}

// AgentListed is an agent rule as listed: its mode and when it was added,
// never its field.
type AgentListed struct {
	Mode  string
	Added time.Time
}

// List returns the rules in the order they were added.
func (a *AgentRules) List() []AgentListed {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AgentListed, len(a.entries))
	for i, e := range a.entries {
		out[i] = AgentListed{Mode: e.Mode, Added: e.Added}
	}
	return out
}

// RulesGeneration changes whenever a rule is added at runtime (an agent
// rule, which TrustedValue applies at once): an answer of TrustedValue
// remembered under one generation must be asked again under another.
func (m *Masker) RulesGeneration() uint64 {
	if m.o.Rules.Agent == nil {
		return 0
	}
	return m.o.Rules.Agent.generation.Load()
}

// AgentAdd adds an agent rule (locklog_pii_add): CheckAgentRule, then
// the rule stored.
func (m *Masker) AgentAdd(source, shownPath, mode string, now time.Time, lim AgentLimits) error {
	r, err := m.CheckAgentRule(source, shownPath, mode, now, lim)
	if err != nil {
		return err
	}
	return m.o.Rules.Agent.Add(r, now, lim)
}

// CheckAgentRule checks an agent rule (locklog_pii_add) without adding
// it: the field named by its shown path (clear names as shown, masked
// names as ⟦key:ID⟧, translated here, in the console, to the clear name).
// It only tightens: the field's names must all have been shown (clear, or
// masked under this epoch), the path holds no glob, no personal value and
// no secret, no human rule decides the field, the mode is redact or
// pseudonym, no agent rule has the field yet and the caps allow one more.
// The rule returned holds the keyed digest of the field, never its name:
// AgentRules.Add stores it in the PII directory only.
func (m *Masker) CheckAgentRule(source, shownPath, mode string, now time.Time, lim AgentLimits) (AgentRule, error) {
	if m.o.Rules == nil || m.o.Rules.Agent == nil {
		return AgentRule{}, errors.New("mask: no PII directory for agent rules")
	}
	if mode != ModeRedact && mode != ModePseudonym {
		return AgentRule{}, ErrRuleMode
	}
	if !validName(source) {
		return AgentRule{}, ErrUnknownField
	}
	if strings.ContainsAny(shownPath, "*?[]") {
		return AgentRule{}, ErrPIIInQuery // no glob: it could probe masked names
	}
	if plain := blankPlaceholders(shownPath); finds(m.o.Values, plain) || finds(m.o.Secrets, plain) || finds(m.o.Rules, plain) {
		return AgentRule{}, ErrPIIInQuery
	}
	parts := splitPath(shownPath)
	clear := make([]string, len(parts))
	masked := false
	for i, p := range parts {
		if strings.HasPrefix(p, Open) {
			masked = true
			id, ok := strings.CutPrefix(strings.TrimSuffix(p, Close), Open+KeyKind+":")
			name, known := m.maskedName(id)
			if !ok || !known {
				return AgentRule{}, ErrUnknownField
			}
			clear[i] = name
			continue
		}
		// A clear name in the path: refuse one holding a value or a
		// secret, and one never shown in clear (it may be a masked name:
		// the answer is the same as for a name that does not exist).
		if finds(m.o.Values, p) || finds(m.o.Secrets, p) || finds(m.o.Rules, p) {
			return AgentRule{}, ErrPIIInQuery
		}
		if !m.shownClear(source, p) {
			return AgentRule{}, ErrUnknownField
		}
		clear[i] = p
	}
	cp := strings.Join(clear, ".")
	// A path through a masked name is matched by its digest only: its
	// shape is not checked.
	if err := checkPath(cp, false); err != nil && !masked {
		return AgentRule{}, ErrUnknownField
	}
	// Through a masked name, the human's rules and trusted fields are not
	// consulted either (their answer would tell of the clear name): the
	// agent's rule only tightens, and a human rule still wins.
	if !masked {
		if _, ok := m.o.Rules.human(source, cp); ok {
			return AgentRule{}, ErrRuleExists
		}
		if m.trusted[cp] {
			return AgentRule{}, ErrRuleExists // trusted by the human: only the human changes it
		}
	}
	a := m.o.Rules.Agent
	r := AgentRule{Digest: a.digest(source, cp), Mode: mode}
	a.mu.Lock()
	err := a.allows(r.Digest, now, lim)
	a.mu.Unlock()
	if err != nil {
		return AgentRule{}, err
	}
	return r, nil
}

// finds reports whether f finds anything in s.
func finds(f Finder, s string) bool { return f != nil && len(f.Find(s)) > 0 }

// writePrivate writes name in dir (0600) atomically.
func writePrivate(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// blankPlaceholders replaces every placeholder of s by a space: their IDs
// are not values.
func blankPlaceholders(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, Open)
		j := strings.Index(s[max(i, 0):], Close)
		if i < 0 || j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteByte(' ')
		s = s[i+j+len(Close):]
	}
}
