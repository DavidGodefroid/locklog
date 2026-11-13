package session

import (
	"errors"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mask"
)

var _ logconsole.AgentRuler = (*Session)(nil)

// AgentRuleStatus counts the agent's masking rules: in all, added in the
// last hour, and the last one's time.
type AgentRuleStatus struct {
	Rules        int        `json:"rules"`
	AddsLastHour int        `json:"adds_last_hour"`
	LastAdd      *time.Time `json:"last_add,omitempty"`
}

// agentPattern splits a pii.add pattern: an optional mode ("redact " or
// "pseudonym "; redact when left out), an optional source ("app:"; the
// profile's only source when left out), and the field as the records
// show it (a masked name by its ⟦key:ID⟧).
func (s *Session) agentPattern(p string) (mode, source, path string, ok bool) {
	mode = mask.ModeRedact
	for _, m := range []string{mask.ModeRedact, mask.ModePseudonym} {
		if rest, cut := strings.CutPrefix(p, m+" "); cut {
			mode, p = m, rest
			break
		}
	}
	if src, rest, cut := strings.Cut(p, ":"); cut {
		if _, known := s.cfg[src]; known {
			return mode, src, rest, rest != ""
		}
	}
	if len(s.names) == 1 && p != "" {
		return mode, s.names[0], p, true
	}
	return "", "", "", false
}

// CheckAgentRule implements logconsole.AgentRuler.
func (s *Session) CheckAgentRule(pattern string) (string, *logconsole.Refusal) {
	mode, source, path, ok := s.agentPattern(pattern)
	if !ok {
		return "", agentRefusal(mask.ErrUnknownField)
	}
	r, err := s.maskers.of(source).CheckAgentRule(source, path, mode, s.now(), s.agent)
	if err != nil {
		if ref := agentRefusal(err); ref != nil {
			return "", ref
		}
		return "", &logconsole.Refusal{Message: "the rule could not be checked", Info: refusal.Info{Code: engine.EMask, Retry: refusal.RetryStop}}
	}
	return r.String(), nil
}

// AddAgentRule implements logconsole.AgentRuler.
func (s *Session) AddAgentRule(canonical string) (*logconsole.Refusal, error) {
	r, err := mask.ParseAgentRule(canonical)
	if err != nil {
		return nil, err
	}
	if s.rules == nil || s.rules.Agent == nil {
		return nil, errors.New("no PII directory for agent rules")
	}
	if err := s.rules.Agent.Add(r, s.now(), s.agent); err != nil {
		if ref := agentRefusal(err); ref != nil {
			return ref, nil
		}
		return nil, err
	}
	return nil, nil
}

// PIIRules implements logconsole.AgentRuler: the rules in force, masked
// as any text the agent gets. An agent rule is listed by its mode and
// when it was added: its field is known by a keyed digest only.
func (s *Session) PIIRules() (maskRules, allow []string) {
	if s.rules == nil {
		return nil, nil
	}
	text := s.maskers.base.Text
	for _, r := range s.rules.Mask {
		t := text(r.Text())
		if r.Managed {
			t += " (managed)"
		}
		maskRules = append(maskRules, t)
	}
	if s.rules.Agent != nil {
		for _, a := range s.rules.Agent.List() {
			maskRules = append(maskRules, "agent "+a.Mode+" (added "+a.Added.UTC().Format(time.RFC3339)+")")
		}
	}
	for _, r := range s.rules.Allow {
		allow = append(allow, text(r.Text()))
	}
	return maskRules, allow
}

// agentRefusal is the agent's refusal of a rule the masker refused, nil
// for an error that is not a refusal. Its texts are fixed: they quote
// nothing of the pattern.
func agentRefusal(err error) *logconsole.Refusal {
	info := refusal.Info{Code: engine.EBadQuery, Retry: refusal.RetryRewrite}
	var msg string
	switch {
	case errors.Is(err, mask.ErrUnknownField):
		info.Code, msg = engine.EUnknownField, "no such field was shown: name it as the records show it, as source:field (the source may be left out with one source), a masked name by its ⟦key:ID⟧"
		info.Hint = hints[engine.EUnknownField]
	case errors.Is(err, mask.ErrPIIInQuery):
		info.Code, msg = engine.EPIIInQuery, "the pattern holds a personal value, a secret or a glob: name one field"
	case errors.Is(err, mask.ErrRuleCap):
		info.Code, info.Retry, msg = engine.EOverBudget, refusal.RetryAskUser, "the agent's masking rules are capped (pii_adds_per_hour, pii_rules_max): tell the user which field to mask"
	case errors.Is(err, mask.ErrRuleExists):
		info.Retry, msg = refusal.RetryStop, "a rule already decides this field"
	case errors.Is(err, mask.ErrRuleMode):
		msg = "an agent rule is redact or pseudonym"
	default:
		return nil
	}
	return &logconsole.Refusal{Message: msg, Info: info}
}
