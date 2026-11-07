package logconsole

import (
	"errors"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// AgentRuler is implemented by an engine that holds the agent's masking
// rules: the console's pii.list and pii.add reach them through the
// backend (console.PIIBackend).
type AgentRuler interface {
	// CheckAgentRule checks a pii.add pattern against what the engine
	// showed and returns the rule's canonical form: its keyed digest and
	// mode, never a field name (a name shown masked must never reach the
	// console's audit, terminal or approved policy). A refusal's text
	// quotes nothing of the pattern.
	CheckAgentRule(pattern string) (canonical string, refused *Refusal)
	// AddAgentRule stores a rule CheckAgentRule returned, in the
	// console's PII directory only (never in .locklog/pii.toml), checking
	// the caps again.
	AddAgentRule(canonical string) (refused *Refusal, err error)
	// PIIRules are the rules in force, as the agent may see them: the
	// human's mask rules, the agent's (by mode and time, never by field)
	// and the approved allow rules.
	PIIRules() (mask, allow []string)
}

var _ console.PIIBackend = (*Backend)(nil)

// PIIRules implements console.PIIBackend: the rules of the engine in
// force, or, with no session open, the approved allow rules of p.
func (b *Backend) PIIRules(p console.Policy) (mask, allow []string) {
	if ar := b.agentRuler(); ar != nil {
		return ar.PIIRules()
	}
	if lp, ok := p.(Policy); ok {
		return nil, slices.Clone(lp.Policy.PIIAllow)
	}
	return nil, nil
}

// CheckMask implements console.PIIBackend. The canonical form it returns
// is what the console prints, saves and audits for the rule: "agent
// <mode> <keyed digest>", never a name. A refusal is audited by the
// console (lockkit v0.13.1: policy/failed, with the client and neither the
// pattern nor this error's text), not here: it would be recorded twice.
func (b *Backend) CheckMask(pattern string) (string, error) {
	b.mu.Lock()
	b.pendingAdd = ""
	b.mu.Unlock()
	ar := b.agentRuler()
	if ar == nil {
		return "", errors.New(errNoPIISessionText)
	}
	canonical, refused := ar.CheckAgentRule(pattern)
	if refused != nil {
		return "", piiRefusal(refused)
	}
	return canonical, nil
}

// SaveMask implements console.PIIBackend: the rule goes to the console's
// PII directory, applied at once by the engine; .locklog/pii.toml is
// never written. A refusal is audited by the console (policy/failed, with
// the client, the canonical pattern and this error's fixed text).
func (b *Backend) SaveMask(pattern string) error {
	ar := b.agentRuler()
	if ar == nil {
		return errors.New(errNoPIISessionText)
	}
	refused, err := ar.AddAgentRule(pattern)
	switch {
	case err != nil:
		b.mu.Lock()
		env := b.env
		b.mu.Unlock()
		if env != nil {
			env.Println("agent rule not saved: " + env.Safe(env.Sanitizer().Error(err)))
		}
		return errors.New(errPIISaveText)
	case refused != nil:
		return piiRefusal(refused)
	}
	// The console records the rule next (its policy record): AuditRecord
	// adds the method and the canonical pattern to that record.
	b.mu.Lock()
	b.pendingAdd = pattern
	b.mu.Unlock()
	return nil
}

// WithMask implements console.PIIBackend: p itself. An agent rule is not
// part of the policy: it lives in the console's PII directory, is applied
// at once by the engine and is counted in the status, so the policy's
// fingerprint (and the open session) stay as they are.
func (b *Backend) WithMask(p console.Policy, _ string) console.Policy { return p }

// PIIRecord is the console's record of a pii.add, with the method: the
// rule's canonical form (a keyed digest, never a name) is the record's
// own pattern (audit.Base.Pattern), absent when the rule was refused
// before it had one.
type PIIRecord struct {
	audit.Base
	Method string `json:"method"`
}

// piiRefusedPrefix is the error class of lockkit's record of a pii.add the
// backend refused (CheckMask, SaveMask: policy/failed, since v0.13.1).
const piiRefusedPrefix = "pii.add refused by the backend: "

// AuditRecord is the console's hook on its own records: the policy record
// of a pii.add (tightened, unsaved or failed, and lockkit's record of a
// refusal by this backend) gets the method, and the canonical pattern
// SaveMask stored when the console's record lacks it. Every other record
// is left as it is.
func (b *Backend) AuditRecord(rec audit.Base) audit.Record {
	if rec.Event != audit.EventPolicy {
		return rec
	}
	b.mu.Lock()
	p := b.pendingAdd
	b.pendingAdd = ""
	b.mu.Unlock()
	switch {
	case p != "":
		if rec.Pattern == "" {
			rec.Pattern = p
		}
	case !strings.HasPrefix(rec.Error, piiRefusedPrefix):
		return rec
	}
	return PIIRecord{Base: rec, Method: ipc.MethodPIIAdd}
}

// errNoPIISessionText refuses a rule while no log session is open: the
// names a rule may name are those the session showed.
const errNoPIISessionText = "no log session: run a log tool first; a rule names a field the records showed"

// errPIISaveText is what the agent and the audit get of a rule that could
// not be saved (the cause is on the console only).
const errPIISaveText = "the rule could not be saved; nothing changed"

// piiRefusal is the agent's error for a refused rule: the engine's fixed
// text and code, then its hint.
func piiRefusal(r *Refusal) error {
	msg := string(r.Info.Code) + ": " + r.Message
	if r.Info.Hint != "" {
		msg += " (" + r.Info.Hint + ")"
	}
	return errors.New(msg)
}

// agentRuler is the open session's engine, if it holds agent rules.
func (b *Backend) agentRuler() AgentRuler {
	b.mu.Lock()
	s := b.cur
	b.mu.Unlock()
	if s == nil || s.closed() {
		return nil
	}
	ar, _ := s.engine.(AgentRuler)
	return ar
}
