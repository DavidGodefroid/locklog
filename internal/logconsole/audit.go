package logconsole

import (
	"context"
	"encoding/json"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/console"
)

// Record is the audit record of one agent call: the method, the sources
// and the range it named, and the outcome. It never holds a predicate, a
// value or a log line: those are the agent's and the logs' text, which the
// detectors may miss.
type Record struct {
	audit.Base
	Method  string   `json:"method"`
	Sources []string `json:"sources,omitempty"`
	From    string   `json:"from,omitempty"`
	To      string   `json:"to,omitempty"`
}

// AuditEvent implements audit.Record.
func (r Record) AuditEvent() string { return r.Event }

// Audit events of locklog's calls.
const EventCall = "log.call"

// newRecord is the record of method with params, stamped with the profile
// and the peer behind ctx. Only the source names and the range (the
// agent's own scope, never content) are kept from params.
func newRecord(ctx context.Context, env console.Env, method string, params json.RawMessage) Record {
	r := Record{Base: audit.Base{Event: EventCall}, Method: method}
	if p := env.Policy(); p != nil {
		r.Profile = p.Profile().Name
	}
	console.StampPeer(ctx, &r.Base)
	var scope struct {
		Sources []string `json:"sources"`
		From    string   `json:"from"`
		To      string   `json:"to"`
	}
	if json.Unmarshal(params, &scope) == nil {
		for _, s := range scope.Sources {
			if len(r.Sources) < 32 && validName(s) {
				r.Sources = append(r.Sources, s)
			}
		}
		if validTime(scope.From) {
			r.From = scope.From
		}
		if validTime(scope.To) {
			r.To = scope.To
		}
	}
	return r
}

// validName is a source name as the config allows it.
func validName(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validTime is an RFC 3339 time or a relative range such as "1h": letters,
// digits and the punctuation of times only, at most 40 characters.
func validTime(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '-' || c == ':' || c == '.' || c == 'T' || c == 'Z' || c == '+' ||
			c == 'h' || c == 'm' || c == 's' || c == 'd') {
			return false
		}
	}
	return true
}
