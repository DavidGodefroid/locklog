package logconsole

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"time"

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
	// Tool is the tool an approved scan runs (log.scan).
	Tool string `json:"tool,omitempty"`
	// Pseudonyms name what an unmask revealed or a lookup resolved, by
	// pseudonym only (never the clear values).
	Pseudonyms []string `json:"pseudonyms,omitempty"`
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
		// A scan's tool and its parameters (the same scope inside).
		Tool  string          `json:"tool"`
		Query json.RawMessage `json:"query"`
	}
	known := map[string]bool{}
	if p, ok := env.Policy().(Policy); ok {
		for _, s := range p.Policy.Profile.Sources {
			known[s.Name] = true
		}
	}
	ok := json.Unmarshal(params, &scope) == nil
	if ok && method == MethodScan {
		switch scope.Tool {
		case "search", "count", "patterns", "trace":
			r.Tool = scope.Tool
		}
		inner := scope.Query
		scope.Sources, scope.From, scope.To = nil, "", ""
		ok = json.Unmarshal(inner, &scope) == nil
	}
	if ok {
		// Only names of the profile's sources: anything else the agent
		// typed is its text, and may be a value.
		for _, s := range scope.Sources {
			if len(r.Sources) < 32 && known[s] && !slices.Contains(r.Sources, s) {
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

// relativeRe is a relative range: a number and a unit.
var relativeRe = regexp.MustCompile(`^[0-9]{1,6}[smhd]$`)

// validTime is an RFC 3339 time or a relative range ("1h", "7d"): never
// any other text the agent typed.
func validTime(s string) bool {
	if relativeRe.MatchString(s) {
		return true
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}
