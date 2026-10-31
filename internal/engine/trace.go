package engine

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// TraceQuery is a trace (locklog_trace): the records of a range that carry
// one id (a request or trace id shown in clear) or one pseudonym, across
// sources, as one timeline.
type TraceQuery struct {
	Sources []string `json:"sources,omitempty"`
	// ID is a clear id (as the agent saw it in a result) or a pseudonym
	// ⟦kind:ID⟧.
	ID   string    `json:"id"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Last, when set, resolves the range at validation (see Query).
	Last   string   `json:"last,omitempty"`
	Fields []string `json:"fields,omitempty"`
	Limit  int      `json:"limit,omitempty"`
	Cursor string   `json:"cursor,omitempty"`
}

// traceID is the validated id of a trace.
type traceID struct {
	id    string
	token bool // a pseudonym placeholder
}

// match reports whether a masked record carries the id: a scalar leaf of
// its fields or labels equal to it, or (for a string leaf or the message)
// the id as a whole word of its masked view. A pseudonym matches its
// placeholder only; a clear id is matched on the evaluation string E, so it
// never matches inside a placeholder (no clear-text oracle).
func (t *traceID) match(rec mask.Record, b *budget) bool {
	if t.inText(rec.Message(), b) {
		return true
	}
	found := false
	var walk func(v mask.Value)
	walk = func(v mask.Value) {
		if found || b.exceeded() {
			return
		}
		switch v.Kind() {
		case mask.Object:
			for _, f := range v.Members() {
				walk(f.Value())
			}
		case mask.Array:
			for _, it := range v.Items() {
				walk(it)
			}
		case mask.String:
			found = t.inText(v.Text(), b)
		case mask.Number, mask.Bool:
			if b.charge(leafCost + int64(len(v.Text()))) {
				return
			}
			found = v.Text() == t.id
		}
	}
	for _, fs := range [][]mask.Field{rec.Fields(), rec.Attrs()} {
		for _, f := range fs {
			walk(f.Value())
		}
	}
	return found && !b.exceeded()
}

// inText reports whether a masked text holds the id.
func (t *traceID) inText(s string, b *budget) bool {
	if s == "" {
		return false
	}
	if b.charge(leafCost + int64(len(s))) {
		return false
	}
	if t.token {
		return strings.Contains(s, t.id)
	}
	return containsWord(evalString(s), t.id)
}

// containsWord reports whether w occurs in s with no letter or digit
// directly before or after it.
func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		before, _ := utf8.DecodeLastRuneInString(s[:j])
		after, _ := utf8.DecodeRuneInString(s[j+len(w):])
		if !wordRune(before) && !wordRune(after) {
			return true
		}
		_, n := utf8.DecodeRuneInString(s[j:])
		i = j + n
	}
	return false
}

func wordRune(r rune) bool {
	return r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

// traceID checks a trace id: a pseudonym placeholder, or printable
// clear text that no detector flags (a clear value of personal data is
// refused: locklog_lookup gives its pseudonym).
func (v *validator) traceID(id string) (*traceID, *Error) {
	if isToken(id) {
		if len(id) > MaxNeedle {
			return nil, refuse(EBadQuery, "id", "want 1 to %d bytes", MaxNeedle)
		}
		return &traceID{id: id, token: true}, nil
	}
	if strings.TrimSpace(id) != id {
		return nil, refuse(EBadQuery, "id", "an id has no leading or trailing spaces")
	}
	if err := v.needle(id, "id"); err != nil {
		return nil, err
	}
	return &traceID{id: id}, nil
}

// Trace runs a trace (locklog_trace). It is a search for the id over the
// range, with the same validation, plan, budgets, stopping points and
// cursors; each page is in time order across the sources of the call
// (untimed records last), and continuations follow the plan.
func (e *Engine) Trace(ctx context.Context, tq TraceQuery) (SearchResult, error) {
	q := Query{Sources: tq.Sources, From: tq.From, To: tq.To, Last: tq.Last, Fields: tq.Fields, Limit: tq.Limit, Cursor: tq.Cursor}
	tr, err := e.validator(0).traceID(tq.ID)
	if err != nil {
		return SearchResult{}, err
	}
	q.trace = tr
	return e.search(ctx, q, "trace")
}
