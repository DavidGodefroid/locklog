package engine

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"strings"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// The clear view (design §3.6, §4.6 "reveal to the human only"): with the
// console's clear-results switch on (Ctrl-O), the records an agent call
// returned are printed on the console's own terminal with their pseudonyms
// replaced by the clear values they stand for. Secrets and redactions stay
// as they are (⟦secret⟧, ⟦redacted⟧), and so do masked field names. None of
// it is ever part of an answer to the agent: only the console calls these.

// maxClearLine bounds one record of the clear view on the terminal.
const maxClearLine = 8 << 10

// ClearRecords renders the records of refs in clear for the console's
// terminal, one line each, in order. A record that cannot be read again,
// or that changed since its ref was made, is named, not shown.
func (e *Engine) ClearRecords(ctx context.Context, refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		line, err := e.clearRecord(ctx, ref)
		if err != "" {
			line = "(" + err + ")"
		}
		out = append(out, line)
	}
	return out
}

func (e *Engine) clearRecord(ctx context.Context, ref string) (string, string) {
	cm, ok := e.o.Masker.(ClearMasker)
	if !ok {
		return "", "no clear view with this masker"
	}
	rr, digest, err := e.Ref(ref)
	if err != nil {
		return "", "the record's reference is no longer valid"
	}
	src, ok := e.o.Sources[rr.Source]
	if !ok {
		return "", "the record's source is gone"
	}
	cctx, cancel := context.WithTimeout(ctx, e.o.Limits.Deadline)
	defer cancel()
	if e.remote(rr.Source) {
		cctx = source.WithLimiter(cctx, e.limiter(ctx, rr.Source))
	}
	raw, rerr := src.Reread(cctx, rr)
	if rerr != nil {
		return "", "the record could not be read again"
	}
	if subtle.ConstantTimeCompare([]byte(e.RecordDigest(raw.Event.Raw)), []byte(digest)) != 1 {
		return "", "the record changed since it was returned"
	}
	rec, clear := cm.MaskClear(rr.Source, raw.Event)
	if rec.Failed() {
		return "", "the record could not be masked"
	}
	shown, merr := rec.MarshalJSON()
	if merr != nil {
		return "", "the record could not be rendered"
	}
	when := "untimed"
	if t, ok := rec.Time(); ok {
		when = t.UTC().Format(time.RFC3339Nano)
	}
	line := rr.Source + " " + when + " " + clearJSON(string(shown), clear)
	if len(line) > maxClearLine {
		line = line[:maxClearLine] + " …(cut)"
	}
	return line, ""
}

// clearJSON replaces in a masked record's JSON each pseudonym the record
// shows by its clear value, JSON-escaped in place.
func clearJSON(shown string, clear map[string]string) string {
	if len(clear) == 0 {
		return shown
	}
	pairs := make([]string, 0, 2*len(clear))
	for p, v := range clear {
		b, _ := json.Marshal(v)
		pairs = append(pairs, p, strings.TrimSuffix(strings.TrimPrefix(string(b), `"`), `"`))
	}
	return strings.NewReplacer(pairs...).Replace(shown)
}

// clearView renders the unmask screen's record in clear (secrets and
// redactions kept), for the console's terminal only.
func clearView(p unmaskPlan) string {
	return clearJSON(string(p.shown), p.clear)
}
