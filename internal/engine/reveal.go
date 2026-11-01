package engine

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// The clear view (design §3.6, §4.6 "reveal to the human only"): with the
// console's clear-results switch on (Ctrl-O), the records an agent call
// returned are printed on the console's own terminal with their pseudonyms
// replaced by the clear values they stand for. Secrets and redactions stay
// as they are (⟦secret⟧, ⟦redacted⟧), and so do masked field names. None of
// it is ever part of an answer to the agent: only the console calls these.
//
// The records come from the call itself: a ClearSink attached to the call
// keeps the raw records it returned, so the clear view sends no request to
// a backend and draws on no budget of the agent's. A record the call did
// not read (a page served from the result cache) is read again from a local
// source; a remote one is not fetched again.

// maxClearLine bounds one record of the clear view on the terminal.
const maxClearLine = 8 << 10

// maxClearKeep bounds the raw bytes a ClearSink keeps for one call.
const maxClearKeep = 16 << 20

// ClearSink keeps the raw records one call returned, for its clear view.
type ClearSink struct {
	mu    sync.Mutex
	raws  map[source.RawRef]source.RawRecord
	bytes int
}

// NewClearSink returns an empty sink.
func NewClearSink() *ClearSink { return &ClearSink{raws: map[source.RawRef]source.RawRecord{}} }

type clearSinkKey struct{}

// WithClearSink attaches a call's clear-view sink to ctx.
func WithClearSink(ctx context.Context, s *ClearSink) context.Context {
	return context.WithValue(ctx, clearSinkKey{}, s)
}

func clearSinkFrom(ctx context.Context) *ClearSink {
	s, _ := ctx.Value(clearSinkKey{}).(*ClearSink)
	return s
}

// keep records a returned record (nil sink: nothing).
func (s *ClearSink) keep(raw source.RawRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytes+len(raw.Event.Raw) > maxClearKeep {
		return
	}
	k := raw.Ref
	if _, ok := s.raws[k]; !ok {
		s.raws[k] = raw
		s.bytes += len(raw.Event.Raw)
	}
}

func (s *ClearSink) get(r source.RawRef) (source.RawRecord, bool) {
	if s == nil {
		return source.RawRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.raws[r]
	return raw, ok
}

// ClearRecords renders the records of refs in clear for the console's
// terminal, one line each, in order, from sink (the call's own records) or,
// for a local source, by reading the record again; everything under one
// deadline. A record it cannot show is named, not shown.
func (e *Engine) ClearRecords(ctx context.Context, sink *ClearSink, refs []string) []string {
	cctx, cancel := context.WithTimeout(ctx, e.o.Limits.Deadline)
	defer cancel()
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		line, err := e.clearRecord(cctx, sink, ref)
		if err != "" {
			line = "(" + err + ")"
		}
		out = append(out, line)
	}
	return out
}

func (e *Engine) clearRecord(ctx context.Context, sink *ClearSink, ref string) (string, string) {
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
	raw, kept := sink.get(rr)
	if !kept {
		if e.remote(rr.Source) {
			return "", "a remote record is not fetched again for the clear view"
		}
		if ctx.Err() != nil {
			return "", "no time left to read the record again"
		}
		var rerr error
		if raw, rerr = src.Reread(ctx, rr); rerr != nil {
			return "", "the record could not be read again"
		}
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
	return cutLine(rr.Source + " " + when + " " + e.clearJSON(string(shown), clear)), ""
}

// cutLine bounds a line of the clear view, on a rune boundary.
func cutLine(s string) string {
	if len(s) <= maxClearLine {
		return s
	}
	n := maxClearLine
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + " …(cut)"
}

// clearJSON replaces in a masked record's JSON each pseudonym the record
// shows by its clear value, JSON-escaped in place. A value that reads as a
// secret on its own stays masked (as unmask refuses it).
func (e *Engine) clearJSON(shown string, clear map[string]string) string {
	if len(clear) == 0 {
		return shown
	}
	pairs := make([]string, 0, 2*len(clear))
	for p, v := range clear {
		if strings.Contains(v, mask.Open) || strings.Contains(e.o.Masker.Text(v), mask.Secret) {
			continue // held a secret span, or reads as a secret: kept masked
		}
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
		q := strings.TrimSpace(b.String())
		pairs = append(pairs, p, strings.TrimSuffix(strings.TrimPrefix(q, `"`), `"`))
	}
	return strings.NewReplacer(pairs...).Replace(shown)
}

// clearView renders the unmask screen's record in clear (secrets and
// redactions kept), for the console's terminal only.
func (e *Engine) clearView(p unmaskPlan) string {
	return cutLine(e.clearJSON(string(p.shown), p.clear))
}
