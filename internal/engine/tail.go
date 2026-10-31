package engine

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"time"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Tail bounds (design §3.1).
const (
	MaxTailDuration = 50 * time.Second
	DefaultTailMax  = 100
	// DefaultTailPoll is the interval between polls of a tail.
	DefaultTailPoll = time.Second
	// tailGrace is how long the last poll may run past the duration.
	tailGrace = 2 * time.Second
	// maxTailSeen bounds the remote records a tail remembers.
	maxTailSeen = 100_000
	// maxTailStale bounds the polls replanned after E_STALE.
	maxTailStale = 3
)

// TailQuery is a tail (locklog_tail): the new records matching a filter
// for up to Duration, at most Max of them.
type TailQuery struct {
	Sources  []string `json:"sources,omitempty"`
	Where    []Pred   `json:"where,omitempty"`
	Text     string   `json:"text,omitempty"`
	Regex    string   `json:"regex,omitempty"`
	Fields   []string `json:"fields,omitempty"`
	Duration string   `json:"duration,omitempty"` // default and ceiling 50s
	Max      int      `json:"max,omitempty"`
}

// TailResult is the answer of a tail: the new records in time order.
// Complete is false when the tail may have left records out: it stopped
// early (at max, a poll failed or could not cover what was written, the
// call's byte budget ran out), the output cap dropped records, a record was
// still being written at the end, or records without a time were seen
// (they are never tailed: search them).
type TailResult struct {
	Epoch          string            `json:"epoch"`
	Records        []json.RawMessage `json:"records"`
	Complete       bool              `json:"complete"`
	Scanned        Scanned           `json:"scanned"`
	Masking        Masking           `json:"masking"`
	MaskedFailures int               `json:"masked_failures,omitempty"`
}

// pos is a record position within its stream, in the source's ref units,
// ordered by offset then length (a Loki ref's length is an ordinal).
type pos struct{ off, length int64 }

func (a pos) after(b pos) bool { return a.off > b.off || a.off == b.off && a.length > b.length }

type streamKey [2]string

func keyOf(r source.RawRef) streamKey { return streamKey{r.Source, r.Stream} }

// held is a local stream's last record seen: it may still be being written
// (a partial line, a multi-line record growing), so it is evaluated only
// once a later record follows it (a later poll sees it again, complete or
// grown), or at the end of the tail.
type held struct {
	raw source.RawRecord
	rec mask.Record
}

// Tail polls the sources until Duration ends or Max match, for the records
// timestamped from the call's start (to the second): new records are told
// by their time, which every source has; records without one are never
// tailed. Each record is evaluated and returned once, and a copy of a
// returned record in another stream (a rotation) is not returned again.
//
// Work follows the new data: a plan of every local stream at the start (no
// record read) gives each stream's end in its granules, and a poll scans
// only granules past what was there or already scanned whole (the growing
// last one again, from its start); within a stream, records up to the last
// one evaluated are skipped. These granule ends are used for pruning only,
// never compared with record positions (their units differ by source). A
// stream first seen during the tail is scanned from its start (its records
// still need a time from the start on). Residuals: a record dated in the
// future that was already in a growing last granule is returned; one
// written with a time before the start is not.
//
// Every record of a scanned granule is masked before evaluation, as in a
// search; a poll's matches are kept only when it completes (stopping points
// are group boundaries), its work always. Each poll's plan, once pruned, is
// admitted against the call's byte budgets, and the polls share the call's
// bytes; everything runs under the duration plus a grace.
func (e *Engine) Tail(ctx context.Context, tq TailQuery) (TailResult, error) {
	dur := MaxTailDuration
	if tq.Duration != "" {
		d, err := time.ParseDuration(tq.Duration)
		if err != nil || d <= 0 || d > MaxTailDuration {
			return TailResult{}, refuse(EBadQuery, "duration", "want a duration up to %s", MaxTailDuration)
		}
		dur = d
	}
	switch {
	case tq.Max == 0:
		tq.Max = DefaultTailMax
	case tq.Max < 0 || tq.Max > e.o.Limits.MaxRecords:
		return TailResult{}, refuse(EBadQuery, "max", "want 1 to %d", e.o.Limits.MaxRecords)
	}
	start := e.o.Now().UTC().Truncate(time.Second)
	q := Query{Sources: tq.Sources, Where: slices.Clone(tq.Where), Text: tq.Text, Regex: tq.Regex, Fields: tq.Fields,
		Limit: tq.Max, From: start, To: start.Add(dur + time.Second)}
	if err := e.validator(e.o.Limits.LocalRange).validate(&q); err != nil {
		return TailResult{}, err
	}
	var needles []string
	if q.Text != "" {
		needles = append(needles, q.Text)
	}
	for _, p := range q.Where {
		if p.Op == OpContains {
			needles = append(needles, p.needle)
		}
	}
	filtered := e.o.Prefilter && len(needles) > 0
	poll := e.o.TailPoll
	if poll <= 0 {
		poll = DefaultTailPoll
	}
	wallEnd := time.Now().Add(dur)
	tctx, tcancel := context.WithDeadline(ctx, wallEnd.Add(tailGrace))
	defer tcancel()
	cancelled := &Error{Code: ESource, Message: "cancelled"}

	// Baseline: every local stream's end, in its granule units.
	done := map[streamKey]int64{}
	for _, s := range q.Sources {
		if e.remote(s) {
			continue
		}
		p, err := e.o.Sources[s].Plan(tctx, source.Range{From: time.Unix(0, 0).UTC(), To: start.Add(24 * time.Hour)}, source.Selector{})
		if err != nil {
			if ctx.Err() != nil {
				return TailResult{}, cancelled
			}
			return TailResult{}, sourceError(err)
		}
		for _, c := range p.Chunks {
			if c.End() != math.MaxInt64 {
				k := streamKey{c.Source, c.Stream}
				done[k] = max(done[k], c.End())
			}
		}
	}

	type rkey struct {
		k streamKey
		p pos
	}
	frontier := map[streamKey]pos{} // local: the last record evaluated
	seenRemote := map[rkey]bool{}   // remote: the records evaluated
	returned := map[string]bool{}   // records returned, by keyed digest and time
	var found []match
	heldAll := map[streamKey]*held{} // each local stream's held record
	res := TailResult{Epoch: e.o.Masker.Epoch(), Records: []json.RawMessage{}, Masking: Masking{Kinds: []string{}}}
	callBytes := e.callBytes(q.Sources)
	covered, early, untimed, partial := true, false, false, false
	ended := false // the duration ended (not max, not a failure)
	stale := 0     // polls replanned after a stream changed

	// evaluate decides one new record into out (the poll's matches).
	var outFailed bool
	evaluate := func(raw source.RawRecord, rec mask.Record, b *budget, out *[]match, failures *int, sawUntimed *bool) {
		t, ok := rec.Time()
		if !ok {
			*sawUntimed = true
			return
		}
		if t.Before(start) {
			return
		}
		// Counted once per record; with the pre-filter on, not
		// counted, as in run.
		if rec.Failed() && !filtered {
			*failures++
		}
		if !q.match(rec, b) {
			return
		}
		d := e.RecordDigest(raw.Event.Raw) + "|" + t.Format(time.RFC3339Nano)
		if returned[d] || slices.ContainsFunc(*out, func(m match) bool { return m.digest == d }) {
			return // a copy of a record already returned (a rotation)
		}
		o, oerr := e.outRecord(raw, rec, q.Fields)
		if oerr != nil {
			outFailed = true // never a silently missing match
			return
		}
		*out = append(*out, match{ts: t, timed: true, out: o, kinds: rec.Kinds(), digest: d})
		// Bounded memory: keep the earliest that can be returned.
		if len(*out) > 2*q.Limit {
			sortMatches(*out, "asc")
			*out = (*out)[:q.Limit]
			early = true
		}
	}

	for polls := 0; ; polls++ {
		left := callBytes - res.Scanned.Bytes
		if left <= 0 {
			covered = false
			break
		}
		pq := q
		pq.To = e.o.Now().UTC().Truncate(time.Second).Add(time.Second)
		plan, perr := e.planQuery(tctx, &pq, math.MaxInt64, math.MaxInt64)
		if perr != nil {
			if ctx.Err() != nil {
				return TailResult{}, cancelled
			}
			if polls == 0 && tctx.Err() == nil {
				return TailResult{}, perr
			}
			covered = false
			break
		}
		// A stream that shrank was truncated (copytruncate): it is new
		// from its start, and its positions restart.
		ends := map[streamKey]int64{}
		for _, c := range plan.Chunks {
			if !e.remote(c.Source) && c.End() != math.MaxInt64 {
				k := streamKey{c.Source, c.Stream}
				ends[k] = max(ends[k], c.End())
			}
		}
		for k, end := range ends {
			if d, ok := done[k]; ok && end < d {
				done[k] = 0
				delete(frontier, k)
				delete(heldAll, k)
			}
		}
		// Prune what was there or already scanned whole.
		var pruned source.Byteplan
		var bytesLocal, bytesRemote int64
		for _, c := range plan.Chunks {
			if d, ok := done[streamKey{c.Source, c.Stream}]; ok && !e.remote(c.Source) && c.End() != math.MaxInt64 {
				gs := slices.DeleteFunc(slices.Clone(c.Granules), func(g source.Granule) bool { return g.End <= d })
				if len(gs) == 0 {
					continue
				}
				if !compressed(c) {
					c.Bytes = 0
					for _, g := range gs {
						c.Bytes += granuleBytes(g, c)
					}
				}
				c.Granules = gs
			}
			pruned.Chunks = append(pruned.Chunks, c)
			if e.remote(c.Source) {
				bytesRemote += c.Bytes
			} else {
				bytesLocal += c.Bytes
			}
		}
		if bytesLocal > e.o.Limits.LocalBytes || bytesRemote > e.o.Limits.RemoteBytes {
			if polls == 0 {
				return TailResult{}, &Error{Code: EOverBudget, Message: "the data to scan for new records exceeds this call's byte budget: narrow the sources or the selector",
					Estimate: &Estimate{Bytes: bytesLocal + bytesRemote, Granules: pruned.Granules()}}
			}
			covered = false
			break
		}

		// The poll's matches are kept only if it completes.
		var pollFound []match
		pollFrontier := map[streamKey]pos{}
		pollSeen := map[rkey]bool{}
		pollHeld := map[streamKey]*held{}
		pollFailures, pollUntimed := 0, false
		outFailed = false
		pctx, cancel := context.WithDeadline(tctx, wallEnd.Add(tailGrace))
		chunk, _, psc, _, rerr := e.run(pctx, pruned, 0, 0, needles, left, q.evalFactor(), func(raw source.RawRecord, rec mask.Record, b *budget) {
			k := keyOf(raw.Ref)
			p := pos{raw.Ref.Offset, raw.Ref.Length}
			if e.remote(raw.Ref.Source) {
				rk := rkey{k, p}
				if seenRemote[rk] || pollSeen[rk] {
					return
				}
				pollSeen[rk] = true
				evaluate(raw, rec, b, &pollFound, &pollFailures, &pollUntimed)
				return
			}
			if f, ok := frontier[k]; ok && !p.after(f) {
				return // evaluated by an earlier poll
			}
			if f, ok := pollFrontier[k]; ok && !p.after(f) {
				return
			}
			// The record before this one is complete: evaluate it;
			// this one is held.
			if h := pollHeld[k]; h != nil {
				pollFrontier[k] = pos{h.raw.Ref.Offset, h.raw.Ref.Length}
				evaluate(h.raw, h.rec, b, &pollFound, &pollFailures, &pollUntimed)
			}
			pollHeld[k] = &held{raw: raw, rec: rec}
		})
		cancel()
		// The poll's work is the call's, whatever its outcome.
		res.Scanned.Bytes += psc.Bytes
		res.Scanned.Records += psc.Records
		res.Scanned.Granules += psc.Granules
		if rerr != nil || outFailed {
			if ctx.Err() != nil {
				return TailResult{}, cancelled
			}
			// A stream that changed between the plan and the scan
			// (written or rotated meanwhile) is planned again.
			if rerr != nil && rerr.Code == EStale && stale < maxTailStale && tctx.Err() == nil {
				stale++
				polls--
				continue
			}
			if polls == 0 && tctx.Err() == nil {
				if rerr != nil {
					return TailResult{}, rerr
				}
				return TailResult{}, &Error{Code: ESource, Message: "a matching record could not be rendered; try again"}
			}
			covered = false
			break
		}
		// The poll completed: keep its results.
		res.MaskedFailures += pollFailures
		untimed = untimed || pollUntimed
		for k := range pollSeen {
			seenRemote[k] = true
		}
		for k, p := range pollFrontier {
			frontier[k] = p
		}
		for _, m := range pollFound {
			returned[m.digest] = true
		}
		found = append(found, pollFound...)
		for k, h := range pollHeld {
			heldAll[k] = h
		}
		if chunk < len(pruned.Chunks) {
			covered = false // more than one call scans: tail again
			break
		}
		for _, c := range pruned.Chunks {
			if !e.remote(c.Source) && c.End() != math.MaxInt64 {
				k := streamKey{c.Source, c.Stream}
				done[k] = max(done[k], c.End())
			}
		}
		if len(seenRemote) > maxTailSeen {
			covered = false
			break
		}
		if len(found) >= q.Limit {
			early = early || time.Now().Before(wallEnd)
			break
		}
		wait := time.Until(wallEnd)
		if wait <= 0 {
			ended = true
			break
		}
		t := time.NewTimer(min(poll, wait))
		select {
		case <-ctx.Done():
			t.Stop()
			return TailResult{}, cancelled
		case <-t.C:
		}
	}
	// At the end of the duration, the held records are what the streams
	// end with: complete ones are evaluated, one still being written is
	// left out.
	if ended {
		var final []match
		failures, sawUntimed := 0, false
		outFailed = false
		for _, h := range heldAll {
			if h.raw.Event.Unterminated {
				partial = true
				continue
			}
			evaluate(h.raw, h.rec, nil, &final, &failures, &sawUntimed)
		}
		if outFailed {
			return TailResult{}, &Error{Code: ESource, Message: "a matching record could not be rendered; try again"}
		}
		res.MaskedFailures += failures
		untimed = untimed || sawUntimed
		found = append(found, final...)
	} else if len(heldAll) > 0 {
		covered = false // held records not evaluated
	}
	sortMatches(found, "asc")
	size := 256
	kinds := map[string]bool{}
	n := 0
	for n < len(found) && n < q.Limit {
		if size+len(found[n].out)+1 > e.o.Limits.MaxOutput && n > 0 {
			break
		}
		size += len(found[n].out) + 1
		res.Records = append(res.Records, found[n].out)
		for _, k := range found[n].kinds {
			kinds[k] = true
		}
		n++
	}
	for k := range kinds {
		res.Masking.Kinds = append(res.Masking.Kinds, k)
	}
	slices.Sort(res.Masking.Kinds)
	res.Complete = covered && !early && !untimed && !partial && n == len(found)
	return res, nil
}
