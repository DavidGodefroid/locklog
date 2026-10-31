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
	// tailOverlap is how far before the previous poll a poll's range
	// starts (records written late with an earlier time).
	tailOverlap = 5 * time.Second
	// tailGrace is how long the last poll may run past the duration.
	tailGrace = 2 * time.Second
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

// TailResult is the answer of a tail: the new records in time order
// (untimed ones last). Complete is false when the tail stopped early (at
// max, or a poll failed or could not cover what was written: tail again)
// or the output cap dropped records.
type TailResult struct {
	Epoch          string            `json:"epoch"`
	Records        []json.RawMessage `json:"records"`
	Complete       bool              `json:"complete"`
	Scanned        Scanned           `json:"scanned"`
	Masking        Masking           `json:"masking"`
	MaskedFailures int               `json:"masked_failures,omitempty"`
}

// tailStream is what a tail tracks of one local stream.
type tailStream struct {
	// floor: records before it were there when the tail started, or
	// were already evaluated by a poll.
	floor int64
	// done is the end of the granules a poll scanned whole: a granule
	// ending there is not scanned again (one that grew past it is).
	done int64
}

// Tail polls the sources for new records until Duration ends or Max match.
//
// For a local stream, "new" is by position: at the start, a plan of every
// stream (no record read) gives each stream's end; a poll scans only the
// granules past what was there or already scanned (the growing last one
// again, from its start), and evaluates only records past them, so each
// poll's work, and its scanned, follows the new data. A stream first seen
// during the tail is new from its start. For a remote stream (or a local
// one of unknown size), "new" is by time: records timestamped from the
// call's start (to the second), each returned once.
//
// Every record of a scanned granule is masked before evaluation, as in a
// search; a poll's matches are kept only when it completes (stopping points
// are group boundaries), and polls run under the call's duration.
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
	wallStart := time.Now()
	wallEnd := wallStart.Add(dur)

	// Baseline: every local stream's end (a plan reads no record).
	streams := map[[2]string]*tailStream{}
	var local []string
	for _, s := range q.Sources {
		if !e.remote(s) {
			local = append(local, s)
		}
	}
	if len(local) > 0 {
		all := source.Range{From: time.Unix(0, 0).UTC(), To: start.Add(24 * time.Hour)}
		for _, s := range local {
			p, err := e.o.Sources[s].Plan(ctx, all, source.Selector{})
			if err != nil {
				return TailResult{}, sourceError(err)
			}
			for _, c := range p.Chunks {
				if c.End() == math.MaxInt64 {
					continue // unknown size: by time
				}
				k := [2]string{c.Source, c.Stream}
				st := streams[k]
				if st == nil {
					st = &tailStream{}
					streams[k] = st
				}
				st.floor = max(st.floor, c.End())
				st.done = max(st.done, c.End())
			}
		}
	}
	byOffset := func(c source.Chunk) bool { return !e.remote(c.Source) && c.End() != math.MaxInt64 }

	type key struct {
		src, stream string
		off         int64
	}
	seen := map[key]bool{} // streams by time only
	res := TailResult{Epoch: e.o.Masker.Epoch(), Records: []json.RawMessage{}, Masking: Masking{Kinds: []string{}}}
	var found []match
	covered, early := true, false
	lastPoll := start
	for polls := 0; ; polls++ {
		pollAt := e.o.Now().UTC()
		pq := q
		pq.From = lastPoll.Add(-tailOverlap)
		if pq.From.Before(start) {
			pq.From = start
		}
		pq.To = pollAt.Truncate(time.Second).Add(time.Second)
		plan, perr := e.planQuery(ctx, &pq, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
		if perr != nil {
			if polls == 0 {
				return TailResult{}, perr
			}
			covered = false
			break
		}
		// Local streams: only granules past what was there or scanned.
		var pruned source.Byteplan
		for _, c := range plan.Chunks {
			if byOffset(c) {
				st := streams[[2]string{c.Source, c.Stream}]
				if st != nil {
					gs := slices.DeleteFunc(slices.Clone(c.Granules), func(g source.Granule) bool { return g.End <= st.done })
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
			}
			pruned.Chunks = append(pruned.Chunks, c)
		}
		offStreams := map[[2]string]bool{}
		for _, c := range pruned.Chunks {
			if byOffset(c) {
				offStreams[[2]string{c.Source, c.Stream}] = true
			}
		}
		// The poll's results are kept only if it completes.
		var pollFound []match
		pollSeen := map[key]bool{}
		pollFloor := map[[2]string]int64{}
		pollFailures := 0
		outFailed := false
		pctx, cancel := context.WithDeadline(ctx, wallEnd.Add(tailGrace))
		chunk, _, psc, _, rerr := e.run(pctx, pruned, 0, 0, needles, e.callBytes(q.Sources), q.evalFactor(), func(raw source.RawRecord, rec mask.Record, b *budget) {
			k2 := [2]string{raw.Ref.Source, raw.Ref.Stream}
			if offStreams[k2] {
				// By position: skip what was there or evaluated.
				floor := int64(0)
				if st := streams[k2]; st != nil {
					floor = st.floor
				}
				if raw.Ref.Offset < max(floor, pollFloor[k2]) {
					return
				}
				pollFloor[k2] = raw.Ref.Offset + max(raw.Ref.Length, 1)
			} else {
				t, ok := rec.Time()
				if !ok || t.Before(start) {
					return
				}
				k := key{raw.Ref.Source, raw.Ref.Stream, raw.Ref.Offset}
				if seen[k] || pollSeen[k] {
					return
				}
				pollSeen[k] = true
			}
			// Each record is evaluated once; with the pre-filter on,
			// failures are not counted, as in run.
			if rec.Failed() && !filtered {
				pollFailures++
			}
			if !q.match(rec, b) {
				return
			}
			out, oerr := e.outRecord(raw, rec, q.Fields)
			if oerr != nil {
				outFailed = true // never a silently missing match
				return
			}
			t, ok := rec.Time()
			pollFound = append(pollFound, match{ts: t, timed: ok, out: out, kinds: rec.Kinds()})
			// Bounded memory: keep the earliest that can be returned.
			if len(pollFound) > 2*q.Limit {
				sortMatches(pollFound, "asc")
				pollFound = pollFound[:q.Limit]
				early = true
			}
		})
		expired := pctx.Err() != nil && ctx.Err() == nil
		cancel()
		if rerr != nil || outFailed {
			if polls == 0 && !expired {
				if rerr != nil {
					return TailResult{}, rerr
				}
				return TailResult{}, &Error{Code: ESource, Message: "a matching record could not be rendered; try again"}
			}
			if ctx.Err() != nil {
				return TailResult{}, &Error{Code: ESource, Message: "cancelled"}
			}
			covered = false
			break
		}
		// The poll completed: keep its work and results.
		res.Scanned.Bytes += psc.Bytes
		res.Scanned.Records += psc.Records
		res.Scanned.Granules += psc.Granules
		res.MaskedFailures += pollFailures
		for k := range pollSeen {
			seen[k] = true
		}
		if chunk < len(pruned.Chunks) {
			covered = false // more than one call scans: tail again
			break
		}
		for _, c := range pruned.Chunks {
			if !byOffset(c) {
				continue
			}
			k2 := [2]string{c.Source, c.Stream}
			st := streams[k2]
			if st == nil {
				st = &tailStream{}
				streams[k2] = st
			}
			st.done = max(st.done, c.End())
			st.floor = max(st.floor, pollFloor[k2])
		}
		found = append(found, pollFound...)
		lastPoll = pollAt
		if len(found) >= q.Limit {
			early = len(found) > q.Limit || time.Now().Before(wallEnd)
			break
		}
		left := time.Until(wallEnd)
		if left <= 0 {
			break
		}
		t := time.NewTimer(min(poll, left))
		select {
		case <-ctx.Done():
			t.Stop()
			return TailResult{}, &Error{Code: ESource, Message: "cancelled"}
		case <-t.C:
		}
	}
	sortMatches(found, "asc")
	out := 256
	kinds := map[string]bool{}
	n := 0
	for n < len(found) && n < q.Limit {
		if out+len(found[n].out)+1 > e.o.Limits.MaxOutput && n > 0 {
			break
		}
		out += len(found[n].out) + 1
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
	res.Complete = covered && !early && n == len(found)
	return res, nil
}
