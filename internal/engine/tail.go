package engine

import (
	"context"
	"encoding/json"
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

// TailResult is the answer of a tail: the records in time order (untimed
// ones are not new records: they are never tailed). Complete is false when
// the tail stopped at max, at the output cap, or when a poll could not
// cover what was written before the call ended (tail again).
type TailResult struct {
	Epoch          string            `json:"epoch"`
	Records        []json.RawMessage `json:"records"`
	Complete       bool              `json:"complete"`
	Scanned        Scanned           `json:"scanned"`
	Masking        Masking           `json:"masking"`
	MaskedFailures int               `json:"masked_failures,omitempty"`
}

// Tail polls the sources for records timestamped from the call's start
// (to the second) until Duration ends or Max match. Each poll plans the
// range from the start to now and scans it whole, as a search would (masked
// first, then evaluated); a record seen by a poll is not returned again.
// Every poll's work is plan based and summed in scanned (charged to the
// rolling budget); what a poll scans depends on the range and the trusted
// selector, never on the matches.
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
	end := start.Add(dur)
	q := Query{Sources: tq.Sources, Where: slices.Clone(tq.Where), Text: tq.Text, Regex: tq.Regex, Fields: tq.Fields,
		Limit: tq.Max, From: start, To: end.Add(time.Second)}
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
	poll := e.o.TailPoll
	if poll <= 0 {
		poll = DefaultTailPoll
	}
	wallEnd := time.Now().Add(dur)
	type key struct {
		src, stream string
		off         int64
	}
	seen := map[key]bool{}
	var found []match
	var sc Scanned
	failures := 0
	covered := true
	outFailed := false
	filtered := e.o.Prefilter && len(needles) > 0
	for {
		pq := q
		pq.To = e.o.Now().UTC().Truncate(time.Second).Add(time.Second)
		if pq.To.After(end.Add(time.Second)) {
			pq.To = end.Add(time.Second)
		}
		if pq.To.After(pq.From) {
			plan, perr := e.planQuery(ctx, &pq, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
			if perr != nil {
				return TailResult{}, perr
			}
			chunk, _, psc, _, rerr := e.run(ctx, plan, 0, 0, needles, e.callBytes(q.Sources), q.evalFactor(), func(raw source.RawRecord, rec mask.Record, b *budget) {
				t, ok := rec.Time()
				if !ok || t.Before(start) || !t.Before(end.Add(time.Second)) {
					return
				}
				k := key{raw.Ref.Source, raw.Ref.Stream, raw.Ref.Offset}
				if seen[k] {
					return
				}
				// Seen whether it matches or not: a later poll
				// never evaluates it again.
				seen[k] = true
				// Counted once per record (polls re-scan the
				// growing granules); with the pre-filter on, not
				// counted, as in run.
				if rec.Failed() && !filtered {
					failures++
				}
				if !q.match(rec, b) {
					return
				}
				out, oerr := e.outRecord(raw, rec, q.Fields)
				if oerr != nil {
					outFailed = true // never a silently missing match
					return
				}
				found = append(found, match{ts: t, timed: true, out: out, kinds: rec.Kinds()})
			})
			if rerr != nil {
				return TailResult{}, rerr
			}
			if outFailed {
				return TailResult{}, &Error{Code: ESource, Message: "a matching record could not be rendered; try again"}
			}
			sc.Bytes += psc.Bytes
			sc.Records += psc.Records
			sc.Granules += psc.Granules
			covered = chunk >= len(plan.Chunks)
			if !covered {
				break // more than one call can scan: tail again
			}
		}
		if len(found) >= q.Limit {
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
	res := TailResult{Epoch: e.o.Masker.Epoch(), Records: []json.RawMessage{}, Masking: Masking{Kinds: []string{}}, Scanned: sc, MaskedFailures: failures}
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
	res.Complete = covered && n == len(found) && len(found) < q.Limit
	return res, nil
}
