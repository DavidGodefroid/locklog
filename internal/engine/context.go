package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// MaxAround bounds before and after of a context call.
const MaxAround = 50

// ContextQuery is a context call (locklog_context): the records around one
// returned record, from its stream, in stream order.
type ContextQuery struct {
	Ref    string   `json:"ref"`
	Before int      `json:"before,omitempty"`
	After  int      `json:"after,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// ContextResult is the answer of a context call. Target is the index in
// Records of the record the ref names. Records are masked as search
// results are, each with its own ref; a record masking failed on is
// withheld (masked_failure).
type ContextResult struct {
	Epoch   string            `json:"epoch"`
	Records []json.RawMessage `json:"records"`
	Target  int               `json:"target"`
	// Complete is false when the output cap dropped the records farthest
	// from the target.
	Complete       bool    `json:"complete"`
	Scanned        Scanned `json:"scanned"`
	Masking        Masking `json:"masking"`
	MaskedFailures int     `json:"masked_failures,omitempty"`
}

// errRef is the refusal of a ref that does not open. It never says why
// (forged, another console's, another type), so a ref tells nothing.
var errRef = &Error{Code: EStale, Span: "ref", Message: "invalid or expired reference: search again"}

// openRef opens an agent's ref for a call: the sealed position, checked
// against the policy, the epoch and the engine's sources.
func (e *Engine) openRef(ref string) (source.RawRef, string, *Error) {
	rr, digest, err := e.Ref(ref)
	if err != nil {
		var re *Error
		if errors.As(err, &re) {
			re.Span = "ref"
			return source.RawRef{}, "", re
		}
		return source.RawRef{}, "", errRef
	}
	if _, ok := e.o.Sources[rr.Source]; !ok {
		return source.RawRef{}, "", errRef
	}
	return rr, digest, nil
}

// Context re-reads the records around a ref (locklog_context). The record
// must still be the one the ref was made on (its keyed digest): a stream
// rewritten since gives E_STALE. Every record is masked before it is
// rendered; the work depends on the stream around the ref only, and
// scanned reports it in granules (charged to the rolling budget).
func (e *Engine) Context(ctx context.Context, cq ContextQuery) (ContextResult, error) {
	if cq.Before < 0 || cq.Before > MaxAround {
		return ContextResult{}, refuse(EBadQuery, "before", "want 0 to %d", MaxAround)
	}
	if cq.After < 0 || cq.After > MaxAround {
		return ContextResult{}, refuse(EBadQuery, "after", "want 0 to %d", MaxAround)
	}
	rr, digest, rerr := e.openRef(cq.Ref)
	if rerr != nil {
		return ContextResult{}, rerr
	}
	v := e.validator(0)
	pq := &Query{Sources: []string{rr.Source}}
	if len(cq.Fields) > MaxFields {
		return ContextResult{}, refuse(EBadQuery, "fields", "at most %d fields", MaxFields)
	}
	for i, f := range cq.Fields {
		if err := v.path(pq, f, fmt.Sprintf("fields[%d]", i)); err != nil {
			return ContextResult{}, err
		}
	}
	// The rolling budgets, before the stream is touched: a context
	// re-read costs at least one granule, and is charged what it read
	// (granule-rounded), whatever its outcome.
	charged := int64(source.GranuleBytes)
	resv, berr := e.ledger.admit(map[string]int64{rr.Source: charged}, e.remote, 1, 0)
	if berr != nil {
		return ContextResult{}, berr
	}
	defer func() { resv.settle(map[string]int64{rr.Source: charged}, e.remote) }()
	cctx, cancel := context.WithTimeout(ctx, e.o.Limits.Deadline)
	defer cancel()
	if e.remote(rr.Source) {
		cctx = source.WithLimiter(cctx, e.limiter(ctx, rr.Source))
	}
	var raws []source.RawRecord
	var processed int64
	var err error
	src := e.o.Sources[rr.Source]
	if m, ok := src.(source.AroundMeter); ok {
		raws, processed, err = m.AroundMeasured(cctx, rr, cq.Before, cq.After)
	} else {
		raws, err = src.Around(cctx, rr, cq.Before, cq.After)
	}
	if err != nil {
		return ContextResult{}, sourceError(err)
	}
	target := -1
	for i, r := range raws {
		if r.Ref.Stream == rr.Stream && r.Ref.Offset == rr.Offset && r.Ref.Length == rr.Length {
			target = i
			break
		}
	}
	if target < 0 || e.RecordDigest(raws[target].Event.Raw) != digest {
		return ContextResult{}, sourceError(source.ErrStale)
	}
	// A source returns at most what was asked; never more.
	lo, hi := max(0, target-cq.Before), min(len(raws), target+cq.After+1)
	raws, target = raws[lo:hi], target-lo
	recs, err := e.maskAll(cctx, rr.Source, raws)
	if err != nil {
		return ContextResult{}, sourceError(err)
	}
	res := ContextResult{Epoch: e.o.Masker.Epoch(), Records: []json.RawMessage{}, Masking: Masking{Kinds: []string{}}, Complete: true}
	outs := make([]json.RawMessage, len(raws))
	granules := map[int]bool{}
	for i := range raws {
		out, oerr := e.outRecord(raws[i], recs[i], cq.Fields)
		if oerr != nil {
			return ContextResult{}, &Error{Code: ESource, Message: "a record could not be rendered; try again"}
		}
		outs[i] = out
		granules[raws[i].Granule] = true
	}
	// Keep the records nearest the target within the output cap.
	keepLo, keepHi := target, target+1
	size := 256 + len(outs[target]) + 1
	for {
		grew := false
		if keepLo > 0 && size+len(outs[keepLo-1])+1 <= e.o.Limits.MaxOutput {
			keepLo--
			size += len(outs[keepLo]) + 1
			grew = true
		}
		if keepHi < len(outs) && size+len(outs[keepHi])+1 <= e.o.Limits.MaxOutput {
			size += len(outs[keepHi]) + 1
			keepHi++
			grew = true
		}
		if !grew {
			break
		}
	}
	res.Complete = keepLo == 0 && keepHi == len(outs)
	res.Records = outs[keepLo:keepHi]
	res.Target = target - keepLo
	res.Masking.Kinds = kindsOf(recs[keepLo:keepHi])
	for _, r := range recs[keepLo:keepHi] {
		if r.Failed() {
			res.MaskedFailures++
		}
	}
	// The work is granule-rounded: what the source processed (reading
	// back, decompressing) when it measures it, else the granules of the
	// records.
	n := max(int64(len(granules)), (processed+source.GranuleBytes-1)/source.GranuleBytes)
	res.Scanned = Scanned{Bytes: n * source.GranuleBytes, Records: int64(len(raws)), Granules: int(n)}
	charged = res.Scanned.Bytes
	return res, nil
}

// kindsOf is the sorted set of masked kinds of records.
func kindsOf(recs []mask.Record) []string {
	set := map[string]bool{}
	for _, r := range recs {
		for _, k := range r.Kinds() {
			set[k] = true
		}
	}
	out := []string{}
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
