package logconsole

import (
	"context"
	"sync"
	"time"
)

// maxExposurePairs bounds the (pseudonym, record) pairs an Exposure keeps
// for one epoch: past it, the counts are lower bounds.
const maxExposurePairs = 1 << 18

// ExposedRecord is one record a call returned to the agent: a key of its
// own (a prefix of its keyed digest, never its text) and the pseudonyms it
// held.
type ExposedRecord struct {
	Key        string
	Pseudonyms []string
}

// Exposer is an engine that names the records of a call's result
// (ExposedRecord) and the pseudonym epoch they are of.
type Exposer interface {
	Exposed(result any) (epoch string, recs []ExposedRecord)
}

// Exposure counts, for the epoch in force, how many distinct records
// holding each pseudonym were returned to agents: fed by the calls the
// console answered and audited, by pseudonym and record key only (never a
// clear value nor a record's text). The unmask screen shows it. It is the
// console's own count, kept in memory: a console started during the epoch
// counts from its start (Since).
type Exposure struct {
	mu    sync.Mutex
	since time.Time
	epoch string
	// recs are the record keys holding each pseudonym.
	recs  map[string]map[string]struct{}
	pairs int
	// full: a pair was not kept (maxExposurePairs): counts are lower
	// bounds.
	full bool
}

// NewExposure returns an empty count, started at since.
func NewExposure(since time.Time) *Exposure {
	return &Exposure{since: since, recs: map[string]map[string]struct{}{}}
}

// Add counts the records a call returned in epoch. A new epoch starts the
// count again (pseudonyms do not link across epochs).
func (x *Exposure) Add(epoch string, recs []ExposedRecord) {
	if x == nil || epoch == "" || len(recs) == 0 {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if epoch != x.epoch {
		// No record of the new epoch was returned before (it would have
		// started its count then): Since stays the console's start.
		x.epoch, x.recs, x.pairs, x.full = epoch, map[string]map[string]struct{}{}, 0, false
	}
	for _, r := range recs {
		for _, p := range r.Pseudonyms {
			ks := x.recs[p]
			if _, ok := ks[r.Key]; ok {
				continue
			}
			if x.pairs >= maxExposurePairs {
				x.full = true
				continue
			}
			if ks == nil {
				ks = map[string]struct{}{}
				x.recs[p] = ks
			}
			ks[r.Key] = struct{}{}
			x.pairs++
		}
	}
}

// Count returns, for each pseudonym, the distinct records holding it
// returned to agents in epoch, whether the counts are exact (false: lower
// bounds) and since when the console counts.
func (x *Exposure) Count(epoch string, pseudonyms []string) ([]int, bool, time.Time) {
	if x == nil {
		return make([]int, len(pseudonyms)), false, time.Time{}
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]int, len(pseudonyms))
	if epoch != x.epoch {
		return out, true, x.since
	}
	for i, p := range pseudonyms {
		out[i] = len(x.recs[p])
	}
	return out, !x.full, x.since
}

type exposureKey struct{}

// WithExposure attaches the console's exposure count to ctx.
func WithExposure(ctx context.Context, x *Exposure) context.Context {
	return context.WithValue(ctx, exposureKey{}, x)
}

// ExposureFrom returns the console's exposure count, nil when none.
func ExposureFrom(ctx context.Context) *Exposure {
	x, _ := ctx.Value(exposureKey{}).(*Exposure)
	return x
}
