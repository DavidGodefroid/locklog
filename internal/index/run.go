package index

import (
	"context"
	"time"
)

// Indexer is a source that can build its local index step by step.
type Indexer interface {
	// IndexStep indexes about maxBytes and reports the bytes processed and
	// whether nothing was left to index. With upkeep false it does only
	// backfill (streams and granules never indexed), not the re-indexing
	// of grown tails.
	IndexStep(ctx context.Context, maxBytes int64, upkeep bool) (processed int64, done bool, err error)
}

// RunOptions configure Run.
type RunOptions struct {
	// BytesPerHour is the index building budget (a rolling budget of its
	// own, apart from the agents' budgets).
	BytesPerHour int64
	// Busy reports that agent calls are running. While busy, only the
	// backfill runs (first start, a new file, at the full budget); the
	// upkeep of grown tails waits.
	Busy func() bool
	// Flush persists the index (Store.Flush); called after steps, at most
	// every FlushEvery.
	Flush      func() error
	FlushEvery time.Duration
	// Idle is the pause when every source is done (new data is picked up
	// on the next pass).
	Idle time.Duration
	// OnError is told of a step's error (the source is retried later).
	OnError func(Indexer, error)
	// Now and Sleep are the clock (tests).
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) bool
}

// Run builds the indexes of srcs until ctx ends, under a token bucket of
// BytesPerHour (capacity one minute of budget).
func Run(ctx context.Context, srcs []Indexer, o RunOptions) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) bool {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-t.C:
				return true
			}
		}
	}
	if o.Idle <= 0 {
		o.Idle = 30 * time.Second
	}
	if o.FlushEvery <= 0 {
		o.FlushEvery = 10 * time.Second
	}
	if o.BytesPerHour <= 0 {
		return
	}
	capacity := max(o.BytesPerHour/60, 1<<20)
	tokens := capacity
	last := o.Now()
	lastFlush := last
	flush := func(force bool) {
		if o.Flush != nil && (force || o.Now().Sub(lastFlush) >= o.FlushEvery) {
			if err := o.Flush(); err != nil && o.OnError != nil {
				o.OnError(nil, err)
			}
			lastFlush = o.Now()
		}
	}
	defer flush(true)
	pass := 0
	for ctx.Err() == nil {
		now := o.Now()
		tokens = min(capacity, tokens+int64(float64(o.BytesPerHour)*now.Sub(last).Hours()))
		last = now
		if tokens <= 0 {
			wait := time.Duration(float64(-tokens+1<<20) / float64(o.BytesPerHour) * float64(time.Hour))
			if !o.Sleep(ctx, max(wait, 100*time.Millisecond)) {
				return
			}
			continue
		}
		worked, allDone := false, true
		upkeep := o.Busy == nil || !o.Busy()
		// Rotate the first source each pass, so that one large backfill
		// does not hold up the others.
		pass++
		for k := range srcs {
			src := srcs[(k+pass)%len(srcs)]
			if tokens <= 0 || ctx.Err() != nil {
				allDone = false
				break
			}
			n, done, err := src.IndexStep(ctx, tokens, upkeep)
			tokens -= n
			if n > 0 {
				worked = true
			}
			if err != nil {
				if o.OnError != nil {
					o.OnError(src, err)
				}
				done = true // retried on the next pass
			}
			allDone = allDone && done
		}
		flush(false)
		if allDone || !worked {
			flush(true)
			if !o.Sleep(ctx, o.Idle) {
				return
			}
		}
	}
}
