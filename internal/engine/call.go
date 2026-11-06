package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// DefaultMaxCalls is the number of agent calls an engine runs at once when
// Options.MaxCalls is not set.
const DefaultMaxCalls = 4

// slots bounds the agent calls an engine runs at once (Options.MaxCalls):
// parallel calls would otherwise multiply the per-call budgets (memory,
// masking workers, backend requests).
type slots chan struct{}

func newSlots(n int) slots {
	if n <= 0 {
		n = DefaultMaxCalls
	}
	return make(slots, n)
}

// errBusy is the refusal of a call while the engine runs its most calls at
// once. It names only the configured number.
func errBusy(n int) *Error {
	return &Error{Code: EBusy, Message: fmt.Sprintf("the console is running %d calls already, the most it runs at once: wait for one of them to answer, then try again", n)}
}

// acquire takes a call slot without waiting: a call over the cap is refused
// at once (E_BUSY), before any work. release gives it back.
func (s slots) acquire() (release func(), _ *Error) {
	select {
	case s <- struct{}{}:
		return func() { <-s }, nil
	default:
		return nil, errBusy(cap(s))
	}
}

// slotKey marks a context whose call holds a slot already (a scan's call
// runs a search, a trace runs a search).
type slotKey struct{}

// enter takes a call slot for a free call, unless ctx holds one. Calls a
// human approves one by one (scan, unmask, lookup) take theirs once
// approved: a scan in run, unmask and lookup never (they read one record).
func (e *Engine) enter(ctx context.Context) (context.Context, func(), *Error) {
	if ctx.Value(slotKey{}) != nil {
		return ctx, func() {}, nil
	}
	release, err := e.calls.acquire()
	if err != nil {
		return ctx, nil, err
	}
	return context.WithValue(ctx, slotKey{}, true), release, nil
}

// startKey carries the instant a call started (startCall).
type startKey struct{}

// startCall marks the start of a free call before it plans: the call's
// deadline covers its planning (granule selection, the cost model, a
// remote source's plan requests) as well as its execution. A call of an
// approved scan keeps its own clock (scanCall.deadline, from its request).
func startCall(ctx context.Context) context.Context {
	if _, ok := ctx.Value(startKey{}).(time.Time); ok || scanFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, startKey{}, time.Now())
}

// callStart is when the call of ctx started: startCall's instant, or now
// (a call of an approved scan, whose deadline is measured from its
// request, and a call not marked).
func callStart(ctx context.Context) time.Time {
	if t, ok := ctx.Value(startKey{}).(time.Time); ok && scanFrom(ctx) == nil {
		return t
	}
	return time.Now()
}

// planContext bounds the planning of a call by the call's deadline: for a
// free call its deadline from startCall, for a call of an approved scan
// what scanCallBudget leaves of its request.
func (e *Engine) planContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if sc := scanFrom(ctx); sc != nil {
		return context.WithDeadline(ctx, sc.start.Add(scanCallBudget))
	}
	return context.WithDeadline(ctx, callStart(ctx).Add(e.limits(ctx).Deadline))
}

// planError maps a planning error: planning cut by the call's deadline
// (its caller still waiting) is the call's budget, not the source's.
func planError(ctx, pctx context.Context, err *Error) *Error {
	if err != nil && ctx.Err() == nil && errors.Is(pctx.Err(), context.DeadlineExceeded) {
		return errPlanDeadline()
	}
	return err
}

func errPlanDeadline() *Error {
	return &Error{Code: EOverBudget, Message: "planning this query did not finish within the call's deadline: narrow the range or the sources, or try again"}
}

// runOpts are the options of run.
type runOpts struct {
	// keep reports whether a narrower slice of chunk may hold records of
	// the call (nil: every one).
	keep func(chunk int, g source.Granule) bool
	// maxGroup bounds the planned bytes of a group of an uncompressed
	// stream's granules (0: no bound but the time and the call's bytes).
	maxGroup int64
}

// browseGroups is how many groups of a browsing search's local granules
// the page cache holds at least: a group's rendered matches (a record's
// masked JSON and its ref, a few hundred bytes for a short line) stay
// well under the cache.
const browseGroups = 32

// overlaps reports whether granule g may hold records of [from, to): a
// granule with no known time span may.
func overlaps(g source.Granule, from, to time.Time) bool {
	if g.From.IsZero() || g.To.IsZero() {
		return true
	}
	return g.From.Before(to) && g.To.After(from)
}

// inRange is the keep function of a query over one range (runOpts).
func inRange(from, to time.Time) func(int, source.Granule) bool {
	return func(_ int, g source.Granule) bool { return overlaps(g, from, to) }
}
