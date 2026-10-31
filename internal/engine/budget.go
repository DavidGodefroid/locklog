package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// Budgets are the rolling budgets (design §3.3): what the agent's free
// calls may cost per hour (bytes processed, server-side metric queries) and
// per minute (remote backend requests), per source and for the whole
// console. Search, count, patterns, trace, context re-reads, tail polls and
// continuations all draw on them; an approved scan draws on its own plan
// instead.
type Budgets struct {
	// LocalBytesPerHour and RemoteBytesPerHour bound the bytes processed
	// (plan-based, granule-rounded; remote: the bytes fetched) per rolling
	// hour, by each source and by the console's sources of that kind.
	LocalBytesPerHour, RemoteBytesPerHour int64
	// RemoteRequestsPerMinute paces the requests of free calls to a remote
	// backend (per source and per console).
	RemoteRequestsPerMinute int
	// MetricQueriesPerHour bounds the server-side metric queries of
	// counts answered by a remote backend.
	MetricQueriesPerHour int
	// LookupsPerHour and LookupsPerHourPerUID bound the distinct values
	// log.lookup resolves per rolling hour, for the console and for one
	// peer uid.
	LookupsPerHour, LookupsPerHourPerUID int
}

// DefaultBudgets are the design defaults (non-production).
func DefaultBudgets() Budgets {
	return Budgets{LocalBytesPerHour: 40 << 30, RemoteBytesPerHour: 20 << 30, RemoteRequestsPerMinute: 600,
		MetricQueriesPerHour: 120, LookupsPerHour: 50, LookupsPerHourPerUID: 20}
}

// window is a rolling sum over span.
type window struct {
	span time.Duration
	evs  []windowEv
}

type windowEv struct {
	at time.Time
	n  int64
}

func (w *window) prune(now time.Time) {
	i := 0
	for i < len(w.evs) && !w.evs[i].at.After(now.Add(-w.span)) {
		i++
	}
	if i > 0 {
		w.evs = append(w.evs[:0], w.evs[i:]...)
	}
}

func (w *window) used(now time.Time) int64 {
	w.prune(now)
	var n int64
	for _, e := range w.evs {
		n += e.n
	}
	return n
}

func (w *window) add(now time.Time, n int64) {
	if n > 0 {
		w.evs = append(w.evs, windowEv{at: now, n: n})
	}
}

// freeAt is when the window has room for one more unit under limit.
func (w *window) freeAt(now time.Time, limit int64) time.Time {
	w.prune(now)
	used := int64(0)
	for _, e := range w.evs {
		used += e.n
	}
	for _, e := range w.evs {
		if used < limit {
			break
		}
		used -= e.n
		now = e.at.Add(w.span)
	}
	return now
}

// ledger keeps the rolling budgets of an engine. Keys are a source's name
// ("s:" prefix) and a kind of source for the whole console ("c:local",
// "c:remote").
type ledger struct {
	b   Budgets
	now func() time.Time

	mu       sync.Mutex
	bytes    map[string]*window
	reserved map[string]int64
	reqs     map[string]*window
	metrics  map[string]*window
	lookups  map[string]*lookupWindow
}

func newLedger(b Budgets, now func() time.Time) *ledger {
	return &ledger{b: b, now: now, bytes: map[string]*window{}, reserved: map[string]int64{}, reqs: map[string]*window{},
		metrics: map[string]*window{}, lookups: map[string]*lookupWindow{}}
}

func get(m map[string]*window, k string, span time.Duration) *window {
	w, ok := m[k]
	if !ok {
		w = &window{span: span}
		m[k] = w
	}
	return w
}

func classKey(remote bool) string {
	if remote {
		return "c:remote"
	}
	return "c:local"
}

// bytesLimit is the hourly byte budget of a kind of source.
func (l *ledger) bytesLimit(remote bool) int64 {
	if remote {
		return l.b.RemoteBytesPerHour
	}
	return l.b.LocalBytesPerHour
}

// reservation is what admission set aside for a call: released, and the
// call's actual charge added, when the call ends.
type reservation struct {
	l    *ledger
	keys map[string]int64
	once sync.Once
}

// errBudgetOver is the refusal of a call over a rolling byte budget.
func errBudgetOver(est int64, granules int, rng time.Duration, remote bool) *Error {
	kind := "local"
	if remote {
		kind = "remote"
	}
	return &Error{Code: EOverBudget, Message: fmt.Sprintf("the rolling budget of %s bytes processed per hour is used up: wait for it to refill (locklog_status shows what is left), or ask for locklog_scan", kind),
		Estimate: &Estimate{Bytes: est, Granules: granules, Range: rng}}
}

// admit sets aside est bytes per source (remote reports each source's
// kind) if every source and the console have room for them; it refuses
// otherwise, before any data is touched.
func (l *ledger) admit(est map[string]int64, remote func(string) bool, granules int, rng time.Duration) (*reservation, *Error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	keys := map[string]int64{}
	var total int64
	for s, n := range est {
		keys["s:"+s] += n
		keys[classKey(remote(s))] += n
		total += n
	}
	for k, n := range keys {
		isRemote := k == "c:remote" || k[:2] == "s:" && remote(k[2:])
		limit := l.bytesLimit(isRemote)
		if limit <= 0 {
			continue
		}
		if get(l.bytes, k, time.Hour).used(now)+l.reserved[k]+n > limit {
			return nil, errBudgetOver(total, granules, rng, isRemote)
		}
	}
	for k, n := range keys {
		l.reserved[k] += n
	}
	return &reservation{l: l, keys: keys}, nil
}

// settle releases r and charges actual bytes per source.
func (r *reservation) settle(actual map[string]int64, remote func(string) bool) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		l := r.l
		l.mu.Lock()
		defer l.mu.Unlock()
		for k, n := range r.keys {
			l.reserved[k] -= n
			if l.reserved[k] <= 0 {
				delete(l.reserved, k)
			}
		}
		l.chargeLocked(actual, remote)
	})
}

func (l *ledger) chargeLocked(actual map[string]int64, remote func(string) bool) {
	now := l.now()
	for s, n := range actual {
		get(l.bytes, "s:"+s, time.Hour).add(now, n)
		get(l.bytes, classKey(remote(s)), time.Hour).add(now, n)
	}
}

// bytesLeft is what the next call of a source may still process.
func (l *ledger) bytesLeft(src string, remote bool) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	limit := l.bytesLimit(remote)
	left := limit - get(l.bytes, classKey(remote), time.Hour).used(now) - l.reserved[classKey(remote)]
	if src != "" {
		left = min(left, limit-get(l.bytes, "s:"+src, time.Hour).used(now)-l.reserved["s:"+src])
	}
	return max(left, 0)
}

// errRequestBudget is a remote request the per-minute budget leaves no
// room for before the call's deadline.
var errRequestBudget = errors.New("engine: the remote request budget per minute is used up")

// errMetricBudget is a metric query past the hourly budget.
var errMetricBudget = errors.New("engine: the metric query budget per hour is used up")

// requestLimiter paces the requests of free calls to a remote source
// (source.Limiter): at most RemoteRequestsPerMinute per rolling minute,
// for the source and for the console. A request that would wait past the
// call's deadline fails with errRequestBudget. metric, when set, also
// charges each request as a server-side metric query.
type requestLimiter struct {
	l      *ledger
	src    string
	metric bool
}

var _ source.Limiter = requestLimiter{}

func (r requestLimiter) Wait(ctx context.Context) error {
	for {
		at, err := r.l.takeRequest(r.src, r.metric)
		if err != nil {
			return err
		}
		if at.IsZero() {
			return nil
		}
		if d, ok := ctx.Deadline(); ok && at.After(d) {
			return errRequestBudget
		}
		t := time.NewTimer(time.Until(at))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// takeRequest records a request now and returns the zero time, or returns
// when to try again.
func (l *ledger) takeRequest(src string, metric bool) (time.Time, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if metric && l.b.MetricQueriesPerHour > 0 {
		for _, k := range []string{"s:" + src, "c:remote"} {
			if get(l.metrics, k, time.Hour).used(now) >= int64(l.b.MetricQueriesPerHour) {
				return time.Time{}, errMetricBudget
			}
		}
	}
	keys := []string{"s:" + src, "c:remote"}
	if lim := int64(l.b.RemoteRequestsPerMinute); lim > 0 {
		var at time.Time
		for _, k := range keys {
			if t := get(l.reqs, k, time.Minute).freeAt(now, lim); t.After(now) && t.After(at) {
				at = t
			}
		}
		if !at.IsZero() {
			return at, nil
		}
	}
	for _, k := range keys {
		get(l.reqs, k, time.Minute).add(now, 1)
		if metric {
			get(l.metrics, k, time.Hour).add(now, 1)
		}
	}
	return time.Time{}, nil
}

// metricLeft is the metric queries a remote source may still send.
func (l *ledger) metricLeft(src string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.MetricQueriesPerHour <= 0 {
		return -1
	}
	now := l.now()
	left := int64(l.b.MetricQueriesPerHour) - get(l.metrics, "c:remote", time.Hour).used(now)
	if src != "" {
		left = min(left, int64(l.b.MetricQueriesPerHour)-get(l.metrics, "s:"+src, time.Hour).used(now))
	}
	return int(max(left, 0))
}

// requestsLeft is the requests a remote source may still send this minute.
func (l *ledger) requestsLeft(src string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.RemoteRequestsPerMinute <= 0 {
		return -1
	}
	now := l.now()
	lim := int64(l.b.RemoteRequestsPerMinute)
	left := lim - get(l.reqs, "c:remote", time.Minute).used(now)
	if src != "" {
		left = min(left, lim-get(l.reqs, "s:"+src, time.Minute).used(now))
	}
	return int(max(left, 0))
}

// lookupWindow holds the keyed digests of the distinct values looked up in
// the rolling hour (never the values).
type lookupWindow struct {
	seen map[string]time.Time
}

func (w *lookupWindow) prune(now time.Time) {
	for k, at := range w.seen {
		if !at.After(now.Add(-time.Hour)) {
			delete(w.seen, k)
		}
	}
}

func (l *ledger) lookupWin(k string) *lookupWindow {
	w, ok := l.lookups[k]
	if !ok {
		w = &lookupWindow{seen: map[string]time.Time{}}
		l.lookups[k] = w
	}
	return w
}

// takeLookups records the distinct values (keyed digests) a lookup of uid
// resolves, if the console and uid have room for the new ones.
func (l *ledger) takeLookups(uid int, digests []string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	keys := []struct {
		k     string
		limit int
	}{{"console", l.b.LookupsPerHour}, {fmt.Sprintf("uid:%d", uid), l.b.LookupsPerHourPerUID}}
	for _, k := range keys {
		w := l.lookupWin(k.k)
		w.prune(now)
		n := len(w.seen)
		for _, d := range digests {
			if _, ok := w.seen[d]; !ok {
				n++
			}
		}
		if k.limit > 0 && n > k.limit {
			return false
		}
	}
	for _, k := range keys {
		w := l.lookupWin(k.k)
		for _, d := range digests {
			w.seen[d] = now
		}
	}
	return true
}

// lookupsLeft is the distinct values the console may still look up.
func (l *ledger) lookupsLeft() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.LookupsPerHour <= 0 {
		return -1
	}
	w := l.lookupWin("console")
	w.prune(l.now())
	return max(l.b.LookupsPerHour-len(w.seen), 0)
}

// BudgetStatus is what is left of the rolling budgets (log.status): no
// content, only the console's own counters.
type BudgetStatus struct {
	Local  *ClassBudget `json:"local,omitempty"`
	Remote *ClassBudget `json:"remote,omitempty"`
	// Sources is each source's own budget left.
	Sources []SourceBudget `json:"sources"`
	// LookupsLeft is the distinct values the console may still look up
	// this hour (-1: no limit).
	LookupsLeft int `json:"lookups_left"`
	// Scans is the approved scans in progress.
	Scans int `json:"scans"`
}

// ClassBudget is one kind of source's rolling budget for the console.
type ClassBudget struct {
	BytesPerHour      int64 `json:"bytes_per_hour"`
	BytesLeft         int64 `json:"bytes_left"`
	RequestsLeft      *int  `json:"requests_left_this_minute,omitempty"`
	MetricLeft        *int  `json:"metric_queries_left,omitempty"`
	RequestsPerMinute int   `json:"requests_per_minute,omitempty"`
}

// SourceBudget is one source's rolling budget left.
type SourceBudget struct {
	Name      string `json:"name"`
	BytesLeft int64  `json:"bytes_left"`
}

// BudgetStatus reports what is left of the rolling budgets.
func (e *Engine) BudgetStatus() BudgetStatus {
	var st BudgetStatus
	var local, remote bool
	for _, n := range e.names {
		r := e.remote(n)
		local, remote = local || !r, remote || r
		st.Sources = append(st.Sources, SourceBudget{Name: n, BytesLeft: e.ledger.bytesLeft(n, r)})
	}
	sort.Slice(st.Sources, func(i, j int) bool { return st.Sources[i].Name < st.Sources[j].Name })
	if local {
		st.Local = &ClassBudget{BytesPerHour: e.ledger.b.LocalBytesPerHour, BytesLeft: e.ledger.bytesLeft("", false)}
	}
	if remote {
		rq, mq := e.ledger.requestsLeft(""), e.ledger.metricLeft("")
		st.Remote = &ClassBudget{BytesPerHour: e.ledger.b.RemoteBytesPerHour, BytesLeft: e.ledger.bytesLeft("", true),
			RequestsLeft: &rq, MetricLeft: &mq, RequestsPerMinute: e.ledger.b.RemoteRequestsPerMinute}
	}
	st.LookupsLeft = e.ledger.lookupsLeft()
	st.Scans = e.liveScans()
	return st
}
