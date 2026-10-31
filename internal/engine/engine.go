// Package engine answers the agent's log queries over masked records: it
// validates a query, builds a byte plan from the range and trusted
// selectors only, admits it against the per-call budgets, masks every
// record of each planned granule before any predicate runs, and stops at
// plan-chunk boundaries at its deadline, with a sealed cursor to continue.
//
// Admission, charges, stopping points, cursors, `scanned` and
// `covered_until` are functions of the plan, never of matches (design §3.3,
// §4.4): the work of a call depends on the bytes and their detector hits,
// not on the agent's predicates.
package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Masker is what the engine needs of the masker.
type Masker interface {
	Mask(source string, ev parse.Event) mask.Record
	Text(s string) string
	Epoch() string
}

// Limits are the per-call budgets (design §3.3).
type Limits struct {
	// Range of a query with text, regex or masked-field predicates.
	LocalRange, RemoteRange time.Duration
	// CountRange of a trusted-field-only count.
	CountRange time.Duration
	// Bytes a call's plan may cost (admission).
	LocalBytes, RemoteBytes int64
	// Records per page (ceiling of limit) and output bytes per page.
	MaxRecords int
	MaxOutput  int
	// Deadline of one call.
	Deadline time.Duration
	// MaxMaskFailures in a call before E_MASK.
	MaxMaskFailures int
}

// DefaultLimits are the design defaults.
func DefaultLimits() Limits {
	const day = 24 * time.Hour
	return Limits{LocalRange: 7 * day, RemoteRange: day, CountRange: 30 * day,
		// Admission from the S4/S3 spikes: masking runs at about
		// 1 MB/s/core, so 512 MiB (both kinds) is several free
		// continuations; the code ceiling stays 64 GiB.
		LocalBytes: 512 << 20, RemoteBytes: 512 << 20, MaxRecords: 200, MaxOutput: 64 << 10,
		Deadline: 30 * time.Second, MaxMaskFailures: 3}
}

// Options configure an Engine.
type Options struct {
	Sources map[string]source.Source
	// Trusted reports a trusted field of a source.
	Trusted func(src, field string) bool
	Masker  Masker
	Sealer  *Sealer
	Cost    *CostModel
	// PolicyFP is the fingerprint of the approved policy in force.
	PolicyFP func() string
	// Detect reports a query value a detector flags.
	Detect func(string) bool
	// NameMasked reports a clear path the masker shows masked.
	NameMasked func(src, path string) bool
	Limits     Limits
	// Prefilter (opt-in, refused on production by the config) skips
	// masking a record whose clear text cannot contain a needle.
	Prefilter bool
	// Workers mask in parallel (the console runs with --cpus min(2,
	// nproc)); the cost model is per call, so it is calibrated with the
	// same count.
	Workers int
	Now     func() time.Time
}

// Engine runs queries. It is safe for concurrent use.
type Engine struct {
	o     Options
	names []string

	mu    sync.Mutex
	plans map[string]*frozen // by plan id (LRU by lastUse)
	cache *resultCache
	aggs  aggCache
}

// frozen is a plan frozen at the first call of a query: continuations scan
// exactly it.
type frozen struct {
	id      string
	query   string // keyed digest of the normalised query
	plan    source.Byteplan
	lastUse time.Time
}

const maxPlans = 64

// New returns an engine.
func New(o Options) (*Engine, error) {
	if o.Masker == nil || o.Sealer == nil || o.Cost == nil || o.PolicyFP == nil || o.Trusted == nil {
		return nil, errors.New("engine: masker, sealer, cost model, policy fingerprint and trusted fields are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits()
	}
	if o.Workers <= 0 {
		o.Workers = 1
	}
	e := &Engine{o: o, plans: map[string]*frozen{}, cache: newResultCache(64 << 20)}
	for n := range o.Sources {
		e.names = append(e.names, n)
	}
	sort.Strings(e.names)
	return e, nil
}

func (e *Engine) remote(src string) bool {
	k := e.o.Sources[src].Kind()
	return k != "file" && k != "journald" && k != "docker"
}

// validator returns the validator of a call; trustedOnlyCount widens the
// range to the count budget.
func (e *Engine) validator(maxRange time.Duration) *validator {
	return &validator{now: e.o.Now(), sources: e.names, trusted: e.o.Trusted, detect: e.o.Detect,
		nameMasked: e.o.NameMasked, maxRange: maxRange, limitMax: e.o.Limits.MaxRecords}
}

// queryDigest is the keyed digest of a validated query (cursor excluded).
func (e *Engine) queryDigest(kind string, q any) string {
	b, _ := json.Marshal(q)
	return e.o.Sealer.Digest("locklog/query/v1", []byte(kind), b)
}

// cursorState is sealed into a cursor; the agent sees only ciphertext.
type cursorState struct {
	Plan     string `json:"p"`
	Query    string `json:"q"`
	Chunk    int    `json:"c"`
	Granule  int    `json:"g"`
	Cache    string `json:"k,omitempty"`
	Epoch    string `json:"e"`
	PolicyFP string `json:"f"`
	// From and To are the range resolved at the first call: a query by
	// last is continued over that window, not over a new one.
	From time.Time `json:"a"`
	To   time.Time `json:"b"`
}

// refState is sealed into a record ref.
type refState struct {
	Source   string `json:"s"`
	Stream   string `json:"t"`
	Offset   int64  `json:"o"`
	Length   int64  `json:"l"`
	Digest   string `json:"d"` // HMAC(K_ref, raw text)
	Epoch    string `json:"e"`
	PolicyFP string `json:"f"`
}

// Ref opens a sealed ref (for context, unmask, reveal).
func (e *Engine) Ref(ref string) (source.RawRef, string, error) {
	var st refState
	if err := e.o.Sealer.Open("Lr1", ref, &st); err != nil {
		return source.RawRef{}, "", err
	}
	if st.PolicyFP != e.o.PolicyFP() {
		return source.RawRef{}, "", &Error{Code: EPolicyChanged, Message: "the policy changed since this reference was made"}
	}
	return source.RawRef{Source: st.Source, Stream: st.Stream, Offset: st.Offset, Length: st.Length}, st.Digest, nil
}

// RecordDigest is the keyed digest of a raw record bound into its ref.
func (e *Engine) RecordDigest(raw string) string {
	return e.o.Sealer.Digest("locklog/record/v1", []byte(raw))
}

func (e *Engine) seal(prefix string, v any) string {
	s, err := e.o.Sealer.Seal(prefix, v)
	if err != nil {
		panic(err) // crypto/rand failure
	}
	return s
}

// Scanned is the plan-based work of a call.
type Scanned struct {
	Bytes    int64 `json:"bytes"`
	Records  int64 `json:"records"`
	Granules int   `json:"granules"`
}

// Masking reports what was masked in the returned records.
type Masking struct {
	Kinds []string `json:"kinds"`
}

// SearchResult is the answer of a search (design §3.4).
type SearchResult struct {
	Epoch        string            `json:"epoch"`
	Records      []json.RawMessage `json:"records"`
	Complete     bool              `json:"complete"`
	CoveredUntil *time.Time        `json:"covered_until,omitempty"`
	Cursor       string            `json:"cursor,omitempty"`
	Scanned      Scanned           `json:"scanned"`
	Masking      Masking           `json:"masking"`
	// MaskedFailures counts records withheld whole because masking
	// failed.
	MaskedFailures int `json:"masked_failures,omitempty"`
}

// planQuery builds and admits the plan of a validated query.
func (e *Engine) planQuery(ctx context.Context, q *Query, remoteBudget, localBudget int64) (source.Byteplan, *Error) {
	var plan source.Byteplan
	r := source.Range{From: q.From, To: q.To}
	var bytesLocal, bytesRemote int64
	for _, name := range q.Sources {
		src := e.o.Sources[name]
		p, err := src.Plan(ctx, r, q.selector(name, e.o.Trusted))
		if err != nil {
			return source.Byteplan{}, sourceError(err)
		}
		if e.remote(name) {
			bytesRemote += p.Bytes()
		} else {
			bytesLocal += p.Bytes()
		}
		plan.Chunks = append(plan.Chunks, p.Chunks...)
	}
	if bytesLocal > localBudget || bytesRemote > remoteBudget {
		return source.Byteplan{}, &Error{Code: EOverBudget, Message: "the plan exceeds this call's byte budget (narrow the range or the sources, or ask for locklog_scan)",
			Estimate: &Estimate{Bytes: plan.Bytes(), Granules: plan.Granules(), Range: q.To.Sub(q.From)}}
	}
	if q.Order == "asc" {
		slices.Reverse(plan.Chunks) // sources plan newest stream first
	}
	return plan, nil
}

// sourceError maps an error of a source to a fixed, content-free refusal of
// its class. Source errors may name files, hosts or label values, so their
// text never reaches the agent.
func sourceError(err error) *Error {
	switch {
	case errors.Is(err, source.ErrStale), errors.Is(err, source.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return &Error{Code: EStale, Message: "a log stream changed since the plan was made: run the query again"}
	case errors.Is(err, context.Canceled):
		return &Error{Code: ESource, Message: "cancelled"}
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Code: ESource, Message: "the source did not answer in time; try again"}
	case errors.Is(err, fs.ErrPermission):
		return &Error{Code: ESource, Message: "the console may not read a log of this source (permission denied)"}
	case errors.Is(err, source.ErrNotIndexable):
		return &Error{Code: ESource, Message: "the count needs fields the index does not hold"}
	}
	return &Error{Code: ESource, Message: "the source failed to read its logs"}
}

// callBytes is the bytes one call may process (remote sources, whose
// plans have no byte size before the fetch, stop there with a cursor).
func (e *Engine) callBytes(srcs []string) int64 {
	n := e.o.Limits.LocalBytes
	for _, s := range srcs {
		if e.remote(s) {
			n = min(n, e.o.Limits.RemoteBytes)
		}
	}
	return n
}

// freeze stores a plan for continuations and returns its id.
func (e *Engine) freeze(query string, plan source.Byteplan) *frozen {
	var b [12]byte
	rand.Read(b[:])
	f := &frozen{id: hex.EncodeToString(b[:]), query: query, plan: plan, lastUse: e.o.Now()}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.plans) >= maxPlans {
		var oldest *frozen
		for _, p := range e.plans {
			if oldest == nil || p.lastUse.Before(oldest.lastUse) {
				oldest = p
			}
		}
		delete(e.plans, oldest.id)
	}
	e.plans[f.id] = f
	return f
}

// openCursor opens a cursor, before the query is validated: a query by last
// takes the window sealed in it (restoreWindow).
func (e *Engine) openCursor(cursor string) (cursorState, *Error) {
	var st cursorState
	if err := e.o.Sealer.Open("Lc1", cursor, &st); err != nil {
		return st, &Error{Code: EStale, Span: "cursor", Message: "invalid or expired cursor: run the query again without it"}
	}
	if st.PolicyFP != e.o.PolicyFP() {
		return st, &Error{Code: EPolicyChanged, Span: "cursor", Message: "the policy changed: run the query again"}
	}
	if st.Epoch != e.o.Masker.Epoch() {
		return st, &Error{Code: EStale, Span: "cursor", Message: "the pseudonym epoch changed: run the query again"}
	}
	return st, nil
}

// restoreWindow resolves the last of a continued query to the window of its
// first call; the query digest, over the resolved range, then matches.
func restoreWindow(q *Query, st cursorState) {
	if q.Last != "" && q.From.IsZero() && q.To.IsZero() && !st.From.IsZero() {
		q.From, q.To, q.Last = st.From, st.To, ""
	}
}

// resume returns the frozen plan of an opened cursor of a query.
func (e *Engine) resume(st cursorState, query string) (*frozen, *Error) {
	if st.Query != query {
		return nil, &Error{Code: EStale, Span: "cursor", Message: "the cursor belongs to another query"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f := e.plans[st.Plan]
	if f == nil || f.query != query {
		return nil, &Error{Code: EStale, Span: "cursor", Message: "the cursor expired: run the query again"}
	}
	f.lastUse = e.o.Now()
	return f, nil
}

// run executes a frozen plan from (chunk, granule) until the plan ends, the
// call's byte budget is used, or the next group of granules would not fit
// before the deadline. Each group is first fetched (read, decompressed or
// downloaded), then every record of it is masked before visit sees it.
//
// Stopping points are group boundaries, decided from planned bytes before a
// fetch and from the bytes actually fetched before masking (remote sources:
// their deadline starts when the fetch completes). Both depend only on the
// range and the trusted selector, never on the predicates. It returns the
// position reached and the work done.
func (e *Engine) run(ctx context.Context, plan source.Byteplan, chunk, gran int, needles []string, callBytes int64,
	visit func(raw source.RawRecord, rec mask.Record)) (int, int, Scanned, int, *Error) {
	// Deadlines are wall-clock (Options.Now is the query clock).
	start := time.Now()
	deadline := start.Add(e.o.Limits.Deadline)
	var sc Scanned
	failures := 0
	filtered := e.o.Prefilter && len(needles) > 0
	for chunk < len(plan.Chunks) {
		if callBytes > 0 && sc.Bytes >= callBytes {
			return chunk, gran, sc, failures, nil
		}
		c := plan.Chunks[chunk]
		remaining := time.Until(deadline)
		groups := granuleGroups(c, gran, max(e.o.Cost.Budget(remaining), 1))
		if len(groups) == 0 {
			chunk, gran = chunk+1, 0
			continue
		}
		g := groups[0]
		sub := c
		sub.Granules = c.Granules[g[0]:g[1]]
		var planned int64
		for _, gr := range sub.Granules {
			planned += granuleBytes(gr, c.Bytes)
		}
		// Stop before a group that would not fit (but always make
		// progress on the first group of a call).
		if sc.Granules > 0 && e.o.Cost.Time(planned) > remaining {
			return chunk, gran, sc, failures, nil
		}
		groupCtx, cancel := context.WithDeadline(ctx, deadline.Add(e.o.Limits.Deadline/2))
		raws, total, fetched, err := e.fetch(groupCtx, sub, needles)
		if err == nil && sc.Granules > 0 && e.o.Cost.Time(fetched) > time.Until(deadline) {
			// Fetched more than the time left can mask: drop the group
			// unmasked; the next call fetches it again.
			cancel()
			return chunk, gran, sc, failures, nil
		}
		maskStart := time.Now()
		var recs []mask.Record
		if err == nil {
			recs, err = e.maskAll(groupCtx, c.Source, raws)
		}
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				// The group overran far past its estimate: drop it
				// (stopping points are group boundaries),
				// recalibrate and stop.
				e.o.Cost.Recalibrate()
				if sc.Granules == 0 {
					return chunk, gran, sc, failures, &Error{Code: ESource, Message: "the first plan granule did not finish in time; try again"}
				}
				return chunk, gran, sc, failures, nil
			}
			if ctx.Err() != nil {
				return chunk, gran, sc, failures, &Error{Code: ESource, Message: "cancelled"}
			}
			return chunk, gran, sc, failures, sourceError(err)
		}
		if took := time.Since(maskStart); took > e.o.Cost.Time(fetched)*3/2 && took > 100*time.Millisecond {
			e.o.Cost.Recalibrate() // overrun: recalibrate at once
		}
		for i := range raws {
			// With the pre-filter on, only the records whose clear
			// text holds the needles are masked: their failures
			// would tell which ones do, so they are not counted
			// (failed records are still withheld whole); see
			// prefilter.go.
			if recs[i].Failed() && !filtered {
				failures++
			}
			visit(raws[i], recs[i])
		}
		if failures >= e.o.Limits.MaxMaskFailures {
			return chunk, gran, sc, failures, &Error{Code: EMask, Message: "masking failed on several records: the call is refused"}
		}
		// Reported work is granule-rounded: the planned bytes of the
		// granules (a remote slice, unknown before the fetch, by the
		// bytes fetched, which depend on time and selector only).
		if planned > 0 {
			sc.Bytes += planned
		} else {
			sc.Bytes += fetched
		}
		sc.Records += int64(total) // before the pre-filter
		sc.Granules += len(sub.Granules)
		gran = g[1]
		if gran >= len(c.Granules) {
			chunk, gran = chunk+1, 0
		}
	}
	return chunk, gran, sc, failures, nil
}

// fetch reads the records of a group of granules: those to mask, how many
// the group holds (before any filtering: scanned.records never depends on
// the clear text) and the bytes it cost. With the opt-in pre-filter, a
// record whose clear text cannot contain every needle is dropped before
// masking (non-production only).
func (e *Engine) fetch(ctx context.Context, c source.Chunk, needles []string) ([]source.RawRecord, int, int64, error) {
	it, err := e.o.Sources[c.Source].Scan(ctx, c)
	if err != nil {
		return nil, 0, 0, err
	}
	defer it.Close()
	var raws []source.RawRecord
	total := 0
	for {
		raw, err := it.Next()
		if errors.Is(err, io.EOF) {
			return raws, total, it.Processed(), nil
		}
		if err != nil {
			return nil, total, it.Processed(), err
		}
		total++
		if e.o.Prefilter && len(needles) > 0 && !prefilterPass(raw.Event, needles) {
			continue
		}
		raws = append(raws, raw)
	}
}

// maskAll masks every record on the workers, in order. It returns only after
// every worker stopped (responses are released after workers are done).
func (e *Engine) maskAll(ctx context.Context, src string, raws []source.RawRecord) ([]mask.Record, error) {
	recs := make([]mask.Record, len(raws))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < max(1, e.o.Workers); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				recs[i] = e.o.Masker.Mask(src, raws[i].Event)
			}
		}()
	}
	for i := range raws {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	return recs, ctx.Err()
}

// outRecord renders a masked record for the agent: the masker's JSON plus
// the source and the sealed ref; with fields, only those paths.
func (e *Engine) outRecord(raw source.RawRecord, rec mask.Record, fields []string) (json.RawMessage, error) {
	ref := e.seal("Lr1", refState{Source: raw.Ref.Source, Stream: raw.Ref.Stream, Offset: raw.Ref.Offset,
		Length: raw.Ref.Length, Digest: e.RecordDigest(raw.Event.Raw), Epoch: e.o.Masker.Epoch(), PolicyFP: e.o.PolicyFP()})
	var b bytes.Buffer
	b.WriteString(`{"source":`)
	js, _ := json.Marshal(raw.Ref.Source)
	b.Write(js)
	b.WriteString(`,"ref":`)
	js, _ = json.Marshal(ref)
	b.Write(js)
	if len(fields) == 0 {
		body, err := rec.MarshalJSON()
		if err != nil {
			return nil, err
		}
		if len(body) > 2 {
			b.WriteByte(',')
			b.Write(body[1:])
		} else {
			b.WriteByte('}')
		}
		return b.Bytes(), nil
	}
	if t, ok := rec.Time(); ok {
		b.WriteString(`,"ts":`)
		js, _ = json.Marshal(t.UTC().Format(time.RFC3339Nano))
		b.Write(js)
	}
	if rec.Failed() {
		b.WriteString(`,"masked_failure":true}`)
		return b.Bytes(), nil
	}
	b.WriteString(`,"fields":{`)
	n := 0
	for _, f := range fields {
		if msgPaths[f] {
			if _, ok := rec.Lookup(f); !ok {
				continue // the message goes under "msg"
			}
		}
		v, ok := rec.Lookup(f)
		if !ok {
			continue
		}
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		js, _ = json.Marshal(f)
		b.Write(js)
		b.WriteByte(':')
		vj, err := v.MarshalJSON()
		if err != nil {
			return nil, err
		}
		b.Write(vj)
	}
	b.WriteByte('}')
	if (slices.Contains(fields, "msg") || slices.Contains(fields, "message")) && rec.Message() != "" {
		b.WriteString(`,"msg":`)
		js, _ = json.Marshal(rec.Message())
		b.Write(js)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// match is one matched record kept for a page.
type match struct {
	ts    time.Time
	timed bool
	out   json.RawMessage
	kinds []string
}

// Search runs a search (locklog_search).
func (e *Engine) Search(ctx context.Context, q Query) (SearchResult, error) {
	cursor := q.Cursor
	q.Cursor = ""
	maxRange := e.o.Limits.LocalRange
	for _, s := range q.Sources {
		if _, ok := e.o.Sources[s]; ok && e.remote(s) {
			maxRange = min(maxRange, e.o.Limits.RemoteRange)
		}
	}
	if len(q.Sources) == 0 {
		for _, s := range e.names {
			if e.remote(s) {
				maxRange = min(maxRange, e.o.Limits.RemoteRange)
			}
		}
	}
	var st cursorState
	if cursor != "" {
		var err *Error
		if st, err = e.openCursor(cursor); err != nil {
			return SearchResult{}, err
		}
		restoreWindow(&q, st)
	}
	if err := e.validator(maxRange).validate(&q); err != nil {
		return SearchResult{}, err
	}
	digest := e.queryDigest("search", q)
	res := SearchResult{Epoch: e.o.Masker.Epoch(), Records: []json.RawMessage{}, Masking: Masking{Kinds: []string{}}}

	var f *frozen
	chunk, gran := 0, 0
	var pending []match
	if cursor != "" {
		var err *Error
		if f, err = e.resume(st, digest); err != nil {
			return SearchResult{}, err
		}
		chunk, gran = st.Chunk, st.Granule
		if st.Cache != "" {
			cached, ok := e.cache.take(st.Cache)
			if !ok {
				return SearchResult{}, &Error{Code: EStale, Span: "cursor", Message: "the cursor expired: run the query again"}
			}
			pending = cached
		}
	} else {
		plan, err := e.planQuery(ctx, &q, e.o.Limits.RemoteBytes, e.o.Limits.LocalBytes)
		if err != nil {
			return SearchResult{}, err
		}
		f = e.freeze(digest, plan)
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
	var failures int
	if len(pending) < q.Limit {
		var sc Scanned
		var err *Error
		var found []match
		chunk, gran, sc, failures, err = e.run(ctx, f.plan, chunk, gran, needles, e.callBytes(q.Sources), func(raw source.RawRecord, rec mask.Record) {
			// Granules hold records around the range: keep the
			// range's (and the untimed ones).
			if t, ok := rec.Time(); ok && !q.rangeContains(t, false) {
				return
			}
			if !q.match(rec) {
				return
			}
			out, oerr := e.outRecord(raw, rec, q.Fields)
			if oerr != nil {
				return
			}
			t, ok := rec.Time()
			found = append(found, match{ts: t, timed: ok, out: out, kinds: rec.Kinds()})
		})
		if err != nil {
			return SearchResult{}, err
		}
		sortMatches(found, q.Order)
		pending = append(pending, found...)
		res.Scanned = sc
		res.MaskedFailures = failures
	}
	// Fill the page within the record and output caps; the rest is kept
	// for the next page.
	size := 256
	kinds := map[string]bool{}
	n := 0
	for n < len(pending) && n < q.Limit {
		if size+len(pending[n].out)+1 > e.o.Limits.MaxOutput && n > 0 {
			break
		}
		size += len(pending[n].out) + 1
		res.Records = append(res.Records, pending[n].out)
		for _, k := range pending[n].kinds {
			kinds[k] = true
		}
		n++
	}
	for k := range kinds {
		res.Masking.Kinds = append(res.Masking.Kinds, k)
	}
	sort.Strings(res.Masking.Kinds)
	rest := pending[n:]
	done := chunk >= len(f.plan.Chunks)
	res.Complete = done && len(rest) == 0
	if !res.Complete {
		st := cursorState{Plan: f.id, Query: digest, Chunk: chunk, Granule: gran, Epoch: e.o.Masker.Epoch(), PolicyFP: e.o.PolicyFP(),
			From: q.From, To: q.To}
		if len(rest) > 0 {
			st.Cache = e.cache.put(rest)
		}
		res.Cursor = e.seal("Lc1", st)
		if cu, ok := coveredUntil(f.plan, chunk, gran, q); ok {
			res.CoveredUntil = &cu
		}
	} else {
		to := q.To
		res.CoveredUntil = &to
	}
	return res, nil
}

func sortMatches(ms []match, order string) {
	sort.SliceStable(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if a.timed != b.timed {
			return a.timed // untimed last
		}
		if order == "desc" {
			return a.ts.After(b.ts)
		}
		return a.ts.Before(b.ts)
	})
}

// coveredUntil is, for an ascending query, the earliest known start of a
// granule not yet scanned (every record before it was scanned when the
// remaining granules' spans are known from the index); for a descending
// one, the latest known end. It is derived from the plan only.
func coveredUntil(plan source.Byteplan, chunk, gran int, q Query) (time.Time, bool) {
	var best time.Time
	for ci := chunk; ci < len(plan.Chunks); ci++ {
		c := plan.Chunks[ci]
		gi := 0
		if ci == chunk {
			gi = gran
		}
		for ; gi < len(c.Granules); gi++ {
			g := c.Granules[gi]
			if !g.Indexed {
				return time.Time{}, false
			}
			if g.From.IsZero() {
				continue
			}
			if q.Order == "desc" {
				if best.IsZero() || g.To.After(best) {
					best = g.To
				}
			} else if best.IsZero() || g.From.Before(best) {
				best = g.From
			}
		}
	}
	if best.IsZero() {
		return time.Time{}, false
	}
	if best.Before(q.From) {
		best = q.From
	}
	if best.After(q.To) {
		best = q.To
	}
	return best.Truncate(time.Second), true
}

// String describes an engine for status screens (no content).
func (e *Engine) String() string {
	return fmt.Sprintf("engine: %d sources, cost %s", len(e.names), e.o.Cost)
}
