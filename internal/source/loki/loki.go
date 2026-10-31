// Package loki is the Loki log source. It sends only allowlisted read
// requests through the egress client, selects server-side by time and by
// trusted stream labels only (trusted structured metadata and text are
// matched locally, after masking), drops every untrusted label and metadata
// field from what it returns, and plans fixed time slices whose cost is the
// bytes actually fetched.
package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Kind is the source kind.
const Kind = "loki"

// Defaults from the S3 spike.
const (
	// Limit is the entries per query_range page (Loki's default max).
	Limit = 5000
	// InFlight is the requests in flight per source (the knee measured).
	InFlight = 4
	// MaxSlices bounds the time slices of one plan.
	MaxSlices = 512
)

// sliceWidths are the plan granule widths: the smallest one that cuts the
// range into at most MaxSlices slices is used. Slices are aligned to the Unix
// epoch, so a plan is a function of the range and the selector only.
var sliceWidths = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour}

// hiddenLabels are labels Loki adds that locklog never shows.
var hiddenLabels = map[string]bool{"__stream_shard__": true}

// Client is the egress client of the source (egress.Client).
type Client interface {
	GetWith(ctx context.Context, path string, q url.Values, hdr map[string]string) (egress.Response, error)
}

// encodingFlag asks Loki 3 to return structured metadata apart from the
// stream labels. The source sends it on every request, whatever headers its
// client was built with, and refuses a streams answer that does not say it
// applied it (without it, Loki merges metadata into each stream's labels).
const encodingFlag = "categorize-labels"

var requestHeaders = map[string]string{"X-Loki-Response-Encoding-Flags": encodingFlag}

// Options configure a Loki source.
type Options struct {
	Name   string
	Client Client
	Parser *parse.Parser
	// Selector is the profile's selector, ANDed into every query.
	Selector map[string]string
	// TrustedLabels and TrustedMetadata are shown (after the detectors)
	// and selectable; every other label and metadata field is dropped.
	TrustedLabels   []string
	TrustedMetadata []string
	// InFlight overrides InFlight (tests).
	InFlight int
	// Limit overrides Limit (tests).
	Limit int
	Now   func() time.Time
}

// Source is a Loki source. It is safe for concurrent use.
type Source struct {
	o   Options
	sem chan struct{}
}

// New validates opts.
func New(o Options) (*Source, error) {
	if o.Client == nil || o.Parser == nil {
		return nil, errors.New("loki source: client and parser are required")
	}
	if len(o.Selector) == 0 {
		return nil, errors.New("loki source: an empty selector would read every stream")
	}
	for k, v := range o.Selector {
		if !nameRe.MatchString(k) {
			return nil, fmt.Errorf("loki source: invalid selector label %q", k)
		}
		if v == "" {
			// x="" means "x absent" to Loki: it would widen the scope.
			return nil, fmt.Errorf("loki source: selector label %s needs a value", k)
		}
	}
	// A | name="v" filter matches stream labels too: a trusted metadata
	// name that is also a stream label would select on either.
	for _, m := range o.TrustedMetadata {
		if _, sel := o.Selector[m]; sel || slices.Contains(o.TrustedLabels, m) {
			return nil, fmt.Errorf("loki source: %q is both a stream label and trusted structured metadata", m)
		}
	}
	if o.InFlight <= 0 {
		o.InFlight = InFlight
	}
	if o.Limit <= 0 {
		o.Limit = Limit
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Source{o: o, sem: make(chan struct{}, o.InFlight)}, nil
}

// Name returns the source name.
func (s *Source) Name() string { return s.o.Name }

// Kind returns "loki".
func (s *Source) Kind() string { return Kind }

func (s *Source) trustedLabel(n string) bool { return slices.Contains(s.o.TrustedLabels, n) }
func (s *Source) trustedMeta(n string) bool  { return slices.Contains(s.o.TrustedMetadata, n) }

// pushable reports whether a term means the same in Loki as locally: a
// term on a trusted stream label, without an empty value (Loki's x="" also
// matches an absent x, and x!="" means "present", where
// source.Selector.Match needs x present and empty for = "").
//
// Terms on trusted structured metadata are never pushed: a LogQL
// | name="v" filter matches a stream label of that name as well as the
// metadata, and anyone who writes to Loki can add such a label to a
// stream. They are evaluated locally, on the metadata the categorized
// response returns apart from the labels.
func (s *Source) pushable(t source.Term) bool {
	return (t.Op == "=" || t.Op == "in" || t.Op == "!=") && s.trustedLabel(t.Field) && len(t.Values) > 0 && !slices.Contains(t.Values, "")
}

// selector builds the server-side selector: the profile's, plus the
// pushable terms as stream matchers. Other terms are ignored here (the
// engine evaluates every term after masking).
func (s *Source) selector(sel source.Selector) Selector {
	var out Selector
	for k, v := range s.o.Selector {
		out.Stream = append(out.Stream, Matcher{Name: k, Op: "=", Values: []string{v}})
	}
	for _, t := range sel.Terms {
		if !s.pushable(t) {
			continue
		}
		switch t.Op {
		case "=", "in":
			m := Matcher{Name: t.Field, Op: "=~", Values: t.Values}
			if len(t.Values) == 1 {
				m.Op = "="
			}
			out.Stream = append(out.Stream, m)
		case "!=":
			m := Matcher{Name: t.Field, Op: "!~", Values: t.Values}
			if len(t.Values) == 1 {
				m.Op = "!="
			}
			out.Stream = append(out.Stream, m)
		}
	}
	return out
}

// do sends one request under the call's limiter and the in-flight cap.
func (s *Source) do(ctx context.Context, path string, q url.Values) ([]byte, error) {
	resp, err := s.doResp(ctx, path, q)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// doResp is do, returning the response (its status and body, also on a
// non-2xx answer) with the error.
func (s *Source) doResp(ctx context.Context, path string, q url.Values) (egress.Response, error) {
	if l := source.LimiterFrom(ctx); l != nil {
		if err := l.Wait(ctx); err != nil {
			return egress.Response{}, err
		}
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return egress.Response{}, ctx.Err()
	}
	defer func() { <-s.sem }()
	return s.o.Client.GetWith(ctx, path, q, requestHeaders)
}

// limitRefusals are Loki 3.5's answers to a query over one of its limits
// (status, message prefix): pkg/querier/queryrange/limits.go,
// pkg/util/validation/validate.go, pkg/lokifrontend, pkg/util/server/error.go.
var limitRefusals = []struct {
	status int
	prefix string
}{
	{400, "maximum of series ("},
	{400, "the query time range exceeds the limit"},
	{429, "too many outstanding requests"},
	{504, "request timed out"},
}

// limitRefused reports whether resp is Loki refusing a query over a limit.
func limitRefused(resp egress.Response) bool {
	body := strings.TrimSpace(string(resp.Body))
	for _, r := range limitRefusals {
		if resp.Status == r.status && strings.HasPrefix(body, r.prefix) {
			return true
		}
	}
	return false
}

// sliceCount returns the number of epoch-aligned slices of width w covering r.
func sliceCount(r source.Range, w time.Duration) int64 {
	start := r.From.Truncate(w)
	return int64((r.To.Sub(start) + w - 1) / w)
}

// width returns the slice width of a range: the smallest of sliceWidths
// that covers it in at most MaxSlices aligned slices. A range that needs
// more slices even at the widest is an error.
func width(r source.Range) (time.Duration, error) {
	for _, w := range sliceWidths {
		if sliceCount(r, w) <= MaxSlices {
			return w, nil
		}
	}
	return 0, fmt.Errorf("loki source: the range needs more than %d slices of %v: narrow it", MaxSlices, sliceWidths[len(sliceWidths)-1])
}

// Plan returns one chunk of epoch-aligned time slices covering r, for the
// selector built from the profile and the trusted terms. The slices' byte
// cost is unknown until fetched: the engine charges the bytes fetched.
func (s *Source) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	q, err := s.selector(sel).Render()
	if err != nil {
		return source.Byteplan{}, err
	}
	if !r.From.Before(r.To) {
		return source.Byteplan{}, nil
	}
	w, err := width(r)
	if err != nil {
		return source.Byteplan{}, err
	}
	start := r.From.Truncate(w)
	var gs []source.Granule
	for t := start; t.Before(r.To); t = t.Add(w) {
		gs = append(gs, source.Granule{Start: t.UnixNano(), End: t.Add(w).UnixNano(), From: t, To: t.Add(w)})
	}
	return source.Byteplan{Chunks: []source.Chunk{{Source: s.o.Name, Stream: q, Granules: gs}}}, nil
}

// entry is one log entry of a response.
type entry struct {
	ts     int64
	line   string
	stream map[string]string
	meta   map[string]string
	key    string // stream labels, canonical
}

// queryResponse is Loki's query_range answer (streams), in the
// categorize-labels encoding.
type queryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType    string   `json:"resultType"`
		EncodingFlags []string `json:"encodingFlags"`
		Result        []struct {
			Stream map[string]string   `json:"stream"`
			Metric map[string]string   `json:"metric"`
			Values [][]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func labelsKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%d:%s=%d:%s,", len(k), k, len(m[k]), m[k])
	}
	return b.String()
}

var errResponse = errors.New("loki source: unexpected response")

var errUncategorized = errors.New("loki source: the response is not in the categorize-labels encoding (Loki 3 with structured metadata is required)")

// decodeStreams decodes a streams response into entries, sorted by (ts,
// stream, line): a deterministic order, independent of how Loki grouped
// them. It is not a streaming decoder: the egress client reads the body
// whole, capped at egress.MaxResponseBytes (64 MiB), and it is decoded in
// one json.Unmarshal, so a page costs its body plus its entries in memory.
// Lines are cut at parse.MaxLineBytes (256 KiB) when parsed (record).
func decodeStreams(body []byte) ([]entry, error) {
	var r queryResponse
	if err := json.Unmarshal(body, &r); err != nil || r.Status != "success" || r.Data.ResultType != "streams" {
		return nil, errResponse
	}
	// Without the flag applied, metadata sits among the stream labels,
	// where an untrusted field could pass for a trusted label: fail closed.
	if !slices.Contains(r.Data.EncodingFlags, encodingFlag) {
		return nil, errUncategorized
	}
	var out []entry
	for _, st := range r.Data.Result {
		key := labelsKey(st.Stream)
		for _, v := range st.Values {
			if len(v) < 2 {
				return nil, errResponse
			}
			var tsStr, line string
			if json.Unmarshal(v[0], &tsStr) != nil || json.Unmarshal(v[1], &line) != nil {
				return nil, errResponse
			}
			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				return nil, errResponse
			}
			e := entry{ts: ts, line: line, stream: st.Stream, key: key}
			if len(v) >= 3 {
				var md struct {
					StructuredMetadata map[string]string `json:"structuredMetadata"`
				}
				if json.Unmarshal(v[2], &md) == nil {
					e.meta = md.StructuredMetadata
				}
			}
			out = append(out, e)
		}
	}
	sortEntries(out)
	return out, nil
}

func sortEntries(es []entry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		if a.key != b.key {
			return a.key < b.key
		}
		return a.line < b.line
	})
}

// errCrowded is returned when a page cannot move past one nanosecond: at
// least Limit entries share it, and Loki pages by time only, so the rest of
// them cannot be fetched. The slice fails rather than return part of it.
var errCrowded = errors.New("at least a page of entries share one nanosecond: they cannot be paged completely")

// fetchSlice returns every entry of [from, to) for query q, in order, and
// the response bytes it fetched. Pages are cut by Limit; the next page
// starts at the last timestamp of the page, and the entries already
// returned at that timestamp are skipped. A full page that brings nothing
// new at one timestamp is an error (errCrowded), never a silent cut.
func (s *Source) fetchSlice(ctx context.Context, q string, from, to int64) ([]entry, int64, error) {
	var out []entry
	var fetched int64
	start := from
	for {
		v := url.Values{}
		v.Set("query", q)
		v.Set("start", strconv.FormatInt(start, 10))
		// grafana/loki:3.5.7 excludes a log query's end; what is at `to`
		// (the next slice's) is dropped anyway, should a backend include it.
		v.Set("end", strconv.FormatInt(to, 10))
		v.Set("limit", strconv.Itoa(s.o.Limit))
		v.Set("direction", "forward")
		body, err := s.do(ctx, "/loki/api/v1/query_range", v)
		if err != nil {
			return nil, fetched, err
		}
		fetched += int64(len(body))
		page, err := decodeStreams(body)
		if err != nil {
			return nil, fetched, err
		}
		// Skip what the previous page already returned at start.
		seen := map[string]int{}
		for i := len(out) - 1; i >= 0 && out[i].ts == start; i-- {
			seen[out[i].key+"\x00"+out[i].line]++
		}
		// A page that is not full, or that reaches `to`, holds the rest
		// of the slice (pages are cut in time order).
		done := len(page) < s.o.Limit
		n := 0
		var last int64 = -1
		for _, e := range page {
			if e.ts >= to {
				done = true
				continue
			}
			if e.ts < start {
				continue
			}
			// Over every in-range entry of the page, new or not.
			last = max(last, e.ts)
			k := e.key + "\x00" + e.line
			if e.ts == start && seen[k] > 0 {
				seen[k]--
				continue
			}
			out = append(out, e)
			n++
		}
		switch {
		case done:
			// One order for the whole slice, whatever the page cuts and
			// Loki's order of ties: ordinals within a nanosecond (Reread,
			// Around) then point at the same entries.
			sortEntries(out)
			return out, fetched, nil
		case last < 0:
			// A full page with nothing in [start, to): not Loki's paging.
			return nil, fetched, errResponse
		case last == start && n == 0:
			return nil, fetched, errCrowded
		}
		start = last
	}
}

// record turns an entry into a raw record: the line parsed, the entry's
// timestamp as the record time, the trusted labels and metadata as attrs.
func (s *Source) record(c source.Chunk, e entry, ordinal int) source.RawRecord {
	ev := s.o.Parser.Line(e.line)
	ev.SetTime(time.Unix(0, e.ts).UTC())
	var attrs []parse.Member
	add := func(m map[string]string, trusted func(string) bool) {
		keys := make([]string, 0, len(m))
		for k := range m {
			if trusted(k) && !hiddenLabels[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			attrs = append(attrs, parse.Member{Key: k, Value: parse.Value{Kind: parse.KindString, Str: m[k]}})
		}
	}
	add(e.stream, s.trustedLabel)
	add(e.meta, s.trustedMeta)
	ev.Attrs = attrs
	ev.Offset, ev.Length = e.ts, int64(ordinal+1)
	return source.RawRecord{
		Ref:     source.RawRef{Source: s.o.Name, Stream: c.Stream, Offset: e.ts, Length: int64(ordinal + 1)},
		Event:   ev,
		Granule: 0,
	}
}

// Scan fetches the chunk's slices (up to InFlight at once) and yields their
// records in time order.
func (s *Source) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	if len(c.Granules) == 0 {
		return nil, errors.New("loki source: empty chunk")
	}
	ctx, cancel := context.WithCancel(ctx)
	it := &iter{s: s, c: c, cancel: cancel, results: make([]chan sliceResult, len(c.Granules))}
	for i := range c.Granules {
		it.results[i] = make(chan sliceResult, 1)
	}
	go func() {
		var wg sync.WaitGroup
		gate := make(chan struct{}, s.o.InFlight)
		for i, g := range c.Granules {
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				it.results[i] <- sliceResult{err: ctx.Err()}
				continue
			}
			wg.Add(1)
			go func(i int, g source.Granule) {
				defer wg.Done()
				defer func() { <-gate }()
				es, n, err := s.fetchSlice(ctx, c.Stream, g.Start, g.End)
				it.results[i] <- sliceResult{entries: es, bytes: n, err: err}
			}(i, g)
		}
		wg.Wait()
	}()
	return it, nil
}

type sliceResult struct {
	entries []entry
	bytes   int64
	err     error
}

type iter struct {
	s         *Source
	c         source.Chunk
	cancel    context.CancelFunc
	results   []chan sliceResult
	cur       int
	entries   []entry
	pos       int
	processed int64
	ordinal   int
	lastTS    int64
	err       error
}

func (it *iter) Next() (source.RawRecord, error) {
	for it.pos >= len(it.entries) {
		if it.err != nil {
			return source.RawRecord{}, it.err
		}
		if it.cur >= len(it.results) {
			return source.RawRecord{}, io.EOF
		}
		r := <-it.results[it.cur]
		it.processed += r.bytes
		if r.err != nil {
			it.err = fmt.Errorf("loki source: %w", r.err)
			return source.RawRecord{}, it.err
		}
		it.entries, it.pos = r.entries, 0
		it.cur++
	}
	e := it.entries[it.pos]
	it.pos++
	if e.ts == it.lastTS {
		it.ordinal++
	} else {
		it.ordinal, it.lastTS = 0, e.ts
	}
	rec := it.s.record(it.c, e, it.ordinal)
	rec.Granule = it.cur - 1
	return rec, nil
}

// Processed returns the response bytes fetched so far.
func (it *iter) Processed() int64 { return it.processed }

// Close stops the fetches.
func (it *iter) Close() error {
	it.cancel()
	return nil
}

// Reread fetches the entry at ref again: ref.Offset is its timestamp and
// ref.Length its ordinal (from 1) among the entries of that nanosecond.
func (s *Source) Reread(ctx context.Context, ref source.RawRef) (source.RawRecord, error) {
	es, _, err := s.fetchSlice(ctx, ref.Stream, ref.Offset, ref.Offset+1)
	if err != nil {
		return source.RawRecord{}, fmt.Errorf("loki source: %w", err)
	}
	i := int(ref.Length) - 1
	if i < 0 || i >= len(es) {
		return source.RawRecord{}, source.ErrStale
	}
	return s.record(source.Chunk{Stream: ref.Stream}, es[i], i), nil
}

// AroundWindow bounds how far Around looks on each side.
const AroundWindow = 15 * time.Minute

// Around returns up to before entries before ref, ref's entry and up to
// after entries after it, from the same query.
func (s *Source) Around(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, error) {
	before, after = max(0, min(before, 50)), max(0, min(after, 50))
	from := ref.Offset - int64(AroundWindow)
	to := ref.Offset + int64(AroundWindow)
	es, _, err := s.fetchSlice(ctx, ref.Stream, from, to)
	if err != nil {
		return nil, fmt.Errorf("loki source: %w", err)
	}
	// Ordinals restart at each nanosecond.
	idx := -1
	ord := 0
	ords := make([]int, len(es))
	for i, e := range es {
		if i > 0 && es[i-1].ts == e.ts {
			ord++
		} else {
			ord = 0
		}
		ords[i] = ord
		if e.ts == ref.Offset && int64(ord+1) == ref.Length {
			idx = i
		}
	}
	if idx < 0 {
		return nil, source.ErrStale
	}
	lo, hi := max(0, idx-before), min(len(es), idx+after+1)
	out := make([]source.RawRecord, 0, hi-lo)
	for i := lo; i < hi; i++ {
		out = append(out, s.record(source.Chunk{Stream: ref.Stream}, es[i], ords[i]))
	}
	return out, nil
}

type labelsResponse struct {
	Status string   `json:"status"`
	Data   []string `json:"data"`
}

// Describe lists the trusted labels and metadata fields with the trusted
// labels' values (asked only for trusted labels), the names of other labels
// (masked by the caller), and the source kind. Every label request carries
// the profile's selector as its query: only the profile's streams are
// described.
func (s *Source) Describe(ctx context.Context) (source.Schema, error) {
	sch := source.Schema{Kind: Kind, Format: s.o.Parser.Options().Format, Streams: 1}
	sel, err := s.selector(source.Selector{}).Render()
	if err != nil {
		return sch, err
	}
	end := s.o.Now()
	v := url.Values{}
	v.Set("query", sel)
	v.Set("start", strconv.FormatInt(end.Add(-24*time.Hour).UnixNano(), 10))
	v.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	body, err := s.do(ctx, "/loki/api/v1/labels", v)
	if err != nil {
		return sch, fmt.Errorf("loki source: %w", err)
	}
	var lr labelsResponse
	if json.Unmarshal(body, &lr) != nil || lr.Status != "success" {
		return sch, errResponse
	}
	for _, l := range lr.Data {
		if hiddenLabels[l] || !nameRe.MatchString(l) {
			continue
		}
		info := source.FieldInfo{Name: l, Trusted: s.trustedLabel(l)}
		if info.Trusted {
			vb, err := s.do(ctx, "/loki/api/v1/label/"+l+"/values", v)
			if err != nil {
				return sch, fmt.Errorf("loki source: %w", err)
			}
			var vr labelsResponse
			if json.Unmarshal(vb, &vr) == nil && vr.Status == "success" && len(vr.Data) <= 64 {
				info.Values = vr.Data
			}
		}
		sch.Fields = append(sch.Fields, info)
	}
	for _, m := range s.o.TrustedMetadata {
		sch.Fields = append(sch.Fields, source.FieldInfo{Name: m, Trusted: true})
	}
	return sch, nil
}

type matrixResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string    `json:"metric"`
			Values [][2]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

type vectorResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string  `json:"metric"`
			Value  [2]json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// MaxBoundaryFetches bounds the boundaries whose entries one count fetches
// (each a log request under the call's limiter); past it, the count is not
// served and the engine scans.
const MaxBoundaryFetches = 64

// maxBoundaryBytes bounds the response bytes of one count's boundary
// fetches (both rounds); past it, the count is not served. A var for tests.
var maxBoundaryBytes int64 = 8 << 20

// IndexCounts answers a trusted-label count with server-side metric queries:
// no line leaves the source.
//
// The engine's buckets are [b, b+bucket); Loki's count_over_time at t counts
// (t-bucket, t], to the nanosecond. Loki cannot be asked for the engine's
// windows directly: its query frontend rounds a range query's start down
// to the step (pkg/querier/queryrange/splitters.go, alignStartEnd), and
// grafana/loki:3.5.7 returns no point at all for an offset under 1 ms (an
// offset of 1 ms or more would move whole milliseconds across buckets). So
// the counts are Loki's windows, corrected at the boundaries:
//
//   - sum by (labels) (count_over_time({selector}[bucket])) at the points
//     From+bucket .. To, step bucket (one bucket for the range: an instant
//     query at To): the point at t is bucket t-bucket;
//   - the entries exactly on a boundary b belong to the bucket starting at
//     b, not to the one Loki ends at b. A guard query,
//     sum(count_over_time({selector}[1ms])) at From .. To, finds the
//     boundaries with an entry in (b-1ms, b] (an instant count: From and
//     To); the entries of those are fetched at exactly b and moved (Loki's
//     window misses those at From and counts those at To, outside the
//     range).
//
// Grouping: Loki adds each entry's structured metadata to the labels a
// metric groups by, under the label's name unless the stream has that label
// (pkg/logql/log/metrics_extraction.go, LabelsBuilder.Add). An untrusted
// metadata field could then pass for a by-label's value. So each by-label is
// counted present (L!="" in the stream selector: the metadata becomes
// L_extracted) and absent (L="", not grouped on, value ""), one metric query
// per combination.
//
// Ingestion during the count: the guard and the boundary fetches run before
// and after the metric queries, and must agree, else the count is not
// served.
//
// Cost: one metric query per by-label combination (up to 4), two guard
// queries, and twice one log request per boundary to correct (at most
// MaxBoundaryFetches, at most 8 MiB of responses in all), every request
// under the call's limiter. The boundary lines never leave the source.
//
// Not served (source.ErrNotIndexable): a Loki limit refusal (too many
// series, too long a range, too many outstanding requests, a timeout); a
// point off the grid asked for; a
// count by anything but a trusted stream label (structured metadata
// included), or by more than two; a term on anything but a trusted stream
// label, or with no value or an empty one; an empty range; a bucket under a
// second, not whole seconds, not dividing the range, or cutting it into
// more than 11000 points; a bucketed range whose ends are not multiples of
// the bucket since the epoch; more than MaxBoundaryFetches boundaries to
// fetch or more than 8 MiB of them, or one with a page or more of entries
// at its nanosecond.
func (s *Source) IndexCounts(ctx context.Context, q source.CountQuery) (source.CountResult, error) {
	if len(q.By) > 2 {
		return source.CountResult{}, source.ErrNotIndexable
	}
	for _, b := range q.By {
		if !s.trustedLabel(b) || !nameRe.MatchString(b) {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	for _, t := range q.Selector.Terms {
		if !s.pushable(t) {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}
	span := q.Range.To.Sub(q.Range.From)
	bucket := q.Bucket
	instant := bucket == 0
	if instant {
		bucket = span
	}
	if bucket < time.Second || bucket%time.Second != 0 || span <= 0 || span%bucket != 0 || span/bucket > 11000 {
		return source.CountResult{}, source.ErrNotIndexable
	}
	// Loki evaluates range queries at multiples of the step since the
	// epoch: buckets that start elsewhere cannot be answered exactly.
	if !instant && (q.Range.From.UnixNano()%int64(bucket) != 0 || q.Range.To.UnixNano()%int64(bucket) != 0) {
		return source.CountResult{}, source.ErrNotIndexable
	}
	base := s.selector(q.Selector)
	sel, err := base.Render()
	if err != nil {
		return source.CountResult{}, err
	}
	by := slices.Clone(q.By)
	from, to, w := q.Range.From.UnixNano(), q.Range.To.UnixNano(), int64(bucket)
	n := (to - from) / w
	type key struct {
		k    int64 // bucket index
		vals string
	}
	counts := map[key]int64{}
	valsOf := map[string][]string{}
	keyOf := func(labels map[string]string) string {
		vals := make([]string, len(by))
		for i, b := range by {
			vals[i] = labels[b] // "" (absent) when the label is missing
		}
		k := strings.Join(vals, "\x00")
		valsOf[k] = vals
		return k
	}

	// The boundaries to correct, and their entries, before and after.
	guard := func() ([]int64, error) {
		if instant {
			return []int64{from, to}, nil
		}
		gs, err := s.metric(ctx, fmt.Sprintf("sum by () (count_over_time(%s [1ms]))", sel), false, q.Range.From, q.Range.To, bucket)
		if err != nil {
			return nil, err
		}
		var bounds []int64
		for _, sr := range gs {
			for _, p := range sr.points {
				if p.at < from || p.at > to || (p.at-from)%w != 0 {
					return nil, source.ErrNotIndexable
				}
				if p.n > 0 {
					bounds = append(bounds, p.at)
				}
			}
		}
		slices.Sort(bounds)
		if len(bounds) > MaxBoundaryFetches {
			return nil, source.ErrNotIndexable
		}
		return bounds, nil
	}
	var boundaryBytes int64
	fetch := func(bounds []int64) (map[int64][]entry, error) {
		out := map[int64][]entry{}
		for _, b := range bounds {
			es, n, err := s.fetchSlice(ctx, sel, b, b+1)
			if boundaryBytes += n; boundaryBytes > maxBoundaryBytes {
				return nil, source.ErrNotIndexable
			}
			if errors.Is(err, errCrowded) {
				return nil, source.ErrNotIndexable
			}
			if err != nil {
				return nil, fmt.Errorf("loki source: %w", err)
			}
			out[b] = es
		}
		return out, nil
	}
	bounds1, err := guard()
	if err != nil {
		return source.CountResult{}, err
	}
	fetched1, err := fetch(bounds1)
	if err != nil {
		return source.CountResult{}, err
	}

	// Loki's windows, (From+k*bucket, From+(k+1)*bucket], for each
	// present/absent combination of the by-labels.
	for combo := 0; combo < 1<<len(by); combo++ {
		cs := Selector{Stream: slices.Clone(base.Stream)}
		var grouped []string
		for i, b := range by {
			if combo&(1<<i) != 0 {
				cs.Stream = append(cs.Stream, Matcher{Name: b, Op: "!=", Values: []string{""}})
				grouped = append(grouped, b)
			} else {
				cs.Stream = append(cs.Stream, Matcher{Name: b, Op: "=", Values: []string{""}})
			}
		}
		csel, err := cs.Render()
		if err != nil {
			return source.CountResult{}, err
		}
		expr := fmt.Sprintf("sum by (%s) (count_over_time(%s [%ds]))", strings.Join(grouped, ", "), csel, w/int64(time.Second))
		series, err := s.metric(ctx, expr, instant, q.Range.From.Add(bucket), q.Range.To, bucket)
		if err != nil {
			return source.CountResult{}, err
		}
		for _, sr := range series {
			labels := map[string]string{}
			for _, g := range grouped {
				if sr.metric[g] == "" {
					return source.CountResult{}, errResponse
				}
				labels[g] = sr.metric[g]
			}
			vk := keyOf(labels)
			for _, p := range sr.points {
				// The point at From+(k+1)*bucket ends bucket k.
				if p.at <= from || (p.at-from)%w != 0 || (p.at-from)/w > n {
					return source.CountResult{}, source.ErrNotIndexable
				}
				counts[key{(p.at-from)/w - 1, vk}] += p.n
			}
		}
	}

	bounds2, err := guard()
	if err != nil {
		return source.CountResult{}, err
	}
	if !slices.Equal(bounds1, bounds2) {
		return source.CountResult{}, source.ErrNotIndexable
	}
	fetched2, err := fetch(bounds2)
	if err != nil {
		return source.CountResult{}, err
	}
	for _, b := range bounds1 {
		if !sameEntries(fetched1[b], fetched2[b]) {
			return source.CountResult{}, source.ErrNotIndexable
		}
	}

	// Move the entries exactly on a boundary b: out of the bucket Loki
	// ends at b (b-bucket, if it is in the range), into the one starting
	// at b (if it is in the range).
	for _, b := range bounds1 {
		k := (b - from) / w
		for _, e := range fetched1[b] {
			vk := keyOf(e.stream)
			if b > from {
				counts[key{k - 1, vk}]--
			}
			if b < to {
				counts[key{k, vk}]++
			}
		}
	}

	var res source.CountResult
	for k, c := range counts {
		switch {
		case c < 0:
			// Loki's counts and its entries disagree: not an exact
			// answer.
			return source.CountResult{}, source.ErrNotIndexable
		case c > 0:
			res.Rows = append(res.Rows, source.CountRow{Bucket: time.Unix(0, from+k.k*w).UTC(), Vals: slices.Clone(valsOf[k.vals]), N: c})
		}
	}
	sort.Slice(res.Rows, func(i, j int) bool {
		if !res.Rows[i].Bucket.Equal(res.Rows[j].Bucket) {
			return res.Rows[i].Bucket.Before(res.Rows[j].Bucket)
		}
		return slices.Compare(res.Rows[i].Vals, res.Rows[j].Vals) < 0
	})
	res.IndexedFrom = q.Range.From
	return res, nil
}

// sameEntries reports whether a and b hold the same entries (stream, line
// and time), as multisets.
func sameEntries(a, b []entry) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, e := range a {
		m[fmt.Sprintf("%d\x00%s\x00%s", e.ts, e.key, e.line)]++
	}
	for _, e := range b {
		k := fmt.Sprintf("%d\x00%s\x00%s", e.ts, e.key, e.line)
		if m[k] == 0 {
			return false
		}
		m[k]--
	}
	return true
}

type metricPoint struct {
	at int64 // nanoseconds
	n  int64
}

type metricSeries struct {
	metric map[string]string
	points []metricPoint
}

// metric sends a metric query: an instant one at end, or a range one from
// start to end by step.
func (s *Source) metric(ctx context.Context, expr string, instant bool, start, end time.Time, step time.Duration) ([]metricSeries, error) {
	v := url.Values{}
	v.Set("query", expr)
	path := "/loki/api/v1/query_range"
	if instant {
		path = "/loki/api/v1/query"
		v.Set("time", strconv.FormatInt(end.UnixNano(), 10))
	} else {
		v.Set("start", strconv.FormatInt(start.UnixNano(), 10))
		v.Set("end", strconv.FormatInt(end.UnixNano(), 10))
		v.Set("step", strconv.FormatInt(int64(step/time.Second), 10))
	}
	resp, err := s.doResp(ctx, path, v)
	if err != nil {
		if limitRefused(resp) {
			// Over a Loki limit: the engine scans instead.
			return nil, source.ErrNotIndexable
		}
		return nil, fmt.Errorf("loki source: %w", err)
	}
	body := resp.Body
	var mr matrixResponse
	if instant {
		var vr vectorResponse
		if json.Unmarshal(body, &vr) != nil || vr.Status != "success" || vr.Data.ResultType != "vector" {
			return nil, errResponse
		}
		for _, r := range vr.Data.Result {
			mr.Data.Result = append(mr.Data.Result, struct {
				Metric map[string]string    `json:"metric"`
				Values [][2]json.RawMessage `json:"values"`
			}{Metric: r.Metric, Values: [][2]json.RawMessage{r.Value}})
		}
	} else if json.Unmarshal(body, &mr) != nil || mr.Status != "success" || mr.Data.ResultType != "matrix" {
		return nil, errResponse
	}
	var out []metricSeries
	for _, r := range mr.Data.Result {
		sr := metricSeries{metric: r.Metric}
		for _, p := range r.Values {
			at, ok := parseSeconds(p[0])
			var c string
			if !ok || json.Unmarshal(p[1], &c) != nil {
				return nil, errResponse
			}
			f, err := strconv.ParseFloat(c, 64)
			if err != nil || f < 0 || f != math.Trunc(f) || f > 1<<53 {
				return nil, errResponse
			}
			sr.points = append(sr.points, metricPoint{at: at, n: int64(f)})
		}
		out = append(out, sr)
	}
	return out, nil
}

// parseSeconds reads a metric point's time, a JSON number of seconds with
// a decimal fraction ("1730289899.999"), exactly, as nanoseconds.
func parseSeconds(raw json.RawMessage) (int64, bool) {
	t := string(raw)
	sec, frac, _ := strings.Cut(t, ".")
	if sec == "" || len(frac) > 9 || strings.Trim(sec, "0123456789") != "" || strings.Trim(frac, "0123456789") != "" || len(sec) > 11 {
		return 0, false
	}
	s, _ := strconv.ParseInt(sec, 10, 64)
	f, _ := strconv.ParseInt((frac + "000000000")[:9], 10, 64)
	return s*1e9 + f, true
}
