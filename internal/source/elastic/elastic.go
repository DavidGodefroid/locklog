// Package elastic is the Elasticsearch (8.x) and OpenSearch (2.x) log
// source. It sends only allowlisted read requests on the source's own
// indices through the egress client, with bodies it builds from typed
// values (a time range, terms on trusted keyword fields, sort and
// search_after, two aggregation kinds); text is matched locally, after
// masking. It asks only for the message field and the trusted fields, and
// drops anything else a response holds. Plans are fixed time slices whose
// cost is the bytes actually fetched, as for Loki.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
const Kind = "elasticsearch"

// Flavours of a backend, from GET /.
const (
	FlavourElasticsearch = "elasticsearch"
	FlavourOpenSearch    = "opensearch"
)

// Defaults.
const (
	// InFlight is the requests in flight per source.
	InFlight = 4
	// MaxSlices bounds the time slices of one plan.
	MaxSlices = 512
	// DefaultTimeField and DefaultMessageField are the ECS names.
	DefaultTimeField    = "@timestamp"
	DefaultMessageField = "message"
)

// sliceWidths are the plan granule widths (as for Loki): the smallest that
// cuts the range into at most MaxSlices epoch-aligned slices.
var sliceWidths = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour}

// Client is the egress client of the source (egress.Client).
type Client interface {
	Send(ctx context.Context, method, path string, q url.Values, body []byte) (egress.Response, error)
}

// Options configure a source.
type Options struct {
	Name   string
	Client Client
	Parser *parse.Parser
	// Indices are the indices, aliases, data streams or trailing-'*'
	// patterns read (validated: egress.ValidIndex).
	Indices []string
	// Selector is the profile's scope: field = value terms ANDed into
	// every query (optional: the indices already scope the source).
	Selector map[string]string
	// TrustedFields are keyword fields shown (after the detectors),
	// selectable and countable; every other field is dropped.
	TrustedFields []string
	// TimeField is the record time (default @timestamp); MessageField the
	// text parsed as the line (default message).
	TimeField    string
	MessageField string
	// TieBreaker is a keyword field unique per document (an event id):
	// pages then resume exactly after the last hit. Without it, a page
	// resumes at the last hit's timestamp and skips the hits it returned;
	// more than Size documents at one timestamp is then an error.
	TieBreaker string
	// ReadOnlyRoles are OpenSearch roles the human vouches grant no
	// write or manage permission (besides the built-in readall roles).
	ReadOnlyRoles []string
	// InFlight overrides InFlight; Size the hits per page (default and
	// cap MaxSize).
	InFlight int
	Size     int
	Now      func() time.Time
}

// Source is an Elasticsearch / OpenSearch source. It is safe for
// concurrent use.
type Source struct {
	o   Options
	seg string // the indices path segment
	sem chan struct{}
}

// New validates o.
func New(o Options) (*Source, error) {
	if o.Client == nil || o.Parser == nil {
		return nil, errors.New("elasticsearch source: client and parser are required")
	}
	seg, err := egress.IndexSegment(o.Indices)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch source: %w", err)
	}
	if o.TimeField == "" {
		o.TimeField = DefaultTimeField
	}
	if o.MessageField == "" {
		o.MessageField = DefaultMessageField
	}
	names := append([]string{o.TimeField, o.MessageField}, o.TrustedFields...)
	if o.TieBreaker != "" {
		names = append(names, o.TieBreaker)
	}
	for k, v := range o.Selector {
		if err := checkValue(v); err != nil || v == "" {
			return nil, fmt.Errorf("elasticsearch source: selector %s needs a non-empty value without control characters", k)
		}
		names = append(names, k)
	}
	for _, f := range names {
		if err := checkField(f); err != nil {
			return nil, fmt.Errorf("elasticsearch source: %w", err)
		}
	}
	if slices.Contains(o.TrustedFields, o.MessageField) {
		return nil, errors.New("elasticsearch source: the message field is text, always masked; it cannot be trusted")
	}
	if o.InFlight <= 0 {
		o.InFlight = InFlight
	}
	if o.Size <= 0 || o.Size > MaxSize {
		o.Size = MaxSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.TrustedFields = slices.Clone(o.TrustedFields)
	sort.Strings(o.TrustedFields)
	return &Source{o: o, seg: seg, sem: make(chan struct{}, o.InFlight)}, nil
}

// Name returns the source name.
func (s *Source) Name() string { return s.o.Name }

// Kind returns "elasticsearch".
func (s *Source) Kind() string { return Kind }

func (s *Source) trusted(f string) bool { return slices.Contains(s.o.TrustedFields, f) }

var errResponse = errors.New("elasticsearch source: unexpected response")

// do sends one request under the call's limiter and the in-flight cap.
func (s *Source) do(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	if l := source.LimiterFrom(ctx); l != nil {
		if err := l.Wait(ctx); err != nil {
			return nil, err
		}
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.sem }()
	resp, err := s.o.Client.Send(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// readParams are the query parameters of every read of the indices: a
// pattern expands to open, non-hidden indices only.
func readParams() url.Values { return url.Values{"expand_wildcards": {"open"}} }

// filter builds the server-side filter: the profile's selector, plus the
// terms on trusted fields. Terms on other fields are ignored here (the
// engine evaluates them after masking).
func (s *Source) filter(sel source.Selector) Filter {
	var f Filter
	for k, v := range s.o.Selector {
		f.In = append(f.In, FieldValues{Field: k, Values: []string{v}})
	}
	for _, t := range sel.Terms {
		if !s.trusted(t.Field) || len(t.Values) == 0 {
			continue
		}
		switch t.Op {
		case "=", "in":
			f.In = append(f.In, FieldValues{Field: t.Field, Values: slices.Clone(t.Values)})
		case "!=":
			f.NotIn = append(f.NotIn, FieldValues{Field: t.Field, Values: slices.Clone(t.Values)})
		}
	}
	return f.normalise()
}

// width returns the slice width of a range.
func width(r source.Range) time.Duration {
	d := r.To.Sub(r.From)
	for _, w := range sliceWidths {
		if d/w < MaxSlices {
			return w
		}
	}
	return sliceWidths[len(sliceWidths)-1]
}

// Plan returns one chunk of epoch-aligned time slices covering r, for the
// filter built from the profile and the trusted terms. The slices' byte
// cost is unknown until fetched: the engine charges the bytes fetched.
func (s *Source) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	stream, err := s.filter(sel).Encode()
	if err != nil {
		return source.Byteplan{}, fmt.Errorf("elasticsearch source: %w", err)
	}
	w := width(r)
	start := r.From.Truncate(w)
	var gs []source.Granule
	for t := start; t.Before(r.To); t = t.Add(w) {
		gs = append(gs, source.Granule{Start: t.UnixNano(), End: t.Add(w).UnixNano(), From: t, To: t.Add(w)})
	}
	if len(gs) == 0 {
		return source.Byteplan{}, nil
	}
	return source.Byteplan{Chunks: []source.Chunk{{Source: s.o.Name, Stream: stream, Granules: gs}}}, nil
}

// hit is one document of a response, reduced to what locklog keeps.
type hit struct {
	ts     int64
	id     string // index and _id: identity, never shown
	tie    string // the tiebreaker's sort value
	line   string
	fields map[string][]string // trusted fields only
	sort   []any
}

type searchResponse struct {
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
	Hits *struct {
		Total *struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []struct {
			Index  string                     `json:"_index"`
			ID     string                     `json:"_id"`
			Fields map[string]json.RawMessage `json:"fields"`
			Sort   []json.RawMessage          `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

// complete reports a response that answered on every shard in time: a
// partial answer would silently miss records.
func (r *searchResponse) complete() error {
	if r.TimedOut {
		return errors.New("elasticsearch source: the search timed out on the server")
	}
	if r.Shards.Failed > 0 {
		return errors.New("elasticsearch source: the search failed on some shards")
	}
	return nil
}

// stringValues decodes a fields entry: an array of scalars, kept as text.
func stringValues(raw json.RawMessage) ([]string, bool) {
	var vs []json.RawMessage
	if json.Unmarshal(raw, &vs) != nil {
		return nil, false
	}
	var out []string
	for _, v := range vs {
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		var x any
		if dec.Decode(&x) != nil {
			return nil, false
		}
		switch x := x.(type) {
		case string:
			out = append(out, x)
		case json.Number:
			out = append(out, x.String())
		case bool:
			out = append(out, strconv.FormatBool(x))
		default:
			return nil, false // an object: not a keyword value
		}
	}
	return out, true
}

// sortValue decodes a sort value: a number or a string, nothing else.
func sortValue(raw json.RawMessage) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if dec.Decode(&x) != nil {
		return nil, false
	}
	switch x.(type) {
	case json.Number, string:
		return x, true
	}
	return nil, false
}

// decodeHits decodes a search page: only the message and the trusted
// fields are kept (whatever else the response carries is dropped here).
func (s *Source) decodeHits(body []byte) ([]hit, error) {
	var r searchResponse
	if err := json.Unmarshal(body, &r); err != nil || r.Hits == nil {
		return nil, errResponse
	}
	if err := r.complete(); err != nil {
		return nil, err
	}
	var out []hit
	for _, h := range r.Hits.Hits {
		if len(h.Sort) < 1 {
			return nil, errResponse
		}
		sv := make([]any, len(h.Sort))
		for i, raw := range h.Sort {
			v, ok := sortValue(raw)
			if !ok {
				if i == 0 {
					return nil, errResponse
				}
				return nil, errors.New("elasticsearch source: a document lacks the tiebreaker field")
			}
			sv[i] = v
		}
		n, ok := sv[0].(json.Number)
		if !ok {
			return nil, errResponse
		}
		ts, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return nil, errResponse
		}
		e := hit{ts: ts, id: strconv.Itoa(len(h.Index)) + ":" + h.Index + "/" + h.ID, sort: sv, fields: map[string][]string{}}
		if len(sv) > 1 {
			e.tie = fmt.Sprint(sv[1])
		}
		if raw, ok := h.Fields[s.o.MessageField]; ok {
			if vs, ok := stringValues(raw); ok {
				e.line = strings.Join(vs, "\n")
			}
		}
		for name, raw := range h.Fields {
			if !s.trusted(name) {
				continue // untrusted: dropped
			}
			if vs, ok := stringValues(raw); ok && len(vs) > 0 {
				e.fields[name] = vs
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// sortHits orders hits by (ts, tiebreaker, identity): deterministic,
// whatever order the shards answered ties in.
func sortHits(hs []hit) {
	sort.SliceStable(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		if a.tie != b.tie {
			return a.tie < b.tie
		}
		return a.id < b.id
	})
}

func (s *Source) sortSpec() []map[string]SortSpec {
	out := []map[string]SortSpec{{s.o.TimeField: {Order: "asc", NumericType: "date_nanos", UnmappedType: "date_nanos"}}}
	if s.o.TieBreaker != "" {
		out = append(out, map[string]SortSpec{s.o.TieBreaker: {Order: "asc", UnmappedType: "keyword"}})
	}
	return out
}

func (s *Source) fieldList() []string {
	return append([]string{s.o.MessageField}, s.o.TrustedFields...)
}

func (s *Source) searchPath() string { return "/" + s.seg + "/_search" }
func (s *Source) countPath() string  { return "/" + s.seg + "/_count" }

// fetchSlice returns every hit of [from, to) (Unix nanoseconds) for f, in
// order, and the response bytes it fetched. Pages are cut by Size and
// continue with search_after.
func (s *Source) fetchSlice(ctx context.Context, f Filter, from, to int64) ([]hit, int64, error) {
	q, err := f.query(s.o.TimeField, time.Unix(0, from), time.Unix(0, to))
	if err != nil {
		return nil, 0, err
	}
	var out []hit
	var fetched int64
	var after []any
	seen := map[string]bool{} // identities at the resume timestamp (no tiebreaker)
	for {
		body, err := searchJSON(SearchBody{Size: s.o.Size, Timeout: SearchTimeout, Fields: s.fieldList(), Query: q,
			Sort: s.sortSpec(), SearchAfter: after})
		if err != nil {
			return nil, fetched, err
		}
		resp, err := s.do(ctx, http.MethodPost, s.searchPath(), readParams(), body)
		if err != nil {
			return nil, fetched, err
		}
		fetched += int64(len(resp))
		page, err := s.decodeHits(resp)
		if err != nil {
			return nil, fetched, err
		}
		n := 0
		for _, h := range page {
			if seen[h.id] {
				continue
			}
			if h.ts >= from && h.ts < to {
				out = append(out, h)
			}
			n++
		}
		if len(page) < s.o.Size {
			break
		}
		last := page[len(page)-1]
		if s.o.TieBreaker != "" {
			after = last.sort
			continue
		}
		// No tiebreaker: resume at the last timestamp, skipping what was
		// returned there.
		if n == 0 {
			return nil, fetched, fmt.Errorf("elasticsearch source: more than %d documents share one timestamp: set a tiebreaker field", s.o.Size)
		}
		if after == nil || after[0].(json.Number).String() != strconv.FormatInt(last.ts-1, 10) {
			clear(seen)
		}
		for _, h := range page {
			if h.ts == last.ts {
				seen[h.id] = true
			}
		}
		after = []any{json.Number(strconv.FormatInt(last.ts-1, 10))}
	}
	sortHits(out)
	return out, fetched, nil
}

// record turns a hit into a raw record: the message parsed as the line,
// the sort timestamp as the record time, the trusted fields as attrs.
func (s *Source) record(stream string, h hit, ordinal int) source.RawRecord {
	ev := s.o.Parser.Line(h.line)
	ev.SetTime(time.Unix(0, h.ts).UTC())
	keys := make([]string, 0, len(h.fields))
	for k := range h.fields {
		if s.trusted(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var attrs []parse.Member
	for _, k := range keys {
		vs := h.fields[k]
		v := parse.Value{Kind: parse.KindString, Str: vs[0]}
		if len(vs) > 1 {
			v = parse.Value{Kind: parse.KindArray}
			for _, x := range vs {
				v.Items = append(v.Items, parse.Value{Kind: parse.KindString, Str: x})
			}
		}
		attrs = append(attrs, parse.Member{Key: k, Value: v})
	}
	ev.Attrs = attrs
	ev.Offset, ev.Length = h.ts, int64(ordinal+1)
	return source.RawRecord{Ref: source.RawRef{Source: s.o.Name, Stream: stream, Offset: h.ts, Length: int64(ordinal + 1)}, Event: ev}
}

// streamFilter decodes a chunk's or reference's stream, refusing one this
// source would not have built (an untrusted field, a changed selector).
func (s *Source) streamFilter(stream string) (Filter, error) {
	f, err := DecodeFilter(stream)
	if err != nil {
		return Filter{}, fmt.Errorf("elasticsearch source: %w", err)
	}
	for _, x := range append(slices.Clone(f.In), f.NotIn...) {
		if _, ok := s.o.Selector[x.Field]; !ok && !s.trusted(x.Field) {
			return Filter{}, errors.New("elasticsearch source: the stream names an untrusted field")
		}
	}
	for k, v := range s.o.Selector {
		if !slices.ContainsFunc(f.In, func(x FieldValues) bool { return x.Field == k && slices.Equal(x.Values, []string{v}) }) {
			return Filter{}, source.ErrStale
		}
	}
	return f, nil
}

// Scan fetches the chunk's slices (up to InFlight at once) and yields their
// records in time order.
func (s *Source) Scan(ctx context.Context, c source.Chunk) (source.Iterator, error) {
	if len(c.Granules) == 0 {
		return nil, errors.New("elasticsearch source: empty chunk")
	}
	f, err := s.streamFilter(c.Stream)
	if err != nil {
		return nil, err
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
				hs, n, err := s.fetchSlice(ctx, f, g.Start, g.End)
				it.results[i] <- sliceResult{hits: hs, bytes: n, err: err}
			}(i, g)
		}
		wg.Wait()
	}()
	return it, nil
}

type sliceResult struct {
	hits  []hit
	bytes int64
	err   error
}

type iter struct {
	s         *Source
	c         source.Chunk
	cancel    context.CancelFunc
	results   []chan sliceResult
	cur       int
	hits      []hit
	pos       int
	processed int64
	ordinal   int
	lastTS    int64
	err       error
}

func (it *iter) Next() (source.RawRecord, error) {
	for it.pos >= len(it.hits) {
		if it.err != nil {
			return source.RawRecord{}, it.err
		}
		if it.cur >= len(it.results) {
			return source.RawRecord{}, io.EOF
		}
		r := <-it.results[it.cur]
		it.processed += r.bytes
		if r.err != nil {
			it.err = fmt.Errorf("elasticsearch source: %w", r.err)
			return source.RawRecord{}, it.err
		}
		it.hits, it.pos = r.hits, 0
		it.cur++
	}
	h := it.hits[it.pos]
	it.pos++
	if h.ts == it.lastTS {
		it.ordinal++
	} else {
		it.ordinal, it.lastTS = 0, h.ts
	}
	rec := it.s.record(it.c.Stream, h, it.ordinal)
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

// Reread fetches the document at ref again: ref.Offset is its timestamp
// and ref.Length its ordinal (from 1) among the documents of that
// nanosecond.
func (s *Source) Reread(ctx context.Context, ref source.RawRef) (source.RawRecord, error) {
	f, err := s.streamFilter(ref.Stream)
	if err != nil {
		return source.RawRecord{}, err
	}
	hs, _, err := s.fetchSlice(ctx, f, ref.Offset, ref.Offset+1)
	if err != nil {
		return source.RawRecord{}, fmt.Errorf("elasticsearch source: %w", err)
	}
	i := int(ref.Length) - 1
	if i < 0 || i >= len(hs) {
		return source.RawRecord{}, source.ErrStale
	}
	return s.record(ref.Stream, hs[i], i), nil
}

// AroundWindow bounds how far Around looks on each side.
const AroundWindow = 15 * time.Minute

// Around returns up to before documents before ref, ref's document and up
// to after documents after it, from the same filter.
func (s *Source) Around(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, error) {
	before, after = max(0, min(before, 50)), max(0, min(after, 50))
	f, err := s.streamFilter(ref.Stream)
	if err != nil {
		return nil, err
	}
	hs, _, err := s.fetchSlice(ctx, f, ref.Offset-int64(AroundWindow), ref.Offset+int64(AroundWindow))
	if err != nil {
		return nil, fmt.Errorf("elasticsearch source: %w", err)
	}
	idx, ord := -1, 0
	ords := make([]int, len(hs))
	for i, h := range hs {
		if i > 0 && hs[i-1].ts == h.ts {
			ord++
		} else {
			ord = 0
		}
		ords[i] = ord
		if h.ts == ref.Offset && int64(ord+1) == ref.Length {
			idx = i
		}
	}
	if idx < 0 {
		return nil, source.ErrStale
	}
	lo, hi := max(0, idx-before), min(len(hs), idx+after+1)
	out := make([]source.RawRecord, 0, hi-lo)
	for i := lo; i < hi; i++ {
		out = append(out, s.record(ref.Stream, hs[i], ords[i]))
	}
	return out, nil
}
