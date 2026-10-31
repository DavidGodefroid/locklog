// Package source defines the internal interface of log sources: the byte
// plan of a range, the scan of one plan chunk, and the re-read of one record
// by its raw position.
//
// Everything a Source returns (records, names, errors) is raw log content or
// derived from it: it is consumed only by internal/engine and internal/mask,
// which mask it before anything leaves the console.
package source

import (
	"context"
	"errors"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
)

// GranuleBytes is the size of a plan granule of a byte stream: streams are
// cut into fixed, query-independent sections of GranuleBytes bytes, aligned
// to stream offsets (the last one of a stream is shorter). A record belongs
// to the granule its first line starts in, and records never cross a
// granule boundary (see parse.NewSectionReader). Plans, charges, cursors and
// stopping points are counted in granules, so they never reveal the length of
// one record.
const GranuleBytes = 1 << 20

// Range is the absolute time range [From, To).
type Range struct {
	From, To time.Time
}

// Contains reports whether t is in r.
func (r Range) Contains(t time.Time) bool { return !t.Before(r.From) && t.Before(r.To) }

// Overlaps reports whether [from, to] (inclusive) overlaps r.
func (r Range) Overlaps(from, to time.Time) bool { return !to.Before(r.From) && from.Before(r.To) }

// Term is a predicate on a trusted field, used for planning: = and != on one
// value, "in" on a set. Values are the field's clear values (trusted fields
// are shown to the agent in clear after the detectors).
type Term struct {
	Field string
	// Label is set for a term on a label of the source's frame (Loki
	// stream labels, journald and docker attributes: parse.Event.Attrs),
	// unset for a line field. They are separate namespaces: a source
	// applies a term only in its own one.
	Label  bool
	Op     string // "=", "!=", "in"
	Values []string
}

// Selector is the conjunction of trusted-field terms of a query: the part a
// source may use to narrow its plan (index, server-side labels).
type Selector struct {
	Terms []Term
}

// Match reports whether a record whose trusted line fields have values
// fields and whose labels have values labels (missing ones absent) satisfies
// every term.
func (s Selector) Match(fields, labels map[string]string) bool {
	for _, t := range s.Terms {
		vals := fields
		if t.Label {
			vals = labels
		}
		v, ok := vals[t.Field]
		switch t.Op {
		case "=", "in":
			if !ok || !contains(t.Values, v) {
				return false
			}
		case "!=":
			if ok && contains(t.Values, v) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func contains(vs []string, v string) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

// Granule is one plan granule of a stream.
type Granule struct {
	// Start and End are stream offsets [Start, End): records whose first
	// line starts there.
	Start, End int64
	// Indexed is set when the local index holds this granule; From, To
	// and Records are then exact (From/To zero when it holds no timed
	// record). For a granule that is not indexed they are unknown.
	Indexed  bool
	From, To time.Time
	Records  int64
	// Bytes is the planned cost of the granule (its length for a byte
	// stream); 0 when unknown before the fetch (a remote time slice,
	// charged by the bytes actually fetched).
	Bytes int64
}

// Chunk is a unit of a byte plan: consecutive granules of one stream.
type Chunk struct {
	Source string
	// Stream identifies the stream (a file identity, a remote stream).
	Stream string
	// Granules are consecutive and in stream order.
	Granules []Granule
	// Bytes is the number of bytes processing the chunk costs: the
	// granules' bytes, plus for a compressed stream the decompressed bytes
	// before the first granule that must be read and discarded.
	Bytes int64
	// Version is the stream's state the plan was made on (e.g. its size at
	// open); a scan of a chunk whose stream changed incompatibly fails
	// with ErrStale.
	Version string
}

// Start returns the stream offset of the chunk's first granule.
func (c Chunk) Start() int64 { return c.Granules[0].Start }

// End returns the stream offset after the chunk's last granule.
func (c Chunk) End() int64 { return c.Granules[len(c.Granules)-1].End }

// Byteplan is the plan of a range: chunks in the order they are scanned
// (newest stream first, stream order within a stream).
type Byteplan struct {
	Chunks []Chunk
}

// Bytes returns the plan's total cost in bytes.
func (p Byteplan) Bytes() int64 {
	var n int64
	for _, c := range p.Chunks {
		n += c.Bytes
	}
	return n
}

// Granules returns the plan's number of granules.
func (p Byteplan) Granules() int {
	n := 0
	for _, c := range p.Chunks {
		n += len(c.Granules)
	}
	return n
}

// RawRef locates one record: its source, stream, granule and raw position.
type RawRef struct {
	Source string
	Stream string
	Offset int64
	Length int64
}

// RawRecord is one record read from a source: raw, unmasked.
type RawRecord struct {
	Ref   RawRef
	Event parse.Event
	// Granule identifies the granule the record belongs to, as the source
	// numbers them (file: the absolute granule number of the stream; other
	// sources document theirs).
	Granule int
}

// Iterator yields the records of a chunk in stream order.
type Iterator interface {
	// Next returns the next record, or io.EOF after the last one.
	Next() (RawRecord, error)
	// Processed returns the bytes processed so far (read, decompressed,
	// discarded).
	Processed() int64
	Close() error
}

// FieldInfo describes one field name a source has seen.
type FieldInfo struct {
	Name string
	// Label is set for a label of the source's frame (a Loki stream
	// label, a docker container or stream), unset for a line field.
	Label   bool
	Trusted bool
	// Values are the trusted field's distinct values (raw, masked by the
	// caller), when the source knows them and they are few.
	Values []string
}

// Schema is a source's description. Names, values and paths are raw.
type Schema struct {
	Kind    string
	Format  string
	Fields  []FieldInfo
	Streams int
	// Bytes is the estimated size of the source's data.
	Bytes int64
	// Oldest and Newest bound the source's records, when known.
	Oldest, Newest time.Time
	// IndexedFrom is the start of the newest contiguous indexed span:
	// every record from IndexedFrom on (before IndexedUntil when set: a
	// growing file's newest lines are being indexed) is in the local
	// index, allowing a minute of timestamp disorder. Zero when nothing can
	// be claimed. It describes what the index holds: counts may still scan
	// part of that range (a grown granule goes to the residual whole).
	IndexedFrom, IndexedUntil time.Time
	// FullyIndexed is set when every granule is indexed.
	FullyIndexed bool
}

// Source is a log source.
type Source interface {
	Name() string
	Kind() string
	Describe(ctx context.Context) (Schema, error)
	// Plan returns the chunks that may hold records of r matching sel.
	// It reads no record content beyond what identifying a stream needs.
	Plan(ctx context.Context, r Range, sel Selector) (Byteplan, error)
	Scan(ctx context.Context, c Chunk) (Iterator, error)
	// Reread returns the record at ref, or ErrStale when the stream no
	// longer holds it.
	Reread(ctx context.Context, ref RawRef) (RawRecord, error)
	// Around returns up to before records before ref, the record itself
	// and up to after records after it, from ref's stream.
	Around(ctx context.Context, ref RawRef, before, after int) ([]RawRecord, error)
}

// Errors of sources. Their text never holds log content.
var (
	ErrStale    = errors.New("source: the stream changed since the plan or reference was made")
	ErrNotFound = errors.New("source: no such stream")
)

// ErrNotIndexable is returned by IndexCounts when a selector or group field
// is not in the index of every stream.
var ErrNotIndexable = errors.New("source: the count needs fields the index (or the server) does not hold")

// CountQuery is a count of records by trusted fields per time bucket.
type CountQuery struct {
	Range    Range
	Selector Selector
	// By are line fields, ByLabels labels; a row's Vals are the By values
	// then the ByLabels values.
	By       []string
	ByLabels []string
	// Bucket is a whole number of minutes (0: one bucket for the range).
	Bucket time.Duration
}

// CountRow is the count of one bucket and one tuple of By values (raw:
// index.Absent, index.Redacted and index.Other stand for themselves).
type CountRow struct {
	Bucket time.Time
	Vals   []string
	N      int64
}

// CountResult is what an index (or a server-side metric query) answers, and the plan of what it cannot.
type CountResult struct {
	Rows []CountRow
	// Untimed counts indexed records without a time in matching
	// granules (not in any bucket).
	Untimed int64
	// Residual is the plan of the granules the index does not hold: the
	// caller scans them and adds their counts.
	Residual Byteplan
	// IndexedFrom, IndexedUntil: see Schema.
	IndexedFrom, IndexedUntil time.Time
}

// Counter is a source that answers trusted-field counts without a scan (the
// local index, Loki metric queries), returning the plan of what it cannot.
type Counter interface {
	IndexCounts(ctx context.Context, q CountQuery) (CountResult, error)
}

// Limiter paces the requests of a call to a backend (the rolling request
// budget of free calls, an approved scan's own plan-based rate).
type Limiter interface {
	Wait(ctx context.Context) error
}

type limiterKey struct{}

// WithLimiter attaches the call's request limiter to ctx.
func WithLimiter(ctx context.Context, l Limiter) context.Context {
	return context.WithValue(ctx, limiterKey{}, l)
}

// LimiterFrom returns the call's limiter, or nil.
func LimiterFrom(ctx context.Context) Limiter {
	l, _ := ctx.Value(limiterKey{}).(Limiter)
	return l
}

type byteLimitKey struct{}

// WithByteLimit attaches to ctx the bytes a scan may process (Iterator's
// Processed). The engine checks Processed after every record; a source that
// buffers before it yields (a remote slice, fetched page by page, sorted
// whole) checks the limit itself as it fetches, and fails with ErrByteLimit
// instead of buffering past it.
func WithByteLimit(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, byteLimitKey{}, n)
}

// ByteLimitFrom returns the byte limit of ctx, or 0 (none).
func ByteLimitFrom(ctx context.Context) int64 {
	n, _ := ctx.Value(byteLimitKey{}).(int64)
	return max(n, 0)
}

// ErrByteLimit is returned by a scan (or a source's bounded read) that would
// process more than its byte limit.
var ErrByteLimit = errors.New("source: past the byte limit of the call")
