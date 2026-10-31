//go:build unix

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

// bigLoki is a fake Loki client serving large pages: an entry every
// `every` from t0, the first of each minute at level error (short), the
// others padded to pad bytes. It counts the response bytes it served and
// the requests in flight.
type bigLoki struct {
	every time.Duration
	pad   int
	mu    sync.Mutex
	// served is the response bytes served, maxPage the largest response,
	// in and maxIn the requests in flight.
	served, maxPage int64
	in, maxIn       int
}

func (b *bigLoki) GetWith(_ context.Context, path string, q url.Values, _ map[string]string) (egress.Response, error) {
	b.mu.Lock()
	b.in++
	b.maxIn = max(b.maxIn, b.in)
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.in--
		b.mu.Unlock()
	}()
	if path != "/loki/api/v1/query_range" {
		return egress.Response{Status: 200, Body: []byte(`{"status":"success","data":[]}`)}, nil
	}
	start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
	end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	step := int64(b.every)
	first := t0.UnixNano() + max((start-t0.UnixNano()+step-1)/step, 0)*step
	var values [][]string
	for ts := first; ts < end && len(values) < limit; ts += step {
		tm := time.Unix(0, ts).UTC()
		line := fmt.Sprintf("time=%s level=info msg=\"entry %d\" pad=%s", tm.Format(time.RFC3339Nano), ts, strings.Repeat("x", b.pad))
		if (ts-t0.UnixNano())%int64(time.Minute) == 0 {
			line = fmt.Sprintf("time=%s level=error msg=\"minute %d\"", tm.Format(time.RFC3339Nano), ts)
		}
		values = append(values, []string{strconv.FormatInt(ts, 10), line})
	}
	body, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{
		"resultType": "streams", "encodingFlags": []string{"categorize-labels"},
		"result": []map[string]any{{"stream": map[string]string{"env": "prod"}, "values": values}}}})
	b.mu.Lock()
	b.served += int64(len(body))
	b.maxPage = max(b.maxPage, int64(len(body)))
	b.mu.Unlock()
	return egress.Response{Status: 200, Body: body}, nil
}

// TestLokiPagedUnderBudget: a Loki range holding many times one call's
// byte budget, served in large pages, is read in partial pages with a
// cursor that resumes where the last call stopped, ascending and
// descending; each call fetches at most its budget plus the pages in
// flight, never the range whole.
func TestLokiPagedUnderBudget(t *testing.T) {
	const budget = 256 << 10
	const inFlight = 2
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			bl := &bigLoki{every: 5 * time.Second, pad: 4 << 10}
			p, _ := parse.New(parse.Options{})
			src, err := loki.New(loki.Options{Name: "lk", Client: bl, Parser: p, Selector: map[string]string{"env": "prod"},
				TrustedLabels: []string{"level"}, InFlight: inFlight, Limit: 4, Now: func() time.Time { return t0.Add(2 * time.Hour) }})
			if err != nil {
				t.Fatal(err)
			}
			f := newFixture(t, "x\n", func(o *Options) {
				o.Sources["lk"] = src
				o.Limits.RemoteBytes = budget
			})
			qq := q(func(q *Query) {
				q.From, q.To = t0, t0.Add(time.Hour) // 60 slices of 1 min
				q.Sources = []string{"lk"}
				q.Where = []Pred{{Field: "level", Op: OpEq, Value: raw("error")}}
				q.Limit = 200
				q.Order = order
			})
			var recs []json.RawMessage
			calls := 0
			for {
				bl.mu.Lock()
				bl.served = 0
				bl.mu.Unlock()
				res, err := f.eng.Search(ctx, qq)
				if err != nil {
					t.Fatalf("call %d: %v", calls, err)
				}
				calls++
				bl.mu.Lock()
				served, page := bl.served, bl.maxPage
				bl.mu.Unlock()
				// The budget, plus what the slices in flight fetched
				// past it (a page each, and the slice the budget
				// stopped in).
				if bound := int64(budget) + int64(inFlight+1)*page; served > bound {
					t.Fatalf("call %d fetched %d bytes, bound %d", calls, served, bound)
				}
				recs = append(recs, res.Records...)
				if res.Complete {
					break
				}
				if res.Cursor == "" || calls > 100 {
					t.Fatalf("call %d: incomplete without a cursor", calls)
				}
				qq.Cursor = res.Cursor
			}
			if calls < 4 {
				t.Fatalf("%d calls: the range fitted a call's budget", calls)
			}
			ts := recordTimes(t, recs)
			checkOrder(t, ts, 60, order == "desc")
			seen := map[time.Time]bool{}
			for _, x := range ts {
				if seen[x] {
					t.Fatalf("record at %v returned twice", x)
				}
				seen[x] = true
			}
			if bl.maxIn > inFlight {
				t.Fatalf("%d requests in flight", bl.maxIn)
			}
		})
	}
}

// denseLoki is a fake Loki client: an entry every `every` from t0, except
// in [dense, dense+denseFor) where there is one every denseEvery, padded to
// pad bytes. Every entry is at level error and unique by its timestamp.
type denseLoki struct {
	every, denseEvery, denseFor time.Duration
	dense                       time.Time
	pad                         int
	mu                          sync.Mutex
	served, maxPage             int64
}

// next returns the first entry timestamp at or after ts.
func (d *denseLoki) next(ts int64) int64 {
	ds, de := d.dense.UnixNano(), d.dense.Add(d.denseFor).UnixNano()
	step := int64(d.every)
	base := t0.UnixNano()
	if ts >= ds && ts < de {
		base, step = ds, int64(d.denseEvery)
	}
	n := base + max((ts-base+step-1)/step, 0)*step
	if ts < ds && n > ds {
		return ds
	}
	if n >= de && ts < de {
		// back on the sparse grid after the dense span
		return d.next(de)
	}
	return n
}

func (d *denseLoki) GetWith(_ context.Context, path string, q url.Values, _ map[string]string) (egress.Response, error) {
	if path != "/loki/api/v1/query_range" {
		return egress.Response{Status: 200, Body: []byte(`{"status":"success","data":[]}`)}, nil
	}
	start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
	end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	var values [][]string
	for ts := d.next(start); ts < end && len(values) < limit; ts = d.next(ts + 1) {
		tm := time.Unix(0, ts).UTC()
		line := fmt.Sprintf("time=%s level=error msg=\"entry %d\"", tm.Format(time.RFC3339Nano), ts)
		if ts >= d.dense.UnixNano() && ts < d.dense.Add(d.denseFor).UnixNano() {
			line += " pad=" + strings.Repeat("x", d.pad)
		}
		values = append(values, []string{strconv.FormatInt(ts, 10), line})
	}
	body, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{
		"resultType": "streams", "encodingFlags": []string{"categorize-labels"},
		"result": []map[string]any{{"stream": map[string]string{"env": "prod"}, "values": values}}}})
	d.mu.Lock()
	d.served += int64(len(body))
	d.maxPage = max(d.maxPage, int64(len(body)))
	d.mu.Unlock()
	return egress.Response{Status: 200, Body: body}, nil
}

func denseFixture(t *testing.T, d *denseLoki, budget int64) *fixture {
	t.Helper()
	p, _ := parse.New(parse.Options{})
	src, err := loki.New(loki.Options{Name: "lk", Client: d, Parser: p, Selector: map[string]string{"env": "prod"},
		TrustedLabels: []string{"level"}, InFlight: 2, Limit: 8, Now: func() time.Time { return t0.Add(2 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	return newFixture(t, "x\n", func(o *Options) {
		o.Sources["lk"] = src
		o.Limits.RemoteBytes = budget
	})
}

// TestLokiDenseSliceSplit: a 1-minute slice holding about ten times one
// call's byte budget is split into narrower slices and paged with a
// cursor, ascending and descending: every record of the range is returned
// once, in order, each call fetching about its budget; a continuation
// cursor replayed returns the same page.
func TestLokiDenseSliceSplit(t *testing.T) {
	const budget = 256 << 10
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			d := &denseLoki{every: 5 * time.Second, denseEvery: 100 * time.Millisecond, denseFor: time.Minute,
				dense: t0.Add(3 * time.Minute), pad: 4 << 10}
			f := denseFixture(t, d, budget)
			qq := q(func(q *Query) {
				q.From, q.To = t0, t0.Add(10*time.Minute)
				q.Sources = []string{"lk"}
				q.Limit = 200
				q.Order = order
			})
			var recs []json.RawMessage
			calls, empty, replayed := 0, 0, false
			for {
				d.mu.Lock()
				d.served = 0
				d.mu.Unlock()
				res, err := f.eng.Search(ctx, qq)
				if err != nil {
					t.Fatalf("call %d: %v", calls, err)
				}
				calls++
				d.mu.Lock()
				served, page := d.served, d.maxPage
				d.mu.Unlock()
				if bound := int64(budget) + 3*page; served > bound {
					t.Fatalf("call %d fetched %d bytes, bound %d", calls, served, bound)
				}
				if len(res.Records) == 0 {
					empty++
				}
				if !replayed && qq.Cursor != "" && len(res.Records) > 0 && empty > 0 {
					// Replay the cursor of this page: the same records.
					again, err := f.eng.Search(ctx, qq)
					if err != nil {
						t.Fatalf("replay: %v", err)
					}
					if a, b := recordTimes(t, again.Records), recordTimes(t, res.Records); !slices.Equal(a, b) {
						t.Fatalf("replayed cursor: %d records, first call %d", len(a), len(b))
					}
					replayed = true
				}
				recs = append(recs, res.Records...)
				if res.Complete {
					break
				}
				if res.Cursor == "" || calls > 400 {
					t.Fatalf("call %d: incomplete without a cursor", calls)
				}
				qq.Cursor = res.Cursor
			}
			if empty == 0 {
				t.Fatal("no call split a slice: the dense minute fitted a call's budget")
			}
			if !replayed {
				t.Fatal("no cursor replayed after a split")
			}
			// A query's split plans take one slot: other queries'
			// cursors are never evicted by a dense one.
			f.eng.mu.Lock()
			plans := len(f.eng.plans)
			f.eng.mu.Unlock()
			if plans != 1 {
				t.Fatalf("%d frozen plans after one query", plans)
			}
			ts := recordTimes(t, recs)
			checkOrder(t, ts, 9*12+600, order == "desc")
			seen := map[time.Time]bool{}
			for _, x := range ts {
				if seen[x] {
					t.Fatalf("record at %v returned twice", x)
				}
				seen[x] = true
			}
		})
	}
}

// TestLokiSliceOverAtNarrowest: a stream holding more than one call's
// budget in one second is refused, with a message that does not speak of
// local files.
func TestLokiSliceOverAtNarrowest(t *testing.T) {
	d := &denseLoki{every: 5 * time.Second, denseEvery: time.Millisecond, denseFor: 2 * time.Second,
		dense: t0.Add(30 * time.Second), pad: 4 << 10}
	f := denseFixture(t, d, 256<<10)
	qq := q(func(q *Query) {
		q.From, q.To = t0, t0.Add(2*time.Minute)
		q.Sources = []string{"lk"}
		q.Limit = 200
	})
	for calls := 0; ; calls++ {
		res, err := f.eng.Search(ctx, qq)
		if err != nil {
			if code(err) != EOverBudget {
				t.Fatalf("call %d: %v", calls, err)
			}
			var e *Error
			if !errors.As(err, &e) || e.Message != errSliceOver().Message {
				t.Fatalf("call %d: %v, want the narrowest-slice refusal", calls, err)
			}
			if strings.Contains(e.Message, "compressed") || strings.Contains(e.Message, "file") {
				t.Fatalf("remote refusal speaks of files: %s", e.Message)
			}
			return
		}
		if res.Complete || calls > 20 {
			t.Fatalf("call %d: the over-dense second was not refused", calls)
		}
		qq.Cursor = res.Cursor
	}
}

// TestLokiDenseSliceCount: a count by pattern (never served by Loki's
// metric queries) over a dense slice pages through the split slices and
// counts every record once.
func TestLokiDenseSliceCount(t *testing.T) {
	d := &denseLoki{every: 5 * time.Second, denseEvery: 100 * time.Millisecond, denseFor: time.Minute,
		dense: t0.Add(3 * time.Minute), pad: 4 << 10}
	f := denseFixture(t, d, 256<<10)
	cq := CountQuery{Query: q(func(q *Query) {
		q.From, q.To = t0, t0.Add(10*time.Minute)
		q.Sources = []string{"lk"}
	}), ByPattern: true}
	var total int64
	for calls := 0; ; calls++ {
		res, err := f.eng.Count(ctx, cq)
		if err != nil {
			t.Fatalf("call %d: %v", calls, err)
		}
		if res.Complete {
			for _, g := range res.Groups {
				total += g.N
			}
			break
		}
		if res.Cursor == "" || calls > 400 {
			t.Fatalf("call %d: incomplete without a cursor", calls)
		}
		cq.Cursor = res.Cursor
	}
	if total != 9*12+600 {
		t.Fatalf("counted %d records, want %d", total, 9*12+600)
	}
}

// TestLokiSplitFullPlans: with the frozen plans full, a query's splits
// never evict another query's plan.
func TestLokiSplitFullPlans(t *testing.T) {
	d := &denseLoki{every: 5 * time.Second, denseEvery: 100 * time.Millisecond, denseFor: time.Minute,
		dense: t0.Add(3 * time.Minute), pad: 4 << 10}
	f := denseFixture(t, d, 256<<10)
	qq := q(func(q *Query) {
		q.From, q.To = t0, t0.Add(10*time.Minute)
		q.Sources = []string{"lk"}
		q.Limit = 200
	})
	res, err := f.eng.Search(ctx, qq) // the query's own plan
	if err != nil || res.Complete {
		t.Fatalf("first call: %v, complete %v", err, res.Complete)
	}
	var foreign []string
	for len(f.eng.plans) < maxPlans {
		foreign = append(foreign, f.eng.freeze("other", source.Byteplan{}, false).id)
	}
	splits := 0
	for calls := 0; !res.Complete; calls++ {
		if calls > 400 {
			t.Fatal("no end")
		}
		qq.Cursor = res.Cursor
		if res, err = f.eng.Search(ctx, qq); err != nil {
			t.Fatalf("call %d: %v", calls, err)
		}
		if len(res.Records) == 0 {
			splits++
		}
	}
	if splits == 0 {
		t.Fatal("no split")
	}
	f.eng.mu.Lock()
	defer f.eng.mu.Unlock()
	for _, id := range foreign {
		if f.eng.plans[id] == nil {
			t.Fatalf("a split evicted another query's plan (%d splits)", splits)
		}
	}
}
