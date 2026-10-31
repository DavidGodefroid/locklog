package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
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
