//go:build integration

// Package loki_test runs the Loki source against a real Loki (CI starts
// grafana/loki; locally: LOCKLOG_LOKI_URL=http://127.0.0.1:3100 under the
// heavy lease). Run with: go test -tags integration ./test/loki
package loki_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

func lokiURL(t *testing.T) string {
	u := os.Getenv("LOCKLOG_LOKI_URL")
	if u == "" {
		t.Skip("LOCKLOG_LOKI_URL not set")
	}
	return strings.TrimSuffix(u, "/")
}

// push writes entries with the push API directly (the source itself can
// only read).
func push(t *testing.T, base string, run string, start time.Time, n int) {
	t.Helper()
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][]any           `json:"values"`
	}
	levels := []string{"info", "info", "warn", "error"}
	streams := map[string]*stream{}
	for i := 0; i < n; i++ {
		lv := levels[i%4]
		app := []string{"api", "worker"}[i%2]
		k := app + lv
		if streams[k] == nil {
			streams[k] = &stream{Stream: map[string]string{"run": run, "app": app, "level": lv, "pod": "p" + strconv.Itoa(i%3)}}
		}
		ts := start.Add(time.Duration(i) * 100 * time.Millisecond)
		streams[k].Values = append(streams[k].Values, []any{strconv.FormatInt(ts.UnixNano(), 10),
			fmt.Sprintf(`{"msg":"request %d for u%d@example.com","status":%d}`, i, i%7, 200+100*(i%4)),
			map[string]string{"trace_id": fmt.Sprintf("t%d", i/5), "user_email": fmt.Sprintf("u%d@example.com", i%7)}})
	}
	var body struct {
		Streams []*stream `json:"streams"`
	}
	for _, s := range streams {
		body.Streams = append(body.Streams, s)
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(base+"/loki/api/v1/push", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("push: %d %s", resp.StatusCode, msg)
	}
}

// pushEdges writes one entry at each of ats (app=api, level=edge), in a
// stream of their own.
func pushEdges(t *testing.T, base, run string, ats []time.Time) {
	t.Helper()
	var vals [][]any
	for i, at := range ats {
		vals = append(vals, []any{strconv.FormatInt(at.UnixNano(), 10), fmt.Sprintf(`{"msg":"edge %d"}`, i), map[string]string{"trace_id": "edge"}})
	}
	b, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{
		"stream": map[string]string{"run": run, "app": "api", "level": "edge", "pod": "p0"}, "values": vals}}})
	resp, err := http.Post(base+"/loki/api/v1/push", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("push: %d %s", resp.StatusCode, msg)
	}
}

func newSource(t *testing.T, base, run string) *loki.Source {
	t.Helper()
	cl, err := egress.New(&config.Remote{URL: base, Auth: config.AuthNone}, egress.LokiRoutes, egress.Credentials{},
		egress.Options{Headers: egress.LokiHeaders})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := parse.New(parse.Options{})
	s, err := loki.New(loki.Options{Name: "loki", Client: cl, Parser: p, Selector: map[string]string{"run": run},
		TrustedLabels: []string{"app", "level"}, TrustedMetadata: []string{"trace_id"}, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func scan(t *testing.T, s *loki.Source, r source.Range, sel source.Selector) []source.RawRecord {
	t.Helper()
	plan, err := s.Plan(context.Background(), r, sel)
	if err != nil {
		t.Fatal(err)
	}
	var out []source.RawRecord
	for _, c := range plan.Chunks {
		it, err := s.Scan(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		for {
			rec, err := it.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, rec)
		}
		it.Close()
	}
	return out
}

func TestLokiSourceAgainstLoki(t *testing.T) {
	base := lokiURL(t)
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	start := time.Now().Add(-20 * time.Minute).Truncate(5 * time.Minute) // on Loki's step grid
	const n = 2400
	push(t, base, run, start, n)
	r := source.Range{From: start, To: start.Add(10 * time.Minute)}
	// The bucket edges: the last nanosecond of the first 5 m bucket, the
	// first of the second, the last of the range, and To (outside it).
	// The first pushed entry is exactly on From.
	edges := []time.Time{start.Add(5*time.Minute - 1), start.Add(5 * time.Minute), r.To.Add(-1), r.To}
	pushEdges(t, base, run, edges)
	const inRange = n + 3
	s := newSource(t, base, run)
	var recs []source.RawRecord
	for i := 0; i < 60; i++ {
		if recs = scan(t, s, r, source.Selector{}); len(recs) >= inRange {
			break
		}
		time.Sleep(time.Second)
	}
	if len(recs) != inRange {
		t.Fatalf("%d records, want %d", len(recs), inRange)
	}
	seen := map[string]bool{}
	for i, rec := range recs {
		if seen[rec.Event.Raw] {
			t.Fatalf("duplicate %q", rec.Event.Raw)
		}
		seen[rec.Event.Raw] = true
		if i > 0 && rec.Event.Time.Before(recs[i-1].Event.Time) {
			t.Fatal("out of order")
		}
		for _, a := range rec.Event.Attrs {
			if a.Key != "app" && a.Key != "level" && a.Key != "trace_id" {
				t.Fatalf("attr %q returned (untrusted label or metadata)", a.Key)
			}
		}
	}
	// Server-side selection on a trusted label and trusted metadata.
	sel := source.Selector{Terms: []source.Term{{Field: "level", Op: "=", Values: []string{"error"}}, {Field: "trace_id", Op: "=", Values: []string{"t7"}}}}
	if got := scan(t, s, r, sel); len(got) != 2 { // entries 35 and 39
		t.Fatalf("selected %d records, want 2", len(got))
	}
	// Metric counts are exactly the engine's buckets, [b, b+5m) from From:
	// From in, To out, an edge entry in the bucket it starts.
	want := map[string]int64{}
	levels := []string{"info", "info", "warn", "error"}
	bucketOf := func(at time.Time) string {
		return r.From.Add(at.Sub(r.From) / (5 * time.Minute) * (5 * time.Minute)).Format(time.RFC3339Nano)
	}
	for i := 0; i < n; i++ {
		want[bucketOf(start.Add(time.Duration(i)*100*time.Millisecond))+" "+levels[i%4]]++
	}
	for _, at := range edges {
		if at.Before(r.To) {
			want[bucketOf(at)+" edge"]++
		}
	}
	res, err := s.IndexCounts(context.Background(), source.CountQuery{Range: r, By: []string{"level"}, Bucket: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	gotN := map[string]int64{}
	for _, row := range res.Rows {
		gotN[row.Bucket.Format(time.RFC3339Nano)+" "+row.Vals[0]] += row.N
	}
	if !maps.Equal(gotN, want) {
		t.Fatalf("metric counts\n got %v\nwant %v", gotN, want)
	}
	// One bucket: the instant query counts [From, To).
	one, err := s.IndexCounts(context.Background(), source.CountQuery{Range: r})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Rows) != 1 || one.Rows[0].N != inRange || !one.Rows[0].Bucket.Equal(r.From) {
		t.Fatalf("instant count %+v, want %d at %v", one.Rows, inRange, r.From)
	}
	// Reread.
	got, err := s.Reread(context.Background(), recs[100].Ref)
	if err != nil || got.Event.Raw != recs[100].Event.Raw {
		t.Fatalf("reread: %v", err)
	}
	sch, err := s.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sch.Fields {
		if f.Name == "__stream_shard__" {
			t.Fatal("shard label shown")
		}
	}
}
