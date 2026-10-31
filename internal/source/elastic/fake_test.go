package elastic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// readOnlyGrants is the _privileges answer of a read-only role (recorded
// from Elasticsearch 8.15).
const readOnlyGrants = `{"cluster":["monitor"],"global":[],"indices":[{"names":["logs-*"],"privileges":["read","view_index_metadata"],"allow_restricted_indices":false}],"applications":[],"run_as":[]}`

// resolvedLogs is the _resolve/index answer of logs-* (shape recorded from
// Elasticsearch 8.15): two indices, an alias, a data stream.
const resolvedLogs = `{"indices":[{"name":"logs-a","aliases":["logs-current"],"attributes":["open"]},{"name":"logs-b","attributes":["open"]},{"name":".ds-logs-app-2026.10.30-000001","attributes":["open"],"data_stream":"logs-app"}],"aliases":[{"name":"logs-current","indices":["logs-a"]}],"data_streams":[{"name":"logs-app","backing_indices":[".ds-logs-app-2026.10.30-000001"],"timestamp_field":"@timestamp"}]}`

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// fakeDoc is one document: its time (milliseconds, as a date field) and
// flat fields (keyword values, and the message).
type fakeDoc struct {
	index  string
	id     string
	ts     time.Time
	fields map[string]any // string or []string
}

// fakeES answers the requests locklog sends over an in-memory set of
// documents, with Elasticsearch's semantics for the subset locklog uses:
// bool filters (range, term, terms, must_not), sort on the time field
// (date_nanos numeric type) and an optional tiebreaker, search_after,
// size, the fields option, date_histogram and terms aggregations, _count,
// _field_caps, the root and the privilege checks. Bodies are decoded
// strictly into the builder's types: an unknown key is a 400.
type fakeES struct {
	mu        sync.Mutex
	seg       string
	docs      []fakeDoc
	flavour   string // "" (Elasticsearch) or "opensearch"
	grants    string // the _privileges answer
	resolved  string // the _resolve/index answer
	roles     []string
	security  bool // privilege endpoints answer
	requests  []string
	bodies    [][]byte
	inflight  int32
	maxIn     int32
	delay     time.Duration
	types     map[string]string // field_caps types
	timedOut  bool
	shardFail bool
}

func newFake(docs []fakeDoc) *fakeES {
	return &fakeES{seg: "logs-*", docs: docs, security: true, grants: readOnlyGrants, resolved: resolvedLogs,
		types: map[string]string{"@timestamp": "date", "app": "keyword", "level": "keyword", "pod": "keyword", "event.id": "keyword", "message": "text", "user_email": "keyword"}}
}

func (f *fakeES) fail(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"reason": msg}, "status": code})
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(v)
}

func (f *fakeES) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := atomic.AddInt32(&f.inflight, 1)
	defer atomic.AddInt32(&f.inflight, -1)
	for {
		m := atomic.LoadInt32(&f.maxIn)
		if n <= m || atomic.CompareAndSwapInt32(&f.maxIn, m, n) {
			break
		}
	}
	time.Sleep(f.delay)
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	pre := "/" + f.seg
	switch {
	case r.Method == "GET" && r.URL.Path == "/":
		if f.flavour == "opensearch" {
			_, _ = w.Write([]byte(`{"name":"n","version":{"distribution":"opensearch","number":"2.17.1"},"tagline":"The OpenSearch Project"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"n","version":{"number":"8.15.3","build_flavor":"default"},"tagline":"You Know, for Search"}`))
	case r.Method == "GET" && r.URL.Path == "/_resolve/index"+pre:
		if r.URL.Query().Get("expand_wildcards") != "open" {
			f.fail(w, 400, "expand_wildcards")
			return
		}
		_, _ = w.Write([]byte(f.resolved))
	case r.Method == "GET" && r.URL.Path == "/_security/user/_privileges":
		if !f.security || f.flavour == "opensearch" {
			f.fail(w, 400, "security is not enabled")
			return
		}
		_, _ = w.Write([]byte(f.grants))
	case r.Method == "GET" && r.URL.Path == "/_plugins/_security/authinfo":
		if !f.security || f.flavour != "opensearch" {
			f.fail(w, 404, "no handler")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user_name": "reader", "roles": f.roles, "backend_roles": []string{}})
	case r.Method == "GET" && r.URL.Path == pre+"/_field_caps":
		want := strings.Split(r.URL.Query().Get("fields"), ",")
		fields := map[string]any{"_id": map[string]any{"_id": map[string]any{"type": "_id"}}}
		for name, t := range f.types {
			if slices.Contains(want, "*") || slices.Contains(want, name) {
				fields[name] = map[string]any{t: map[string]any{"type": t, "searchable": true, "aggregatable": t != "text"}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"indices": []string{"logs-a", "logs-b"}, "fields": fields})
	case r.Method == "GET" && r.URL.Path == pre+"/_mapping":
		_, _ = w.Write([]byte(`{"logs-a":{"mappings":{}}}`))
	case r.Method == "POST" && r.URL.Path == pre+"/_count":
		var cb CountBody
		if err := strictDecode(body, &cb); err != nil {
			f.fail(w, 400, err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(f.match(cb.Query)), "_shards": map[string]any{"total": 1, "failed": 0}})
	case r.Method == "POST" && r.URL.Path == pre+"/_search":
		var sb SearchBody
		if err := strictDecode(body, &sb); err != nil {
			f.fail(w, 400, err.Error())
			return
		}
		f.search(w, sb)
	default:
		f.fail(w, 404, "no handler")
	}
}

func values(d fakeDoc, field string) ([]string, bool) {
	v, ok := d.fields[field]
	if !ok {
		return nil, false
	}
	switch v := v.(type) {
	case string:
		return []string{v}, true
	case []string:
		return v, true
	}
	return nil, false
}

func clauseMatches(c Clause, d fakeDoc) bool {
	for field, rs := range c.Range {
		if field != "@timestamp" {
			return false
		}
		lo, _ := time.Parse(time.RFC3339Nano, rs.GTE)
		hi, _ := time.Parse(time.RFC3339Nano, rs.LT)
		// A date field truncates finer bounds to milliseconds.
		lo, hi = lo.Truncate(time.Millisecond), hi.Truncate(time.Millisecond)
		return !d.ts.Before(lo) && d.ts.Before(hi)
	}
	for field, v := range c.Term {
		vs, _ := values(d, field)
		return slices.Contains(vs, v)
	}
	for field, want := range c.Terms {
		vs, _ := values(d, field)
		for _, v := range vs {
			if slices.Contains(want, v) {
				return true
			}
		}
		return false
	}
	return false
}

func (f *fakeES) match(q Query) []fakeDoc {
	var out []fakeDoc
next:
	for _, d := range f.docs {
		for _, c := range q.Bool.Filter {
			if !clauseMatches(c, d) {
				continue next
			}
		}
		for _, c := range q.Bool.MustNot {
			if clauseMatches(c, d) {
				continue next
			}
		}
		out = append(out, d)
	}
	return out
}

func (f *fakeES) search(w http.ResponseWriter, sb SearchBody) {
	hits := f.match(sb.Query)
	var tie string
	if len(sb.Sort) > 1 {
		for k := range sb.Sort[1] {
			tie = k
		}
	}
	key := func(d fakeDoc) []any {
		k := []any{d.ts.UnixNano()}
		if tie != "" {
			vs, _ := values(d, tie)
			if len(vs) == 0 {
				k = append(k, nil)
			} else {
				k = append(k, vs[0])
			}
		}
		return k
	}
	less := func(a, b []any) int {
		if a[0].(int64) != b[0].(int64) {
			if a[0].(int64) < b[0].(int64) {
				return -1
			}
			return 1
		}
		if len(a) > 1 {
			as, _ := a[1].(string)
			bs, _ := b[1].(string)
			return strings.Compare(as, bs)
		}
		return 0
	}
	// Ties without a tiebreaker come back in a shard-dependent order:
	// reverse insertion order here.
	slices.Reverse(hits)
	sort.SliceStable(hits, func(i, j int) bool { return less(key(hits[i]), key(hits[j])) < 0 })
	if sb.SearchAfter != nil {
		after := []any{}
		for _, v := range sb.SearchAfter {
			switch v := v.(type) {
			case json.Number:
				n, _ := strconv.ParseInt(v.String(), 10, 64)
				after = append(after, n)
			default:
				after = append(after, v)
			}
		}
		var rest []fakeDoc
		for _, h := range hits {
			if less(key(h), after) > 0 {
				rest = append(rest, h)
			}
		}
		hits = rest
	}
	total := len(hits)
	if len(hits) > sb.Size {
		hits = hits[:sb.Size]
	}
	var out []any
	for _, h := range hits {
		fields := map[string]any{}
		src := map[string]any{"@timestamp": h.ts.Format(time.RFC3339Nano)}
		for k, v := range h.fields {
			src[k] = v
			// The fake answers every field asked, and a few more: the
			// source must drop them.
			if slices.Contains(sb.Fields, k) || k == "user_email" {
				vs, _ := values(h, k)
				fields[k] = vs
			}
		}
		out = append(out, map[string]any{"_index": h.index, "_id": h.id, "_score": nil, "_source": src, "fields": fields, "sort": key(h)})
	}
	resp := map[string]any{"took": 1, "timed_out": f.timedOut, "_shards": map[string]any{"total": 2, "successful": 2, "failed": 0},
		"hits": map[string]any{"total": map[string]any{"value": total, "relation": "eq"}, "hits": out}}
	if f.shardFail {
		resp["_shards"] = map[string]any{"total": 2, "successful": 1, "failed": 1}
	}
	if !sb.TrackTotalHits {
		delete(resp["hits"].(map[string]any), "total")
	}
	if sb.Aggs != nil {
		resp["aggregations"] = f.aggs(sb.Aggs, f.match(sb.Query))
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeES) aggs(aggs map[string]Agg, docs []fakeDoc) map[string]any {
	out := map[string]any{}
	for name, a := range aggs {
		switch {
		case a.DateHistogram != nil:
			ms, _ := strconv.ParseInt(strings.TrimSuffix(a.DateHistogram.FixedInterval, "ms"), 10, 64)
			off, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(a.DateHistogram.Offset, "+"), "ms"), 10, 64)
			groups := map[int64][]fakeDoc{}
			for _, d := range docs {
				t := d.ts.UnixMilli() - off
				k := t - ((t%ms)+ms)%ms + off
				groups[k] = append(groups[k], d)
			}
			var keys []int64
			for k := range groups {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			var buckets []any
			for _, k := range keys {
				b := map[string]any{"key": k, "key_as_string": time.UnixMilli(k).UTC().Format(time.RFC3339), "doc_count": len(groups[k])}
				for sk, sv := range f.aggs(a.Aggs, groups[k]) {
					b[sk] = sv
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"buckets": buckets}
		case a.Terms != nil:
			groups := map[string][]fakeDoc{}
			for _, d := range docs {
				vs, ok := values(d, a.Terms.Field)
				if !ok && a.Terms.Missing != nil {
					vs = []string{*a.Terms.Missing}
				}
				for _, v := range vs {
					groups[v] = append(groups[v], d)
				}
			}
			var keys []string
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if len(groups[keys[i]]) != len(groups[keys[j]]) {
					return len(groups[keys[i]]) > len(groups[keys[j]])
				}
				return keys[i] < keys[j]
			})
			other := 0
			var buckets []any
			for i, k := range keys {
				if i >= a.Terms.Size {
					other += len(groups[k])
					continue
				}
				b := map[string]any{"key": k, "doc_count": len(groups[k])}
				for sk, sv := range f.aggs(a.Aggs, groups[k]) {
					b[sk] = sv
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"doc_count_error_upper_bound": 0, "sum_other_doc_count": other, "buckets": buckets}
		}
	}
	return out
}

// dataset: n documents two seconds apart, every tenth sharing its
// millisecond with the one before, two apps, levels, untrusted pods and
// e-mails.
func dataset(n int) []fakeDoc {
	var out []fakeDoc
	lv := []string{"info", "info", "warn", "error"}
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * 2 * time.Second)
		if i%10 == 1 {
			ts = out[i-1].ts
		}
		out = append(out, fakeDoc{index: []string{"logs-a", "logs-b"}[i%2], id: fmt.Sprintf("d%04d", i), ts: ts, fields: map[string]any{
			"app": []string{"api", "worker"}[i%2], "level": lv[i%4], "pod": fmt.Sprintf("pod-%d", i%3),
			"user_email": fmt.Sprintf("u%d@example.com", i%7), "event.id": fmt.Sprintf("e%05d", i),
			"message": fmt.Sprintf(`{"ts":"2020-01-01T00:00:00Z","msg":"request %d","status":%d}`, i, 200+100*(i%4)),
		}})
	}
	return out
}
