// Package elastictest is a fake Elasticsearch 8 / OpenSearch 2 for the
// tests of the packages that open an Elasticsearch source (the session,
// the engine through it): an http.Handler over in-memory documents that
// answers the requests locklog sends (the root, the privilege checks,
// _resolve/index, _field_caps, _mapping, _settings, _count and _search
// with bool filters, sort, search_after and the two aggregation kinds),
// behind basic or API-key authentication unless Open.
//
// The elastic package's own tests have a richer fake of their own; this
// one only needs to be faithful to the subset a session reads.
package elastictest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source/elastic"
)

// ReadOnlyGrants is the _privileges answer of a read-only role on logs-*
// (shape recorded from Elasticsearch 8.15).
const ReadOnlyGrants = `{"cluster":["monitor"],"global":[],"indices":[{"names":["logs-*"],"privileges":["read","view_index_metadata"],"allow_restricted_indices":false}],"applications":[],"run_as":[]}`

// WriteGrants holds a write privilege on the source's indices.
const WriteGrants = `{"cluster":["monitor"],"global":[],"indices":[{"names":["logs-*"],"privileges":["read","view_index_metadata","write"],"allow_restricted_indices":false}],"applications":[],"run_as":[]}`

// Doc is one document: its index, id, time, and flat keyword fields (and
// the message), each a string or a []string.
type Doc struct {
	Index  string
	ID     string
	TS     time.Time
	Fields map[string]any
}

// Server is the fake. Set its fields before serving.
type Server struct {
	// Pattern is the index segment the source names (default "logs-*").
	Pattern string
	// Indices are the concrete indices the pattern resolves to (default
	// logs-a, logs-b).
	Indices []string
	Docs    []Doc
	// OpenSearch answers as OpenSearch 2 (authinfo, no _privileges).
	OpenSearch bool
	// Grants is the Elasticsearch _privileges answer (default
	// ReadOnlyGrants); Roles the OpenSearch roles of the user.
	Grants string
	Roles  []string
	// Types are the mapped fields and their types (default: @timestamp
	// date, message text, every other field of a document keyword).
	Types map[string]string
	// User and Password, or APIKey (the encoded key), authenticate a
	// request; Open serves every request without credentials.
	User, Password, APIKey string
	Open                   bool

	mu       sync.Mutex
	requests []string
}

// Requests returns the method and path of every request served.
func (f *Server) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *Server) pattern() string {
	if f.Pattern == "" {
		return "logs-*"
	}
	return f.Pattern
}

func (f *Server) indices() []string {
	if len(f.Indices) == 0 {
		return []string{"logs-a", "logs-b"}
	}
	return f.Indices
}

func (f *Server) types() map[string]string {
	if f.Types != nil {
		return f.Types
	}
	t := map[string]string{"@timestamp": "date", "message": "text"}
	for _, d := range f.Docs {
		for k := range d.Fields {
			if _, ok := t[k]; !ok {
				t[k] = "keyword"
			}
		}
	}
	return t
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"reason": msg}, "status": code})
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(v)
}

func (f *Server) authorized(r *http.Request) bool {
	if f.Open {
		return true
	}
	if f.APIKey != "" && r.Header.Get("Authorization") == "ApiKey "+f.APIKey {
		return true
	}
	u, p, ok := r.BasicAuth()
	return ok && f.User != "" && u == f.User && p == f.Password
}

// mapping is the _mapping answer: every index maps every field.
func (f *Server) mapping() map[string]any {
	props := map[string]any{}
	for name, t := range f.types() {
		// Dotted names as nested objects.
		parts := strings.Split(name, ".")
		m := props
		for _, p := range parts[:len(parts)-1] {
			obj, _ := m[p].(map[string]any)
			if obj == nil {
				obj = map[string]any{"properties": map[string]any{}}
				m[p] = obj
			}
			m = obj["properties"].(map[string]any)
		}
		m[parts[len(parts)-1]] = map[string]any{"type": t}
	}
	out := map[string]any{}
	for _, ix := range f.indices() {
		out[ix] = map[string]any{"mappings": map[string]any{"properties": props}}
	}
	return out
}

// ServeHTTP implements http.Handler.
func (f *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if !f.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="security"`)
		fail(w, http.StatusUnauthorized, "missing authentication credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	pre := "/" + f.pattern()
	switch {
	case r.Method == "GET" && r.URL.Path == "/":
		if f.OpenSearch {
			_, _ = w.Write([]byte(`{"name":"n","version":{"distribution":"opensearch","number":"2.17.1"},"tagline":"The OpenSearch Project"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"n","version":{"number":"8.15.3","build_flavor":"default"},"tagline":"You Know, for Search"}`))
	case r.Method == "GET" && r.URL.Path == "/_resolve/index"+pre:
		var ixs []any
		for _, ix := range f.indices() {
			ixs = append(ixs, map[string]any{"name": ix, "attributes": []string{"open"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"indices": ixs, "aliases": []any{}, "data_streams": []any{}})
	case r.Method == "GET" && r.URL.Path == "/_security/user/_privileges":
		if f.OpenSearch {
			fail(w, 400, "no handler")
			return
		}
		g := f.Grants
		if g == "" {
			g = ReadOnlyGrants
		}
		_, _ = w.Write([]byte(g))
	case r.Method == "GET" && r.URL.Path == "/_plugins/_security/authinfo":
		if !f.OpenSearch {
			fail(w, 404, "no handler")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user_name": f.User, "roles": f.Roles, "backend_roles": []string{}})
	case r.Method == "GET" && r.URL.Path == pre+"/_field_caps":
		want := strings.Split(r.URL.Query().Get("fields"), ",")
		fields := map[string]any{}
		for name, t := range f.types() {
			if slices.Contains(want, "*") || slices.Contains(want, name) {
				fields[name] = map[string]any{t: map[string]any{"type": t, "searchable": true, "aggregatable": t != "text"}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"indices": f.indices(), "fields": fields})
	case r.Method == "GET" && r.URL.Path == pre+"/_mapping":
		_ = json.NewEncoder(w).Encode(f.mapping())
	case r.Method == "GET" && r.URL.Path == pre+"/_settings":
		out := map[string]any{}
		for _, ix := range f.indices() {
			out[ix] = map[string]any{"settings": map[string]any{"index.number_of_shards": "1"},
				"defaults": map[string]any{"index.mode": "standard", "index.mapping.ignore_above": "2147483647"}}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == "POST" && r.URL.Path == pre+"/_count":
		var cb elastic.CountBody
		if err := strictDecode(body, &cb); err != nil {
			fail(w, 400, "bad count body")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(f.match(cb.Query)), "_shards": map[string]any{"total": 1, "failed": 0}})
	case r.Method == "POST" && r.URL.Path == pre+"/_search":
		var sb elastic.SearchBody
		if err := strictDecode(body, &sb); err != nil {
			fail(w, 400, "bad search body")
			return
		}
		f.search(w, sb)
	default:
		fail(w, 404, "no handler")
	}
}

func values(d Doc, field string) ([]string, bool) {
	switch v := d.Fields[field].(type) {
	case string:
		return []string{v}, true
	case []string:
		return v, true
	}
	return nil, false
}

func clauseMatches(c elastic.Clause, d Doc) bool {
	for _, rs := range c.Range {
		lo, _ := time.Parse(time.RFC3339Nano, rs.GTE)
		hi, _ := time.Parse(time.RFC3339Nano, rs.LT)
		lo, hi = lo.Truncate(time.Millisecond), hi.Truncate(time.Millisecond)
		return !d.TS.Before(lo) && d.TS.Before(hi)
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

func (f *Server) match(q elastic.Query) []Doc {
	var out []Doc
next:
	for _, d := range f.Docs {
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

func (f *Server) search(w http.ResponseWriter, sb elastic.SearchBody) {
	hits := f.match(sb.Query)
	var tie string
	if len(sb.Sort) > 1 {
		for k := range sb.Sort[1] {
			tie = k
		}
	}
	key := func(d Doc) []any {
		k := []any{d.TS.UnixNano()}
		if tie != "" {
			if vs, _ := values(d, tie); len(vs) > 0 {
				k = append(k, vs[0])
			} else {
				k = append(k, nil)
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
		if len(a) > 1 && len(b) > 1 {
			as, _ := a[1].(string)
			bs, _ := b[1].(string)
			return strings.Compare(as, bs)
		}
		return 0
	}
	sort.SliceStable(hits, func(i, j int) bool { return less(key(hits[i]), key(hits[j])) < 0 })
	if sb.SearchAfter != nil {
		var after []any
		for _, v := range sb.SearchAfter {
			if n, ok := v.(json.Number); ok {
				i, _ := strconv.ParseInt(n.String(), 10, 64)
				after = append(after, i)
			} else {
				after = append(after, v)
			}
		}
		var rest []Doc
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
	out := []any{}
	for _, h := range hits {
		fields := map[string]any{}
		for k := range h.Fields {
			if slices.Contains(sb.Fields, k) {
				vs, _ := values(h, k)
				fields[k] = vs
			}
		}
		out = append(out, map[string]any{"_index": h.Index, "_id": h.ID, "_score": nil, "fields": fields, "sort": key(h)})
	}
	resp := map[string]any{"took": 1, "timed_out": false, "_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
		"hits": map[string]any{"hits": out}}
	if sb.TrackTotalHits {
		resp["hits"].(map[string]any)["total"] = map[string]any{"value": total, "relation": "eq"}
	}
	if sb.Aggs != nil {
		resp["aggregations"] = aggs(sb.Aggs, f.match(sb.Query))
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func aggs(as map[string]elastic.Agg, docs []Doc) map[string]any {
	out := map[string]any{}
	for name, a := range as {
		switch {
		case a.DateHistogram != nil:
			ms, _ := strconv.ParseInt(strings.TrimSuffix(a.DateHistogram.FixedInterval, "ms"), 10, 64)
			off, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(a.DateHistogram.Offset, "+"), "ms"), 10, 64)
			groups := map[int64][]Doc{}
			for _, d := range docs {
				t := d.TS.UnixMilli() - off
				k := t - ((t%ms)+ms)%ms + off
				groups[k] = append(groups[k], d)
			}
			var keys []int64
			for k := range groups {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			buckets := []any{}
			for _, k := range keys {
				b := map[string]any{"key": k, "key_as_string": time.UnixMilli(k).UTC().Format(time.RFC3339), "doc_count": len(groups[k])}
				for sk, sv := range aggs(a.Aggs, groups[k]) {
					b[sk] = sv
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"buckets": buckets}
		case a.Terms != nil:
			groups := map[string][]Doc{}
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
			buckets := []any{}
			for i, k := range keys {
				if i >= a.Terms.Size {
					other += len(groups[k])
					continue
				}
				b := map[string]any{"key": k, "doc_count": len(groups[k])}
				for sk, sv := range aggs(a.Aggs, groups[k]) {
					b[sk] = sv
				}
				buckets = append(buckets, b)
			}
			out[name] = map[string]any{"doc_count_error_upper_bound": 0, "sum_other_doc_count": other, "buckets": buckets}
		}
	}
	return out
}
