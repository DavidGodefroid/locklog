// Package lokitest is a fake Loki 3 for the tests of the packages that
// open a Loki source (the session, the engine through it): an
// http.Handler over in-memory entries that answers the requests locklog
// sends (labels, label values, query_range for streams and for the
// metric form, the instant metric query), with Loki's paging (limit over
// all streams, forward, end excluded) and categorized labels, behind
// basic authentication unless Open.
//
// The loki package's own tests have a richer fake of their own; this one
// only needs to be faithful to the subset a session reads.
package lokitest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is one log entry.
type Entry struct {
	TS     int64 // Unix nanoseconds
	Labels map[string]string
	Meta   map[string]string
	Line   string
}

// Server is the fake. Set its fields before serving.
type Server struct {
	Entries []Entry
	// User and Password authenticate a request (basic); Open serves every
	// request without credentials.
	User, Password string
	Open           bool

	mu       sync.Mutex
	requests []string
}

// Requests returns the path of every request served.
func (f *Server) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

var (
	matcherRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)(=~|!~|!=|=)("(?:[^"\\]|\\.)*")`)
	metricRe  = regexp.MustCompile(`^sum by \(([^)]*)\) \(count_over_time\((.*) \[(\d+(?:ms|s))\]\)\)$`)
)

type matcher struct{ name, op, value string }

// parse reads a selector {a="b", ...} and its | name="v" filters.
func parse(q string) (stream, meta []matcher, err error) {
	if !strings.HasPrefix(q, "{") {
		return nil, nil, fmt.Errorf("no stream selector")
	}
	end := strings.Index(q, "}")
	if end < 0 {
		return nil, nil, fmt.Errorf("unterminated selector")
	}
	read := func(s string) ([]matcher, error) {
		var out []matcher
		for _, m := range matcherRe.FindAllStringSubmatch(s, -1) {
			v, err := strconv.Unquote(m[3])
			if err != nil {
				return nil, err
			}
			out = append(out, matcher{m[1], m[2], v})
		}
		return out, nil
	}
	if stream, err = read(q[1:end]); err != nil {
		return nil, nil, err
	}
	meta, err = read(q[end+1:])
	return stream, meta, err
}

func matches(ms []matcher, l map[string]string) bool {
	for _, m := range ms {
		v := l[m.name]
		switch m.op {
		case "=":
			if v != m.value {
				return false
			}
		case "!=":
			if v == m.value {
				return false
			}
		case "=~", "!~":
			re := regexp.MustCompile("^(?:" + m.value + ")$")
			if re.MatchString(v) != (m.op == "=~") {
				return false
			}
		}
	}
	return true
}

func merged(e Entry) map[string]string {
	m := map[string]string{}
	for k, v := range e.Labels {
		m[k] = v
	}
	for k, v := range e.Meta {
		m[k] = v
	}
	return m
}

func labelsKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strconv.Quote(m[k]) + ",")
	}
	return b.String()
}

func (f *Server) authorized(r *http.Request) bool {
	if f.Open {
		return true
	}
	u, p, ok := r.BasicAuth()
	return ok && f.User != "" && u == f.User && p == f.Password
}

func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
}

// ServeHTTP implements http.Handler.
func (f *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.Path)
	f.mu.Unlock()
	if !f.authorized(r) {
		http.Error(w, "no org id or credentials", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	categorize := r.Header.Get("X-Loki-Response-Encoding-Flags") == "categorize-labels"
	var sel []matcher
	if qq := q.Get("query"); qq != "" && strings.HasPrefix(r.URL.Path, "/loki/api/v1/label") {
		s, _, err := parse(qq)
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		sel = s
	}
	switch {
	case r.URL.Path == "/ready":
		_, _ = w.Write([]byte("ready\n"))
	case r.URL.Path == "/loki/api/v1/labels":
		set := map[string]bool{}
		for _, e := range f.Entries {
			if matches(sel, e.Labels) {
				for k := range e.Labels {
					set[k] = true
				}
			}
		}
		out := []string{}
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		ok(w, out)
	case strings.HasPrefix(r.URL.Path, "/loki/api/v1/label/"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/loki/api/v1/label/"), "/values")
		set := map[string]bool{}
		for _, e := range f.Entries {
			if v, has := e.Labels[name]; has && matches(sel, e.Labels) {
				set[v] = true
			}
		}
		out := []string{}
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		ok(w, out)
	case r.URL.Path == "/loki/api/v1/query":
		at, _ := strconv.ParseInt(q.Get("time"), 10, 64)
		m := metricRe.FindStringSubmatch(q.Get("query"))
		if m == nil {
			http.Error(w, "unsupported", 400)
			return
		}
		series, err := f.metric(m, at, at, "")
		if err != nil {
			http.Error(w, "bad query", 400)
			return
		}
		result := []any{}
		for _, s := range series {
			result = append(result, map[string]any{"metric": s.metric, "value": s.values[0]})
		}
		ok(w, map[string]any{"resultType": "vector", "result": result})
	case r.URL.Path == "/loki/api/v1/query_range":
		query := q.Get("query")
		start, _ := strconv.ParseInt(q.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(q.Get("end"), 10, 64)
		if m := metricRe.FindStringSubmatch(query); m != nil {
			series, err := f.metric(m, start, end, q.Get("step"))
			if err != nil {
				http.Error(w, "bad query", 400)
				return
			}
			result := []any{}
			for _, s := range series {
				result = append(result, map[string]any{"metric": s.metric, "values": s.values})
			}
			ok(w, map[string]any{"resultType": "matrix", "result": result})
			return
		}
		stream, meta, err := parse(query)
		if err != nil {
			http.Error(w, "parse error", 400)
			return
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		var hits []Entry
		for _, e := range f.Entries {
			if e.TS >= start && e.TS < end && matches(stream, e.Labels) && matches(meta, merged(e)) {
				hits = append(hits, e)
			}
		}
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].TS < hits[j].TS })
		if len(hits) > limit {
			hits = hits[:limit]
		}
		streams := map[string]map[string]any{}
		var order []string
		for _, e := range hits {
			labels := e.Labels
			if !categorize {
				labels = merged(e)
			}
			k := labelsKey(labels)
			if streams[k] == nil {
				streams[k] = map[string]any{"stream": labels, "values": [][]any{}}
				order = append(order, k)
			}
			val := []any{strconv.FormatInt(e.TS, 10), e.Line}
			if categorize {
				val = append(val, map[string]any{"structuredMetadata": e.Meta})
			}
			streams[k]["values"] = append(streams[k]["values"].([][]any), val)
		}
		result := []any{}
		for _, k := range order {
			result = append(result, streams[k])
		}
		data := map[string]any{"resultType": "streams", "result": result}
		if categorize {
			data["encodingFlags"] = []string{"categorize-labels"}
		}
		ok(w, data)
	default:
		http.NotFound(w, r)
	}
}

type series struct {
	metric map[string]string
	values [][]any
}

// metric evaluates sum by (...) (count_over_time(sel [range])) as Loki
// 3.5 does: a range query's start rounded down and its end up to the
// step; at each step t, the entries in (t-range, t].
func (f *Server) metric(m []string, start, end int64, stepS string) ([]series, error) {
	var by []string
	if m[1] != "" {
		by = strings.Split(m[1], ", ")
	}
	stream, meta, err := parse(m[2])
	if err != nil {
		return nil, err
	}
	d, err := time.ParseDuration(m[3])
	if err != nil {
		return nil, err
	}
	rng := int64(d)
	step := int64(1)
	if stepS != "" {
		s, _ := strconv.ParseInt(stepS, 10, 64)
		step = s * 1e9
		start -= start % step
		if r := end % step; r != 0 {
			end += step - r
		}
	}
	out := map[string]*series{}
	var order []string
	for t := start; t <= end; t += step {
		counts := map[string]int{}
		metrics := map[string]map[string]string{}
		var keys []string
		for _, e := range f.Entries {
			if e.TS > t-rng && e.TS <= t && matches(stream, e.Labels) && matches(meta, merged(e)) {
				mm := map[string]string{}
				for _, l := range by {
					if v, has := e.Labels[l]; has {
						mm[l] = v
					} else if v, has := e.Meta[l]; has {
						mm[l] = v
					}
				}
				k := labelsKey(mm)
				if counts[k] == 0 {
					keys = append(keys, k)
				}
				counts[k]++
				metrics[k] = mm
			}
		}
		ms := t / 1e6
		for _, k := range keys {
			if out[k] == nil {
				out[k] = &series{metric: metrics[k]}
				order = append(order, k)
			}
			out[k].values = append(out[k].values, []any{json.RawMessage(strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)), strconv.Itoa(counts[k])})
		}
	}
	res := make([]series, 0, len(order))
	for _, k := range order {
		res = append(res, *out[k])
	}
	return res, nil
}
