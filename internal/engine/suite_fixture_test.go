//go:build unix

package engine

// The LL-16 suites (suite_*_test.go) run the agent methods over one
// multi-source fixture: a file source per format (json, logfmt, plain,
// syslog, combined, cri, docker-json), a journald source and a docker
// json-file source, all fed the same records, each rendered in its source's
// own format. Every agent call goes through Handle (the IPC methods) and is
// followed through its continuation pages.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/docker"
	"github.com/DavidGodefroid/locklog/internal/source/file"
	"github.com/DavidGodefroid/locklog/internal/source/journald"
	"github.com/DavidGodefroid/locklog/internal/source/journald/journal/journaltest"
)

// suiteFileFormats are the file sources of the fixture, one per format;
// each is named after its format.
var suiteFileFormats = []string{"json", "logfmt", "plain", "syslog", "combined", "cri", "docker-json"}

const (
	srcJournal = "journal"
	srcDocker  = "docker"
	// suiteContainer is the docker source's one container.
	suiteContainer = "shop-api-1"
	suiteMachineID = "0123456789abcdef0123456789abcdef"
	// tsMark stands for a record's time in its payload; clfMark for it
	// in the access-log (common log format) form.
	tsMark  = "{TS}"
	clfMark = "{CLF}"
)

// suiteSources are every source of the fixture.
func suiteSources() []string { return append(slices.Clone(suiteFileFormats), srcJournal, srcDocker) }

// The suite clock: records start at suiteBase; queries cover the day.
var (
	suiteBase = time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)
	suiteFrom = suiteBase.Add(-2 * time.Hour)
	suiteTo   = suiteBase.Add(22 * time.Hour)
	suiteNow  = suiteTo
)

// Trusted names of the fixture: line fields, and labels (docker's
// container and stream).
var (
	suiteTrustedFields = []string{"level", "status", "status_class", "method", "PRIORITY", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER"}
	suiteTrustedLabels = []string{docker.ContainerField, "stream"}
	suiteIndexed       = []string{"level", "status", "status_class", "method"}
)

// suiteRecord is one record of a suite corpus: its time and its payload, a
// JSON, logfmt or plain line (Kind) in which tsMark stands for the time.
// Logfmt, when set, is the payload the logfmt source writes instead.
type suiteRecord struct {
	TS       time.Time
	Kind     string
	Payload  string
	Logfmt   string
	Canaries []masktest.Canary
}

func (r suiteRecord) payload(logfmt bool) string {
	p := r.Payload
	if logfmt && r.Logfmt != "" {
		p = r.Logfmt
	}
	p = strings.ReplaceAll(p, clfMark, r.TS.UTC().Format("02/Jan/2006:15:04:05 -0700"))
	return strings.ReplaceAll(p, tsMark, r.TS.UTC().Format("2006-01-02T15:04:05.000Z"))
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// render writes a record as a line of a file format.
func render(format string, r suiteRecord) string {
	p := r.payload(format == "logfmt")
	ts := r.TS.UTC()
	iso := ts.Format(time.RFC3339Nano)
	switch format {
	case "json":
		if r.Kind == "json" {
			return p
		}
		return `{"ts":"` + iso + `","level":"info","msg":` + jsonString(p) + `}`
	case "logfmt":
		if r.Kind == "logfmt" || r.Logfmt != "" {
			return p
		}
		return "ts=" + iso + " level=info msg=" + strconv.Quote(p)
	case "plain":
		if r.Kind == "plain" {
			return p
		}
		return iso + " INFO " + p
	case "syslog":
		return "<11>1 " + iso + " host-a shop 4242 - - " + p
	case "combined":
		if r.Kind == "combined" {
			return p
		}
		ua := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p)
		return "198.51.100.23 - - [" + ts.Format("02/Jan/2006:15:04:05 -0700") + `] "GET /api/orders/4812 HTTP/1.1" 502 512 "-" "` + ua + `"`
	case "cri":
		return iso + " stdout F " + p
	case "docker-json":
		return dockerFrame(p, ts)
	}
	panic("render: unknown format " + format)
}

func dockerFrame(payload string, ts time.Time) string {
	return `{"log":` + jsonString(payload+"\n") + `,"stream":"stdout","attrs":{"team":"shop"},"time":"` + ts.UTC().Format(time.RFC3339Nano) + `"}`
}

// journalEntry renders a record as a journald entry: the payload as
// MESSAGE and as an allowed field, with trusted journald fields.
func journalEntry(r suiteRecord) journaltest.Entry {
	p := r.payload(false)
	return journaltest.Entry{Realtime: uint64(r.TS.UnixMicro()), Fields: []string{
		"MESSAGE=" + p, "PRIORITY=3", "_SYSTEMD_UNIT=shop.service", "SYSLOG_IDENTIFIER=shop", "REQUEST_NOTE=" + p}}
}

// suiteConfig configures a fixture; the zero value is the non-production
// default (detect, pre-filter off) with every detector of the corpus kinds.
type suiteConfig struct {
	Structured string
	// Rules is the project's .locklog/pii.toml (default
	// masktest.RulesForCorpus); NoAgentMeta skips the agent rule on
	// "meta" the corpus's rule positions assume.
	Rules       string
	NoAgentMeta bool
	Prefilter   bool
	// Cost defaults to fixedCost(1) (whole plans in one call).
	Cost    *CostModel
	Workers int
	Limits  func(*Limits)
	// Epoch shares a pseudonym epoch between fixtures.
	Epoch *pii.Pseudonymizer
	// Index builds the local index of the indexable sources.
	Index bool
	// Files are file sources over files already written (by format: the
	// source of that name reads them); JournalRoot a journald source over
	// a journal directory already written (<root>/<machine-id>/). They
	// stand in for the records of those sources (the volume incident).
	Files       map[string][]string
	JournalRoot string
}

type suite struct {
	t        testing.TB
	root     string
	store    *index.Store
	masker   *mask.Masker
	agent    *mask.AgentRules
	eng      *Engine
	piiDir   string
	project  string
	indexers []index.Indexer
	recs     map[string][]suiteRecord
}

// newSuite writes recs (by source; a source without records is not
// configured) and returns the engine over them.
func newSuite(t testing.TB, recs map[string][]suiteRecord, cfg suiteConfig) *suite {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &suite{t: t, root: base, recs: recs, piiDir: filepath.Join(base, "pii"), project: filepath.Join(base, "project", ".locklog", "pii.toml")}
	if s.store, err = index.Open(filepath.Join(base, "index")); err != nil {
		t.Fatal(err)
	}
	ep := cfg.Epoch
	if ep == nil {
		if ep, err = pii.NewEpoch(suiteBase); err != nil {
			t.Fatal(err)
		}
	}
	rulesText := cfg.Rules
	if rulesText == "" {
		rulesText = masktest.RulesForCorpus
	}
	if err := os.MkdirAll(filepath.Dir(s.project), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.project, []byte(rulesText), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := mask.LoadProjectRules(s.project)
	if err != nil {
		t.Fatal(err)
	}
	if s.agent, err = mask.OpenAgentRules(s.piiDir); err != nil {
		t.Fatal(err)
	}
	rules.Agent = s.agent
	values, err := mask.ValueDetectors(masktest.ValueDetectors)
	if err != nil {
		t.Fatal(err)
	}
	structured := cfg.Structured
	if structured == "" {
		structured = mask.StructuredDetect
	}
	s.masker, err = mask.New(mask.Options{Structured: structured, Values: values, Rules: &rules, Pseudonyms: ep,
		SecretName: masktest.SecretNameForCorpus, Trusted: append([]string{"ts"}, suiteTrustedFields...)})
	if err != nil {
		t.Fatal(err)
	}
	m := s.masker
	sensitive := func(src string) func(f, v string) bool {
		return func(f, v string) bool { return m.TrustedValue(src, f, v) != v }
	}
	srcs := map[string]source.Source{}
	for _, format := range suiteFileFormats {
		rs, ok := recs[format]
		paths, given := cfg.Files[format]
		if !ok && !given {
			continue
		}
		dir := filepath.Join(base, "logs")
		if given {
			dir = filepath.Dir(paths[0])
		} else {
			var b strings.Builder
			for _, r := range rs {
				b.WriteString(render(format, r))
				b.WriteByte('\n')
			}
			os.MkdirAll(dir, 0o755)
			path := filepath.Join(dir, format+".log")
			if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			paths = []string{path}
		}
		p, err := parse.New(parse.Options{Format: format})
		if err != nil {
			t.Fatal(err)
		}
		fs, err := file.New(file.Options{Name: format, Paths: paths, Roots: []string{dir}, Parser: p,
			Trusted: suiteIndexed, Index: s.store, Sensitive: sensitive(format)})
		if err != nil {
			t.Fatal(err)
		}
		srcs[format] = fs
		s.indexers = append(s.indexers, fs)
	}
	if rs, ok := recs[srcJournal]; ok || cfg.JournalRoot != "" {
		root := cfg.JournalRoot
		if root == "" {
			root = filepath.Join(base, "journal")
			os.MkdirAll(filepath.Join(root, suiteMachineID), 0o755)
			var es []journaltest.Entry
			for _, r := range rs {
				es = append(es, journalEntry(r))
			}
			if err := os.WriteFile(filepath.Join(root, suiteMachineID, "system.journal"), journaltest.Build(journaltest.Options{Compact: true, PerArray: 1000}, es), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		p, _ := parse.New(parse.Options{})
		js, err := journald.New(journald.Options{Name: srcJournal, Roots: []string{root}, Parser: p, Allow: []string{"REQUEST_NOTE"}})
		if err != nil {
			t.Fatal(err)
		}
		srcs[srcJournal] = js
	}
	if rs, ok := recs[srcDocker]; ok {
		root, mapDir := filepath.Join(base, "containers"), filepath.Join(base, "map")
		id := strings.Repeat("a", 64)
		os.MkdirAll(filepath.Join(root, id), 0o710)
		os.MkdirAll(mapDir, 0o755)
		var b strings.Builder
		for _, r := range rs {
			b.WriteString(dockerFrame(r.payload(false), r.TS))
			b.WriteByte('\n')
		}
		if err := os.WriteFile(filepath.Join(root, id, id+"-json.log"), []byte(b.String()), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mapDir, "map.v1"), []byte("locklog-map 1\nc "+id+" "+suiteContainer+" 1 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ds, err := docker.New(docker.Options{Name: srcDocker, Containers: []string{"shop-*"}, Attrs: []string{"team"}, Root: root, MapDir: mapDir,
			Trusted: append(slices.Clone(suiteIndexed), "stream"), Index: s.store, Sensitive: sensitive(srcDocker),
			Self: func() []string { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		srcs[srcDocker] = ds
		s.indexers = append(s.indexers, ds)
	}
	// The agent rule the corpus's "meta" positions assume, per source.
	if !cfg.NoAgentMeta {
		p, _ := parse.New(parse.Options{})
		for name := range srcs {
			m.Mask(name, p.Line(`{"meta":{"note":"x"}}`))
			if err := m.AgentAdd(name, "meta", mask.ModePseudonym, suiteBase, mask.AgentLimits{PerHour: 100, Total: 100}); err != nil && !errors.Is(err, mask.ErrRuleExists) {
				t.Fatal(err)
			}
		}
	}
	key := make([]byte, 32)
	rand.Read(key)
	sealer, _ := NewSealer(key)
	cost := cfg.Cost
	if cost == nil {
		cost = fixedCost(1)
	}
	o := Options{
		Sources: srcs,
		Trusted: func(_, name string, label bool) bool {
			if label {
				return slices.Contains(suiteTrustedLabels, name)
			}
			return slices.Contains(suiteTrustedFields, name)
		},
		Masker: m, Sealer: sealer, Cost: cost,
		PolicyFP:   func() string { return "fp-suite" },
		Detect:     func(v string) bool { return m.Text(v) != v },
		NameMasked: func(_, p string) bool { return pii.LooksPersonal(p) },
		Limits:     DefaultLimits(),
		Prefilter:  cfg.Prefilter,
		Workers:    cfg.Workers,
		Now:        func() time.Time { return suiteNow },
	}
	if cfg.Limits != nil {
		cfg.Limits(&o.Limits)
	}
	if s.eng, err = New(o); err != nil {
		t.Fatal(err)
	}
	if cfg.Index {
		s.indexAll()
	}
	return s
}

// indexAll builds the whole local index of the indexable sources.
func (s *suite) indexAll() {
	s.t.Helper()
	for _, ix := range s.indexers {
		for i := 0; ; i++ {
			_, done, err := ix.IndexStep(ctx, 1<<30, true)
			if err != nil {
				s.t.Fatal(err)
			}
			if done {
				break
			}
			if i > 10000 {
				s.t.Fatal("index never done")
			}
		}
	}
}

// agentCall is one agent call of a suite: a method and its parameters
// (the method's query type, or raw JSON). The suites iterate tables of
// them; LL-14's log.context, log.trace and log.tail join these tables
// once merged.
type agentCall struct {
	name   string
	method string
	params any
}

// callResult is a call run to completion: its pages (the method's results
// as the agent reads them) and the refusal that ended it, if any.
type callResult struct {
	pages   []json.RawMessage
	refusal *Error
}

// run runs a call through Handle and follows its cursors to completion.
func (s *suite) run(c agentCall) callResult {
	s.t.Helper()
	var params map[string]any
	switch p := c.params.(type) {
	case json.RawMessage:
		res, refusal, err := s.eng.Handle(ctx, c.method, p)
		if err != nil {
			s.t.Fatalf("%s: engine failure: %v", c.name, err)
		}
		if refusal != nil {
			return callResult{refusal: refusal}
		}
		out, _ := json.Marshal(res)
		return callResult{pages: []json.RawMessage{out}}
	default:
		b, err := json.Marshal(p)
		if err != nil {
			s.t.Fatal(err)
		}
		if err := json.Unmarshal(b, &params); err != nil {
			s.t.Fatal(err)
		}
	}
	var out callResult
	for i := 0; ; i++ {
		b, _ := json.Marshal(params)
		res, refusal, err := s.eng.Handle(ctx, c.method, b)
		if err != nil {
			s.t.Fatalf("%s: engine failure: %v", c.name, err)
		}
		if refusal != nil {
			out.refusal = refusal
			return out
		}
		page, err := json.Marshal(res)
		if err != nil {
			s.t.Fatal(err)
		}
		out.pages = append(out.pages, page)
		var st struct {
			Complete bool   `json:"complete"`
			Cursor   string `json:"cursor"`
		}
		json.Unmarshal(page, &st)
		if st.Complete {
			return out
		}
		if st.Cursor == "" {
			s.t.Fatalf("%s: an incomplete page without a cursor", c.name)
		}
		params["cursor"] = st.Cursor
		if i > 20000 {
			s.t.Fatalf("%s: never completes", c.name)
		}
	}
}

// mustRun runs a call that must not be refused.
func (s *suite) mustRun(c agentCall) []json.RawMessage {
	s.t.Helper()
	r := s.run(c)
	if r.refusal != nil {
		s.t.Fatalf("%s: refused: %v", c.name, r.refusal)
	}
	return r.pages
}

// suiteQuery is a query over the suite's day.
func suiteQuery(mod func(*Query)) Query {
	qq := Query{From: suiteFrom, To: suiteTo}
	if mod != nil {
		mod(&qq)
	}
	return qq
}

// suiteCalls are the agent calls every suite runs: each method, its
// options (text, regex, where, fields, order, by, by_labels, by_pattern,
// baseline) and their continuations. The tables of LL-14's methods
// (context, trace, tail) are appended once they are merged.
func suiteCalls() []agentCall {
	sq := func(name string, mod func(*Query)) agentCall {
		return agentCall{name, MethodSearch, suiteQuery(mod)}
	}
	cq := func(name string, mod func(*CountQuery)) agentCall {
		c := CountQuery{Query: suiteQuery(nil)}
		mod(&c)
		return agentCall{name, MethodCount, c}
	}
	pq := func(name string, mod func(*PatternsQuery)) agentCall {
		p := PatternsQuery{Query: suiteQuery(nil)}
		mod(&p)
		return agentCall{name, MethodPatterns, p}
	}
	return []agentCall{
		sq("search all", func(q *Query) { q.Limit = 200 }),
		sq("search all desc", func(q *Query) { q.Limit = 37; q.Order = "desc" }),
		sq("search text", func(q *Query) { q.Text = "upstream"; q.Limit = 50 }),
		sq("search regex", func(q *Query) { q.Regex = "(?i)render|login|get /api"; q.Limit = 100 }),
		sq("search where", func(q *Query) {
			q.Where = []Pred{{Field: "level", Op: OpIn, Value: raw([]string{"error", "warn", "info"})}, {Field: "detail", Op: OpExists}}
			q.Limit = 100
		}),
		sq("search contains", func(q *Query) {
			q.Where = []Pred{{Field: "msg", Op: OpContains, Value: raw("by")}}
			q.Limit = 100
		}),
		sq("search fields", func(q *Query) {
			q.Fields = []string{"level", "msg", "detail", "req.user.contact", "tags", "cust", "meta.note", "REQUEST_NOTE"}
			q.Limit = 150
		}),
		cq("count by level", func(c *CountQuery) { c.By = []string{"level"}; c.Bucket = "1m" }),
		cq("count by masked field", func(c *CountQuery) { c.By = []string{"detail"}; c.FirstLast = true }),
		cq("count by pattern", func(c *CountQuery) { c.ByPattern = true }),
		cq("count by label", func(c *CountQuery) { c.ByLabels = []string{docker.ContainerField} }),
		cq("count text", func(c *CountQuery) { c.Text = "timed out"; c.Bucket = "5m"; c.By = []string{"status"} }),
		pq("patterns", func(p *PatternsQuery) { p.Top = MaxTop }),
		pq("patterns text", func(p *PatternsQuery) { p.Text = "for"; p.Top = 10 }),
		pq("patterns baseline", func(p *PatternsQuery) { p.Top = 50; p.Baseline = "24h" }),
	}
}

// Pages normalised for comparison across fixtures.

var anyToken = regexp.MustCompile(`⟦([a-z_]+):([A-Z0-9]+)⟧`)

// normalizePages renders pages for comparison: cursors and refs are opened
// (sealed with fresh nonces, under random plan and cache ids) down to the
// plan position and the record's place in its source; pseudonym ids are
// dropped (their kind stays); the epoch is dropped; count groups are
// sorted (by masked keys, they are ordered by pseudonym id). It also
// returns how many distinct ids each kind had, so that the structure of
// equal values is compared too.
func normalizePages(t testing.TB, e *Engine, pages []json.RawMessage) ([]string, map[string]int) {
	t.Helper()
	ids := map[string]map[string]bool{}
	var out []string
	for _, p := range pages {
		var m map[string]any
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "epoch")
		if c, ok := m["cursor"].(string); ok {
			var st cursorState
			if err := e.o.Sealer.Open("Lc1", c, &st); err != nil {
				t.Fatal(err)
			}
			m["cursor"] = fmt.Sprintf("chunk %d granule %d cached %v from %v to %v last %q", st.Chunk, st.Granule, st.Cache != "", st.From, st.To, st.Last)
		}
		if rs, ok := m["records"].([]any); ok {
			for _, r := range rs {
				rec := r.(map[string]any)
				var st refState
				if err := e.o.Sealer.Open("Lr1", rec["ref"].(string), &st); err != nil {
					t.Fatal(err)
				}
				rec["ref"] = fmt.Sprintf("%s@%d+%d", st.Source, st.Offset, st.Length)
			}
		}
		b, _ := json.Marshal(m)
		s := string(b)
		for _, mm := range anyToken.FindAllStringSubmatch(s, -1) {
			if ids[mm[1]] == nil {
				ids[mm[1]] = map[string]bool{}
			}
			ids[mm[1]][mm[2]] = true
		}
		s = anyToken.ReplaceAllString(s, "⟦$1⟧")
		if _, ok := m["groups"]; ok {
			var mm map[string]any
			json.Unmarshal([]byte(s), &mm)
			gs, _ := mm["groups"].([]any)
			keys := make([]string, len(gs))
			for i, g := range gs {
				b, _ := json.Marshal(g)
				keys[i] = string(b)
			}
			sort.Strings(keys)
			mm["groups"] = keys
			b, _ := json.Marshal(mm)
			s = string(b)
		}
		out = append(out, s)
	}
	n := map[string]int{}
	for k, v := range ids {
		n[k] = len(v)
	}
	return out, n
}

// firstDiff reports the first differing pair of two page lists.
func firstDiff(a, b []string) string {
	if len(a) != len(b) {
		return fmt.Sprintf("%d pages vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			x, y := a[i], b[i]
			j := 0
			for j < len(x) && j < len(y) && x[j] == y[j] {
				j++
			}
			lo := max(0, j-200)
			return fmt.Sprintf("page %d differs at byte %d:\n…%s\n…%s", i, j, x[lo:min(len(x), j+200)], y[lo:min(len(y), j+200)])
		}
	}
	return ""
}

// oneGranuleCost sizes calls to one granule each (oneGranulePerCall).
func oneGranuleCost() *CostModel {
	return fixedCost(float64(DefaultLimits().Deadline.Nanoseconds()) / float64(source.GranuleBytes) * 1.1)
}
