//go:build unix

package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
)

// leakPerSource is the number of corpus records per source: every source
// sees every (kind, encoding, position) of the corpus (847 of them), and
// the nine sources hold more than 10 000 events.
const leakPerSource = 1200

// leakCorpus deals a seeded masktest corpus out to the fixture's sources.
func leakCorpus(seed uint64) map[string][]suiteRecord {
	srcs := suiteSources()
	lines := masktest.New(seed).Lines(len(srcs) * leakPerSource)
	out := map[string][]suiteRecord{}
	for i, l := range lines {
		name := srcs[i%len(srcs)]
		j := len(out[name])
		ts := fmt.Sprintf("2026-10-30T14:%02d:%02d.%03dZ", (i/60)%60, i%60, i%1000)
		out[name] = append(out[name], suiteRecord{TS: suiteBase.Add(time.Duration(j) * time.Second), Kind: l.Format,
			Payload: strings.ReplaceAll(l.Text, ts, tsMark), Canaries: l.Canaries})
	}
	return out
}

// leakScanner scans what the agent reads for every form of every canary
// (masktest.Scan: raw, lower case, percent- and JSON-escaped, decoded). A
// record is scanned for the canaries of the corpus record it comes from
// (found by its source and time); everything else (counts, patterns,
// refusals, the rest of a page) for every canary of the corpus.
type leakScanner struct {
	t      *testing.T
	bySec  map[string]map[int64][]masktest.Canary
	bySrc  map[string][]masktest.Canary
	grams  map[string][]int // lower-cased form prefix -> forms
	short  []int            // forms shorter than gramLen
	forms  []leakForm
	words  map[string]*regexp.Regexp
	hits   []masktest.Hit
	pages  int
	nrecs  int
	nglobs int
}

type leakForm struct {
	c    masktest.Canary
	form string // lower case
}

const gramLen = 6

func newLeakScanner(t *testing.T, recs map[string][]suiteRecord) *leakScanner {
	l := &leakScanner{t: t, bySec: map[string]map[int64][]masktest.Canary{}, bySrc: map[string][]masktest.Canary{},
		grams: map[string][]int{}, words: map[string]*regexp.Regexp{}}
	seen := map[string]bool{}
	for src, rs := range recs {
		l.bySec[src] = map[int64][]masktest.Canary{}
		for _, r := range rs {
			l.bySec[src][r.TS.Unix()] = append(l.bySec[src][r.TS.Unix()], r.Canaries...)
			l.bySrc[src] = append(l.bySrc[src], r.Canaries...)
			for _, c := range r.Canaries {
				for _, f := range masktest.Forms(c) {
					f = strings.ToLower(f)
					if f == "" || seen[f] {
						continue
					}
					seen[f] = true
					l.forms = append(l.forms, leakForm{c, f})
					if len(f) < gramLen {
						l.short = append(l.short, len(l.forms)-1)
					} else {
						l.grams[f[:gramLen]] = append(l.grams[f[:gramLen]], len(l.forms)-1)
					}
				}
				for _, w := range masktest.WordForms(c) {
					if l.words[w] == nil {
						l.words[w] = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])` + regexp.QuoteMeta(w) + `(?:$|[^\p{L}\p{N}_])`)
					}
				}
			}
		}
	}
	return l
}

// views are the texts a canary is looked for in, as masktest.Scan reads
// them: raw, decoded twice, without replacement characters; lower case.
func views(s string) []string {
	texts := []string{s}
	for _, v := range pii.DetectionViews(s) {
		for _, w := range pii.DetectionViews(v.Text) {
			texts = append(texts, w.Text, strings.ReplaceAll(w.Text, "�", ""))
		}
	}
	for i := range texts {
		texts[i] = strings.ToLower(texts[i])
	}
	return texts
}

// Sealed values (a page's cursor, a record's ref) are AEAD ciphertext and
// well-formed pseudonyms are ids: neither is log content, and over
// thousands of pages their random letters would match the 6- to
// 8-character canary forms (digit runs, secret heads) by chance. The
// whole-corpus scan blanks exactly those (the page's top-level "cursor",
// each record's top-level "ref", and well-formed pseudonyms); a record is
// also scanned whole with its own canaries (masktest.Scan).
var (
	wellFormed  = regexp.MustCompile(`⟦[a-z_]+:[A-Z0-9]+⟧`)
	recordTSKey = []byte(`"ts":"`)
)

// blankKey returns obj (a JSON object) with its top-level key blanked.
func blankKey(t testing.TB, obj []byte, key string) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		t.Fatalf("not a JSON object: %v", err)
	}
	if _, ok := m[key]; !ok {
		return obj
	}
	m[key] = json.RawMessage(`""`)
	b, _ := json.Marshal(m)
	return b
}

// global scans text for every canary of the corpus.
func (l *leakScanner) global(where string, out []byte) {
	l.nglobs++
	s := wellFormed.ReplaceAllString(string(out), "⟦x⟧")
	vs := views(s)
	found := map[int]bool{}
	hit := func(fi int) {
		if !found[fi] {
			found[fi] = true
			l.hits = append(l.hits, masktest.Hit{Canary: l.forms[fi].c, Form: l.forms[fi].form, Where: where})
		}
	}
	for _, v := range vs {
		for i := 0; i+gramLen <= len(v); i++ {
			for _, fi := range l.grams[v[i:i+gramLen]] {
				if strings.HasPrefix(v[i:], l.forms[fi].form) {
					hit(fi)
				}
			}
		}
		for _, fi := range l.short {
			if strings.Contains(v, l.forms[fi].form) {
				hit(fi)
			}
		}
	}
	for w, re := range l.words {
		for _, v := range vs {
			if re.MatchString(v) {
				l.hits = append(l.hits, masktest.Hit{Canary: masktest.Canary{Kind: "person_name", Value: w}, Form: w, Where: where})
				break
			}
		}
	}
}

// page scans one page: each record with its own canaries and against the
// corpus, the rest against the corpus.
func (l *leakScanner) page(where string, page []byte) {
	l.pages++
	var m map[string]json.RawMessage
	if err := json.Unmarshal(page, &m); err != nil {
		l.t.Fatalf("%s: page is not a JSON object: %v", where, err)
	}
	if _, ok := m["cursor"]; ok {
		m["cursor"] = json.RawMessage(`""`)
	}
	if rs, ok := m["records"]; ok {
		var recs []json.RawMessage
		json.Unmarshal(rs, &recs)
		for _, r := range recs {
			l.record(where, r)
		}
		delete(m, "records")
	}
	page, _ = json.Marshal(m)
	l.global(where, page)
}

func (l *leakScanner) record(where string, rec []byte) {
	l.nrecs++
	var head struct {
		Source string `json:"source"`
		TS     string `json:"ts"`
	}
	json.Unmarshal(rec, &head)
	cs := l.bySrc[head.Source]
	if t, err := time.Parse(time.RFC3339Nano, head.TS); err == nil && bytes.Contains(rec, recordTSKey) {
		if own, ok := l.bySec[head.Source][t.Unix()]; ok {
			cs = own
		}
	}
	if head.Source == "" || len(cs) == 0 {
		l.t.Errorf("%s: a record of no known source: %.200s", where, rec)
		return
	}
	l.hits = append(l.hits, masktest.Scan(where, rec, cs)...)
	l.global(where+" (record)", blankKey(l.t, rec, "ref"))
}

// refusal scans a refusal for the canaries the call carried, and the
// corpus.
func (l *leakScanner) refusal(where string, e *Error, cs []masktest.Canary) {
	b, _ := json.Marshal(e)
	l.hits = append(l.hits, masktest.Scan(where, b, cs)...)
	l.global(where, b)
	l.hits = append(l.hits, masktest.Scan(where+" (text)", []byte(e.Error()), cs)...)
}

func (l *leakScanner) report(label string) {
	l.t.Helper()
	for i, h := range l.hits {
		if i >= 20 {
			break
		}
		l.t.Errorf("%s: %s %q leaked as %q in %s", label, h.Canary.Kind, h.Canary.Value, h.Form, h.Where)
	}
	if len(l.hits) > 0 {
		l.t.Fatalf("%s: %d leaks", label, len(l.hits))
	}
}

// TestLeakScannerFires is the scanner's positive control: every canary of
// the corpus's first records (every kind in every encoding and position)
// is found in its raw line by the whole-corpus scan, in another source's
// record (a record carrying a canary not its own), and under a nested
// "cursor" or "ref" key; a page's top-level cursor and a record's ref are
// the only values blanked.
func TestLeakScannerFires(t *testing.T) {
	recs := leakCorpus(16)
	l := newLeakScanner(t, recs)
	per := len(masktest.Kinds) * len(masktest.Encodings)
	missed := 0
	for i, r := range recs["json"][:2*per] {
		for _, c := range r.Canaries {
			found := func(where string, out []byte) bool {
				l.hits = nil
				l.global(where, out)
				for _, h := range l.hits {
					if h.Canary.Value == c.Value || h.Canary.Kind == "person_name" && c.Kind == "person_name" {
						return true
					}
				}
				return false
			}
			raw := r.payload(false)
			if !found("raw", []byte(raw)) {
				missed++
				t.Errorf("record %d: %s %q not found in its raw line %.200q", i, c.Kind, c.Value, raw)
				continue
			}
			// The line as another record's text, under nested
			// "cursor" and "ref" keys, and in a page.
			other := recs["logfmt"][(i+1)%len(recs["logfmt"])]
			rec, _ := json.Marshal(map[string]any{"source": "logfmt", "ts": other.TS.Format(time.RFC3339Nano), "ref": "x",
				"msg": raw, "fields": map[string]any{"cursor": raw, "ref": raw}})
			l.hits = nil
			l.record("cross-record", rec)
			if len(l.hits) == 0 {
				t.Errorf("record %d: %s %q in another record's message not found", i, c.Kind, c.Value)
			}
			nested, _ := json.Marshal(map[string]any{"cursor": "", "groups": []any{map[string]any{"cursor": raw}}})
			if !found("nested cursor", nested) {
				t.Errorf("record %d: %s %q under a nested cursor key not found", i, c.Kind, c.Value)
			}
		}
	}
	if missed > 0 {
		t.Fatalf("%d canaries the scanner cannot see", missed)
	}
	// Blanked from the whole-corpus scan: a page's cursor and a record's
	// ref (a record is still scanned whole for its own canaries).
	c := recs["json"][0].Canaries[0]
	l.hits = nil
	l.page("blanked", []byte(`{"cursor":`+jsonString(c.Value)+`,"complete":false}`))
	l.global("blanked ref", blankKey(t, []byte(`{"source":"json","ref":`+jsonString(c.Value)+`}`), "ref"))
	if len(l.hits) != 0 {
		t.Errorf("a blanked value was scanned: %+v", l.hits)
	}
}

// TestSuiteLeak: a seeded corpus with canaries of every detector kind in
// every position and encoding, in every file format, journald and docker;
// every agent method and option, every continuation page and every
// refusal is scanned: no form of any canary reaches the agent.
func TestSuiteLeak(t *testing.T) {
	heavySuite(t)
	recs := leakCorpus(16)
	total := 0
	for _, rs := range recs {
		total += len(rs)
	}
	if total < 10_000 {
		t.Fatalf("%d events", total)
	}
	for _, mode := range []string{mask.StructuredRedactUnknown, mask.StructuredDetect} {
		t.Run(mode, func(t *testing.T) {
			// Calls of one granule each: every source's plan is
			// continued through cursors.
			s := newSuite(t, recs, suiteConfig{Structured: mode, Workers: 2, Cost: oneGranuleCost()})
			l := newLeakScanner(t, recs)
			matched := 0
			for _, c := range suiteCalls() {
				start := time.Now()
				r := s.run(c)
				t.Logf("%s: %d pages in %v", c.name, len(r.pages), time.Since(start))
				if r.refusal != nil {
					l.refusal(c.name, r.refusal, nil)
					t.Errorf("%s: refused: %v", c.name, r.refusal)
					continue
				}
				if len(r.pages) < 2 && c.method == MethodSearch {
					t.Errorf("%s: %d pages: the call was not continued", c.name, len(r.pages))
				}
				start = time.Now()
				for i, p := range r.pages {
					l.page(fmt.Sprintf("%s page %d", c.name, i), p)
				}
				t.Logf("%s: scanned in %v", c.name, time.Since(start))
				if c.name == "search all" {
					matched = l.nrecs
				}
			}
			if matched != total {
				t.Errorf("search all returned %d records, want %d", matched, total)
			}
			start := time.Now()
			leakRefusals(t, s, mode, l, recs)
			t.Logf("refusals in %v", time.Since(start))
			l.report(mode)
			t.Logf("%s: %d pages, %d records, %d whole-corpus scans", mode, l.pages, l.nrecs, l.nglobs)
		})
	}
}

// leakRefusals runs calls carrying canaries (in every encoding) where the
// agent may write anything: text, regex, values, field paths, labels,
// sources, cursors, the baseline, unknown keys and mistyped values of the
// raw parameters. Refusals and answers alike hold none of them. The
// thousands of calls run on a fixture of the corpus's first records of
// each source (every kind and encoding is still in the data); the
// over-budget refusal runs on the whole fixture.
func leakRefusals(t *testing.T, whole *suite, mode string, l *leakScanner, recs map[string][]suiteRecord) {
	per := len(masktest.Kinds) * len(masktest.Encodings)
	head := map[string][]suiteRecord{}
	for src, rs := range recs {
		head[src] = rs[:min(len(rs), 2*per)]
	}
	s := newSuite(t, head, suiteConfig{Structured: mode, Workers: 2})
	var sample []masktest.Canary
	var encoded []string
	// Per pull request, a subset: every kind raw, and every kind and
	// every encoding at least once; LOCKLOG_SUITE_FULL=1 (the CI suites
	// job) writes every kind in every encoding.
	full := os.Getenv("LOCKLOG_SUITE_FULL") == "1"
	seen := map[string]bool{}
	keep := func(keys ...string) bool {
		if full {
			return true
		}
		fresh := false
		for _, k := range keys {
			if !seen[k] {
				seen[k], fresh = true, true
			}
		}
		return fresh
	}
	for _, r := range recs["json"][:per] {
		c := r.Canaries[0]
		if !keep("raw " + c.Kind) {
			continue
		}
		sample = append(sample, c)
		encoded = append(encoded, c.Value)
	}
	lines := masktest.New(99).Lines(per)
	for _, ln := range lines {
		c, enc := ln.Canaries[0], masktest.Encodings[ln.Encoding]
		if !keep("kind "+c.Kind, "encoding "+enc) {
			continue
		}
		sample = append(sample, c)
		encoded = append(encoded, masktest.Encode(c.Value, enc))
	}
	t.Logf("%d canaries written into the calls (full %v)", len(encoded), full)
	from, _ := json.Marshal(suiteFrom)
	to, _ := json.Marshal(suiteTo)
	refused := 0
	for i, w := range encoded {
		c := []masktest.Canary{sample[i]}
		sq := func(mod func(*Query)) Query { return suiteQuery(mod) }
		calls := []agentCall{
			{"text", MethodSearch, sq(func(q *Query) { q.Text = w })},
			{"regex", MethodSearch, sq(func(q *Query) { q.Regex = regexp.QuoteMeta(w) })},
			{"value", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: "detail", Op: OpEq, Value: raw(w)}} })},
			{"in", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: "level", Op: OpIn, Value: raw([]string{"error", w})}} })},
			{"contains", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: "msg", Op: OpContains, Value: raw(w)}} })},
			{"matches", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: "msg", Op: OpMatches, Value: raw(regexp.QuoteMeta(w))}} })},
			{"field", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: w, Op: OpExists}} })},
			{"nested field", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Field: "req." + w + ".x", Op: OpExists}} })},
			{"label", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Label: w, Op: OpEq, Value: raw("x")}} })},
			{"label value", MethodSearch, sq(func(q *Query) { q.Where = []Pred{{Label: "container", Op: OpEq, Value: raw(w)}} })},
			{"projection", MethodSearch, sq(func(q *Query) { q.Fields = []string{w}; q.Limit = 1 })},
			{"source", MethodSearch, sq(func(q *Query) { q.Sources = []string{w} })},
			{"cursor", MethodSearch, sq(func(q *Query) { q.Cursor = w })},
			{"last", MethodSearch, Query{Last: w}},
			{"order", MethodSearch, sq(func(q *Query) { q.Order = w })},
			{"count by", MethodCount, CountQuery{Query: suiteQuery(nil), By: []string{w}}},
			{"count by label", MethodCount, CountQuery{Query: suiteQuery(nil), ByLabels: []string{w}}},
			{"count bucket", MethodCount, CountQuery{Query: suiteQuery(nil), Bucket: w}},
			{"count text", MethodCount, CountQuery{Query: suiteQuery(func(q *Query) { q.Text = w })}},
			{"patterns baseline", MethodPatterns, PatternsQuery{Query: suiteQuery(nil), Baseline: w}},
			{"patterns text", MethodPatterns, PatternsQuery{Query: suiteQuery(func(q *Query) { q.Text = w })}},
			{"unknown key", MethodSearch, json.RawMessage(`{"from":` + string(from) + `,"to":` + string(to) + `,` + jsonString(w) + `:1}`)},
			{"mistyped value", MethodSearch, json.RawMessage(`{"from":` + jsonString(w) + `}`)},
			{"mistyped nested", MethodCount, json.RawMessage(`{"from":` + string(from) + `,"to":` + string(to) + `,"where":[{"field":"x","op":"=","value":1,` + jsonString(w) + `:[1]}]}`)},
			{"malformed", MethodPatterns, json.RawMessage(`{"text":` + jsonString(w) + `,`)},
			{"method", w, json.RawMessage(`{}`)},
		}
		for _, call := range calls {
			where := fmt.Sprintf("%s with %s %q", call.name, sample[i].Kind, w)
			// An answer's first page (its data's every page is scanned
			// by the main pass).
			r := s.runPages(call, 1)
			if r.refusal != nil {
				refused++
				l.refusal(where, r.refusal, c)
				continue
			}
			for j, p := range r.pages {
				l.hits = append(l.hits, masktest.Scan(fmt.Sprintf("%s page %d", where, j), p, c)...)
				l.page(fmt.Sprintf("%s page %d", where, j), p)
			}
		}
	}
	if refused < len(encoded)*10 {
		t.Errorf("only %d calls refused: the refusal paths are not exercised", refused)
	}
	// Over budget, with its estimate.
	small := *whole
	o := whole.eng.o
	o.Limits.LocalBytes = 1 << 10
	small.eng, _ = New(o)
	r := small.run(agentCall{"over budget", MethodSearch, suiteQuery(func(q *Query) { q.Text = "upstream" })})
	if r.refusal == nil || r.refusal.Code != EOverBudget || r.refusal.Estimate == nil {
		t.Fatalf("over budget: %+v", r)
	}
	l.refusal("over budget", r.refusal, nil)
}

// TestSuiteAgentRuleNamesNothing is the round-6 leak case: an agent rule
// naming a field shown masked (by its pseudonym) and one naming a clear
// field, added from what the engine showed, never put a name, nor any name
// shown masked, in the project's .locklog/pii.toml or in clear in the PII
// directory, which holds keyed digests only (0700, files 0600); the rules
// apply to what the engine shows next.
func TestSuiteAgentRuleNamesNothing(t *testing.T) {
	maskedName := "jean.secretname@example.com"
	var rs []suiteRecord
	for i := range 300 {
		rs = append(rs, suiteRecord{TS: suiteBase.Add(time.Duration(i) * time.Second), Kind: "json",
			Payload: fmt.Sprintf(`{"ts":"%s","level":"error","order":"%d","client":"acme","%s":"Lyon","msg":"payment failed"}`, tsMark, 4800+i%20, maskedName)})
	}
	for _, mode := range []string{mask.StructuredDetect, mask.StructuredRedactUnknown} {
		t.Run(mode, func(t *testing.T) {
			s := newSuite(t, map[string][]suiteRecord{"json": rs, srcDocker: rs},
				suiteConfig{Structured: mode, Rules: "[[mask]]\nfield = \"client\"\n", NoAgentMeta: true})
			before, _ := os.ReadFile(s.project)
			pages := s.mustRun(agentCall{"search", MethodSearch, suiteQuery(func(q *Query) { q.Limit = 5 })})
			var res SearchResult
			json.Unmarshal(pages[0], &res)
			var shown string
			for _, r := range res.Records {
				var rec struct {
					Fields map[string]json.RawMessage `json:"fields"`
				}
				json.Unmarshal(r, &rec)
				for k := range rec.Fields {
					if strings.HasPrefix(k, mask.Open+mask.KeyKind+":") {
						shown = k
					}
				}
				if strings.Contains(string(r), "secretname") || strings.Contains(string(r), "Lyon") && mode == mask.StructuredRedactUnknown {
					t.Fatalf("shown: %s", r)
				}
			}
			if shown == "" {
				t.Fatalf("no masked name shown: %s", pages[0])
			}
			lim := mask.AgentLimits{PerHour: 10, Total: 50}
			for _, src := range []string{"json", srcDocker} {
				// The clear masked name is refused, as is a glob.
				if err := s.masker.AgentAdd(src, maskedName, mask.ModeRedact, suiteBase, lim); !errors.Is(err, mask.ErrPIIInQuery) {
					t.Errorf("%s: a rule by the clear masked name: %v", src, err)
				}
				if err := s.masker.AgentAdd(src, shown, mask.ModeRedact, suiteBase, lim); err != nil {
					t.Fatalf("%s: rule by pseudonym: %v", src, err)
				}
				if mode == mask.StructuredDetect {
					if err := s.masker.AgentAdd(src, "order", mask.ModePseudonym, suiteBase, lim); err != nil {
						t.Fatalf("%s: rule on a clear field: %v", src, err)
					}
				}
			}
			after, _ := os.ReadFile(s.project)
			if !bytes.Equal(before, after) {
				t.Errorf("the project's pii.toml changed:\n%s", after)
			}
			names := []string{maskedName, "jean", "secretname", "example.com", "order", "client", "Lyon", "4812",
				strings.TrimSuffix(strings.TrimPrefix(shown, mask.Open+mask.KeyKind+":"), mask.Close)}
			fi, err := os.Stat(s.piiDir)
			if err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("PII directory: %v %v", fi.Mode(), err)
			}
			nfiles := 0
			filepath.Walk(s.piiDir, func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return err
				}
				nfiles++
				b, _ := os.ReadFile(p)
				for _, n := range names {
					if bytes.Contains(bytes.ToLower(b), bytes.ToLower([]byte(n))) {
						t.Errorf("%s holds %q", filepath.Base(p), n)
					}
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("%s mode %04o", filepath.Base(p), fi.Mode().Perm())
				}
				if filepath.Base(p) == "agent-rules.json" {
					var es []map[string]any
					if err := json.Unmarshal(b, &es); err != nil {
						t.Fatal(err)
					}
					for _, e := range es {
						d, _ := e["digest"].(string)
						if _, err := hex.DecodeString(d); err != nil || len(d) != 64 || len(e) != 3 {
							t.Errorf("agent rule entry %v: not a keyed digest", e)
						}
					}
				}
				return nil
			})
			if nfiles != 2 {
				t.Errorf("%d files in the PII directory", nfiles)
			}
			// The rules apply to what the engine shows next.
			pages = s.mustRun(agentCall{"search", MethodSearch, suiteQuery(func(q *Query) { q.Limit = 200 })})
			for _, p := range pages {
				if strings.Contains(string(p), "Lyon") || strings.Contains(string(p), "secretname") {
					t.Fatalf("after the rule: %.400s", p)
				}
				if mode == mask.StructuredDetect && regexp.MustCompile(`"order":"48`).Match(p) {
					t.Fatalf("order shown after its rule: %.400s", p)
				}
			}
			// The rules persist as digests: the PII directory reopens
			// with every rule (their names are not stored to read back).
			ag, err := mask.OpenAgentRules(s.piiDir)
			if err != nil || ag.Len() != map[string]int{mask.StructuredDetect: 4, mask.StructuredRedactUnknown: 2}[mode] {
				t.Fatalf("reopened: %v %v", ag.Len(), err)
			}
		})
	}
}
