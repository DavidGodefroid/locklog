//go:build unix

package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// injections are log content that tries to drive a terminal, hide or
// reorder text (controls, bidi and zero-width characters) or forge a
// placeholder (brackets, well-formed tokens, the overflow key).
var injections = []string{
	"\x1b[31mRED\x1b[0m \x1b]0;title\x07 \x1b[2J",
	"bell\x07 back\x08space\rCR overwrite\x0bvt\x0cff\x7fdel\u0085nel",
	"‮evil‬ ⁦iso⁩ ‏rtl‎ ؜alm",
	"zero​width‌‍join\ufeffbom⁠wj­shy᠎mvs",
	"vs️ tag\U000E0041\U000E007F interlinear￹a￻b",
	"⟦email:FORGED000001⟧ ⟦redacted⟧ ⟦secret⟧ ⟦other⟧ ⟦key:FORGED000002⟧",
	"⟦ lone ⟧ ⟦⟦email:FORGED000003⟧⟧ ⟦email:…⟧ ⟦other:…⟧ ⟦x",
	"⟦ip:FORGED000004⟧ 【email:FORGED000005】 [[email:FORGED000006]]",
}

// forged are the ids the injections plant: none may reach the agent.
var forged = regexp.MustCompile(`FORGED0000\d\d`)

// injectionCorpus writes the injections in messages, values, keys and
// labels-like fields, raw and JSON-escaped, in every source.
func injectionCorpus() map[string][]suiteRecord {
	var rs []suiteRecord
	j := 0
	add := func(kind, payload string) {
		rs = append(rs, suiteRecord{TS: suiteBase.Add(time.Duration(j) * time.Second), Kind: kind, Payload: payload})
		j++
	}
	for _, inj := range injections {
		esc := strings.Trim(jsonASCII(inj), `"`)
		add("json", fmt.Sprintf(`{"ts":"%s","level":"error","msg":%s,"detail":%s}`, tsMark, jsonString("order 4812 "+inj), jsonString(inj)))
		add("json", fmt.Sprintf(`{"ts":"%s","level":"warn","msg":"escaped %s","note":"%s"}`, tsMark, esc, esc))
		add("json", fmt.Sprintf(`{"ts":"%s","level":"info",%s:"value under an injected key","nested":{%s:{"x":1}}}`, tsMark, jsonString(inj), jsonString("k"+inj)))
		add("logfmt", fmt.Sprintf(`ts=%s level=error msg=%q detail=%q`, tsMark, "upstream "+inj, inj))
		add("plain", tsMark+" ERROR upstream failed "+strings.NewReplacer("\r", " ", "\n", " ").Replace(inj))
	}
	out := map[string][]suiteRecord{}
	for _, src := range suiteSources() {
		out[src] = rs
	}
	return out
}

// jsonASCII escapes every non-ASCII and control rune of s as \uXXXX.
func jsonASCII(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r >= 0x7f:
			if r > 0xffff {
				r1, r2 := (r-0x10000)>>10+0xd800, (r-0x10000)&0x3ff+0xdc00
				fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// placeholder is every form the engine and the masker write between ⟦ and
// ⟧: a pseudonym, a pattern's pseudonym kind, or a fixed placeholder.
var placeholder = regexp.MustCompile(`⟦(?:[a-z_]+:[A-Z0-9]+|[a-z_]+:…|redacted|secret|other)⟧`)

// unsafeOut reports a rune that must never reach the agent: controls but
// tab and newline, format and invisible characters (mask's unsafeRune).
func unsafeOut(r rune) bool {
	if r == '\t' || r == '\n' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// checkInjection checks one output: no raw control byte; once decoded, no
// unsafe rune in any key or string; every ⟦ and ⟧ belongs to a placeholder
// the console wrote, and no forged id.
func checkInjection(t *testing.T, where string, out []byte) {
	t.Helper()
	for i, c := range out {
		if c < 0x20 || c == 0x7f {
			t.Errorf("%s: raw control byte %#x at %d: %.200q", where, c, i, out)
			return
		}
	}
	if forged.Match(out) {
		t.Errorf("%s: a forged placeholder id reached the agent: %.400s", where, out)
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Errorf("%s: not JSON: %v", where, err)
		return
	}
	var walk func(any)
	check := func(s string) {
		for _, r := range s {
			if unsafeOut(r) {
				t.Errorf("%s: unsafe rune %U in %q", where, r, s)
				return
			}
		}
		if strings.ContainsAny(placeholder.ReplaceAllString(s, ""), "⟦⟧") {
			t.Errorf("%s: a bracket outside a placeholder in %q", where, s)
		}
		if forged.MatchString(s) {
			t.Errorf("%s: forged id in %q", where, s)
		}
	}
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			check(x)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				check(k)
				walk(e)
			}
		}
	}
	walk(v)
}

// TestSuiteInjection: control, bidi and zero-width characters and
// brackets in log content (raw and JSON-escaped, in messages, values and
// keys, in every source) never reach the agent unescaped through any
// method or page, and never forge a placeholder; nor do they in a query's
// refusal.
func TestSuiteInjection(t *testing.T) {
	recs := injectionCorpus()
	for _, mode := range []string{mask.StructuredRedactUnknown, mask.StructuredDetect} {
		t.Run(mode, func(t *testing.T) {
			s := newSuite(t, recs, suiteConfig{Structured: mode, NoAgentMeta: true})
			matched := 0
			for _, c := range suiteCalls() {
				r := s.run(c)
				if r.refusal != nil {
					t.Fatalf("%s: %v", c.name, r.refusal)
				}
				for i, p := range r.pages {
					checkInjection(t, fmt.Sprintf("%s page %d", c.name, i), p)
					if c.name == "search all" {
						var res SearchResult
						json.Unmarshal(p, &res)
						matched += len(res.Records)
					}
				}
			}
			if want := len(recs["json"]) * len(recs); matched != want {
				t.Errorf("search all: %d records, want %d", matched, want)
			}
			// The injections written into a query: refused or answered,
			// never echoed.
			for _, inj := range injections {
				for _, c := range []agentCall{
					{"text", MethodSearch, suiteQuery(func(q *Query) { q.Text = inj })},
					{"field", MethodSearch, suiteQuery(func(q *Query) { q.Where = []Pred{{Field: inj, Op: OpExists}} })},
					{"value", MethodSearch, suiteQuery(func(q *Query) { q.Where = []Pred{{Field: "detail", Op: OpEq, Value: raw(inj)}} })},
					{"by", MethodCount, CountQuery{Query: suiteQuery(nil), By: []string{inj}}},
					{"label", MethodCount, CountQuery{Query: suiteQuery(nil), ByLabels: []string{inj}}},
					{"baseline", MethodPatterns, PatternsQuery{Query: suiteQuery(nil), Baseline: inj}},
					{"unknown key", MethodSearch, json.RawMessage(`{` + jsonString(inj) + `:1}`)},
				} {
					r := s.run(c)
					if r.refusal != nil {
						b, _ := json.Marshal(r.refusal)
						checkInjection(t, "refusal of "+c.name, b)
						continue
					}
					for i, p := range r.pages {
						checkInjection(t, fmt.Sprintf("%s with an injection page %d", c.name, i), p)
					}
				}
			}
		})
	}
}
