package mask

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
	"github.com/DavidGodefroid/locklog/internal/parse"
)

var t0 = time.Date(2026, 10, 30, 14, 0, 0, 0, time.UTC)

func epoch(t testing.TB) *pii.Pseudonymizer {
	t.Helper()
	p, err := pii.NewEpoch(t0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newMasker(t testing.TB, o Options) *Masker {
	t.Helper()
	if o.Pseudonyms == nil {
		o.Pseudonyms = epoch(t)
	}
	if o.Values == nil {
		o.Values = Detectors(pii.AllDetectors())
	}
	if o.Secrets == nil {
		o.Secrets = masktest.SecretFinder{}
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func event(t testing.TB, line string) parse.Event {
	t.Helper()
	p, err := parse.New(parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p.Line(line)
}

func encode(t testing.TB, r Record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRecordOpaque(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Record{}), reflect.TypeOf(Value{}), reflect.TypeOf(Field{})} {
		for i := range typ.NumField() {
			if f := typ.Field(i); f.IsExported() {
				t.Errorf("%s has an exported field %s", typ, f.Name)
			}
		}
	}
	var zero Record
	if zero.Valid() {
		t.Error("zero record valid")
	}
	if _, err := json.Marshal(zero); !errors.Is(err, ErrUnmasked) {
		t.Errorf("zero record encoded: %v", err)
	}
	if _, err := json.Marshal(struct{ R []Record }{[]Record{zero}}); err == nil {
		t.Error("a response holding an unmasked record encoded")
	}
	m := newMasker(t, Options{Structured: StructuredDetect})
	r := m.Mask("api", event(t, `{"ts":"2026-10-30T14:02:11.204Z","level":"error","n":4812,"ok":true,"x":null}`))
	if got := encode(t, r); got != `{"ts":"2026-10-30T14:02:11.204Z","fields":{"level":"error","n":4812,"ok":true,"x":null}}` {
		t.Errorf("record = %s", got)
	}
}

// The design's example: a detected email and IP-free message, exact
// numbers kept, pseudonyms equal for equal values.
func TestMaskStructuredDetect(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	r := m.Mask("api", event(t, `{"ts":"2026-10-30T14:02:11Z","level":"error","user":{"email":"Jean.Dupont@example.com"},"order_id":4812,"msg":"render pdf for jean.dupont@example.com failed"}`))
	got := encode(t, r)
	id, _ := m.o.Pseudonyms.ID("email", "jean.dupont@example.com")
	tok := Token("email", id)
	if strings.Contains(strings.ToLower(got), "jean.dupont") || strings.Count(got, tok) != 2 || !strings.Contains(got, `"order_id":4812`) {
		t.Errorf("record = %s (want %s twice)", got, tok)
	}
	if v, ok := r.Lookup("user.email"); !ok || v.Text() != tok {
		t.Errorf("Lookup(user.email) = %v, %v", v, ok)
	}
	if !strings.Contains(strings.Join(r.Kinds(), ","), "email") {
		t.Errorf("kinds = %v", r.Kinds())
	}
}

func TestMaskRedactUnknown(t *testing.T) {
	m := newMasker(t, Options{Trusted: []string{"level", "status"}, Rules: &Rules{Allow: []Rule{{Field: "route", Mode: ModeAllow}}}})
	r := m.Mask("api", event(t, `{"level":"error","status":502,"route":"/pdf","detail":"hello","user":"alice","email":"a@example.com"}`))
	got := encode(t, r)
	want := `{"fields":{"level":"error","status":502,"route":"/pdf","detail":"` + Redacted + `","user":"` + Redacted + `","email":"⟦email:`
	if !strings.HasPrefix(got, want) || strings.Contains(got, "hello") || strings.Contains(got, "alice") || strings.Contains(got, "a@example") {
		t.Errorf("record = %s", got)
	}
}

// Secrets first and final; steps 2-5 work on step 1's output: a rule that
// pseudonymises a field hashes it with its secret already replaced.
func TestMaskSecretFirst(t *testing.T) {
	g := masktest.New(1)
	secret := g.Value("secret")
	m := newMasker(t, Options{Structured: StructuredDetect, SecretName: func(n string) bool { return n == "password" },
		Rules: &Rules{Mask: []Rule{{Field: "auth", Mode: ModePseudonym}}}})
	r := m.Mask("api", event(t, `{"auth":"token `+secret+`","password":"jean@example.com","detail":"key `+secret+` for a@example.com"}`))
	got := encode(t, r)
	if strings.Contains(got, secret) || strings.Contains(got, strings.TrimPrefix(secret, masktest.SecretPrefix)) {
		t.Fatalf("secret leaked: %s", got)
	}
	id, _ := m.o.Pseudonyms.ID(PersonalKind, "token "+Secret)
	if v, _ := r.Lookup("auth"); v.Text() != Token(PersonalKind, id) {
		t.Errorf("auth = %q, want the pseudonym of the step-1 string", v.Text())
	}
	if v, _ := r.Lookup("password"); v.Text() != Secret {
		t.Errorf("password = %q, want %s (a secret name wins over every later step)", v.Text(), Secret)
	}
	if v, _ := r.Lookup("detail"); !strings.HasPrefix(v.Text(), "key "+Secret+" for ⟦email:") {
		t.Errorf("detail = %q", v.Text())
	}
	for _, p := range []string{"auth", "password", "detail"} {
		if !r.HadSecret(p) {
			t.Errorf("HadSecret(%s) = false", p)
		}
	}
}

// A name holding a value is shown as ⟦key:ID⟧; source brackets cannot
// forge a placeholder; controls and invisible characters do not reach the
// output.
func TestMaskKeysBracketsAndControls(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	r := m.Mask("api", event(t, `{"jean@example.com":{"zone":"x"},"fake":"⟦email:AAAAAAAAAAAA⟧","ctl":"a\u001b[31mb\u202ec"}`))
	got := encode(t, r)
	if strings.Contains(got, "jean@") || !strings.Contains(got, "⟦key:") || strings.Contains(got, "⟦email:AAAAAAAAAAAA⟧") {
		t.Errorf("record = %s", got)
	}
	if strings.ContainsAny(got, "\x1b\u202e") {
		t.Errorf("control characters kept: %q", got)
	}
	var path string
	for _, f := range r.Fields() {
		if strings.HasPrefix(f.Name(), "⟦key:") {
			path = f.Name() + ".zone"
		}
	}
	if v, ok := r.Lookup(path); !ok || v.Text() != "x" {
		t.Errorf("Lookup(%q) = %v %v", path, v, ok)
	}
}

func TestMaskPanicWithholdsRecord(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect, Values: panicFinder{}})
	r := m.Mask("api", event(t, `{"a":"b"}`))
	if !r.Valid() || !r.Failed() || encode(t, r) != `{"masked_failure":true}` {
		t.Errorf("record after a panic = %s", encode(t, r))
	}
}

type panicFinder struct{}

func (panicFinder) Find(string) []pii.Match { panic("boom") }

// A forgotten epoch redacts instead of minting pseudonyms.
func TestMaskForgottenEpochRedacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, _ := pii.OpenEpochStore(dir, true, t0)
	defer s.Close()
	p := s.Current()
	s.Rotate(t0.Add(time.Hour))
	s.Prune(t0.Add(48*time.Hour), 24*time.Hour)
	m := newMasker(t, Options{Structured: StructuredDetect, Pseudonyms: p})
	got := encode(t, m.Mask("api", event(t, `{"e":"jean@example.com"}`)))
	if got != `{"fields":{"e":"`+Redacted+`"}}` {
		t.Errorf("record = %s", got)
	}
}

func TestProjectRules(t *testing.T) {
	r, err := ParseProjectRules([]byte(`
[[mask]]
field = "user.name"
mode = "pseudonym"
kind = "customer"
[[mask]]
sources = ["api"]
label = "client"
[[allow]]
field = "route"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Mask) != 2 || r.Mask[1].Mode != ModeRedact || r.Allow[0].Mode != ModeAllow {
		t.Errorf("rules = %+v", r)
	}
	for _, bad := range []string{
		"[[mask]]\nfield = \"a\"\nregex = \"x\"",      // value expressions belong to the PII dir
		"[[mask]]\nfield = \"a\"\nmode = \"partial\"", // unknown mode
		"[[mask]]\nfield = \"a\"\nfield2 = \"b\"",
		"[[allow]]\nfield = \"a\"\nmode = \"redact\"",
		"[[mask]]\nfield = \"a..b\"",
		"[[mask]]\nfield = \"a*b\"",
		"[[mask]]\nfield = \"⟦key:X⟧\"",
		"[[mask]]\nfield = \"a\"\nkind = \"customer\"",
	} {
		if _, err := ParseProjectRules([]byte(bad)); err == nil {
			t.Errorf("accepted: %q", bad)
		}
	}
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &r})
	got := encode(t, m.Mask("api", event(t, `{"user":{"name":"Zed"},"client":"acme","route":"/x"}`)))
	if !strings.Contains(got, `"name":"⟦customer:`) || !strings.Contains(got, `"client":"`+Redacted) || strings.Contains(got, "Zed") {
		t.Errorf("record = %s", got)
	}
}

func TestRulesChangeClassification(t *testing.T) {
	base := Rules{Mask: []Rule{{Field: "a", Mode: ModeRedact}}, Allow: []Rule{{Field: "r", Mode: ModeAllow}}}
	tighter := Rules{Mask: []Rule{{Field: "a", Mode: ModeRedact}, {Field: "b", Mode: ModeRedact}}}
	if l := Change(base, tighter); len(l) != 0 {
		t.Errorf("tightening classified as loosening: %v", l)
	}
	// A new pseudonym can turn ⟦redacted⟧ (redact-unknown) into a
	// linkable pseudonym: the human reviews it.
	pseudo := Rules{Mask: []Rule{{Field: "a", Mode: ModeRedact}, {Field: "b", Mode: ModePseudonym, Kind: "email"}}, Allow: base.Allow}
	if l := Change(base, pseudo); len(l) != 1 {
		t.Errorf("an added pseudonym rule: loosenings = %v, want 1", l)
	}
	looser := Rules{Allow: []Rule{{Field: "r", Mode: ModeAllow}, {Field: "x", Mode: ModeAllow}}}
	if l := Change(base, looser); len(l) != 2 {
		t.Errorf("loosenings = %v, want the removed mask rule and the added allow rule", l)
	}
	if base.Fingerprint() == tighter.Fingerprint() {
		t.Error("fingerprint unchanged by a rule change")
	}
}

func TestValueRules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "values.toml"), []byte("[[value]]\nkind = \"customer_id\"\nregex = 'CUST-[0-9]{6}'\n"), 0o600)
	vs, err := LoadValueRules(dir)
	if err != nil || len(vs) != 1 {
		t.Fatal(vs, err)
	}
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &Rules{Values: vs}})
	got := encode(t, m.Mask("api", event(t, `{"m":"order for CUST-123456 ok"}`)))
	if strings.Contains(got, "123456") || !strings.Contains(got, "⟦customer_id:") {
		t.Errorf("record = %s", got)
	}
	for _, bad := range []string{"[[value]]\nkind = \"x\"\nregex = 'a*'\n", "[[value]]\nkind = \"X\"\nregex = 'a'\n", "[[value]]\nkind = \"x\"\nregex = '('\n"} {
		os.WriteFile(filepath.Join(dir, "values.toml"), []byte(bad), 0o600)
		if _, err := LoadValueRules(dir); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Agent rules only tighten, name only fields shown, and are stored only
// as keyed digests in the PII directory: no name, and no masked name in
// particular, is written anywhere (round-6 amendment).
func TestAgentRulesTightenOnlyAndLeakNoName(t *testing.T) {
	piiDir := filepath.Join(t.TempDir(), "pii")
	project := filepath.Join(t.TempDir(), ".locklog")
	os.MkdirAll(project, 0o755)
	projectFile := filepath.Join(project, "pii.toml")
	os.WriteFile(projectFile, []byte("[[mask]]\nfield = \"client\"\n"), 0o644)
	before, _ := os.ReadFile(projectFile)
	ag, err := OpenAgentRules(piiDir)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := LoadProjectRules(projectFile)
	rules.Agent = ag
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &rules, Trusted: []string{"level"}})
	maskedName := "jean.secretname@example.com"
	line := `{"level":"error","order":"4812","client":"acme","` + maskedName + `":"Lyon"}`
	r := m.Mask("api", event(t, line))
	var shownKey string
	for _, f := range r.Fields() {
		if strings.HasPrefix(f.Name(), Open+KeyKind) {
			shownKey = f.Name()
		}
	}
	lim := AgentLimits{PerHour: 10, Total: 50}
	// Refusals.
	cases := []struct {
		path, mode string
		want       error
	}{
		{"order", "partial", ErrRuleMode},
		{"ord*", ModeRedact, ErrPIIInQuery},
		{"jean@example.com", ModeRedact, ErrPIIInQuery},
		{maskedName, ModeRedact, ErrPIIInQuery},     // a clear path naming a masked name
		{"never_seen", ModeRedact, ErrUnknownField}, // same answer as for a masked name
		{"⟦key:AAAAAAAAAAAA⟧", ModeRedact, ErrUnknownField},
		{"client", ModeRedact, ErrRuleExists}, // a human rule decides it
		{"level", ModeRedact, ErrRuleExists},  // trusted by the human
	}
	for _, c := range cases {
		if err := m.AgentAdd("api", c.path, c.mode, t0, lim); !errors.Is(err, c.want) {
			t.Errorf("AgentAdd(%q, %s) = %v, want %v", c.path, c.mode, err, c.want)
		}
	}
	// Accepted: a clear-shown field and a masked name by its pseudonym.
	if err := m.AgentAdd("api", "order", ModePseudonym, t0, lim); err != nil {
		t.Fatal(err)
	}
	if err := m.AgentAdd("api", shownKey, ModeRedact, t0, lim); err != nil {
		t.Fatal(err)
	}
	if err := m.AgentAdd("api", "order", ModeRedact, t0, lim); !errors.Is(err, ErrRuleExists) {
		t.Errorf("an agent rule changed an existing one: %v", err)
	}
	r = m.Mask("api", event(t, line))
	got := encode(t, r)
	if strings.Contains(got, `"order":"4812"`) || strings.Contains(got, "Lyon") || !strings.Contains(got, `"client":"`+Redacted) {
		t.Errorf("record after agent rules = %s", got)
	}
	// Nothing written holds a name: neither the project file nor the PII
	// directory.
	after, _ := os.ReadFile(projectFile)
	if !bytes.Equal(before, after) {
		t.Error("the project's pii.toml changed")
	}
	filepath.Walk(piiDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, name := range []string{maskedName, "jean", "secretname", "order"} {
			if bytes.Contains(b, []byte(name)) {
				t.Errorf("%s holds %q", p, name)
			}
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %04o", p, fi.Mode().Perm())
		}
		return nil
	})
	// Reopened, the rules still apply; the cap holds.
	ag2, err := OpenAgentRules(piiDir)
	if err != nil || ag2.Len() != 2 {
		t.Fatalf("reopen: %v, %v", ag2, err)
	}
	for i := range 20 {
		name := "f" + string(rune('a'+i))
		m.noteClear("api", name)
		err := m.AgentAdd("api", name, ModeRedact, t0, AgentLimits{PerHour: 3, Total: 50})
		if i >= 1 && !errors.Is(err, ErrRuleCap) {
			t.Fatalf("rule %d past the hourly cap: %v", i, err)
		}
	}
}

// Harness v1: a seeded corpus of 10 000 lines, canaries of every kind in
// every position and encoding, masked in both structured modes: no form
// of any canary in the encoded records.
func TestLeakHarnessCorpus(t *testing.T) {
	lines := masktest.New(42).Lines(10_000)
	p, _ := parse.New(parse.Options{})
	for _, mode := range []string{StructuredDetect, StructuredRedactUnknown} {
		m := newMasker(t, Options{Structured: mode, Trusted: []string{"ts", "level", "status"}})
		var hits []masktest.Hit
		for _, l := range lines {
			out, err := json.Marshal(m.Mask("api", p.Line(l.Text)))
			if err != nil {
				t.Fatal(err)
			}
			hits = append(hits, masktest.Scan(l.Text, out, l.Canaries)...)
			hits = append(hits, masktest.Scan("text:"+l.Text, []byte(m.Text(l.Text)), l.Canaries)...)
		}
		for i, h := range hits {
			if i >= 20 {
				break
			}
			t.Errorf("%s: %s %q leaked as %q in %q", mode, h.Canary.Kind, h.Canary.Value, h.Form, h.Where)
		}
		if len(hits) > 0 {
			t.Fatalf("%s: %d leaks", mode, len(hits))
		}
	}
}

type noFinder struct{}

func (noFinder) Find(string) []pii.Match { return nil }

// The harness finds leaks: without detectors, nearly every line leaks
// its canary, in whatever encoding it was written.
func TestLeakHarnessFindsLeaks(t *testing.T) {
	lines := masktest.New(42).Lines(2000)
	p, _ := parse.New(parse.Options{})
	m := newMasker(t, Options{Structured: StructuredDetect, Values: noFinder{}, Secrets: noFinder{}})
	leaked := 0
	for _, l := range lines {
		out, _ := json.Marshal(m.Mask("api", p.Line(l.Text)))
		if len(masktest.Scan("", out, l.Canaries)) > 0 {
			leaked++
		}
	}
	// Some positions are masked by their names alone (personal names).
	if leaked < len(lines)*85/100 {
		t.Errorf("the harness found %d leaks in %d unmasked lines", leaked, len(lines))
	}
}

// FuzzMaskNoLeak: whatever the line, no value the detectors (or the
// secret finder) recognise survives in the masked record.
func FuzzMaskNoLeak(f *testing.F) {
	for _, l := range masktest.New(3).Lines(200) {
		f.Add(l.Text)
	}
	f.Add(`{"a":"x jean@example.com y","b":4111111111111111}`)
	f.Add(`{"cust":{"id":"jean@example.com"},"password":{"v":["x"]},"meta":{"n":"BE68539007547034"}}`)
	rules, err := ParseProjectRules([]byte(masktest.RulesForCorpus))
	if err != nil {
		f.Fatal(err)
	}
	ms := []*Masker{
		newMasker(f, Options{Structured: StructuredDetect}),
		newMasker(f, Options{Structured: StructuredRedactUnknown, Rules: &rules, SecretName: masktest.SecretNameForCorpus}),
		newMasker(f, Options{Structured: StructuredDetect, Rules: &rules, SecretName: masktest.SecretNameForCorpus}),
	}
	p, _ := parse.New(parse.Options{})
	values := Detectors(pii.AllDetectors())
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 4096 {
			return
		}
		for _, m := range ms {
			fuzzOneNoLeak(t, m, p, values, line)
		}
	})
}

func fuzzOneNoLeak(t *testing.T, m *Masker, p *parse.Parser, values Detectors, line string) {
	{
		r := m.Mask("api", p.Line(line))
		out, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if r.Failed() {
			t.Fatalf("masking failed on %q", line)
		}
		var texts []string
		var walkV func(v Value)
		walkV = func(v Value) {
			switch v.Kind() {
			case Object:
				for _, f := range v.Members() {
					texts = append(texts, f.Name())
					walkV(f.Value())
				}
			case Array:
				for _, it := range v.Items() {
					walkV(it)
				}
			default:
				texts = append(texts, v.Text())
			}
		}
		for _, f := range append(r.Fields(), r.Attrs()...) {
			texts = append(texts, f.Name())
			walkV(f.Value())
		}
		texts = append(texts, r.Message())
		for _, s := range texts {
			plain := blankLen(s)
			for _, mt := range append(values.Find(plain), masktest.SecretFinder{}.Find(plain)...) {
				if mt.Kind == pii.CutKind {
					continue
				}
				t.Fatalf("%s %q survived in %q (record %s)", mt.Kind, plain[mt.Start:mt.End], s, out)
			}
		}
	}
}

// The masker's modes are the profile's.
func TestModesMatchConfig(t *testing.T) {
	if StructuredRedactUnknown != config.StructuredRedactUnknown || StructuredDetect != config.StructuredDetect {
		t.Error("structured modes differ from internal/config")
	}
}

// A secret name, a human rule or an agent rule on an object or an array
// decides for everything under it (design §4.2: secrets first and final).
func TestContainerNamesAndRulesCoverChildren(t *testing.T) {
	rules, err := ParseProjectRules([]byte("[[mask]]\nfield = \"user\"\n[[mask]]\nfield = \"cust\"\nmode = \"pseudonym\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	rules.Agent = ag
	for _, mode := range []string{StructuredDetect, StructuredRedactUnknown} {
		m := newMasker(t, Options{Structured: mode, Rules: &rules, SecretName: func(n string) bool { return n == "password" }})
		line := `{"user":{"first":"Bobby"},"cust":{"id":"C-77 Bobbie","more":[{"n":"Bobbo"}]},"password":{"value":"hunter2xyz"},"pw":1,"user_name":{"given":"Robert"},"meta":{"note":"Robertine","deep":{"x":"Robertina"}},"arr":[{"password":["hunter3xyz"]}]}`
		m.Mask("api", event(t, line)) // shows "meta" to the agent
		if err := m.AgentAdd("api", "meta", ModeRedact, t0, AgentLimits{PerHour: 10, Total: 50}); err != nil && !errors.Is(err, ErrRuleExists) {
			t.Fatal(err)
		}
		out := encode(t, m.Mask("api", event(t, line)))
		for _, clear := range []string{"Bobby", "Bobbie", "Bobbo", "C-77", "hunter2xyz", "hunter3xyz", "Robert", "Robertine", "Robertina"} {
			if strings.Contains(out, clear) {
				t.Errorf("%s: %q survived: %s", mode, clear, out)
			}
		}
		if !strings.Contains(out, `"password":"`+Secret+`"`) {
			t.Errorf("%s: a secret-named object is not masked whole: %s", mode, out)
		}
	}
}

// The corpus positions under a rule, a secret name or an agent rule are
// masked by those alone: no detector runs.
func TestLeakHarnessRulePositions(t *testing.T) {
	rules, err := ParseProjectRules([]byte(masktest.RulesForCorpus))
	if err != nil {
		t.Fatal(err)
	}
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	rules.Agent = ag
	p, _ := parse.New(parse.Options{})
	per := len(masktest.Kinds) * len(masktest.Encodings)
	lines := masktest.New(7).Lines(per * masktest.Positions * 3)
	for _, mode := range []string{StructuredDetect, StructuredRedactUnknown} {
		m := newMasker(t, Options{Structured: mode, Rules: &rules, Values: noFinder{}, Secrets: noFinder{}, SecretName: masktest.SecretNameForCorpus, Trusted: []string{"ts"}})
		m.Mask("api", p.Line(`{"meta":{"note":"x"}}`))
		if err := m.AgentAdd("api", "meta", ModePseudonym, t0, AgentLimits{PerHour: 10, Total: 50}); err != nil && !errors.Is(err, ErrRuleExists) {
			t.Fatal(err)
		}
		var hits []masktest.Hit
		for i, l := range lines {
			if pos := (i / per) % masktest.Positions; pos < 8 {
				continue
			}
			out, err := json.Marshal(m.Mask("api", p.Line(l.Text)))
			if err != nil {
				t.Fatal(err)
			}
			hits = append(hits, masktest.Scan(l.Text, out, l.Canaries)...)
		}
		for i, h := range hits {
			if i < 10 {
				t.Errorf("%s: %s %q leaked as %q in %q", mode, h.Canary.Kind, h.Canary.Value, h.Form, h.Where)
			}
		}
	}
}

func TestRedactTextNoPseudonymAndZeroLimits(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	got := m.RedactText("is jean@example.com there? key AKIAIOSFODNN7EXAMPLE")
	if strings.Contains(got, "jean") || strings.Contains(got, Open+"email") || !strings.Contains(got, Redacted) {
		t.Errorf("RedactText = %q", got)
	}
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	for _, lim := range []AgentLimits{{}, {PerHour: 1}, {Total: 1}} {
		if err := ag.add("api", "x", ModeRedact, t0, lim); !errors.Is(err, ErrRuleCap) {
			t.Errorf("limits %+v: add = %v, want ErrRuleCap", lim, err)
		}
	}
}

// A rule, a secret name or an agent rule on the key the message was
// lifted from decides for the message; a child's allow never beats an
// inherited pseudonym rule.
func TestMessageKeyRulesAndInheritedStrength(t *testing.T) {
	for _, tc := range []struct{ rules, line, clear string }{
		{"[[mask]]\nfield = \"msg\"\n", `{"msg":"order for Bobby Smithers","x":1}`, "Bobby"},
		{"[[mask]]\nfield = \"log\"\nmode = \"pseudonym\"\n", `{"log":"Bobby Smithers"}`, "Bobby"},
		{"[[mask]]\nfield = \"user\"\nmode = \"pseudonym\"\n[[allow]]\nfield = \"*.first\"\n", `{"user":{"first":"Bobby"}}`, "Bobby"},
	} {
		rules, err := ParseProjectRules([]byte(tc.rules))
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{StructuredDetect, StructuredRedactUnknown} {
			m := newMasker(t, Options{Structured: mode, Rules: &rules})
			if out := encode(t, m.Mask("api", event(t, tc.line))); strings.Contains(out, tc.clear) {
				t.Errorf("%s %q: %q survived: %s", mode, tc.rules, tc.clear, out)
			}
		}
	}
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	rules := Rules{Agent: ag}
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &rules, SecretName: func(n string) bool { return n == "password" }})
	line := `{"msg":"order for Bobby Smithers","x":1}`
	m.Mask("api", event(t, line))
	if err := m.AgentAdd("api", "msg", ModeRedact, t0, AgentLimits{PerHour: 10, Total: 50}); err != nil {
		t.Fatal(err)
	}
	if out := encode(t, m.Mask("api", event(t, line))); strings.Contains(out, "Bobby") {
		t.Errorf("an agent rule on msg is ignored: %s", out)
	}
}

// A number or bool that is not a valid literal (cut past DetectLimit, or
// built by hand) is a string: never written raw into the JSON.
func TestInvalidLiteralIsAString(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect, Trusted: []string{"t"}})
	for _, line := range []string{`{"n":` + strings.Repeat("7", 70000) + `}`, `{"t":` + strings.Repeat("7", 70000) + `}`} {
		if _, err := json.Marshal(m.Mask("api", event(t, line))); err != nil {
			t.Errorf("a long number breaks the record's JSON: %v", err)
		}
	}
	ev := parse.Event{Fields: []parse.Member{{Key: "n", Value: parse.Value{Kind: parse.KindNumber, Str: `1,"x":2`}}}}
	out := encode(t, m.Mask("api", ev))
	if strings.Contains(out, `"x":2`) {
		t.Errorf("a bad number literal forged a field: %s", out)
	}
}

// Glued values past the re-pass rounds are withheld, never left clear;
// a value redact-unknown withholds says nothing of its kinds.
func TestGluedValuesAndRedactedKinds(t *testing.T) {
	glued := strings.Repeat("+32475123456", 1) + "+32475123457+32475123458+32475123459+32475123450+32475123451+32475123452"
	m := newMasker(t, Options{Structured: StructuredDetect})
	for _, line := range []string{`{"x":"` + glued + `"}`, `{"msg":"` + glued + `"}`, glued} {
		if out := encode(t, m.Mask("api", event(t, line))); strings.Contains(out, "3247512345") {
			t.Errorf("a glued phone survived: %s", out)
		}
	}
	if out := m.Text(glued); strings.Contains(out, "3247512345") {
		t.Errorf("Text: a glued phone survived: %s", out)
	}
	if out := m.RedactText(glued); strings.Contains(out, "3247512345") {
		t.Errorf("RedactText: a glued phone survived: %s", out)
	}
	r := newMasker(t, Options{Structured: StructuredRedactUnknown}).Mask("api", event(t, `{"x":"mail john.doe@example.com","y":"BE71096123456769"}`))
	if k := r.Kinds(); len(k) != 1 || k[0] != "redacted" {
		t.Errorf("Kinds = %v, want [redacted]", k)
	}
}

func TestRedactedSecretsAndPseudonymOrder(t *testing.T) {
	sec := "sk_test_" + strings.Repeat("a1", 16)
	r := newMasker(t, Options{Structured: StructuredRedactUnknown}).Mask("api", event(t, `{"x":"`+sec+`","y":"hello"}`))
	if k := r.Kinds(); len(k) != 1 || k[0] != "redacted" || r.HadSecret("x") {
		t.Errorf("a withheld secret is described: Kinds = %v, HadSecret = %v", k, r.HadSecret("x"))
	}
	rules, err := ParseProjectRules([]byte("[[mask]]\nfield = \"x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	r = newMasker(t, Options{Structured: StructuredDetect, Rules: &rules}).Mask("api", event(t, `{"x":"`+sec+`"}`))
	if r.HadSecret("x") || slices.Contains(r.Kinds(), "secret") {
		t.Errorf("a redacted secret is described: %v", r.Kinds())
	}
	a := Rule{Field: "user.*", Mode: ModePseudonym, Kind: "customer"}
	b := Rule{Field: "user.email", Mode: ModePseudonym, Kind: "email"}
	if l := Change(Rules{Mask: []Rule{a, b}}, Rules{Mask: []Rule{b, a}}); len(l) == 0 {
		t.Error("reordering pseudonym rules is not reported")
	}
	c := Rule{Field: "e", Mode: ModePseudonym, Kind: "customer"}
	d := Rule{Field: "e", Mode: ModePseudonym, Kind: "email"}
	if l := Change(Rules{Mask: []Rule{c, d}}, Rules{Mask: []Rule{d}}); len(l) == 0 {
		t.Error("removing a duplicate pseudonym rule is not reported")
	}
	if _, err := ParseProjectRules([]byte("[[mask]]\nfield = \"e\"\nmode = \"pseudonym\"\n[[mask]]\nfield = \"e\"\nmode = \"pseudonym\"\nkind = \"email\"\n")); err == nil {
		t.Error("duplicate rules accepted")
	}
}

func TestExponentNumbersInvalidBytesAndWithheldKinds(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	for _, line := range []string{
		`{"n":4.111111111111111E15}`, `{"n":4.111111111111111e15}`, `{"n":-4.111111111111111E+15}`,
		`{"n":41111111111111110e-1}`, `{"n":4111111111111111.0}`,
		"{\"s\":\"andr\xe9@example.com\"}", "contact andr\xe9@example.com now",
		"{\"s\":\"4111\xff1111\xff1111\xff1111\"}", "{\"s\":\"BE68\xff539007547034\"}",
	} {
		out := encode(t, m.Mask("api", event(t, line)))
		for _, clear := range []string{"4111111111111111", "4.111111111111111", "example.com", "539007547034", "1111"} {
			if strings.Contains(out, clear) {
				t.Errorf("%q: %q survived: %s", line, clear, out)
			}
		}
	}
	glued := "+32475123456+32475123457+32475123458+32475123459+32475123450+32475123451"
	for _, line := range []string{`{"x":"` + glued + `"}`, glued + " sk_test_" + strings.Repeat("a1", 16)} {
		if k := m.Mask("api", event(t, line)).Kinds(); len(k) != 1 || k[0] != "redacted" {
			t.Errorf("%q: Kinds = %v, want [redacted]", line, k)
		}
	}
	ag, err := OpenAgentRules(filepath.Join(t.TempDir(), "pii"))
	if err != nil {
		t.Fatal(err)
	}
	rules := Rules{Agent: ag}
	am := newMasker(t, Options{Structured: StructuredDetect, Rules: &rules})
	am.Mask("api", event(t, `{"note":"x"}`))
	if err := am.AgentAdd("api", "note", ModeRedact, t0, AgentLimits{PerHour: 10, Total: 50}); err != nil {
		t.Fatal(err)
	}
	if k := am.Mask("api", event(t, `{"note":"mail john.doe@example.com"}`)).Kinds(); len(k) != 1 || k[0] != "redacted" {
		t.Errorf("agent redact: Kinds = %v, want [redacted]", k)
	}
}

// A glob mask rule also covers keys holding dots (IP addresses, hosts).
func TestMaskGlobOverDottedKeys(t *testing.T) {
	rules, err := ParseProjectRules([]byte("[[mask]]\nfield = \"hosts.*.owner\"\n[[mask]]\nfield = \"users.*\"\nmode = \"pseudonym\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := newMasker(t, Options{Structured: StructuredDetect, Rules: &rules})
	for _, line := range []string{
		`{"hosts":{"web01.example.org":{"owner":"Jean Bon"}}}`,
		`{"hosts":{"10.0.0.1":{"owner":"Jean Bon"}}}`,
		`{"users":{"a.b":{"n":"Jean Bon"}}}`,
	} {
		if out := encode(t, m.Mask("api", event(t, line))); strings.Contains(out, "Jean") {
			t.Errorf("%s: %s", line, out)
		}
	}
}

func TestMaskRuleGlobMatchesReference(t *testing.T) {
	ref := func(fs, ps []string) bool {
		var rec func(i, j int) bool
		rec = func(i, j int) bool {
			if i == len(fs) {
				return j == len(ps)
			}
			if fs[i] == "*" {
				for k := j + 1; k <= len(ps); k++ {
					if rec(i+1, k) {
						return true
					}
				}
				return false
			}
			return j < len(ps) && fs[i] == ps[j] && rec(i+1, j+1)
		}
		return rec(0, 0)
	}
	segs := []string{"a", "b", "*"}
	paths := []string{"a", "b", "c"}
	var gen func(n int, alpha []string) [][]string
	gen = func(n int, alpha []string) [][]string {
		if n == 0 {
			return [][]string{nil}
		}
		var out [][]string
		for _, p := range gen(n-1, alpha) {
			for _, x := range alpha {
				out = append(out, append(slices.Clone(p), x))
			}
		}
		return out
	}
	for fn := 1; fn <= 4; fn++ {
		for _, fs := range gen(fn, segs) {
			for pn := 1; pn <= 5; pn++ {
				for _, ps := range gen(pn, paths) {
					r := Rule{Field: strings.Join(fs, "."), Mode: ModeRedact}
					if got, want := maskRuleMatches(r, "api", strings.Join(ps, ".")), ref(fs, ps) || ruleMatches(r, "api", strings.Join(ps, ".")); got != want {
						t.Fatalf("%s on %s = %v, want %v", r.Field, strings.Join(ps, "."), got, want)
					}
				}
			}
		}
	}
}

// A record whose time the reader inherited from the previous timed record
// (a stack-trace continuation) keeps that time in the masked view, as the
// local index counts it: index counts and scans agree.
func TestMaskKeepsInheritedTime(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	ev := event(t, `continuation line`)
	at := time.Date(2026, 10, 30, 14, 2, 11, 0, time.UTC)
	ev.Time, ev.HasTime, ev.Inherited = at, false, true
	if ts, ok := m.Mask("api", ev).Time(); !ok || !ts.Equal(at) {
		t.Errorf("Time() = %v, %v; want %v, true", ts, ok, at)
	}
}
