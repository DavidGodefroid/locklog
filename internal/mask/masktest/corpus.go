// Package masktest generates seeded log corpora with planted canaries
// (synthetic personal values and secrets, in every position and encoding)
// and scans bytes for any of them: the leak harness of design §4.7.
// Everything here is synthetic.
package masktest

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/pii"
)

// Canary is one planted value: its kind and its clear form.
type Canary struct {
	Kind  string
	Value string
}

// Line is one generated log line and the canaries planted in it.
type Line struct {
	Text     string
	Format   string // json, logfmt, plain
	Canaries []Canary
	// Position and Encoding index Positions and Encodings.
	Position, Encoding int
}

// Kinds the generator plants. Every one is covered by a lockkit detector
// ("secret" by the secret detector of step 1; "ip" and "person_name" by
// the value detectors of the same names, which a test must enable).
var Kinds = []string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn", "secret", "ip", "person_name"}

// ValueDetectors are the value detectors that cover every kind of Kinds
// but "secret". phone_loose plants nothing of its own: it widens phone to
// national numbers without a trunk 0, an opt-in for its false positives
// whose recall is lockkit's to test.
var ValueDetectors = []string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn", "ip", "person_name"}

// Given names and surnames of the synthetic people (all in lockkit's
// gazetteer).
var (
	givenNames = []string{"Jean", "Marie", "Pieter", "Sophie", "Emma"}
	surnames   = []string{"Dupont", "Janssens", "Peeters", "Lefebvre", "Dubois", "Claes"}
)

// Gen generates canaries and lines from a seed.
type Gen struct{ r *rand.Rand }

// New returns a generator for seed.
func New(seed uint64) *Gen { return &Gen{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))} }

func (g *Gen) digits(n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(byte('0' + g.r.IntN(10)))
	}
	return b.String()
}

func (g *Gen) word(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	for range n {
		b.WriteByte(letters[g.r.IntN(len(letters))])
	}
	return b.String()
}

// Value returns a fresh valid value of kind.
func (g *Gen) Value(kind string) string {
	switch kind {
	case "email":
		return g.word(4+g.r.IntN(6)) + "." + g.word(5) + "@" + g.word(6) + ".example"
	case "phone":
		return "+32 47" + g.digits(1) + " " + g.digits(2) + " " + g.digits(2) + " " + g.digits(2)
	case "iban":
		bban := g.digits(10)
		n, _ := strconv.ParseUint(bban, 10, 64)
		chk := n % 97
		if chk == 0 {
			chk = 97
		}
		bban += fmt.Sprintf("%02d", chk)
		return "BE" + ibanCheck("BE", bban) + bban
	case "card":
		d := "4" + g.digits(14)
		return d + luhnDigit(d)
	case "be_niss":
		for {
			yy, mm, dd := g.r.IntN(100), 1+g.r.IntN(12), 1+g.r.IntN(28)
			body := fmt.Sprintf("%02d%02d%02d%03d", yy, mm, dd, 1+g.r.IntN(997))
			n, _ := strconv.ParseUint(body, 10, 64)
			return body + fmt.Sprintf("%02d", 97-n%97)
		}
	case "fr_nir":
		body := fmt.Sprintf("%d%02d%02d%02d%03d%03d", 1+g.r.IntN(2), g.r.IntN(100), 1+g.r.IntN(12), 1+g.r.IntN(95), 1+g.r.IntN(990), 1+g.r.IntN(999))
		n, _ := strconv.ParseUint(body, 10, 64)
		return body + fmt.Sprintf("%02d", 97-n%97)
	case "nl_bsn":
		for {
			d := g.digits(8)
			sum := 0
			for i := 0; i < 8; i++ {
				sum += int(d[i]-'0') * (9 - i)
			}
			if last := sum % 11; last <= 9 && d != "00000000" {
				return d + strconv.Itoa(last)
			}
		}
	case "us_ssn":
		return fmt.Sprintf("%03d-%02d-%04d", 100+g.r.IntN(565), 1+g.r.IntN(98), 1+g.r.IntN(9998))
	case "secret":
		return g.secret()
	case "ip":
		v4 := fmt.Sprintf("%d.%d.%d.%d", []int{81, 91, 145, 185, 212}[g.r.IntN(5)], g.r.IntN(256), g.r.IntN(256), 1+g.r.IntN(254))
		v6 := fmt.Sprintf("2a02:%x:%x::%x", 0x1000+g.r.IntN(0xefff), 1+g.r.IntN(0xfffe), 1+g.r.IntN(0xfffe))
		switch g.r.IntN(4) {
		case 0:
			return v4
		case 1:
			return v6
		case 2:
			return strings.ToUpper(v6)
		default:
			return "::ffff:" + v4 // IPv4-mapped
		}
	case "person_name":
		return givenNames[g.r.IntN(len(givenNames))] + " " + surnames[g.r.IntN(len(surnames))]
	}
	panic("masktest: unknown kind " + kind)
}

// secretShapes are the synthetic secrets: token shapes lockkit's secret
// detector knows, each with its fixed prefix (the scan also looks for
// the part after it).
var secretShapes = []struct {
	prefix, alphabet string
	n                int
}{
	{"sk_test_", "0123456789abcdef", 32},                                                            // Stripe
	{"ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 36},                  // GitHub
	{"AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16},                                                // AWS
	{"glpat-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 20},                // GitLab
	{"eyJhbGciOiJIUzI1NiJ9.", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 24}, // JWT
}

func (g *Gen) secret() string {
	sh := secretShapes[g.r.IntN(len(secretShapes))]
	v := sh.prefix + g.from(sh.alphabet, sh.n)
	if strings.HasPrefix(sh.prefix, "eyJ") {
		v += "." + g.from(sh.alphabet, 43)
	}
	return v
}

// SecretBody is the part of a synthetic secret after its fixed prefix.
func SecretBody(v string) string {
	for _, sh := range secretShapes {
		if strings.HasPrefix(v, sh.prefix) {
			return v[len(sh.prefix):]
		}
	}
	return v
}

func (g *Gen) from(alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[g.r.IntN(len(alphabet))])
	}
	return b.String()
}

func ibanCheck(country, bban string) string {
	s := bban + country + "00"
	m := 0
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			v := int(c-'A') + 10
			m = (m*100 + v) % 97
		} else {
			m = (m*10 + int(c-'0')) % 97
		}
	}
	return fmt.Sprintf("%02d", 98-m)
}

func luhnDigit(d string) string {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-1-i)%2 == 0 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return strconv.Itoa((10 - sum%10) % 10)
}

// Encodings a canary is written with.
var Encodings = []string{"raw", "percent", "double-percent", "json-u", "html", "fullwidth", "zero-width"}

// Encode writes v with encoding enc (every character for the escapes).
func Encode(v, enc string) string {
	switch enc {
	case "percent":
		return percentAll(v, 1)
	case "double-percent":
		return percentAll(v, 2)
	}
	var b strings.Builder
	for i, c := range v {
		switch enc {
		case "json-u":
			fmt.Fprintf(&b, `\u%04x`, c)
		case "html":
			fmt.Fprintf(&b, "&#%d;", c)
		case "fullwidth":
			if c > ' ' && c < 0x7f {
				b.WriteRune(c - 0x21 + 0xff01)
			} else {
				b.WriteRune(c)
			}
		case "zero-width":
			b.WriteRune(c)
			if i < len(v)-1 {
				b.WriteString("\u200b")
			}
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func percentAll(v string, times int) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if times == 1 {
			fmt.Fprintf(&b, "%%%02X", v[i])
		} else {
			fmt.Fprintf(&b, "%%25%02X", v[i])
		}
	}
	return b.String()
}

// Lines generates n lines: every kind, in every position (JSON value,
// nested value, key, number, array item, logfmt value, free text) and
// every encoding, in turn.
// Positions is the number of places Lines plants a canary in.
const Positions = 11

// RulesForCorpus is the project rule file the corpus's rule positions
// assume.
const RulesForCorpus = "[[mask]]\nfield = \"cust\"\nmode = \"pseudonym\"\n"

// SecretNameForCorpus is the secret-name test the corpus's secret
// positions assume.
func SecretNameForCorpus(name string) bool { return name == "password" || name == "token" }

func (g *Gen) Lines(n int) []Line {
	out := make([]Line, 0, n)
	for i := range n {
		kind := Kinds[i%len(Kinds)]
		encI := (i / len(Kinds)) % len(Encodings)
		enc := Encodings[encI]
		v := g.Value(kind)
		w := Encode(v, enc)
		ts := fmt.Sprintf("2026-10-30T14:%02d:%02d.%03dZ", (i/60)%60, i%60, i%1000)
		var text, format string
		jsonW := jsonEscape(w) // a json-u canary keeps its escapes: JSON decodes them
		if enc == "json-u" {
			jsonW = w
		}
		pos := (i / (len(Kinds) * len(Encodings))) % Positions
		switch pos {
		case 0:
			text, format = fmt.Sprintf(`{"ts":"%s","level":"error","detail":"%s","status":502}`, ts, jsonW), "json"
		case 1:
			text, format = fmt.Sprintf(`{"ts":"%s","req":{"user":{"contact":"%s"}},"status":200}`, ts, jsonW), "json"
		case 2:
			text, format = fmt.Sprintf(`{"ts":"%s","by_value":{"%s":1}}`, ts, jsonW), "json"
		case 3:
			if kind == "card" || kind == "be_niss" || kind == "nl_bsn" || kind == "fr_nir" {
				text, format = fmt.Sprintf(`{"ts":"%s","ref":%s}`, ts, v), "json"
			} else {
				text, format = fmt.Sprintf(`{"ts":"%s","tags":["a","%s"]}`, ts, jsonW), "json"
			}
		case 4:
			text, format = fmt.Sprintf(`ts=%s level=warn detail="%s" order=4812`, ts, strings.ReplaceAll(w, `"`, `'`)), "logfmt"
		case 5:
			text, format = fmt.Sprintf(`%s ERROR render pdf for %s failed: upstream timed out`, ts, w), "plain"
		case 6:
			text, format = fmt.Sprintf(`{"ts":"%s","msg":"login by %s from 203.0.113.9"}`, ts, jsonW), "json"
		case 7:
			text, format = fmt.Sprintf(`%s GET /api/orders?q=%s&page=2 HTTP/1.1 200`, ts, w), "plain"
		case 8: // under an object a project rule pseudonymises (RulesForCorpus)
			text, format = fmt.Sprintf(`{"ts":"%s","cust":{"id":"C-77 %s","tags":["%s"]}}`, ts, jsonW, jsonW), "json"
		case 9: // under an object whose name is a secret's (SecretNameForCorpus)
			text, format = fmt.Sprintf(`{"ts":"%s","password":{"value":"%s"},"token":["%s"]}`, ts, jsonW, jsonW), "json"
		case 10: // under an object an agent rule names ("meta")
			text, format = fmt.Sprintf(`{"ts":"%s","meta":{"note":"%s","deep":{"x":"%s"}}}`, ts, jsonW, jsonW), "json"
		}
		out = append(out, Line{Text: text, Format: format, Canaries: []Canary{{kind, v}}, Position: pos, Encoding: encI})
	}
	return out
}

func jsonEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Forms are the forms of a canary the scan looks for: raw, lower case,
// percent-encoded, JSON-escaped, and its normalised form (no separators).
func Forms(c Canary) []string {
	v := c.Value
	forms := []string{v, strings.ToLower(v), url.QueryEscape(v), percentAll(v, 1), jsonUEscape(v)}
	compact := strings.NewReplacer(" ", "", "-", "", ".", "").Replace(v)
	number := c.Kind != "email" && c.Kind != "secret" && c.Kind != "ip" && c.Kind != "person_name"
	if number || c.Kind == "person_name" {
		forms = append(forms, compact)
	}
	switch c.Kind {
	case "secret":
		// The body, its head and tail, and each JWT segment: a part of a
		// secret is a leak.
		body := SecretBody(v)
		forms = append(forms, body)
		if len(body) >= 16 {
			forms = append(forms, body[:8], body[len(body)-8:])
		}
		if strings.HasPrefix(v, "eyJ") {
			for _, seg := range strings.Split(v, ".") {
				if len(seg) >= 8 {
					forms = append(forms, seg)
				}
			}
		}
	case "ip":
		// The address without its last group (its /24 or /112): a network
		// prefix is a leak.
		if i := strings.LastIndexAny(v, ".:"); i > 0 {
			forms = append(forms, v[:i+1])
		}
	}
	// Digit runs of 6+ of the value: a partial leak of a number.
	if number && len(compact) >= 9 {
		forms = append(forms, compact[:7], compact[len(compact)-7:])
	}
	return forms
}

// WordForms are the forms of a canary the scan looks for as whole words:
// each part of a person's name (a masker hiding the given name but showing
// the surname leaks).
func WordForms(c Canary) []string {
	if c.Kind != "person_name" {
		return nil
	}
	return strings.Fields(c.Value)
}

func jsonUEscape(v string) string {
	var b strings.Builder
	for _, c := range v {
		fmt.Fprintf(&b, `\u%04x`, c)
	}
	return b.String()
}

// Hit is a canary form found in scanned bytes.
type Hit struct {
	Canary Canary
	Form   string
	Where  string
}

// Scan returns every form of every canary found in out, also once out is
// decoded (percent, JSON escapes, HTML references, two rounds), NFKC-normalised and
// stripped of invisible and replacement characters: an encoded canary
// that survived is found too.
func Scan(where string, out []byte, cs []Canary) []Hit {
	var hits []Hit
	texts := []string{string(out)}
	// Two rounds: the record's JSON escapes ("\u0026") hide an HTML or
	// percent encoding beneath.
	for _, v := range pii.DetectionViews(string(out)) {
		for _, w := range pii.DetectionViews(v.Text) {
			texts = append(texts, w.Text, strings.ReplaceAll(w.Text, "\ufffd", ""))
		}
	}
	for _, c := range cs {
		for _, f := range Forms(c) {
			if f == "" {
				continue
			}
			for _, s := range texts {
				if strings.Contains(s, f) || strings.Contains(strings.ToLower(s), strings.ToLower(f)) {
					hits = append(hits, Hit{c, f, where})
					break
				}
			}
		}
		for _, f := range WordForms(c) {
			re := regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])` + regexp.QuoteMeta(f) + `(?:$|[^\p{L}\p{N}_])`)
			for _, s := range texts {
				if re.MatchString(s) {
					hits = append(hits, Hit{c, f, where})
					break
				}
			}
		}
	}
	return hits
}
