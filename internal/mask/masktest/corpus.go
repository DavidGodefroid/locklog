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
}

// Kinds the generator plants. Every one is covered by a detector (or by
// SecretFinder, for "secret").
var Kinds = []string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn", "secret"}

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
		return SecretPrefix + g.hex(32)
	}
	panic("masktest: unknown kind " + kind)
}

func (g *Gen) hex(n int) string {
	const h = "0123456789abcdef"
	var b strings.Builder
	for range n {
		b.WriteByte(h[g.r.IntN(16)])
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

// SecretPrefix starts every synthetic secret; SecretFinder finds them.
// (A stand-in for lockkit's secret detectors, wired by a later change.)
const SecretPrefix = "sk_test_"

var secretRe = regexp.MustCompile(`sk_test_[0-9a-f]{32}`)

// SecretFinder finds the synthetic secrets, also through detection views.
type SecretFinder struct{}

// Find implements mask.Finder.
func (SecretFinder) Find(s string) []pii.Match {
	var out []pii.Match
	add := func(t string, src func(a, b int) (int, int)) {
		for _, loc := range secretRe.FindAllStringIndex(t, -1) {
			a, b := src(loc[0], loc[1])
			out = append(out, pii.Match{Start: a, End: b, Kind: "secret"})
		}
	}
	add(s, func(a, b int) (int, int) { return a, b })
	for _, v := range pii.DetectionViews(s) {
		add(v.Text, v.Source)
	}
	return out
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

func isAlnum(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// Lines generates n lines: every kind, in every position (JSON value,
// nested value, key, number, array item, logfmt value, free text) and
// every encoding, in turn.
func (g *Gen) Lines(n int) []Line {
	out := make([]Line, 0, n)
	for i := range n {
		kind := Kinds[i%len(Kinds)]
		enc := Encodings[(i/len(Kinds))%len(Encodings)]
		v := g.Value(kind)
		w := Encode(v, enc)
		ts := fmt.Sprintf("2026-10-30T14:%02d:%02d.%03dZ", (i/60)%60, i%60, i%1000)
		var text, format string
		jsonW := jsonEscape(w) // a json-u canary keeps its escapes: JSON decodes them
		if enc == "json-u" {
			jsonW = w
		}
		switch pos := (i / (len(Kinds) * len(Encodings))) % 8; pos {
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
		}
		out = append(out, Line{Text: text, Format: format, Canaries: []Canary{{kind, v}}})
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
	if c.Kind != "email" && c.Kind != "secret" {
		forms = append(forms, compact)
	}
	if c.Kind == "secret" {
		forms = append(forms, strings.TrimPrefix(v, SecretPrefix))
	}
	// Digit runs of 6+ of the value: a partial leak of a number.
	if c.Kind != "email" && c.Kind != "secret" && len(compact) >= 9 {
		forms = append(forms, compact[:7], compact[len(compact)-7:])
	}
	return forms
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
	}
	return hits
}
