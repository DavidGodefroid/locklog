package parse

import (
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// combinedFormat decodes NCSA common and combined access logs (nginx's
// default, Apache's %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"),
// with any further quoted or bare fields after them kept in the message:
//
//	203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://ref/" "Mozilla/5.0"
//
// The request line is the message; the address, user, method, protocol,
// status, its class ("5xx"), size, referer and user agent are fields.
type combinedFormat struct{}

func (combinedFormat) Name() string { return "combined" }

var combinedRe = regexp.MustCompile(`^(\S{1,255}) (\S{1,255}) (\S{1,255}) \[([0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4})\] "((?:[^"\\]|\\.)*)" ([1-5][0-9]{2}|-) ([0-9]{1,20}|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(?: (.*))?$`)

// Detect needs the "[" of the timestamp within the first 800 bytes (three
// fields of at most 255 bytes) before it runs the expression.
func (combinedFormat) Detect(line string) bool {
	if strings.IndexByte(line[:min(len(line), 800)], '[') < 0 {
		return false
	}
	return combinedMatch(line) != nil
}

// combinedMatch returns combinedRe.FindStringSubmatchIndex(text), computed
// by hand: the expression's NFA dominated the decoding of access logs (and
// so the local index's backfill). FuzzCombinedMatch holds the two equal.
func combinedMatch(text string) []int {
	m := make([]int, 22)
	for i := range m {
		m[i] = -1
	}
	m[0] = 0
	i := 0
	// Three space-separated fields of 1 to 255 non-space runes.
	for g := 1; g <= 3; g++ {
		j := i
		for j < len(text) && text[j] != ' ' {
			switch text[j] {
			case '\t', '\n', '\f', '\r':
				return nil
			}
			j++
		}
		// Runes as the expression steps them (an invalid byte is one).
		if n := utf8.RuneCountInString(text[i:j]); n < 1 || n > 255 || j >= len(text) {
			return nil
		}
		m[2*g], m[2*g+1] = i, j
		i = j + 1
	}
	// [dd/Mmm/yyyy:hh:mm:ss +zzzz]
	const tsLen = 26
	if len(text) < i+tsLen+2 || text[i] != '[' || text[i+tsLen+1] != ']' {
		return nil
	}
	ts := text[i+1 : i+1+tsLen]
	for k := 0; k < tsLen; k++ {
		c := ts[k]
		var ok bool
		switch k {
		case 2, 6:
			ok = c == '/'
		case 11, 14, 17:
			ok = c == ':'
		case 20:
			ok = c == ' '
		case 21:
			ok = c == '+' || c == '-'
		case 3:
			ok = c >= 'A' && c <= 'Z'
		case 4, 5:
			ok = c >= 'a' && c <= 'z'
		default:
			ok = c >= '0' && c <= '9'
		}
		if !ok {
			return nil
		}
	}
	m[8], m[9] = i+1, i+1+tsLen
	i += tsLen + 2
	// "request"
	if len(text) < i+2 || text[i] != ' ' || text[i+1] != '"' {
		return nil
	}
	j, ok := combinedQuoted(text, i+2)
	if !ok {
		return nil
	}
	m[10], m[11] = i+2, j
	i = j + 1
	// status
	if i >= len(text) || text[i] != ' ' {
		return nil
	}
	i++
	switch {
	case i < len(text) && text[i] == '-':
		m[12], m[13] = i, i+1
		i++
	case i+3 <= len(text) && text[i] >= '1' && text[i] <= '5' && isDigit(text[i+1]) && isDigit(text[i+2]):
		m[12], m[13] = i, i+3
		i += 3
	default:
		return nil
	}
	// bytes
	if i >= len(text) || text[i] != ' ' {
		return nil
	}
	i++
	if i < len(text) && text[i] == '-' {
		m[14], m[15] = i, i+1
		i++
	} else {
		j := i
		for j < len(text) && isDigit(text[j]) {
			j++
		}
		if j == i || j-i > 20 {
			return nil
		}
		m[14], m[15] = i, j
		i = j
	}
	// The rest: ( "referer" "user agent")? ( extra)? to the end, the
	// optional groups tried first, as the expression does.
	rest := func(i int, m []int) bool {
		switch {
		case i == len(text):
			return true
		case text[i] == ' ' && strings.IndexByte(text[i+1:], '\n') < 0:
			m[20], m[21] = i+1, len(text)
			return true
		}
		return false
	}
	if i+1 < len(text) && text[i] == ' ' && text[i+1] == '"' {
		a := slices.Clone(m)
		if j, ok := combinedQuoted(text, i+2); ok && j+2 < len(text) && text[j+1] == ' ' && text[j+2] == '"' {
			if k, ok := combinedQuoted(text, j+3); ok {
				a[16], a[17], a[18], a[19] = i+2, j, j+3, k
				if rest(k+1, a) {
					a[1] = len(text)
					return a
				}
			}
		}
	}
	if !rest(i, m) {
		return nil
	}
	m[1] = len(text)
	return m
}

// combinedQuoted scans a quoted field's content from i: ((?:[^"\\]|\\.)*)
// then the closing quote, whose index it returns.
func combinedQuoted(text string, i int) (int, bool) {
	for i < len(text) {
		switch text[i] {
		case '"':
			return i, true
		case '\\':
			if i+1 >= len(text) || text[i+1] == '\n' {
				return 0, false
			}
			i += 2
		default:
			i++
		}
	}
	return 0, false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (combinedFormat) Decode(text string, o *Options) (Event, bool) {
	// Detect's checks, with the expression run once.
	if strings.IndexByte(text[:min(len(text), 800)], '[') < 0 {
		return Event{}, false
	}
	m := combinedMatch(text)
	if m == nil {
		return Event{}, false
	}
	g := func(i int) (string, bool) {
		if m[2*i] < 0 {
			return "", false
		}
		return text[m[2*i]:m[2*i+1]], true
	}
	ev := Event{Format: "combined"}
	if ts, _ := g(4); ts != "" {
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts); err == nil {
			if t, ok := checkRange(t.UTC()); ok {
				ev.Time, ev.HasTime = t, true
			}
		}
	}
	var fields []Member
	add := func(k, v string) {
		if v != "-" && v != "" {
			fields = append(fields, strMember(k, v))
		}
	}
	addr, _ := g(1)
	add("remote_addr", addr)
	ident, _ := g(2)
	add("ident", ident)
	user, _ := g(3)
	add("remote_user", user)
	req, _ := g(5)
	req = unescapeCLF(req)
	if parts := strings.Fields(req); len(parts) == 3 && isToken(parts[0]) && strings.HasPrefix(parts[2], "HTTP/") {
		add("method", parts[0])
		add("protocol", parts[2])
	}
	if st, _ := g(6); st != "-" {
		fields = append(fields, Member{Key: "status", Value: Value{Kind: KindNumber, Str: st}}, strMember("status_class", st[:1]+"xx"))
	}
	if b, _ := g(7); b != "-" {
		if t := strings.TrimLeft(b, "0"); t != "" {
			b = t // a JSON number literal has no leading zero
		} else {
			b = "0"
		}
		fields = append(fields, Member{Key: "bytes", Value: Value{Kind: KindNumber, Str: b}})
	}
	if ref, ok := g(8); ok {
		add("referer", unescapeCLF(ref))
		ua, _ := g(9)
		add("user_agent", unescapeCLF(ua))
	}
	ev.Fields, ev.Message = fields, req
	if extra, ok := g(10); ok && extra != "" {
		ev.Message = req + " " + extra
	}
	return ev, true
}

// isToken reports an HTTP method token.
func isToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// unescapeCLF undoes the escaping nginx and Apache apply inside quoted
// fields (\" and \\; \xHH stays as written).
func unescapeCLF(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
