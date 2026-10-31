package parse

import (
	"regexp"
	"strings"
	"time"
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
	return combinedRe.MatchString(line)
}

func (combinedFormat) Decode(text string, o *Options) (Event, bool) {
	if !(combinedFormat{}).Detect(text) {
		return Event{}, false
	}
	m := combinedRe.FindStringSubmatchIndex(text)
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
