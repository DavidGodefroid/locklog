package parse

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// syslogFormat decodes syslog lines as files and relays write them:
//
//   - RFC 5424: `<165>1 2003-10-11T22:14:15.003Z host app 1234 ID47 [sd@1 k="v"] text`
//   - RFC 3164 (BSD), with or without `<PRI>`: `Oct 11 22:14:15 host app[1234]: text`,
//     also with an RFC 3339 timestamp (rsyslog's high-precision template).
//
// The header becomes fields (facility, level, host, app, pid, msgid, and
// structured data as one object per SD-ID); the text after it is the
// message. A 3164 timestamp has no year and no zone: it is read in the
// parser's location, in the latest year that does not put it more than a
// day in the future.
type syslogFormat struct{}

func (syslogFormat) Name() string { return "syslog" }

var (
	syslog5424Re = regexp.MustCompile(`^<([0-9]{1,3})>([1-9][0-9]{0,2}) (\S+) (\S{1,255}) (\S{1,48}) (\S{1,128}) (\S{1,32}) ?`)
	syslog3164Re = regexp.MustCompile(`^(?:<([0-9]{1,3})>)?(?:((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2})|([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2}))) ([^\s:\[\]]{1,255}) `)
	// syslogTagRe is a 3164 tag: "app:", "app[1234]:".
	syslogTagRe = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_./@-]{0,47})(?:\[([0-9]{1,10})\])?: ?`)
)

// syslogNow is the clock that places a year-less 3164 timestamp.
var syslogNow = time.Now

// syslogLevels are the RFC 5424 severities by number, as canonical levels.
var syslogLevels = [8]string{"emergency", "alert", "critical", "error", "warn", "notice", "info", "debug"}

var syslogFacilities = [24]string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}

// Detect accepts an RFC 5424 header, or an RFC 3164 header whose host is
// followed by a tag: a line that only starts with a date is plain text.
func (syslogFormat) Detect(line string) bool {
	if m := syslog5424Re.FindStringSubmatch(line); m != nil {
		_, ok := pri(m[1])
		return ok
	}
	m := syslog3164Re.FindStringSubmatchIndex(line)
	if m == nil || m[2] >= 0 && !validPri(line[m[2]:m[3]]) {
		return false
	}
	return syslogTagRe.MatchString(line[m[1]:])
}

func (f syslogFormat) Decode(text string, o *Options) (Event, bool) {
	if ev, ok := decode5424(text); ok {
		return ev, true
	}
	return decode3164(text, o)
}

func validPri(s string) bool { _, ok := pri(s); return ok }

// pri reads a PRI value (0..191).
func pri(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n > 191 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	return n, true
}

func priFields(p int) []Member {
	return []Member{strMember("facility", syslogFacilities[p>>3]), strMember("level", syslogLevels[p&7])}
}

func strMember(k, v string) Member { return Member{Key: k, Value: Value{Kind: KindString, Str: v}} }

func decode5424(text string) (Event, bool) {
	m := syslog5424Re.FindStringSubmatchIndex(text)
	if m == nil {
		return Event{}, false
	}
	g := func(i int) string { return text[m[2*i]:m[2*i+1]] }
	p, ok := pri(g(1))
	if !ok {
		return Event{}, false
	}
	ev := Event{Format: "syslog"}
	fields := priFields(p)
	if ts := g(3); ts != "-" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return Event{}, false
		}
		if t, ok := checkRange(t.UTC()); ok {
			ev.Time, ev.HasTime = t, true
		}
	}
	for i, k := range []string{"", "", "", "", "host", "app", "pid", "msgid"} {
		if k != "" && g(i) != "-" {
			fields = append(fields, strMember(k, g(i)))
		}
	}
	rest := text[m[1]:]
	if !strings.HasPrefix(rest, "-") || len(rest) > 1 && rest[1] != ' ' {
		sd, n, ok := structuredData(rest)
		if !ok {
			return Event{}, false
		}
		fields = append(fields, sd...)
		rest = rest[n:]
	} else {
		rest = rest[1:]
	}
	rest = strings.TrimPrefix(rest, " ")
	rest = strings.TrimPrefix(rest, "\ufeff") // the BOM of a UTF-8 MSG
	ev.Fields, ev.Message = fields, rest
	return ev, true
}

// structuredData reads RFC 5424 SD-ELEMENTs (`[id k="v" ...]...`): one
// object member per element, keyed by its SD-ID, with its params in order.
// It returns the bytes read.
func structuredData(s string) ([]Member, int, bool) {
	var out []Member
	i := 0
	for i < len(s) && s[i] == '[' {
		i++
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != ']' && s[j] != '=' && s[j] != '"' {
			j++
		}
		if j == i || j-i > 32 || j >= len(s) {
			return nil, 0, false
		}
		el := Member{Key: s[i:j], Value: Value{Kind: KindObject, Members: []Member{}}}
		i = j
		for i < len(s) && s[i] == ' ' {
			i++
			j = i
			for j < len(s) && s[j] != '=' && s[j] != ' ' && s[j] != ']' && s[j] != '"' {
				j++
			}
			if j == i || j-i > 32 || j+1 >= len(s) || s[j] != '=' || s[j+1] != '"' {
				return nil, 0, false
			}
			name := s[i:j]
			var b strings.Builder
			k := j + 2
			for ; k < len(s) && s[k] != '"'; k++ {
				if s[k] == '\\' && k+1 < len(s) && (s[k+1] == '"' || s[k+1] == '\\' || s[k+1] == ']') {
					k++
				}
				b.WriteByte(s[k])
			}
			if k >= len(s) {
				return nil, 0, false
			}
			el.Value.Members = append(el.Value.Members, strMember(name, b.String()))
			i = k + 1
		}
		if i >= len(s) || s[i] != ']' {
			return nil, 0, false
		}
		i++
		out = append(out, el)
	}
	if len(out) == 0 {
		return nil, 0, false
	}
	return out, i, true
}

func decode3164(text string, o *Options) (Event, bool) {
	m := syslog3164Re.FindStringSubmatchIndex(text)
	if m == nil {
		return Event{}, false
	}
	ev := Event{Format: "syslog"}
	var fields []Member
	if m[2] >= 0 {
		p, ok := pri(text[m[2]:m[3]])
		if !ok {
			return Event{}, false
		}
		fields = priFields(p)
	}
	if m[4] >= 0 {
		if t, ok := bsdTime(text[m[4]:m[5]], o.location()); ok {
			ev.Time, ev.HasTime = t, true
		}
	} else if t, err := time.Parse(time.RFC3339Nano, text[m[6]:m[7]]); err == nil {
		if t, ok := checkRange(t.UTC()); ok {
			ev.Time, ev.HasTime = t, true
		}
	}
	fields = append(fields, strMember("host", text[m[8]:m[9]]))
	rest := text[m[1]:]
	if t := syslogTagRe.FindStringSubmatchIndex(rest); t != nil {
		fields = append(fields, strMember("app", rest[t[2]:t[3]]))
		if t[4] >= 0 {
			fields = append(fields, strMember("pid", rest[t[4]:t[5]]))
		}
		rest = rest[t[1]:]
	}
	ev.Fields, ev.Message = fields, rest
	return ev, true
}

// bsdTime reads "Oct 11 22:14:15" in loc, in the latest year that does not
// put it more than a day after now.
func bsdTime(s string, loc *time.Location) (time.Time, bool) {
	now := syslogNow().In(loc)
	// A leap year, so that "Feb 29" parses; the year is chosen below.
	t, err := time.ParseInLocation("2006 Jan _2 15:04:05", "2000 "+s, loc)
	if err != nil {
		return time.Time{}, false
	}
	for y := now.Year() + 1; y >= now.Year()-8; y-- { // a Feb 29 goes back to a leap year
		c := time.Date(y, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
		if c.Day() != t.Day() {
			continue // Feb 29 outside a leap year
		}
		if !c.After(now.Add(24 * time.Hour)) {
			return checkRange(c.UTC())
		}
	}
	return time.Time{}, false
}
