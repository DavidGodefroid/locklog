package parse

import (
	"strconv"
	"strings"
	"time"
)

// timeKeys are the structured keys tried, in order, for an event's timestamp.
var timeKeys = []string{"@timestamp", "timestamp", "time", "ts", "t", "datetime", "date"}

// messageKeys are the structured keys tried, in order, for an event's message.
var messageKeys = []string{"msg", "message", "MESSAGE", "@message", "log"}

// Epoch bounds: plausible log timestamps lie between 1990 and 2200. Anything
// outside is not a timestamp (it is kept as a field).
var (
	minTime = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

// isoLayouts are the textual layouts accepted for timestamps, longest first.
// A layout without a zone is read in the reader's location (UTC by default).
var isoLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z0700",
	"2006-01-02 15:04:05.999999999 Z07:00",
	"2006-01-02 15:04:05.999999999 -0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05,999999999",
	"2006/01/02 15:04:05.999999999",
	"2006/01/02 15:04:05",
}

// ParseTime parses a textual timestamp (RFC 3339 and common ISO-8601 forms,
// or a decimal Unix epoch in s, ms, µs or ns). loc is used for zone-less
// layouts; nil means UTC.
func ParseTime(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	if loc == nil {
		loc = time.UTC
	}
	if c := s[0]; c >= '0' && c <= '9' && !strings.ContainsAny(s, "-/: T") {
		return parseEpoch(s)
	}
	for _, l := range isoLayouts {
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return checkRange(t.UTC())
		}
	}
	return time.Time{}, false
}

// parseEpoch reads a decimal epoch; its magnitude selects the unit. A
// fraction is accepted on seconds only.
func parseEpoch(s string) (time.Time, bool) {
	intPart, frac, hasFrac := strings.Cut(s, ".")
	if intPart == "" || len(intPart) > 19 || !digits(intPart) || (hasFrac && (frac == "" || !digits(frac))) {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var t time.Time
	switch {
	case n < 1e11: // seconds
		var ns int64
		if hasFrac {
			if len(frac) > 9 {
				frac = frac[:9]
			}
			ns, _ = strconv.ParseInt(frac+strings.Repeat("0", 9-len(frac)), 10, 64)
		}
		t = time.Unix(n, ns)
	case hasFrac:
		return time.Time{}, false
	case n < 1e14: // milliseconds
		t = time.UnixMilli(n)
	case n < 1e17: // microseconds
		t = time.UnixMicro(n)
	default: // nanoseconds
		t = time.Unix(0, n)
	}
	return checkRange(t.UTC())
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func checkRange(t time.Time) (time.Time, bool) {
	if t.Before(minTime) || !t.Before(maxTime) {
		return time.Time{}, false
	}
	return t, true
}

// leadingTime finds an ISO-8601 timestamp at the start of a free-text line,
// bare or inside "[...]". It returns the time and the rest of the line. A
// bare number is never a leading time.
func leadingTime(line string, loc *time.Location) (time.Time, string, bool) {
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 0 || end > 64 {
			return time.Time{}, line, false
		}
		if t, ok := isoTime(line[1:end], loc); ok {
			return t, strings.TrimLeft(line[end+1:], " \t"), true
		}
		return time.Time{}, line, false
	}
	if len(line) < 10 || line[0] < '0' || line[0] > '9' {
		return time.Time{}, line, false
	}
	// Candidates: the first one to three space-separated tokens
	// ("2006-01-02 15:04:05.000 +0000" uses three), longest first.
	// Token ends: positions of the first three runs of spaces or tabs.
	var ends []int
	for i := 0; i < len(line) && len(ends) < 3; {
		j := strings.IndexAny(line[i:], " \t")
		if j < 0 {
			break
		}
		ends = append(ends, i+j)
		i += j
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
	}
	ends = append(ends, len(line))
	for n := min(3, len(ends)); n >= 1; n-- {
		cand := line[:ends[n-1]]
		if strings.ContainsRune(cand, '\t') {
			continue // tokens of a timestamp are joined by spaces only
		}
		if t, ok := isoTime(cand, loc); ok {
			return t, strings.TrimLeft(line[ends[n-1]:], " \t"), true
		}
	}
	return time.Time{}, line, false
}

func isoTime(s string, loc *time.Location) (time.Time, bool) {
	if !strings.ContainsAny(s, "-/") {
		return time.Time{}, false
	}
	return ParseTime(s, loc)
}
