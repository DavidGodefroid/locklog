package parse

import (
	"strconv"
	"strings"
)

// logfmtFormat decodes key=value lines (`level=error msg="upstream timed
// out" status=502`). A bare key is a boolean true; a quoted value is
// unescaped as a Go string literal; numeric-looking values are numbers with
// their literal kept.
type logfmtFormat struct{}

func (logfmtFormat) Name() string { return "logfmt" }

func (logfmtFormat) Starts(string) bool { return true }

// Detect requires at least two pairs, the first token a pair, and at least
// two thirds of the tokens pairs.
func (logfmtFormat) Detect(line string) bool {
	_, pairs, tokens, ok := scanLogfmt(line)
	return ok && pairs >= 2 && pairs*3 >= tokens*2 && firstIsPair(line)
}

func firstIsPair(line string) bool {
	s := strings.TrimLeft(line, " \t")
	i := strings.IndexAny(s, " \t=")
	return i > 0 && s[i] == '='
}

func (logfmtFormat) Decode(text string, o *Options) (Event, bool) {
	members, pairs, _, ok := scanLogfmt(text)
	if !ok || pairs == 0 {
		return Event{}, false
	}
	ev := Event{Format: "logfmt"}
	ev.Fields = liftTimeAndMessage(&ev, members, o)
	return ev, true
}

// scanLogfmt tokenises a logfmt line. It reports the members, the number of
// key=value pairs, the number of tokens, and false on a malformed line
// (unterminated quote, invalid key).
func scanLogfmt(line string) (members []Member, pairs, tokens int, ok bool) {
	s := line
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return members, pairs, tokens, true
		}
		tokens++
		// Key: up to '=', space or end; no quotes or controls.
		i := 0
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			if s[i] == '"' || s[i] < 0x20 || s[i] == 0x7f {
				return nil, 0, 0, false
			}
			i++
		}
		key := s[:i]
		if key == "" || len(key) > MaxKeyBytes {
			return nil, 0, 0, false
		}
		s = s[i:]
		if s == "" || s[0] != '=' {
			members = append(members, Member{Key: key, Value: Value{Kind: KindBool, Str: "true"}})
			continue
		}
		s = s[1:]
		pairs++
		if strings.HasPrefix(s, `"`) {
			end, val, good := quoted(s)
			if !good {
				return nil, 0, 0, false
			}
			members = append(members, Member{Key: key, Value: Value{Kind: KindString, Str: val}})
			s = s[end:]
			continue
		}
		j := strings.IndexAny(s, " \t")
		if j < 0 {
			j = len(s)
		}
		raw := s[:j]
		s = s[j:]
		members = append(members, Member{Key: key, Value: scalar(raw)})
	}
}

// quoted reads a double-quoted value at the start of s and returns the index
// after the closing quote and the unescaped value.
func quoted(s string) (int, string, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			lit := s[:i+1]
			if v, err := strconv.Unquote(lit); err == nil {
				// Escapes such as \x80 may produce invalid UTF-8.
				return i + 1, validText([]byte(v)), true
			}
			// Not a valid Go literal (e.g. a lone `\x`): keep the
			// text between the quotes as is.
			return i + 1, lit[1 : len(lit)-1], true
		}
	}
	return 0, "", false
}

// scalar classifies an unquoted logfmt value.
func scalar(raw string) Value {
	switch raw {
	case "":
		return Value{Kind: KindString, Str: ""}
	case "true", "false":
		return Value{Kind: KindBool, Str: raw}
	case "null", "nil":
		return Value{Kind: KindNull}
	}
	if isNumber(raw) {
		return Value{Kind: KindNumber, Str: raw}
	}
	return Value{Kind: KindString, Str: raw}
}

// isNumber reports whether s is a JSON number literal.
func isNumber(s string) bool {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	if i >= len(s) {
		return false
	}
	if s[i] == '0' {
		i++
	} else if s[i] >= '1' && s[i] <= '9' {
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	} else {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		if i >= len(s) || s[i] < '0' || s[i] > '9' {
			return false
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		if i >= len(s) || s[i] < '0' || s[i] > '9' {
			return false
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	return i == len(s)
}
