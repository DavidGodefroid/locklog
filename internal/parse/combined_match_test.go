package parse

import (
	"slices"
	"strings"
	"testing"
)

// combinedMatchSeeds are the edges of the combined expression.
var combinedMatchSeeds = []string{
	`203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://ref/" "Mozilla/5.0"`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 `,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" - - "a" "b" extra fields "x"`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET \"q\" \\ HTTP/1.0" 502 0 "a\"b" "c"x`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 12 "a" "b"` + "\n" + `next`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 12 "a" "b" x` + "\n" + `y`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GE` + "\n" + `T" 200 12`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET \` + "\n" + `" 200 12`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET" 600 12`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET" 200 123456789012345678901`,
	`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET" 200 12345678901234567890 "a"`,
	`203.0.113.7 - - [10/oct/2000:13:55:36 -0700] "GET" 200 1`,
	`203.0.113.7  - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1`,
	"203.0.113.7\t- - [10/Oct/2000:13:55:36 -0700] \"GET\" 200 1",
	"20\v3 - - [10/Oct/2000:13:55:36 -0700] \"GET\" 200 1",
	"\xff\xfe - - [10/Oct/2000:13:55:36 -0700] \"G\xffET\" 200 1",
	strings.Repeat("é", 255) + ` - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1`,
	strings.Repeat("é", 256) + ` - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1`,
	strings.Repeat("\U0001F600", 255) + " " + strings.Repeat("\U0001F600", 255) + " " + strings.Repeat("\U0001F600", 255) + ` [10/Oct/2000:13:55:36 -0700] "GET" 200 1`,
	strings.Repeat("a", 255) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	strings.Repeat("a", 256) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	strings.Repeat("\xff", 1020) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	strings.Repeat("\xff", 1021) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	strings.Repeat("\U0001F600", 256) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	`a - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1 "a" "b`,
	`a - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1 "a"  "b"`,
	`a - - [10/Oct/2000:13:55:36 -0700] "GET" 200 1 "a" "b" `,
	`a - - [10/Oct/2000:13:55:36 -0700]  "GET" 200 1`,
	`a - - [10/Oct/2000:13:55:36 -0700] "GET`,
	`a - -`,
	``,
}

func TestCombinedMatchEqualsExpression(t *testing.T) {
	for _, s := range combinedMatchSeeds {
		want := combinedRe.FindStringSubmatchIndex(s)
		if got := combinedMatch(s); !slices.Equal(got, want) {
			t.Errorf("%q:\n got %v\nwant %v", s, got, want)
		}
	}
}

func BenchmarkCombinedMatch(b *testing.B) {
	line := combinedMatchSeeds[0]
	b.Run("hand", func(b *testing.B) {
		for range b.N {
			combinedMatch(line)
		}
	})
	b.Run("regexp", func(b *testing.B) {
		for range b.N {
			combinedRe.FindStringSubmatchIndex(line)
		}
	})
}

// TestCombinedLongMultibyteFields: the three leading fields are at most 255
// runes each, not 255 bytes, so the "[" of a valid line can sit far past
// byte 800 (#85).
func TestCombinedLongMultibyteFields(t *testing.T) {
	f := strings.Repeat("\U0001F600", 255) // 4 bytes per rune
	line := f + " " + f + " " + f + ` [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 1`
	if strings.IndexByte(line, '[') < 800 {
		t.Fatal("the seed must put the timestamp past byte 800")
	}
	if combinedRe.FindStringSubmatchIndex(line) == nil {
		t.Fatal("the expression must match the seed")
	}
	var c combinedFormat
	if !c.Detect(line) {
		t.Fatal("Detect refused a valid line")
	}
	ev, ok := c.Decode(line, &Options{})
	if !ok || ev.Message != "GET / HTTP/1.0" || !ev.HasTime {
		t.Fatalf("Decode: %v %+v", ok, ev)
	}
	if v, _ := Get(ev.Fields, "remote_addr"); v.Str != f {
		t.Fatalf("remote_addr %q", v.Str)
	}
}
