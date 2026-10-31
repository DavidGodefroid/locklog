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
	strings.Repeat("a", 255) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
	strings.Repeat("a", 256) + ` - - [10/Oct/2000:13:55:36 +0000] "GET" 200 1`,
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
