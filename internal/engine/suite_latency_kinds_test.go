//go:build unix

package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
)

// latencyPair returns two values of kind of the same length (and, for a
// secret, the same token shape): a record's bytes do not tell them apart,
// only their clear text does.
func latencyPair(t testing.TB, kind string) (string, string) {
	g := masktest.New(1616)
	a := g.Value(kind)
	shape := func(v string) string {
		return strings.TrimRightFunc(v[:min(len(v), 8)], func(r rune) bool { return r != '_' && r != '-' })
	}
	for range 100000 {
		b := g.Value(kind)
		if b != a && len(b) == len(a) && (kind != "secret" || shape(b) == shape(a)) {
			return a, b
		}
	}
	t.Fatalf("no second %s like %q", kind, a)
	return "", ""
}

// TestSuiteOracleLatencyKinds is the latency case beyond email (#63): a
// secret kind as well as an email, each in a structured source (json, the
// value in the message) and a free-text one (plain lines), compared as
// TestSuiteOracleLatency compares them (on 2000 records a source, to keep
// the suites job's time): 25 interleaved runs per call, on
// the production (redact-unknown) and non-production (detect) defaults with
// mask-all, a call failing when its medians are more than 5% + 5 ms apart
// and a Mann-Whitney test finds a difference (|z| > 4). The pre-filter
// (opt-in, refused on production) is the control: the harness must see
// its latency on every kind and source. The CPU-hog variants stay with
// TestSuiteOracleLatency (the email case): they test the comparison under
// noise, not the kinds.
func TestSuiteOracleLatencyKinds(t *testing.T) {
	timingCase(t)
	const n = 25
	for _, kind := range []string{"secret", "email"} {
		a, b := latencyPair(t, kind)
		// A needle in A's clear text only: a slice of its random part.
		needle := a[len(a)-10:]
		if kind == "email" {
			needle = a[:strings.IndexByte(a, '@')]
		}
		if strings.Contains(b, needle) {
			t.Fatalf("%s: the needle %q is in both values", kind, needle)
		}
		for _, src := range []string{"json", "plain"} {
			corpus := func(v string) map[string][]suiteRecord {
				var rs []suiteRecord
				for j := range 2000 {
					// Kind "text": json writes it as the msg field, plain
					// as a free-text line after the time and level.
					rs = append(rs, suiteRecord{TS: suiteBase.Add(time.Duration(j) * time.Second), Kind: "text",
						Payload: fmt.Sprintf("login for %s rejected: upstream timed out (attempt %d)", v, j)})
				}
				return map[string][]suiteRecord{src: rs}
			}
			calls := []agentCall{
				{"text", MethodSearch, suiteQuery(func(q *Query) { q.Text = needle; q.Limit = 200 })},
				{"count text", MethodCount, CountQuery{Query: suiteQuery(func(q *Query) { q.Text = needle }), Bucket: "10m"}},
			}
			for _, tc := range []struct {
				name       string
				structured string
				prefilter  bool
			}{
				{"production", mask.StructuredRedactUnknown, false},
				{"non-production", mask.StructuredDetect, false},
				{"non-production pre-filter (control)", mask.StructuredDetect, true},
			} {
				t.Run(kind+"/"+src+"/"+tc.name, func(t *testing.T) {
					ep, _ := pii.NewEpoch(suiteBase)
					cfg := suiteConfig{Structured: tc.structured, Prefilter: tc.prefilter, Epoch: ep, Workers: 2}
					sa := newSuite(t, corpus(a), cfg)
					sb := newSuite(t, corpus(b), cfg)
					for _, v := range []string{a, b} {
						if got := sa.masker.Text(v); !placeholder.MatchString(got) || strings.Contains(got, v) {
							t.Fatalf("%s %q masks as %q", kind, v, got)
						}
					}
					for _, c := range calls {
						if tc.prefilter && c.name != "text" {
							// Counts never use the pre-filter: nothing
							// for the control to see.
							continue
						}
						xa, xb := latencySamples(sa, sb, c, n)
						z := mannWhitneyZ(xa, xb)
						ma, mb := median(slices.Clone(xa)), median(slices.Clone(xb))
						t.Logf("%s: median %v vs %v, Mann-Whitney z %.2f", c.name, ma, mb, z)
						if tc.prefilter {
							// The control: the needle is in A's clear
							// text only, so A masks every record and B
							// none.
							if ma < 2*mb || z < 4 {
								t.Errorf("%s: the harness does not see the pre-filter's latency: %v vs %v (z %.2f)", c.name, ma, mb, z)
							}
							continue
						}
						lo, hi := min(ma, mb), max(ma, mb)
						if hi-lo > lo/20+5*time.Millisecond && (z > 4 || z < -4) {
							t.Errorf("%s: latency tells the planted values apart: median %v vs %v, z %.2f", c.name, ma, mb, z)
						}
					}
				})
			}
		}
	}
}
