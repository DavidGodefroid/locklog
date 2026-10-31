package engine

import (
	"strings"

	"github.com/DavidGodefroid/locklog/internal/parse"
)

// Opt-in pre-filter (design §4.4 rule 2, non-production only): a record is
// masked only if its clear text could contain every needle. It is exact:
// a needle (printable, without placeholder brackets or U+FFFD, validated)
// found in the evaluation string E lies inside one unmasked segment of a
// masked string, which is a substring of the clear message or of a clear
// string leaf; so a record skipped here could not have matched. Its residual
// (latency reveals how many records contain a clear substring) is shown at
// the policy review and documented.
//
// Nothing a call returns depends on the filter: scanned.records counts the
// records fetched before it, and stopping points are plan-based as without
// it. Mask failures are the exception it forces: only the records that pass
// are masked, so a failure count would tell whether a failing record's clear
// text holds the needle. With the filter on (and a needle in the query),
// failures are therefore not counted at all: masked_failures stays 0 and
// no granule is skipped for its failures, while a record that fails is still
// withheld whole (it never matches). Masking the skipped records instead would remove the
// filter's only purpose. The weaker failure signal is a reason the filter is
// refused on production.

// prefilterPass reports whether the record's clear message or one of its
// string or number leaves contains every needle.
func prefilterPass(ev parse.Event, needles []string) bool {
	texts := clearTexts(ev)
	for _, n := range needles {
		found := false
		for _, t := range texts {
			if strings.Contains(t, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func clearTexts(ev parse.Event) []string {
	out := []string{ev.Message}
	var walk func(v parse.Value)
	walk = func(v parse.Value) {
		switch v.Kind {
		case parse.KindString, parse.KindNumber, parse.KindBool:
			out = append(out, v.Str)
		case parse.KindObject:
			for _, m := range v.Members {
				walk(m.Value)
			}
		case parse.KindArray:
			for _, it := range v.Items {
				walk(it)
			}
		}
	}
	for _, m := range ev.Fields {
		walk(m.Value)
	}
	for _, m := range ev.Attrs {
		walk(m.Value)
	}
	return out
}
