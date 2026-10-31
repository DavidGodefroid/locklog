package engine

import (
	"strings"
	"testing"
)

// TestClearRecords: the clear view shows a record's pseudonymised values
// in clear, keeps secrets redacted, and names a ref it cannot show.
func TestClearRecords(t *testing.T) {
	line := "time=2026-10-30T12:00:01Z level=error msg=\"login failed for jane@example.com with password=hunter2hunter2\"\n"
	f := newFixture(t, line, nil)
	ref, m := firstRef(t, f, func(q *Query) {})
	if s, _ := m["msg"].(string); strings.Contains(s, "jane@example.com") || !strings.Contains(s, "⟦email:") {
		t.Fatalf("the search result is not masked: %v", m)
	}
	got := f.eng.ClearRecords(ctx, []string{ref, "Lr1.forged"})
	if len(got) != 2 {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(got[0], "jane@example.com") || strings.Contains(got[0], "⟦email:") || strings.Contains(got[0], "hunter2") || !strings.Contains(got[0], "⟦secret⟧") {
		t.Errorf("clear view: %s", got[0])
	}
	if got[1] != "(the record's reference is no longer valid)" {
		t.Errorf("forged ref: %s", got[1])
	}
}
