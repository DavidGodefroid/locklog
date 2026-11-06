//go:build unix

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClearRecords: the clear view shows a record's pseudonymised values
// in clear, keeps secrets redacted, names a ref it cannot show, and takes
// the call's own records from its sink (nothing read again).
func TestClearRecords(t *testing.T) {
	line := "time=2026-10-30T12:00:01Z level=error msg=\"login failed for jane@example.com with password=hunter2hunter2\"\n"
	f := newFixture(t, line, nil)
	sink := NewClearSink()
	res, err := f.eng.Search(WithClearSink(ctx, sink), q(func(q *Query) { q.Limit = 1 }))
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("%v %d", err, len(res.Records))
	}
	m := rec(t, res.Records[0])
	ref := m["ref"].(string)
	if s, _ := m["msg"].(string); strings.Contains(s, "jane@example.com") || !strings.Contains(s, "⟦email:") {
		t.Fatalf("the search result is not masked: %v", m)
	}
	check := func(got []string) {
		t.Helper()
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
	// No sink: a local record is read again.
	check(f.eng.ClearRecords(ctx, nil, []string{ref, "Lr1.forged"}))
	// With the call's sink, nothing is read again: the file can be gone.
	scans := *f.scans
	if err := os.Remove(filepath.Join(f.root, "logs", "app.log")); err != nil {
		t.Fatal(err)
	}
	check(f.eng.ClearRecords(ctx, sink, []string{ref, "Lr1.forged"}))
	if *f.scans != scans {
		t.Error("the clear view scanned the source")
	}
	if got := f.eng.ClearRecords(ctx, nil, []string{ref}); !strings.HasPrefix(got[0], "(") {
		t.Errorf("a record gone without a sink: %s", got[0])
	}
}
