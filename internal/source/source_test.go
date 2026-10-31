package source

import (
	"testing"
	"time"
)

func TestSelectorMatch(t *testing.T) {
	sel := Selector{Terms: []Term{{Field: "level", Op: "in", Values: []string{"error", "fatal"}}, {Field: "app", Op: "!=", Values: []string{"db"}}}}
	for vals, want := range map[*map[string]string]bool{
		{"level": "error", "app": "api"}: true,
		{"level": "error"}:               true,
		{"level": "error", "app": "db"}:  false,
		{"level": "info", "app": "api"}:  false,
		{"app": "api"}:                   false,
	} {
		if got := sel.Match(*vals); got != want {
			t.Fatalf("%v: %v", *vals, got)
		}
	}
	if (Selector{Terms: []Term{{Field: "a", Op: "~", Values: []string{"x"}}}}).Match(map[string]string{"a": "x"}) {
		t.Fatal("unknown op matched")
	}
}

func TestRange(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := Range{From: t0, To: t0.Add(time.Hour)}
	if !r.Contains(t0) || r.Contains(t0.Add(time.Hour)) || !r.Overlaps(t0.Add(-time.Minute), t0) || r.Overlaps(t0.Add(time.Hour), t0.Add(2*time.Hour)) {
		t.Fatal("range bounds")
	}
	p := Byteplan{Chunks: []Chunk{{Granules: []Granule{{Start: 0, End: 10}, {Start: 10, End: 15}}, Bytes: 15}, {Granules: []Granule{{Start: 0, End: 3}}, Bytes: 3}}}
	if p.Bytes() != 18 || p.Granules() != 3 || p.Chunks[0].Start() != 0 || p.Chunks[0].End() != 15 {
		t.Fatal("plan sums")
	}
}
