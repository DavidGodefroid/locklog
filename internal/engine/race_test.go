//go:build race

package engine

import "testing"

// raceEnabled: the race detector slows masking and evaluation several fold.
const raceEnabled = true

// heavyRace skips, under -race -short (the CI race job), a test that
// replays large corpora through whole queries: it runs in full in the test
// jobs, without the race detector. The engine's own goroutines (the mask
// worker handoff, background calibration, remote fetches) stay raced by
// the lighter tests; what is skipped is race checking of sequential
// whole-query flows (cursors, continuations, admission).
func heavyRace(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("heavy under -race -short: runs in full without -race")
	}
}
