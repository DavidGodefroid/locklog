//go:build race

package engine

import "testing"

// raceEnabled: the race detector slows masking and evaluation several fold.
const raceEnabled = true

// heavyRace skips, under -race -short (the CI race job), a test that
// replays large corpora through whole queries: it runs in full in the test
// jobs, without the race detector, and the concurrent paths it exercises
// (masking workers, remote fetches, frozen plans, caches) are raced by the
// lighter tests.
func heavyRace(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("heavy under -race -short: runs in full without -race")
	}
}
