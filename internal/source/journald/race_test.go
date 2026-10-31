//go:build race

package journald

// raceSlowdown scales wall-clock bounds of tests: the race detector slows
// decoding several fold.
const raceSlowdown = 5
