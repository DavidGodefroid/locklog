//go:build race

package engine

// raceEnabled: the race detector slows masking and evaluation several fold.
const raceEnabled = true
