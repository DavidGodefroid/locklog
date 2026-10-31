//go:build !race

package engine

import "testing"

const raceEnabled = false

// heavyRace: see race_test.go; without -race every test runs.
func heavyRace(*testing.T) {}
