#!/bin/sh
# Runs every fuzz target of the module for FUZZTIME each (default 20s).
# CI runs it on every pull request; run it longer locally or nightly.
set -eu

cd "$(dirname "$0")/.."
fuzztime=${FUZZTIME:-20s}

for pkg in $(go list ./...); do
	dir=$(go list -f '{{.Dir}}' "$pkg")
	targets=$(grep -h -o '^func Fuzz[A-Za-z0-9_]*' "$dir"/*_test.go 2>/dev/null | sed 's/^func //' || true)
	for t in $targets; do
		echo "fuzz: $pkg $t ($fuzztime)"
		go test "$pkg" -run '^$' -fuzz "^$t\$" -fuzztime "$fuzztime"
	done
done
