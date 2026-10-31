#!/bin/sh
# Runs every fuzz target of the module for FUZZTIME each (default 20s).
# CI runs it on every pull request; run it with a longer FUZZTIME locally.
#
# The Go fuzzer sometimes ends a clean run with "context deadline exceeded"
# when -fuzztime runs out while a worker is still busy, with no crasher.
# That exit is treated as a pass only when the output shows
# nothing else wrong: no "Failing input written" line, no panic, and no new
# or changed file under the target's testdata/fuzz directory. Anything else
# fails the run.
set -eu

cd "$(dirname "$0")/.."
fuzztime=${FUZZTIME:-20s}
log=$(mktemp)
trap 'rm -f "$log"' EXIT

# corpus_state prints a listing of the target's corpus files with checksums,
# so a new or rewritten crasher changes it.
corpus_state() {
	if [ -d "$1" ]; then
		find "$1" -type f -exec cksum {} + | sort
	fi
}

for pkg in $(go list ./...); do
	dir=$(go list -f '{{.Dir}}' "$pkg")
	targets=$(grep -h -o '^func Fuzz[A-Za-z0-9_]*' "$dir"/*_test.go 2>/dev/null | sed 's/^func //' || true)
	for t in $targets; do
		echo "fuzz: $pkg $t ($fuzztime)"
		corpus="$dir/testdata/fuzz/$t"
		before=$(corpus_state "$corpus")
		status=0
		go test "$pkg" -run '^$' -fuzz "^$t\$" -fuzztime "$fuzztime" -fuzzminimizetime 100x -parallel "${GOMAXPROCS:-2}" >"$log" 2>&1 || status=$?
		cat "$log"
		[ "$status" -eq 0 ] && continue
		after=$(corpus_state "$corpus")
		if grep -q 'context deadline exceeded' "$log" &&
			! grep -q -e 'Failing input written' -e '^panic:' -e 'fuzzing process hung' -e 'testdata/fuzz/' "$log" &&
			[ "$before" = "$after" ]; then
			echo "fuzz: $pkg $t: fuzzer ended with 'context deadline exceeded' and wrote no failing input; counted as a pass"
			continue
		fi
		echo "fuzz: $pkg $t failed (exit $status)" >&2
		exit "$status"
	done
done
