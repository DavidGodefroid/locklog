#!/bin/sh
# Public-repository hygiene: no employer, client or internal host name in
# any tracked file, examples included. Run in CI and before every push.
# Exit 0 when clean; 1 and the matching lines otherwise.
set -eu

cd "$(dirname "$0")/.."

# The patterns are written split so that this file does not match itself.
pattern='ip''ex|ki''so|full''data|her''dr|eb''ox|pep''pol|bp''ost|mail''id'

if git grep -n -i -I -w -E "$pattern" -- . ':!scripts/hygiene.sh'; then
	echo "hygiene: the lines above name an internal or third-party system; use neutral names (example.com, orders, payments)" >&2
	exit 1
fi
echo "hygiene: clean"
