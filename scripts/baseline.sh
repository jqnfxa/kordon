#!/usr/bin/env bash
#
# Re-measure the whole static baseline and diff it against the committed one.
#
#   scripts/baseline.sh                       # 26 CWEs x 40 files, ~4 minutes
#   scripts/baseline.sh --ctu                 # same, with cross-TU analysis
#   OUT=/tmp/x.json scripts/baseline.sh       # keep the result somewhere else
#
# Writes to $OUT (default: a file in the scratch dir, never the committed
# baseline). Only the integrator writes data/juliet-baseline.json, and only
# after the change is understood -- lanes report their before/after numbers
# in their lane brief instead, so nine lanes do not fight over one file.
#
# Any argument is passed to kordon (--ctu, --ikos). The baseline it is
# compared against must have been taken with the same flags, or the diff
# measures the flags rather than the change: data/juliet-baseline.json is
# default flags; data/juliet-multifile-ctu.json is --multifile with --ctu.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

JULIET="${KORDON_JULIET:-$ROOT/third_party/juliet/C}"
[ -d "$JULIET/testcases" ] || { echo "no Juliet at $JULIET -- scripts/setup-juliet.sh" >&2; exit 1; }
[ -x target/release/kordon ] || { echo "no target/release/kordon -- cargo build --release" >&2; exit 1; }

OUT="${OUT:-${TMPDIR:-/tmp}/kordon-baseline-$(git rev-parse --short HEAD)-$(date +%H%M%S).json}"
BASE="${BASE:-data/juliet-baseline.json}"

args=()
for a in "$@"; do args+=("--kordon-arg=$a"); done

echo "scoring 26 CWEs x 40 files${*:+ with $*} -> $OUT"
scripts/score-juliet.py "$JULIET" --limit 40 --json-out "$OUT" "${args[@]}" | tail -6
echo
echo "against $BASE:"
scripts/compare-baselines.py "$BASE" "$OUT" || true
echo
echo "result kept at $OUT"
