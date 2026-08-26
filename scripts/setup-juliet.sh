#!/bin/sh
# Fetch the NIST Juliet C/C++ test suite, the labelled ground truth
# `scripts/score-juliet.py` scores against.
#
# Not vendored: a 153 MB archive of third-party test code with its own
# provenance, and a measurement input rather than part of Kordon. The
# destination is gitignored for the same reason `third_party/` is.
#
# Read the caveats at the top of score-juliet.py before trusting the numbers.
set -e

DEST="${1:-third_party/juliet}"
URL="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

mkdir -p "$DEST"
cd "$DEST"

# Always resume rather than skipping when the file exists. This host drops the
# connection partway through more often than not, and an earlier version of
# this script treated any existing juliet.zip as complete -- so a truncated
# download was never finished and unzip was handed 70 MB of a 153 MB archive,
# which fails with "cannot find zipfile directory" and looks like a corrupt
# mirror rather than an interrupted transfer.
#
# curl exits 33 or 416 when the file is already whole and there is nothing to
# resume; neither is an error here.
echo "fetching Juliet 1.3 (153 MB, resumable) ..."
# HTTP/2 to this host resets mid-transfer; 1.1 plus retries gets through.
curl -fSL --http1.1 --retry 10 --retry-delay 3 --retry-all-errors \
     -C - -o juliet.zip "$URL" || rc=$?
case "${rc:-0}" in
    0|33) ;;
    *) echo "download incomplete (curl exit ${rc}); re-run to resume" >&2; exit 1 ;;
esac

# Verify before extracting. A truncated archive extracts partially and leaves a
# testcases/ tree that looks usable, which would silently shrink every score.
if ! unzip -tq juliet.zip >/dev/null 2>&1; then
    echo "juliet.zip is incomplete or corrupt; re-run to resume the download" >&2
    exit 1
fi

if [ ! -d C/testcases ]; then
    echo "extracting ..."
    unzip -q -o juliet.zip
fi

echo "Juliet ready at $DEST/C"
echo "score with: scripts/score-juliet.py $DEST/C"
