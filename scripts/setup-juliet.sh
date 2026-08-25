#!/bin/sh
# Fetch the NIST Juliet C/C++ test suite, the labelled ground truth
# `scripts/score-juliet.py` scores against.
#
# Not vendored: it is a 153 MB archive of third-party test code with its own
# provenance, and it is a measurement input rather than part of Kordon. The
# destination is gitignored for the same reason `third_party/` is.
#
# Read the caveats at the top of score-juliet.py before trusting the numbers.
set -e

DEST="${1:-third_party/juliet}"
URL="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

mkdir -p "$DEST"
cd "$DEST"

if [ ! -f juliet.zip ]; then
    echo "fetching Juliet 1.3 (153 MB) ..."
    # HTTP/2 to this host resets mid-transfer; 1.1 plus resume gets through.
    curl -fSL --http1.1 --retry 5 --retry-delay 2 -C - -o juliet.zip "$URL"
fi

if [ ! -d C/testcases ]; then
    echo "extracting ..."
    unzip -q -o juliet.zip
fi

echo "Juliet ready at $DEST/C"
echo "score with: scripts/score-juliet.py $DEST/C"
