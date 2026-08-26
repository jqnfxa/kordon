#!/bin/sh
# Fetch ESBMC, the bounded model checker evaluated in docs/esbmc-evaluation.md.
#
# Not vendored, and not only for size. ESBMC links SMT solvers whose licences
# differ sharply: Z3, Boolector and Bitwuzla are MIT and CVC4 is BSD, but
# MathSAT is non-commercial and Yices is personal-use/GPL3. Always pass --z3
# explicitly rather than trusting whatever the build defaults to.
#
# ESBMC's own code is Apache 2.0 and the CBMC base is BSD 4-clause. Kordon
# invokes it as a subprocess, so none of this reaches Kordon's own licence.
set -e

DEST="${1:-third_party/esbmc}"
VER="${2:-v8.4}"
URL="https://github.com/esbmc/esbmc/releases/download/${VER}/esbmc-linux.zip"

mkdir -p "$DEST"
cd "$DEST"

if [ ! -x bin/esbmc ]; then
    echo "fetching ESBMC ${VER} ..."
    curl -fSL --http1.1 --retry 10 --retry-delay 3 --retry-all-errors \
         -C - -o esbmc-linux.zip "$URL" || rc=$?
    case "${rc:-0}" in 0|33) ;; *) echo "download incomplete; re-run" >&2; exit 1 ;; esac
    unzip -tq esbmc-linux.zip >/dev/null 2>&1 || {
        echo "archive incomplete or corrupt; re-run to resume" >&2; exit 1; }
    unzip -q -o esbmc-linux.zip
    chmod +x bin/esbmc
fi

./bin/esbmc --version
echo "read docs/esbmc-evaluation.md before trusting a number from this"
