#!/usr/bin/env bash
#
# Choose IKOS entry points for a translation unit: the roots of its call graph.
#
# IKOS analyses whole programs from `main`. Library code has none, so entry
# points must be named with -e. Two problems follow, and picking call-graph
# roots solves both at once.
#
# 1. WHICH NAMES. Symbols from llvm-nm are not what IKOS knows. C++ constructor
#    aliases in particular are rejected -- "could not find function
#    '_ZN3acl3AnyC1EOS0_'" -- because clang emits C1/C2 variants that do not
#    survive into IKOS's AR. Reading the names back out of the AR itself, after
#    ikos-pp and ikos-import, is exact by construction.
#
# 2. HOW MANY. A function analysed as an entry point has unconstrained
#    parameters, so every pointer and every scalar it receives is top. Name all
#    of them and the report fills with artifacts of that choice rather than
#    facts about the code. Name only the roots and every other function is
#    reached through a real call site, with real argument values.
#
# Measured on one real C translation unit (13 functions, 1 root):
#
#                              checks  safe  warnings
#     all 13 as entry points     1419  1316       103
#     call-graph roots only      1338  1271        67
#
#   The 36 warnings that disappear are exactly the artifacts: "variable might be
#   uninitialized" falls 35 -> 7 and "memory access might be invalid" 8 -> 0,
#   while "possible buffer overflow" stays at 60. Nothing real is lost.
#
# Usage: scripts/ikos-entry-points.sh <input.bc>      # prints one symbol per line

set -euo pipefail

BC="$1"
IKOS_BIN="${IKOS_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/third_party/ikos/bin}"

PP="$(mktemp --suffix=.bc)"
AR="$(mktemp --suffix=.ar)"
trap 'rm -f "${PP}" "${AR}"' EXIT

# ikos-import alone rejects constructs the analyzer never sees, such as `select`
# -- the preprocessor lowers them first. Running import on raw bitcode fails
# with "llvm select instructions are not supported" even when a full `ikos` run
# on the same file succeeds.
"${IKOS_BIN}/ikos-pp" "${BC}" -o "${PP}" >/dev/null 2>&1
"${IKOS_BIN}/ikos-import" --format=text "${PP}" -o "${AR}" >/dev/null 2>&1

python3 - "${AR}" <<'PY'
import re, sys
ar = open(sys.argv[1]).read()
# Functions are `define <type> @name(...)`. Bare `define @name, align ...` with
# no parameter list is a global variable, not a function.
defined = set(re.findall(r'^define [^\s]+ @([A-Za-z_][A-Za-z0-9_.]*)\(', ar, re.M))
called = set(re.findall(r'call @([A-Za-z_][A-Za-z0-9_.]*)\(', ar))
roots = sorted(defined - called)
# A unit whose every function is called from within it (mutual recursion, or a
# single cycle) has no root. Falling back to every function keeps it analysed,
# at the cost of the parameter artifacts described above.
print('\n'.join(roots if roots else sorted(defined)))
PY
