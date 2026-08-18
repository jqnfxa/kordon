#!/usr/bin/env bash
#
# Produce IKOS-readable bitcode for one translation unit.
#
# Three things have to be right, all of them measured rather than assumed:
#
#   1. The bitcode must come from clang-14. IKOS 3.5 links LLVM 14 and simply
#      rejects an LLVM 18 module -- verified: 18 REJECTED, 14 READABLE.
#
#   2. It must be -O0. At -O1 clang folds expressions like `n - 1` into the
#      address computation and the debug location collapses, so findings can no
#      longer be reported at the line the code was written on.
#
#   3. `fneg` must be lowered. IKOS 3.5's bitcode importer does not implement
#      it -- "unsupported llvm instruction fneg" -- and clang emits it for every
#      floating-point negation. That is fatal for numerical code, which is
#      precisely the kind of code worth running an interval analyser over: it
#      blocked 10 of 40 sampled translation units in one library and the very
#      first file tried in another.
#
#      `fneg x` is rewritten to `fsub -0.0, x`, which is how the same operation
#      was expressed before LLVM 8 introduced the dedicated instruction. The two
#      differ only in edge cases irrelevant to interval analysis (the NaN payload
#      produced, and fneg(-0.0) vs fsub(-0.0,-0.0)).
#
# Usage: scripts/ikos-bitcode.sh <compile_commands_dir> <source-file> <output.bc>

set -euo pipefail

DB_DIR="$1"; SOURCE="$2"; OUT="$3"
CLANG="${CLANG14:-clang-14}"

command -v "${CLANG}" >/dev/null 2>&1 || { echo "error: ${CLANG} not found; run scripts/setup-ikos.sh" >&2; exit 1; }

FLAGS="$(python3 - "$DB_DIR" "$SOURCE" <<'PY'
import json, sys, os
db = sys.argv[1]
path = db if db.endswith('.json') else os.path.join(db, 'compile_commands.json')
target = os.path.realpath(sys.argv[2])
for e in json.load(open(path)):
    if os.path.realpath(e['file']) != target:
        continue
    raw = (e.get('command') or ' '.join(e.get('arguments', []))).split()
    out, skip = [], False
    for i, a in enumerate(raw):
        if i == 0 or skip:
            skip = False
            continue
        if a == '-o':
            skip = True
            continue
        # -O would defeat point 2 above; -c and the inputs are re-supplied.
        if a in ('-c',) or a.startswith('-O') or a.endswith('.o') or a == e['file']:
            continue
        out.append(a)
    print(' '.join(out))
    break
PY
)"

TMP_LL="$(mktemp --suffix=.ll)"
TMP_FIXED="$(mktemp --suffix=.ll)"
trap 'rm -f "${TMP_LL}" "${TMP_FIXED}"' EXIT

# shellcheck disable=SC2086
"${CLANG}" -emit-llvm -S -g -O0 ${FLAGS} "${SOURCE}" -o "${TMP_LL}"

python3 - "${TMP_LL}" "${TMP_FIXED}" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
# "= fneg [fast-math flags] <fp type> <operand>" -> "= fsub [flags] <type> -0.0, <operand>"
fixed, n = re.subn(r'= fneg ((?:[a-z]+ )*)(float|double|fp128|half|x86_fp80) ',
                   r'= fsub \1\2 -0.000000e+00, ', src)
open(sys.argv[2], 'w').write(fixed)
if n:
    print(f"    lowered {n} fneg instruction(s) for IKOS", file=sys.stderr)
PY

llvm-as-14 "${TMP_FIXED}" -o "${OUT}"
