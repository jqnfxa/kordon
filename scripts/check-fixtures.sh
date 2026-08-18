#!/usr/bin/env bash
#
# Every fixture must compile.
#
# A fixture that does not parse still produces findings -- clang analyses what
# it can and reports on the wreckage -- so a broken one looks exactly like a
# working one until you read the AST. One in this repo had its later functions
# appended outside the namespace, so their parameters were typed `int&` instead
# of the intended class, and the check under test was being judged against
# nonsense. Findings alone are not evidence that a fixture is valid.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
for f in testdata/*/*.cpp; do
    # -UNDEBUG so assert-based fixtures expand the way their check needs.
    if clang++ -fsyntax-only -std=c++17 -UNDEBUG "$f" 2>/dev/null; then
        printf '  ok    %s\n' "$f"
    else
        printf '  FAIL  %s\n' "$f"
        clang++ -fsyntax-only -std=c++17 -UNDEBUG "$f" 2>&1 | head -3 | sed 's/^/        /'
        fail=1
    fi
done
exit ${fail}
