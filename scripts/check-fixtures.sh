#!/usr/bin/env bash
# Kept for muscle memory. The harness moved to check-fixtures.py, which also
# checks what each fixture *says* Kordon must find and must not find; this is
# now the compile-only subset of it.
exec "$(dirname "${BASH_SOURCE[0]}")/check-fixtures.py" --compile-only "$@"
