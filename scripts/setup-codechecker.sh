#!/usr/bin/env bash
#
# Install CodeChecker into a local prefix for Kordon.
#
# CodeChecker is Ericsson's analysis driver. Kordon does not need it to run --
# it drives clang-tidy, Clang SA, cppcheck and its own checks directly -- so
# this is optional. What it adds is one engine Kordon has no other access to:
# gcc's -fanalyzer, which on the reference corpus contributed nine
# uninitialised-value positions no other engine reported.
#
# Measured caveats, so the cost is known before installing:
#   * Three of its four analyzers duplicate ones Kordon already drives.
#   * gcc -fanalyzer costs roughly 20 s per translation unit.
#   * A clang-generated compile database breaks it. See --check output.
#
# Everything lands under PREFIX (default third_party/codechecker, which is
# gitignored). Nothing is installed system-wide.
#
# Usage:
#   scripts/setup-codechecker.sh --check   report what is missing, change nothing
#   scripts/setup-codechecker.sh           create the venv and install
#
#   PREFIX=/somewhere scripts/setup-codechecker.sh   install elsewhere

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-${REPO_ROOT}/third_party/codechecker}"
VENV="${PREFIX}/venv"
CC_BIN="${VENV}/bin/CodeChecker"

say()  { printf '\n%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }

check() {
    local ok=0
    say "CodeChecker prerequisites"
    if command -v python3 >/dev/null; then
        info "python3: $(python3 --version 2>&1)"
    else
        info "python3: MISSING"; ok=1
    fi
    if python3 -c 'import venv' 2>/dev/null; then
        info "venv module: present"
    else
        info "venv module: MISSING (apt install python3-venv)"; ok=1
    fi
    for tool in clang-tidy cppcheck; do
        if command -v "$tool" >/dev/null; then
            info "$tool: $($tool --version 2>&1 | head -1)"
        else
            info "$tool: not found (CodeChecker will report it as unavailable)"
        fi
    done
    # The one addition worth installing for.
    if command -v g++ >/dev/null; then
        info "g++: $(g++ --version | head -1) -- provides -fanalyzer"
    else
        info "g++: MISSING; without it CodeChecker adds nothing Kordon lacks"; ok=1
    fi
    if [ -x "${CC_BIN}" ]; then
        info "CodeChecker: $("${CC_BIN}" version 2>/dev/null | grep -m1 'Base package' || echo installed)"
    else
        info "CodeChecker: not installed yet (would go to ${VENV})"
    fi
    return $ok
}

if [ "${1:-}" = "--check" ]; then
    check && say "Everything is in place." || say "Run without --check to install."
    exit 0
fi

check || true

say "Creating virtualenv at ${VENV}"
mkdir -p "${PREFIX}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip
say "Installing CodeChecker (this pulls a few hundred MB of wheels)"
"${VENV}/bin/pip" install codechecker

say "Done."
info "CodeChecker: ${CC_BIN}"
info "Add to PATH for a shell session:"
info "  export PATH=\"${VENV}/bin:\$PATH\""
cat <<'NOTE'

  Before analysing with the gcc analyzer, strip clang-only flags from the
  compile database. g++ rejects them and every translation unit fails to
  compile, which CodeChecker reports as an analysis failure rather than an
  incompatibility:

    -fsanitize=unsigned-integer-overflow
    -fsanitize-ignorelist=...
    -fsanitize-recover=...

  gcc's checkers are also disabled by default; enable them with `-e gcc`:

    CodeChecker analyze compile_commands.json -o out --analyzers gcc -e gcc
    CodeChecker parse out -e json -o out.json
NOTE
