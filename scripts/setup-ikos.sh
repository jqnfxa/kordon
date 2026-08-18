#!/usr/bin/env bash
#
# Build IKOS into a local prefix for Kordon.
#
# IKOS is the abstract-interpretation layer. Unlike every other engine Kordon
# drives, it computes sound value ranges, so it can *prove* an array access in
# bounds rather than only failing to flag it. That matters for two measured
# problems: CWE-119 is 70% of Kordon's remaining misses, and the pro-bounds
# checks that partially cover it are 49% of all output while being unable to
# distinguish corrected code from broken code.
#
# Everything IKOS-specific lands under PREFIX (default third_party/ikos, which
# is gitignored). Nothing is installed system-wide except the distribution's
# own LLVM 14 packages, which cannot be had any other way -- they are not
# downloadable as standalone debs on this release, and the only upstream
# prebuilt for 14.0.6 is an RHEL 8 build whose libstdc++ does not match Ubuntu.
#
# Usage:
#   scripts/setup-ikos.sh --check     report what is missing, change nothing
#   scripts/setup-ikos.sh             install deps (sudo) and build IKOS
#
#   PREFIX=/somewhere scripts/setup-ikos.sh      install elsewhere
#   JOBS=8 scripts/setup-ikos.sh                 limit build parallelism

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-${REPO_ROOT}/third_party/ikos}"
SRC_DIR="${PREFIX}/src"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
IKOS_TAG="v3.5"

# IKOS 3.5 requires LLVM/Clang 14.0.x exactly. It cannot use 18, which is what
# the rest of Kordon runs on -- the two coexist, they are separate packages.
LLVM_VERSION=14
LLVM_ROOT="/usr/lib/llvm-${LLVM_VERSION}"

# Split deliberately: the llvm ones are large and version-pinned, the rest are
# ordinary libraries most systems already have.
APT_LLVM=(llvm-${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-tools clang-${LLVM_VERSION}
          libclang-${LLVM_VERSION}-dev libclang-common-${LLVM_VERSION}-dev)
APT_LIBS=(cmake g++ python3 libgmp-dev libboost-dev libsqlite3-dev libtbb-dev libmpfr-dev)

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }

missing_packages() {
    local missing=()
    for p in "$@"; do
        dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    printf '%s\n' "${missing[@]:-}"
}

check() {
    local ok=0
    say "Checking prerequisites"

    local miss_llvm miss_libs
    miss_llvm="$(missing_packages "${APT_LLVM[@]}" | tr -d '[:space:]')"
    miss_libs="$(missing_packages "${APT_LIBS[@]}" | tr -d '[:space:]')"

    if [ -x "${LLVM_ROOT}/bin/llvm-config" ]; then
        info "LLVM ${LLVM_VERSION}: $(${LLVM_ROOT}/bin/llvm-config --version)"
    else
        info "LLVM ${LLVM_VERSION}: MISSING (${LLVM_ROOT}/bin/llvm-config not found)"
        ok=1
    fi
    [ -z "${miss_libs}" ] && info "support libraries: present" \
                          || { info "support libraries MISSING: ${miss_libs}"; ok=1; }

    if [ -x "${PREFIX}/bin/ikos" ]; then
        info "ikos: $(${PREFIX}/bin/ikos --version 2>&1 | head -1)"
    else
        info "ikos: not built yet (would go to ${PREFIX})"
        ok=1
    fi
    return ${ok}
}

if [ "${1:-}" = "--check" ]; then
    check && say "Everything is in place." || say "Run without --check to install."
    exit 0
fi

# ---------------------------------------------------------------- apt packages

need_apt=()
while read -r p; do [ -n "$p" ] && need_apt+=("$p"); done < <(missing_packages "${APT_LLVM[@]}" "${APT_LIBS[@]}")

if [ "${#need_apt[@]}" -gt 0 ]; then
    say "Installing ${#need_apt[@]} distribution package(s) — this is the only step needing root"
    info "${need_apt[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${need_apt[@]}"
else
    say "All distribution packages already present"
fi

if [ ! -x "${LLVM_ROOT}/bin/llvm-config" ]; then
    echo "error: ${LLVM_ROOT}/bin/llvm-config still missing after install" >&2
    exit 1
fi

# ------------------------------------------------------------------ get source

say "Fetching IKOS ${IKOS_TAG}"
mkdir -p "${PREFIX}"
if [ -d "${SRC_DIR}/.git" ]; then
    info "already cloned at ${SRC_DIR}"
else
    git clone --depth 1 --branch "${IKOS_TAG}" \
        https://github.com/NASA-SW-VnV/ikos.git "${SRC_DIR}"
fi

# ----------------------------------------------------------------------- build

say "Building IKOS (${JOBS} jobs) — expect tens of minutes"
mkdir -p "${SRC_DIR}/build"
cd "${SRC_DIR}/build"

# Both LLVM 14 and 18 are installed, so the LLVM/Clang cmake packages must be
# named explicitly. Left to itself, find_package picks whichever it finds first
# and the build fails deep in a header with no useful message.
cmake -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_DIR="${LLVM_ROOT}/lib/cmake/llvm" \
      -DClang_DIR="${LLVM_ROOT}/lib/cmake/clang" \
      ..

make -j"${JOBS}"
make install

# ---------------------------------------------------------------------- verify

say "Verifying"
if "${PREFIX}/bin/ikos" --version >/dev/null 2>&1; then
    info "$(${PREFIX}/bin/ikos --version 2>&1 | head -1)"
    info "binary: ${PREFIX}/bin/ikos"
    say "Done. Kordon looks for IKOS here automatically; nothing to add to PATH."
else
    echo "error: ${PREFIX}/bin/ikos did not run" >&2
    exit 1
fi
