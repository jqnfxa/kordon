#!/usr/bin/env bash
#
# Lanes: one git worktree per agent, each on its own branch, so several agents
# can work different CWE classes at once without touching each other's files.
#
#   scripts/lane.sh new <name>      create .claude/worktree/<name> on branch lane/<name>
#   scripts/lane.sh list            what exists, and how far each is from main
#   scripts/lane.sh rm <name>       remove the worktree (the branch is kept)
#   scripts/lane.sh sync <name>     rebase the lane onto main
#
# What a new lane gets:
#   - a branch `lane/<name>` cut from the current main
#   - `third_party` symlinked to the main checkout's, so Juliet, IKOS and ESBMC
#     are shared rather than downloaded again (all of it is gitignored anyway)
#   - its own `target/` -- the release binary must not be shared, or one
#     lane's scorer measures another lane's checks
#   - a release build, so the first measurement is one command away
#
# The worktree directory is gitignored. Lane names are the lane briefs in
# docs/lanes/ (bounds-write, integer, lifetime, ...), but any name works.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANES="$ROOT/.claude/worktree"

usage() { sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

cmd="${1:-}"; name="${2:-}"

# Lanes hang off the main checkout only. Run from inside a lane, $ROOT would be
# the lane itself and the new worktree would nest under it.
if [ "$(git -C "$ROOT" rev-parse --git-dir)" != "$(git -C "$ROOT" rev-parse --git-common-dir)" ]; then
    echo "run this from the main checkout, not from a lane worktree" >&2
    exit 1
fi

case "$cmd" in
new)
    [ -n "$name" ] || usage
    dir="$LANES/$name"
    [ -e "$dir" ] && { echo "lane '$name' already exists at $dir" >&2; exit 1; }
    mkdir -p "$LANES"
    if git -C "$ROOT" show-ref --quiet "refs/heads/lane/$name"; then
        git -C "$ROOT" worktree add "$dir" "lane/$name"
    else
        git -C "$ROOT" worktree add -b "lane/$name" "$dir" main
    fi
    # Share the engines and the corpus; keep the build private.
    ln -s "$ROOT/third_party" "$dir/third_party"
    echo "building the lane's own release binary ..."
    (cd "$dir" && cargo build --release --quiet)
    cat <<EOF

lane '$name' is ready:
  worktree  $dir
  branch    lane/$name
  brief     docs/lanes/$name.md   (if this lane has one)

start an agent in it with:
  cd $dir && claude

or point a subagent at it. Everything the lane needs is described by the
kordon-lane skill (.claude/skills/kordon-lane/SKILL.md).
EOF
    ;;
list)
    # grep exits 1 on no match, which under pipefail would make "no lanes yet"
    # look like a failure.
    { git -C "$ROOT" worktree list | grep -F "$LANES" || true; } | while read -r path sha rest; do
        b="$(git -C "$path" rev-parse --abbrev-ref HEAD)"
        ahead="$(git -C "$ROOT" rev-list --count "main..$b" 2>/dev/null || echo '?')"
        behind="$(git -C "$ROOT" rev-list --count "$b..main" 2>/dev/null || echo '?')"
        dirty="$(git -C "$path" status --porcelain | wc -l)"
        printf '  %-18s %-24s +%s/-%s vs main  %s\n' "$(basename "$path")" "$b" "$ahead" "$behind" \
            "$([ "$dirty" -gt 0 ] && echo "($dirty uncommitted)" || echo clean)"
    done
    ;;
rm)
    [ -n "$name" ] || usage
    dir="$LANES/$name"
    [ -d "$dir" ] || { echo "no lane '$name'" >&2; exit 1; }
    if [ -n "$(git -C "$dir" status --porcelain)" ]; then
        echo "lane '$name' has uncommitted changes; commit or discard them first" >&2
        exit 1
    fi
    git -C "$ROOT" worktree remove "$dir"
    echo "removed worktree; branch lane/$name is kept (git branch -D lane/$name to drop it)"
    ;;
sync)
    [ -n "$name" ] || usage
    dir="$LANES/$name"
    [ -d "$dir" ] || { echo "no lane '$name'" >&2; exit 1; }
    git -C "$dir" rebase main
    (cd "$dir" && cargo build --release --quiet)
    ;;
*)
    usage
    ;;
esac
