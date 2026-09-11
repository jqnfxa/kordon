---
name: kordon-integrate
description: The integrator's loop for Kordon's parallel CWE lanes — review each lane/<name> branch, rebase it onto main, run the fixture harness and Rust tests, merge, then re-measure the whole Juliet baseline once, regenerate docs/progress.md, and fold each lane's "For CLAUDE.md" notes into CLAUDE.md and NEXT-SESSION.md. Use from the main checkout when one or more lanes report done, or when asked to merge lanes.
---

# Integrating lanes

Run from the main checkout (`/home/shard/VsCode/kordon`), never from a lane.
Lanes own their branches; main owns the baseline, the progress table and
`CLAUDE.md`. The integrator is the only writer of those three.

## Per lane

    scripts/lane.sh list                       # what exists, ahead/behind, dirty?
    git log --oneline main..lane/<name>
    git diff main...lane/<name> --stat

1. **Read the brief** `docs/lanes/<name>.md` on the lane branch: verdict table
   complete? every syntactic shape has a fixture? `## State` says done? A lane
   with a written verdict and no code is a legitimate result.
2. **Rebase**: `scripts/lane.sh sync <name>` (rebases onto main and rebuilds).
   Conflicts land in predictable places — resolve them mechanically:
   - `CHECKS` array and the tail of `src/tools/clang_query.rs`: keep both
     appends, in either order.
   - `data/cwe_map.toml`: keep both rules; if two lanes changed the *same*
     rule, the one about that CWE wins and the other lane's commit message
     says why it touched it.
   - `DEFAULT_CHECKS` / `ALPHA_CHECKERS` / `CTU_CHECKERS`: union.
   - `EQUIVALENT` / `EXCLUDED` in `score-juliet.py`: keep both entries; two
     lanes editing the same CWE's entry is a conversation, not a merge.
3. **Verify in the lane worktree**:

       cd .claude/worktree/<name>
       cargo test --release && scripts/check-fixtures.py

   Both green, or the lane goes back with the failure quoted.
4. **Merge**: `git merge --no-ff lane/<name>` on main. Keep the lane's commits;
   the message names the lane and the CWEs moved.
5. Leave the worktree until the lane is fully closed (`scripts/lane.sh rm
   <name>` then), so a follow-up can continue in context.

## After the batch

Once, not per lane — the whole point is that nine lanes cost one baseline run:

    cargo build --release && cargo test --release
    scripts/check-fixtures.py
    OUT=/tmp/new.json scripts/baseline.sh            # ~4 minutes
    scripts/compare-baselines.py data/juliet-baseline.json /tmp/new.json

- **Any `REGRESSED` line** is investigated before anything is written: which
  lane, which check, is it a real loss or a scorer change (a `different
  sample` note means a lane touched `EXCLUDED` or the truth extractor — then
  the two runs are not comparable and the *reason* goes in the commit).
- When it is understood: `cp /tmp/new.json data/juliet-baseline.json`,
  `scripts/progress.py`, and update `TIER` / `NEXT` in `scripts/progress.py`
  from the lanes' verdicts. Re-take `--multifile --ctu` and the dynamic baseline
  only when a lane changed something they measure.

## Folding the ground truth back

Each brief has `## For CLAUDE.md`. Append one dated section to `CLAUDE.md` per
integration batch — the same terse, measured style as the existing ones:
what was measured, the number before and after, the one-sentence lesson.
Not the process; the fact. Then:

- `docs/NEXT-SESSION.md` — "Currently open": remove what closed, add what the
  lanes left blocked.
- `docs/cwe-difficulty.md` — move a CWE between tiers only with the measurement
  that justifies it.
- `docs/lanes/README.md` — the lane map's state column.
- memory — if a lane changed something a future session would otherwise
  re-derive (a dead end, a corpus quirk), write it there.

## Commit

    integrate: <lanes>, baseline <before> -> <after> recall, <fp before> -> <fp after> FP

Body: per lane one line (CWEs, before → after), the compare-baselines TOTAL,
regressions explained. Attribution line last.
