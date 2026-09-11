# Lanes: working the CWEs in parallel

One lane per family of CWEs, one agent per lane, one git worktree per agent.
The lanes are independent enough to run at once and merge without fighting:
each owns its fixtures, its brief, and an append-only slice of the shared
tables. `CLAUDE.md`, the baseline and the progress table belong to the
integrator alone.

Reference point, taken 2026-09-11 on `main` at `bd4dc87`, default flags,
40 files per CWE: **533/1101 flawed functions found (48.4%), 446 surfaced
(40.5%), 138/3294 correct functions flagged (4.2%)**. Every lane measures
against `data/juliet-baseline.json` with `scripts/baseline.sh`.

## The map

| lane | CWEs | today | the item that pays first | state |
|---|---|---|---|---|
| [bounds-write](bounds-write.md) | 121, 122, 124 (+787/788/119/129/131/120) | 45 / 31 / 76% | wide-string and copy-loop shapes; the `hoisted_guard` FP | not started |
| [bounds-read](bounds-read.md) | 125, 126, 127 (+170) | — / 11 / 40% | why string-copy sinks hide an under-read the arithmetic shows | not started |
| [integer](integer.md) | 190, 191, 197, 680, 369 | 18 / 32 / 51 / 67 / 56% | CWE-680 allocation-size check; tier F into Advice; the 13–18% FP | not started |
| [lifetime](lifetime.md) | 401, 415, 416, 590, 762/763, 672, 772, 775 | 87 / 93 / 50 / 42 / 85 / 0 / — / 16% | the analyzer's loop budget (416, 590); `alpha.unix.Stream` (775) | not started |
| [init](init.md) | 457, 665, 824, 908 | 58 / 36% | `strcat`/`wcscat` into a never-written buffer (665) | not started |
| [null-chain](null-chain.md) | 476, 252, 690 | 84 / 70 / 10% | an unchecked allocation result — nothing reports it (690) | not started |
| [misc](misc.md) | 483, 562, 563, 843 + the `clang-diagnostic-*` sweep | 95 / 50 / 77 / 0% | the sweep: every diagnostic named so far closed a gap | not started |
| [infra](infra.md) | cross-cutting: CTU default, analyzer budgets, scorer, union measurement, report | — | `widen-loops` / `unroll-loops`; `--ctu` by default | not started |

Numbers are raw recall from the survey in each brief. Two dependencies are
called out inside the briefs: **lifetime** needs **infra** to plumb analyzer
options before the loop-budget item can be measured through Kordon, and
**bounds-read** reuses the copy-loop check that **bounds-write** builds.

## Running a lane

    scripts/lane.sh new bounds-write          # worktree + branch + shared third_party + build
    cd .claude/worktree/bounds-write && claude # then: "work lane bounds-write"

or from a session in the main checkout, spawn the `cwe-lane` agent with the
lane name. The agent loads the `kordon-lane` skill, which is the whole
pipeline; the other skills (`kordon-triage`, `kordon-fixture`, `kordon-check`,
`kordon-measure`) are the steps of it.

    scripts/lane.sh list                       # ahead/behind main, uncommitted work
    scripts/lane.sh sync <lane>                # rebase onto main, rebuild

## Finishing

A lane is done when its brief's definition of done is met (see the
`kordon-lane` skill): every shape has a verdict, every syntactic shape has a
fixture that fails without the change and passes with it, before/after numbers
are recorded with their flags, and `## State` says what is left. The agent
commits on `lane/<lane>` and stops. The integrator (`lane-integrator` agent,
`kordon-integrate` skill) rebases, verifies, merges, re-measures the whole
baseline once, and folds each brief's `## For CLAUDE.md` into `CLAUDE.md`.

## What every lane shares

- the fixture harness: `scripts/check-fixtures.py` — markers are documented in
  its header and in the `kordon-fixture` skill; 5 of the 28 fixtures it runs
  are marked today, the other 23 are listed as *unmarked* and belong to the
  lane named in the brief
- the scorer and the explainer: `scripts/score-juliet.py`,
  `scripts/explain-misses.py <cwe> --misses`
- the whole-baseline diff: `scripts/baseline.sh` → `scripts/compare-baselines.py`
- the shape survey these briefs were written from: re-run it with
  `scripts/explain-misses.py <cwe>`; the numbers in the briefs are a snapshot

## Rules that keep nine branches mergeable

Append only in `src/tools/clang_query.rs` (end of file, end of `CHECKS`),
`data/cwe_map.toml`, `DEFAULT_CHECKS`/`FORCED_WARNINGS`/`ALPHA_CHECKERS`/
`CTU_CHECKERS`, and the `EQUIVALENT`/`EXCLUDED` tables. Never write
`data/juliet-baseline.json`, `docs/progress.md` or `CLAUDE.md` from a lane.
Never edit another lane's fixtures. Full list in the `kordon-lane` skill.
