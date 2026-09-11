# Start here

## Parallel lanes (2026-09-11)

The CWEs are now worked as **eight lanes**, one agent each, one git worktree
each under `.claude/worktree/<lane>` on branch `lane/<lane>`. The map, the
per-lane briefs (scope, measured state, shape verdicts, ordered TODO, fixtures
to mark and build) and the rules that keep the branches mergeable are in
**`docs/lanes/README.md`**. The pipeline an agent follows is the
`kordon-lane` skill (`.claude/skills/`), which hands off to `kordon-triage`,
`kordon-fixture`, `kordon-check` and `kordon-measure`; merging is the
`kordon-integrate` skill, run from this checkout only.

    scripts/lane.sh new <lane>            # worktree, branch, shared third_party, build
    scripts/check-fixtures.py             # every fixture: must find / must stay silent
    scripts/explain-misses.py <cwe> --misses
    scripts/baseline.sh                   # whole baseline vs data/juliet-baseline.json

Lanes never write `data/juliet-baseline.json`, `docs/progress.md` or
`CLAUDE.md`; their numbers and their ground truth go in the brief, and the
integrator folds them in once per batch.

The loop is: **pick a CWE, read its cases, decide what it needs, change one
thing, re-measure, see whether the count moved.** Everything below exists to
make that loop cheap and honest.

## The three documents

| | |
|---|---|
| `docs/progress.md` | **generated** — every CWE with found/total, and what would move it |
| `docs/cwe-difficulty.md` | why each CWE is easy or hard, and therefore what closing it costs |
| `docs/juliet-inventory.md` | what the corpus holds; what is in scope and what is deliberately not |

`CLAUDE.md` holds the measured ground truth — read the sections dated
2026-08-25 and later before re-deriving anything.

## Setup

```sh
scripts/setup-juliet.sh third_party/juliet     # 153 MB, resumable, verifies before extracting
cargo build --release && cargo test --release  # 118 tests
```

## The loop, per CWE

1. **Read the cases before running anything.**
   `ls third_party/juliet/C/testcases/CWE<n>_*/` then read three or four `_01`
   variants. Name the *shapes*, not the count.

2. **Compare the flawed function against its corrected sibling.** This is the
   step that pays. On CWE-126 the corrected function contains the *identical*
   `memcpy` line — only a buffer size differs — so any matcher would have
   discriminated exactly zero. One `diff` saved building the wrong thing.

3. **Decide what the shape needs**, and write the verdict down even when the
   answer is "nothing we can build":
   - the compiler already knows → name the check (tier A, three for three)
   - a shape rule → build it (tier C)
   - a value bound → IKOS or the dynamic layer (tier D)
   - cross-TU or ownership → `--ctu`, or leave it (tier E)
   - defined behaviour → **Advice**, not recall (tier F)
   - application semantics → leave it (tier G)

4. **Validate a new matcher by hand first.**
   `clang-query-18 -c "match ..." file.c -- <flags>` — a malformed matcher
   returns **0 matches, not an error**, and so does a file that failed to
   parse. Both look exactly like "no defects here".

5. **Measure the CWE, then the whole baseline.**
   ```sh
   scripts/score-juliet.py third_party/juliet/C --cwe <n> --limit 40
   scripts/score-juliet.py third_party/juliet/C --limit 40 \
       --json-out data/juliet-baseline.json
   scripts/progress.py
   ```
   A check built for one class routinely adds false positives to another.

6. **Check it against real code before believing it.**
   `~/VsCode/pkt-astronomia` (159 TUs, C and C++) and
   `~/VsCode/Satellite/rtklib_mod` (10 TUs, terse C). A check that scores well
   on Juliet and floods a real project is not an improvement — one index check
   fired on **160 positions across those two, 56 in vendored SOFA**, before the
   right clause was added.

## Read the discrimination column, not recall

`recall − false positives`. A check that fires on every arithmetic line scores
high recall and detects nothing. `bugprone-narrowing-conversions` read as 64%
recall on CWE-190 where real detection was **zero**, because it fires
identically on the guarded and unguarded versions.

## Traps that have each cost a measurement

Every one produced a **plausible number rather than an error**, which is why
they survived. When a CWE reads 0% — or suspiciously well — **check the
instrument before the tool.**

- **`hasDescendant` does not match the node itself.** Cost three measurements.
  Write `anyOf(ignoringParenImpCasts(X), hasDescendant(X))` by default.
- **A relative Juliet root** makes every include fail while cppcheck keeps
  reporting, so the scorer measures one engine instead of four.
- **An over-wide accept set** credits checks that do not discriminate. Three
  times. An `EQUIVALENT` entry claims two CWEs mean the same defect — write
  the narrow set, widen only with a reason.
- **`--checks='-*,clang-diagnostic-…'`** silently analyses nothing.
- **A prefix is not a sample.** Juliet names cases `type_source_operation`, so
  a sorted prefix is one type and one source.
- **clang-tidy's "Error while processing" is cumulative** — every unit after
  the first failure is named too.

## What "done" would mean

Not 100% of the sample. The denominator is 40 files per CWE out of 101,231,
the suite is synthetic, and tiers F and G have honest ceilings well below 100
— chasing them means reporting defined behaviour as a defect.

A better target: **every CWE either scoring well, or carrying a written
verdict saying why it does not and what that would cost.** Nineteen of
twenty-six have one today.

Then the real test, which Juliet cannot give: run against real libraries and
diff a raw tree against its fixed one. `CLAUDE.md` describes the ACL pair set
up for exactly that, and `tmp/pkta_bugs.md` holds thirteen verified defects
found that way — none of which have an analogue anywhere in Juliet.

## Currently open

Every item below now has an owner lane; the brief holds the detail.

- **The analyzer's loop budget** (`infra` TODO 1, `lifetime` TODO 1). Measured
  2026-09-11: `max-loop=4` abandons every path after Juliet's 100-iteration
  init loops; `widen-loops=true` or `unroll-loops=true` recovers the CWE-416
  misses, and only `unroll-loops` recovers the CWE-590 `alloca` free. Kordon
  passes no analyzer options today. The largest single lever found so far.
- **`--ctu` by default** with a compile database (`infra` TODO 2).
- **Sweep the rest of `clang-diagnostic-*`** — measured, as a by-check table
  over Juliet (`misc` TODO 1).
- **CWE-690** — an unchecked allocation result; nothing reports it, verified
  against cppcheck `--inconclusive` and Clang SA (`null-chain` TODO 1).
- **CWE-775** — `alpha.unix.Stream` fires and is not enabled (`lifetime` TODO 3).
- **Say what `--ikos` is worth**, and whether a numeric domain cuts its 44.6%
  FP on CWE-126 (`bounds-read` TODO 2).
- **Move tier F into Advice** (`integer` TODO 2).
- **The union of the layers** (`infra` TODO 4).
- **Windows-only Juliet cases** counted as static misses — 775 loses 13 of 40
  units (`infra` TODO 3).
- **`size_t size = ftell(f); vector(size + 1)`** is reported as a low CWE-190 on
  the bad and the corrected twin alike; the defect is the error return
  accepted as a size, and nothing reports that line (`integer` TODO 5).
- **23 of the 28 harness-run fixtures are unmarked**; each brief names its own.
