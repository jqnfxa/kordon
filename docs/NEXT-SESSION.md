# Start here

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

- **Sweep the rest of `clang-diagnostic-*`.** Three named, three gaps closed.
- **CWE-690** — join CWE-252 (70%) and CWE-476 (84%), both already detected.
- **Say what `--ikos` is worth** — 11% → 86% on CWE-126 is not a footnote.
- **Move tiers F into Advice** so 191 and 197 stop reading as 0% surfaced when
  the truth is "reported, correctly, as not an error".
- **Nothing measures the union of the layers.** Static and dynamic are
  separate runs over separate samples; a defect ASan catches still reads as a
  miss in the static table.
