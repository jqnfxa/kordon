---
name: kordon-lane
description: Operating manual for an agent working one Kordon CWE lane end to end inside its own git worktree (.claude/worktree/<lane>) — triage the Juliet shapes, reduce one to a minimal fixture, make Kordon detect it, run the fixture and Juliet regressions, record the verdict. Use whenever you are assigned a lane from docs/lanes/, or asked to work a specific CWE or CWE family for Kordon.
---

# Working a Kordon lane

You own one lane: a family of CWEs, a brief in `docs/lanes/<lane>.md`, a
branch `lane/<lane>`, and a worktree at `.claude/worktree/<lane>`. Everything
you do happens in that worktree. Other agents are working other lanes at the
same time, so the rules about what you touch are not bureaucracy — they are
what lets nine branches merge.

## Before the first change

1. `pwd` must be your worktree. If it is not, `cd` there. If it does not exist,
   run `scripts/lane.sh new <lane>` from the main checkout.
2. Read, in this order: `docs/lanes/<lane>.md` (your brief), `docs/NEXT-SESSION.md`,
   the `CLAUDE.md` sections that name your CWEs (search for the number), and
   `docs/cwe-difficulty.md`. The brief tells you what has already been decided
   about your CWEs; do not re-derive it.
3. `cargo build --release && scripts/check-fixtures.py` — the harness must be
   green before you start, or you cannot tell your effect from the baseline's.
4. Confirm the corpus: `ls third_party/juliet/C/testcases | head`. `third_party`
   is a symlink to the main checkout's; nothing is downloaded per lane.

## The loop — one shape at a time

Work the brief's TODO in order. For each item:

1. **Triage** (skill `kordon-triage`). Run `scripts/explain-misses.py <cwe>
   --misses`, read three or four missed cases *and their corrected siblings*,
   and give the shape one of the seven verdicts. Write the verdict into the
   brief's table **before** building anything. A verdict of "out of reach" is
   a deliverable; the number does not have to move for the item to be done.

2. **Fixture** (skill `kordon-fixture`). Reduce the shape to a minimal
   `testdata/<name>/` with the defect *and* its corrected twin, marked with
   `@kordon cwe:` and `@bad`/`@good` (or the `_bad`/`_good` naming). Prefer the
   harder form when it exists in the real world: split across translation
   units with `@kordon flags: --ctu`, deeper than one call. Run
   `scripts/check-fixtures.py --only <name>` and **confirm it fails**. A
   fixture that passes before the fix is testing nothing.

3. **Detect** (skill `kordon-check`). Cheapest mechanism first: a compiler
   diagnostic Kordon has not named → an existing checker not enabled → a
   mapping rule that files the finding under the wrong CWE or confidence → a
   `message_contains` discriminator → a new clang-query check → an engine
   change. Most of this repo's gains came from the first three.

4. **Discriminate.** The harness must pass, `good` twins included. If the good
   twin fires, the check has matched the shape and not the defect; find the
   clause that separates them (the operand, not the operator; where the value
   came from; whether the other side was ever tested). Never fix a good twin
   by deleting it.

5. **Measure** (skill `kordon-measure`).
   `scripts/score-juliet.py third_party/juliet/C --cwe <cwe> --limit 40` for
   your CWE, then `scripts/baseline.sh` for **everything** — a check built for
   one class routinely moves another. Any `REGRESSED` line is yours to explain
   or fix before committing. Record before/after in the brief.

6. **Commit** — one shape per commit, in the worktree, on your branch:

       <lane>: <what changed>, CWE-<n> <before> -> <after>

   Body: the shape, the verdict, what discriminates it, what it costs on the
   whole baseline (the TOTAL line from compare-baselines), and the fixture.
   End with the attribution line the session gives you.

7. Repeat from 1 with the next item.

## What you may change

- `testdata/<your fixtures>/`, `docs/lanes/<lane>.md` — freely.
- `src/tools/clang_query.rs` — **append** new checks at the end of the file and
  at the end of the `CHECKS` array; do not reorder or reformat existing ones.
- `data/cwe_map.toml` — append rules in the section for their tool; change an
  existing rule only if it is about your CWE, and say so in the commit.
- `src/tools/clang_tidy.rs` `DEFAULT_CHECKS` / `FORCED_WARNINGS` /
  `CHECKED_FUNCTIONS`, `src/tools/clang_sa.rs` `ALPHA_CHECKERS` /
  `CTU_CHECKERS` — append only.
- `scripts/score-juliet.py` `EQUIVALENT` / `EXCLUDED` — only the entries for your
  CWEs, only with the reason in a comment. Widening an accept set is a claim
  that the other CWE means the same defect; the file records three times that
  went wrong.

## What you never touch

- `data/juliet-baseline.json`, `data/juliet-*-baseline.json`, `docs/progress.md`
  — the integrator regenerates these once, after merging every lane. Your
  numbers go in your brief.
- `CLAUDE.md`, `docs/NEXT-SESSION.md`, `docs/cwe-difficulty.md`,
  `docs/juliet-inventory.md` — write what belongs there into your brief under
  `## For CLAUDE.md`, and the integrator folds it in.
- Another lane's fixtures or checks. If your change moves another lane's CWE
  (compare-baselines will show it), note it in the brief and the commit; do not
  go and fix it there.
- Real project sources under `~/VsCode/`. They are read-only measurement
  targets, and one of them is proprietary.

## Guardrails, all measured the hard way

- **Minimal examples, not large projects.** Build the fixture, make it detect,
  run the regressions. A run over `~/VsCode/Satellite/rtklib_mod` (10 units,
  under a minute) is a fine false-positive spot check for a new check;
  `~/VsCode/pkt-astronomia` (159 units) is a last step, not a loop step.
- **Do not raise recall by loosening a guard.** Every exemption removed is a
  real project's false positive. Three exemptions in this repo looked correct
  and silently matched nothing; read `CLAUDE.md` on `hasDescendant`.
- **Do not chase tier F or G.** Defined behaviour goes to the Advice band, not
  into recall; application semantics get a written verdict.
- **Read the discrimination, not the recall.** `recall − FP`. A check that
  fires on every arithmetic line has high recall and detects nothing.
- **When a CWE reads 0% or suspiciously well, check the instrument first.**
  Six scorer bugs in this repo each produced a plausible number, not an error.
- **Juliet is synthetic.** Its wrapper functions labelled `bad` that only call
  `helperBad()` cap recall below 100% by construction; say so rather than
  reporting at the call site.

## Definition of done for a lane

Every CWE in the brief has, in the brief:

- a verdict per shape (A–G) with the measured detection rate per shape;
- for every shape marked syntactic or mapping: a fixture in `testdata/` that
  fails without the change and passes with it, including its good twin;
- before/after per-CWE and whole-baseline numbers, with the flags used;
- a false-positive note: what the change costs on the whole baseline and on
  `rtklib_mod`;
- a `## For CLAUDE.md` section with the ground truth worth keeping, in the
  same terse, measured style as the existing sections;
- a `## State` section at the end: done / measured / blocked / next, so the
  next agent starts where you stopped.

Then run `scripts/check-fixtures.py` and `cargo test --release` one last time,
commit, and report. Do not merge; the integrator does (skill
`kordon-integrate`).
