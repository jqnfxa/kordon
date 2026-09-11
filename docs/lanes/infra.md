# Lane `infra` — cross-cutting: analyzer budgets, CTU by default, scorer, report

branch `lane/infra` · worktree `.claude/worktree/infra` · skills: `kordon-lane` first

## Scope

No CWE of its own. This lane changes how the engines are driven and how the
result is measured, which moves every other lane's numbers — so each item is
measured on the **whole** baseline, both directions, and the cost in seconds
is recorded alongside. Files: `src/main.rs`, `src/ctu.rs`,
`src/tools/clang_sa.rs`, `src/tools/clang_tidy.rs` (invocation, not the
check lists), `src/report.rs`, `src/dedup.rs`, `scripts/score-juliet*.py`,
`scripts/progress.py`, `scripts/check-fixtures.py`, `testdata/dynamic/`,
`testdata/macros/`.

## Where it stands

- Whole baseline: 533/1101 (48.4%), 446 surfaced (40.5%), 138/3294 FP (4.2%).
  Multi-file: 17.4% → 28.8% with `--ctu`. Dynamic: 57.8% of runnable, 0 FP.
- `--ctu` is opt-in. The user's requirement is that it is **required**.
- `--ctu` reaches 8 translation units along one path and stops:
  `ctu-import-cpp-threshold` defaults to 8, measured in
  `testdata/zero_length_ctu/README.md`; Kordon does not set it.
- Kordon passes exactly one `-analyzer-config` (`src/tools/clang_sa.rs:216`,
  the CTU config) and none to the clang-tidy pass.
- The static scorer counts Windows-only cases as misses: 775 loses 13 of 40
  units, 252 5, 690 2 (`w32CreateFile`, `CreateMutex`, `_wfopen`). The
  dynamic scorer already excludes them.
- Nothing measures the union of the layers.
- `events` is empty on every finding; header findings are dropped when the
  target is a `.cpp`; dedup is exact-line.

### Multi-file cases with `--ctu` (survey 2026-09-11, 25 cases per CWE)

clang-tidy reported FAILED TO COMPILE units in multi-file mode for 762 (2 of 70) and 843 (19 of 64) while the same files parse with `clang++ -fsyntax-only`. Find out which step fails (the tidy pass, the CTU AST dump, the extdef import) and make the report name the unit and the stage. A count that reads as 'failed to compile' for a unit that compiles is the same class of trap as the cumulative error counter. Per-shape tables and the missed functions are in `docs/lanes/survey-2026-09-11.md`.

## TODO — in order

### 1. The analyzer's loop budget — the largest single lever found today

Probed on Juliet CWE-416: `clang --analyze` with the default `max-loop=4`
reports **nothing** on `new int[100]` + a 100-iteration init loop + `delete[]`
+ read, and on the `malloc`/`free` flow variants; with `-analyzer-config
widen-loops=true` **or** `unroll-loops=true` it reports `Use of memory after
it is freed` on both. `max-loop=128` alone does not. Every Juliet case that
"initialises the memory block" has this loop, so the effect is not confined to
416. The two options are not equivalent: on the CWE-590 `alloca` case
(`alloca`, init loop, `free`) **`unroll-loops=true` reports the free and
`widen-loops=true` does not** — widening invalidates the loop's regions, so
`free` sees an unknown pointer. Unrolling is bounded by the loop's constant
trip count and costs time on long loops; widening is cheap and loses
precision. Both may be worth having; the four-run table decides.

Do: (a) plumb analyzer options into **both** passes — a `ANALYZER_CONFIG:
&[&str]` constant applied in `clang_sa.rs` and, for clang-tidy, via
`--extra-arg=-Xclang --extra-arg=-analyzer-config --extra-arg=-Xclang
--extra-arg=<k=v>` (verify clang-tidy honours it; if not, the alternative is
running the affected checkers in the `clang --analyze` pass). Expose
`--analyzer-config k=v` (repeatable) for experiments. (b) Measure four
whole-baseline runs at `--limit 40`: default, `widen-loops=true`,
`unroll-loops=true`, both — recall, FP, surfaced, and wall time. (c) Pick the
default from the discrimination and the time; record all four in `## For
CLAUDE.md`. The `lifetime` lane has the fixture (`uaf_after_loop`) and is
waiting on (a).

### 2. `--ctu` by default when a compile database is given

Measured value is in `CLAUDE.md` (three classes from 0% to detectable). Make
it the default with `-p`, keep `--no-ctu`, and make the failure modes loud: an
index that fails to build, a unit the importer rejects, the 8-unit threshold
being hit (the analyzer prints `display-ctu-progress`; count imports per
path and say in the report when the budget was exhausted). Raise
`ctu-import-cpp-threshold` only with a measured time cost on `pkt-astronomia`
(159 units). Re-take `data/juliet-multifile-ctu.json` afterwards; it is the
regression record for this flag.

### 3. Scorer: `UNPORTABLE`, distinct from `EXCLUDED`

`EXCLUDED` means "not an instance of the defect" and its bar is the standard.
Windows-API cases are instances that cannot compile here; add an `UNPORTABLE`
table (`w32`, `CreateFile`, `_wfopen`, `CreateMutex`, `ImpersonateSelf`, …),
exclude them from the denominator, print the count and the reason on every
run, and re-baseline 775/252/690 — the integrator does the file write; you
report the numbers. Also carry the sample fix into `explain-misses.py`.

### 4. One question per case: did any layer catch it?

`scripts/score-juliet-union.py` (or `--union` in the static scorer): for each
sampled case, static with `--ctu`, static with `--ikos`, and the dynamic run,
credit a hit if any layer reports the CWE in the flawed function (static) or
the sanitizer fires (dynamic); report per CWE `static / dynamic / union` and
the two false-positive columns. Store `data/juliet-union-baseline.json`;
add the column to `progress.py`. This is the number to quote; the per-layer
tables become diagnostics.

### 5. Report: events, headers, anchors

From `docs/acl-report-findings.md` cross-cutting items: (1) `events` is
empty on every finding — populate the path from the plist for `clang-sa-*`
and from clang-tidy's notes where present, shown under `-v`; (4b) headers
reachable from analysed units and inside the project root are in-tree — stop
dropping them, and when findings are dropped, name the files, not just the
count; (2) anchor confidence is not finding confidence — for dead stores
report both ends ("written here, killed there"). Fixture
`testdata/macros/` (a defect inside a macro body) is yours to mark.

### 6. Dedup window

`file + line + CWE` misses the same defect reported on adjacent lines (the
analyzer at the initialisation, cppcheck at the overwrite). A ±1 window per
CWE, measured on the whole baseline for anything it merges wrongly.

### 7. `check-fixtures.py` and `lane.sh` are yours

Keep them working for everyone. Known limits: brace matching is per line;
`@bad`/`@good` scan twelve lines forward for the body; the harness runs
fixtures one at a time.

### 8. Later: the `fault` profile without valgrind

`CLAUDE.md` has the measured dead end (valgrind replaces `malloc`, so the
interposer is ignored) and the direction (exit status + stderr + `gdb -batch
-ex run -ex bt` for a stack, then a backtrace → `RuntimeReport` parser).
After 1–5.

## Don't

- Change a default without the four-run table.
- Widen an accept set in the scorer to make CTU look better.
- Touch check lists (`DEFAULT_CHECKS`, `CHECKS`, `cwe_map.toml`) — those are
  the CWE lanes'.

## For CLAUDE.md

(fill in — the four-run table from TODO 1 and the CTU-default measurement)

## State

not started
