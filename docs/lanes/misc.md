# Lane `misc` — CWE-483, 562, 563, 843, and the `clang-diagnostic-*` sweep

branch `lane/misc` · worktree `.claude/worktree/misc` · skills: `kordon-lane` first

## Scope

The tier-A classes the compiler already knows (483 block delimitation, 562
return of stack address, 563 dead store / unused variable), the one tier-G
class with a Juliet directory (843 type confusion), and the cheapest seam in
the whole project: **every `clang-diagnostic-*` check named so far closed a
real gap, and Kordon names three** (`unused-variable`,
`return-stack-address`, `misleading-indentation`). The rest of that namespace
is unexplored, and this lane explores it for every other lane.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | note |
|---|---|---|---|---|
| 483 | 19/20 = 95.0% (95.0) | 0/53 | +95.0 | done; one `direct · -` miss |
| 562 | 3/6 = 50.0% (50.0) | 0/9 | +50.0 | **ceiling**: 3 of 6 flawed functions are wrappers |
| 563 | 34/44 = 77.3% (70.5) | 3/132 | +75.0 | |
| 843 | **0/44** | 0/103 | 0 | `char`/`short` accessed as `int` through `void *` |

## Shapes and verdicts

### CWE-843

    void *data; { char c = 'a'; data = &c; }      // or short
    printIntLine(*((int *)data));                   // 4-byte read of a 1-byte object

Probed: `alpha.security.ArrayBoundV2` + `alpha.core.CastToStruct` report
nothing; `bugprone-casting-through-void` does not apply (the `void *` is a
variable, not a cast chain); `-Wcast-align` is silent on x86. So: no engine.
Note also that `data = &c` leaves the block — the pointer is **dangling** by
the time it is read, which is a CWE-562/825 shape the `StackAddressEscape`
family does not flag either because the escape is to a local. A matcher
"`void *`/`char *` local assigned `&x` where `x` is `char`/`short`/`bool`,
later cast to a wider pointer type and dereferenced, same function" is C and
Juliet-shaped; real-world value is low. Build it small (medium, CWE-843), or
record G with the probe results — either is a valid outcome, but the number
should not stay 0 without a written reason.

### CWE-563

Misses are the `do nothing` variants (`Initialize · do nothing`, 10/15) —
look at two; likely a flow variant where the store is in one branch. 3 FPs:
name the check (`unreadVariable` is cppcheck's, low). The ACL notes add a
report-quality item: a dead store has two anchors (the write that dies and
the write that kills); Kordon anchors on one, the vendor on the other.
Reporting the pair is strictly better — a report change, hand to `infra` if
it is more than a message tweak.

### CWE-562 / 483

Done. Record the 562 ceiling in `## For CLAUDE.md` (it is already in
`CLAUDE.md`; a one-line pointer suffices) and look at the one 483 miss.

## TODO — in order

### 1. The `clang-diagnostic-*` sweep — measured, not guessed

Write `scripts/sweep-diagnostics.py`: for a stride sample of every in-scope
Juliet CWE (reuse `score-juliet.py`'s sampling, `function_ranges` and
`classify`), compile each file with `clang -fsyntax-only -Weverything
-Wno-<the always-on noise: padded, declaration-after-statement,
unsafe-buffer-usage, reserved-identifier, missing-prototypes,
strict-prototypes, comma, …>`, attribute each `warning: … [-Wname]` line to a
`bad` or `good` function, and print per warning name: bad hits, good hits,
discrimination — the `--by-check` table for compiler diagnostics. Anything
with a positive good-side margin and ≥10 hits is a candidate; anything that
fires equally on both is a guideline and stays out. Candidates to expect:
`-Warray-bounds` (constant index past a fixed array — the 121/122 `_large_`
family the `bounds-write` lane asks about), `-Wsometimes-uninitialized` and
`-Wuninitialized` (457), `-Wdivision-by-zero` (369 constants),
`-Wfree-nonheap-object` (590 direct forms), `-Wtautological-*-out-of-range-compare`,
`-Wshift-count-overflow`, `-Wsizeof-pointer-memaccess`/`-Wsizeof-array-argument`
(131), `-Wdangling*`, `-Wconstant-conversion`/`-Wliteral-conversion` (197,
though explicit casts silence them). For each keeper: name it in
`DEFAULT_CHECKS`, force the flag in `FORCED_WARNINGS`, add the
`[[rule]]` with the CWE and a confidence argued from the discrimination
(the compiler has the whole function; high is often right), and a fixture.
Report the whole table in the brief — the negatives are the other lanes'
verdicts.

### 2. Do the same for cppcheck's `--enable=all --inconclusive` ids

Same script, second engine: which cppcheck ids fire on Juliet's `bad` and not
its `good`, that Kordon's `warning,style,portability` set does not run.
`CLAUDE.md` records that `--enable=all` adds `information` and
`unusedFunction` noise — that is about *counts*, not discrimination; the
table decides.

### 3. CWE-843: build it or close it

As above. Fixture `type_confusion_void_pointer` with the good twin pointing
at an `int`.

### 4. Mark the existing fixtures

`block_delimitation` (483), `disabled_guard` (483, `bugprone-suspicious-
semicolon`), `dead_store` (563), `unused_loop_var` (563).

### 5. 563's three false positives and the `do nothing` misses

Per-CWE `--by-check`; then two of the missed files by hand.

## Don't

- Add a diagnostic on the strength of its name. `-Wall` is not a check set;
  the sweep is.
- Chase 562 past 50%.

## Fixtures

Marked: none yet. To mark: `block_delimitation`, `disabled_guard`,
`dead_store`, `unused_loop_var`. To build: one per adopted diagnostic,
`type_confusion_void_pointer`.

## For CLAUDE.md

(fill in — the sweep table is the deliverable other lanes will read)

## State

not started
