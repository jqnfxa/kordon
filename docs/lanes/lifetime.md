# Lane `lifetime` — CWE-401, 415, 416, 590, 762/763, 672, 772, 775

branch `lane/lifetime` · worktree `.claude/worktree/lifetime` · skills: `kordon-lane` first

## Scope

Allocation lifetime: leak, double free, use after free, free of non-heap
memory, mismatched allocator/deallocator, use after release (iterators), and
descriptor/stream leaks. The engines here are `unix.Malloc`,
`cplusplus.NewDelete[Leaks]`, `unix.MismatchedDeallocator`, cppcheck's
`memleak`/`doubleFree`/`autovarInvalidDeallocation`/`deallocuse`, and Kordon's
`kordon-reinit-without-free`, `kordon-manual-ownership-flag`,
`kordon-transfer-to-non-owner`. The ownership-summary pass `CLAUDE.md` has
described since the first session still does not exist.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | dynamic | multi-file no-ctu → ctu (FP) | tier |
|---|---|---|---|---|---|---|
| 401 leak | 39/45 = 86.7% (73.3) | 30/168 = **17.9%** | +68.8 | 14/25 | 23.1% → 34.6% (17.2) | B |
| 415 double free | 40/43 = 93.0% (93.0) | 6/170 | +89.5 | 16/25 | 40.0% → 50.0% (**24.2**) | B |
| 416 use after free | 21/42 = 50.0% (50.0) | 0/174 | +50.0 | 21/25 | 0% → 30.0% (0) | E |
| 590 free non-heap | 19/45 = 42.2% (42.2) | 0/106 | +42.2 | 15/25 | 0% → 0% | E |
| 762 mismatched | 39/46 = 84.8% (84.8) | 0/169 | +84.8 | 25/25 | 0% → 36.4% (0) | B |
| 775 fd leak | 8/49 = 16.3% (16.3) | 1/108 | +15.4 | 25/25 (valgrind `--track-fds`) | 0% → 0% | E |
| 672 after release | **0/33** | 0/121 | 0 | — | — | G |

### Multi-file cases with `--ctu` (survey 2026-09-11, 25 cases per CWE)

401: 26/57 · 415: 20/63 · 416: 14/50 · 590: **0/57** · 762: 16/53 (2 of 70 units failed to compile) · 775: not sampled · 672: 0/44. 590 is zero across units even with CTU — the stack buffer is declared in the source unit and freed in the sink unit; check whether `autovarInvalidDeallocation` and `unix.Malloc` can see a stack region imported through CTU at all before building anything. Per-shape tables and the missed functions are in `docs/lanes/survey-2026-09-11.md`.

## Shapes and verdicts

### CWE-416 — half the misses are one cause, and it was found today

| shape | found | verdict |
|---|---|---|
| Allocate · use after `delete` | 13/14 | B |
| Allocate · use after **`delete[]`** | **4/14** | **the analyzer's loop budget** — TODO 1 |
| Allocate · use after `free()` in flow variants `_02`…`_15` | **4/12** | same |
| direct · use a block returned freed from a helper | 0/2 | investigate (interprocedural in one TU; should inline) |

Probed directly on `new_delete_array_int_01.cpp` and `malloc_free_int_03.c`:
`clang --analyze` with `core,cplusplus,unix` reports **nothing**; with
`-analyzer-config widen-loops=true` or `unroll-loops=true` it reports `Use of
memory after it is freed` on both. Every missed case initialises the block
with a `for (i = 0; i < 100; i++)` loop before freeing it; the default
`max-loop=4` abandons the path after four iterations, so the code after the
loop is never analysed. `max-loop=128` alone does **not** recover it.

### CWE-590

| shape | found | verdict |
|---|---|---|
| static / declare · `free(data)` | 19/28 | B — `autovarInvalidDeallocation`, `unix.Malloc` "not memory allocated by" |
| **alloca** · `free(data)` | **0/13** | investigate — TODO 2 |
| **placement_new** · `delete data` | **0/4** | no engine — TODO 2 |

Probed: on a three-line `char *p = alloca(100); free(p);` Clang SA reports
`Memory allocated by alloca() should not be deallocated [unix.Malloc]`. On
Juliet's case, which has the 100-iteration init loop between the `alloca` and
the `free`, it reports nothing, and `widen-loops=true` does **not** recover it
(widening invalidates the region binding, so `free` sees an unknown pointer).
**`unroll-loops=true` does recover it** — probed: `Memory allocated by
alloca() should not be deallocated [unix.Malloc]` at the `free`. So unrolling
keeps the region where widening loses it; that is the discriminator between
the two options in TODO 1. Also note the
message "Memory allocated by alloca()" contains neither of the existing
`unix.Malloc` discriminators, so even when it fires it is filed as **CWE-401**
by the bare rule; and `cplusplus.NewDelete` has no "not memory allocated by"
rule at all, so a stack `delete` would be filed as 416. Both are mapping fixes.
Placement new: neither Clang SA nor cppcheck reports `delete p` for
`p = new (storage) T` — a matcher (`delete` of a pointer initialised from a
`cxxNewExpr` with a placement argument, same function) is C.

### CWE-401 / 415 / 762

Working. 401's 17.9% false positives are the item (TODO 5); 415's 24.2%
under `--ctu --multifile` is TODO 6; 762's misses are `_41`+ flow variants.

### CWE-775

`fopen`/`open` never closed: 8/49, and **13 of 40 units failed to compile**
(`w32CreateFile`), which the static scorer does not exclude — that is the
`infra` lane's `UNPORTABLE` item; your number will rise when it lands.
Probed on `fopen_no_close_01.c`: **both `alpha.unix.Stream` ("Opened stream
never closed. Potential resource leak") and `alpha.unix.SimpleStream`
("Opened file is never closed") report it** at the closing brace. Neither is
enabled today (TODO 3); cppcheck `resourceLeak` is presumably the 16%.

### CWE-672

`list<int> data; for (i = data.begin(); …) { if (!*i) data.clear(); cout << *i; }`
— 0/33. `alpha.cplusplus.InvalidatedIterator` is the checker built for exactly
this; cppcheck has `invalidIterator1`/`derefInvalidIterator` and reported
nothing. Probe both (TODO 4). If neither sees it, the verdict is G: a
per-container lifetime model, which is the ownership pass.

## TODO — in order

### 1. The loop budget (416, and probably 590, 401 flow variants) — with `infra`

Kordon has no way to pass `-analyzer-config` options today: the `clang
--analyze` pass sets one (`src/tools/clang_sa.rs:216`), the clang-tidy pass
none. The **`infra` lane** owns the plumbing (a `--analyzer-config` flag or a
constant applied to both passes) and the whole-baseline cost/FP measurement,
because widening changes every path-sensitive result. Your part:

- `testdata/uaf_after_loop/`: `new int[100]` + init loop + `delete[]` + read;
  `malloc` + loop + `free` + read; the good twins reallocate or reorder. Mark
  it; it must **fail** today.
- until infra lands, measure the hypothesis by hand:
  `scripts/explain-misses.py 416 --misses` before, then re-run kordon on the
  missed files with the option injected (`clang --analyze … -Xclang
  -analyzer-config -Xclang widen-loops=true`) and count. Record the numbers
  for both `widen-loops` and `unroll-loops`; they are not the same thing
  (widening loses the region, unrolling keeps it — measured: only
  `unroll-loops` recovers the 590 `alloca` case).
- when infra's flag exists, re-run 416/590/401 and the whole baseline with it
  and put the numbers in `## For CLAUDE.md`.

### 2. CWE-590: the `alloca` and placement-new sources

Three parts. (a) Mapping: add `message_contains = "alloca()"` → 590 for
`unix.Malloc`, and `"not memory allocated by"` → 590 for
`cplusplus.NewDelete`, before the bare rules; the fixture `free_alloca` must
draw 590, not 401 — do this first, it is independent of the loop budget and
the finding already exists on the probe. (b) Detection: `unroll-loops=true`
recovers the Juliet alloca case (measured); it is TODO 1's flag, so the 13
cases move when infra lands it. (c) `kordon-delete-placement-new`:
C, medium — fixture `delete_placement_new` with the good twin calling the
destructor explicitly (`p->~T()`) and never `delete`.

### 3. CWE-775: `alpha.unix.Stream` — confirmed to fire, not enabled

Add it to `ALPHA_CHECKERS` in `src/tools/clang_sa.rs` (append; pick one of
the two — `Stream` models more of `<stdio.h>`, `SimpleStream` is the older
one; measure both), map "never closed"/"Opened stream" → 775 high, and
measure: the checker is alpha, so the false-positive column matters more than
recall. Note the finding anchors on the function's closing brace, which the
scorer attributes to the function correctly. `open()`/`close()` (raw fds)
have no Clang SA model; a matcher "`open(` assigned to a local `int` with no
`close(` of it in the function" is C-narrow and worth one fixture — but the
dynamic layer already gets 100% here, so weigh the cost.

### 4. CWE-672: the iterator checkers

`alpha.cplusplus.InvalidatedIterator`, `alpha.cplusplus.IteratorRange`,
`alpha.cplusplus.MismatchedIterator` in the `clang --analyze` pass; cppcheck
`invalidIterator1` (is it `inconclusive`?). **Probed with the first two on
`list_int_01.cpp` at default options: silent.** Two things to rule out before
calling it G: the loop over the list is unbounded, so this may be the loop
budget again (retry with `unroll-loops=true` / `widen-loops=true`), and the
iterator checkers depend on `alpha.cplusplus.ContainerModeling` /
`IteratorModeling` — enable them explicitly. Fixture `invalidated_iterator`
from the Juliet shape. If a checker fires, map → 672 medium and measure FP on
`pkt-astronomia` (C++ with real containers) once. If nothing fires: verdict G,
and write the shape into the ownership-pass design (TODO 7).

### 5. CWE-401's 17.9% false positives

`--by-check --cwe 401`. Suspect `cppcoreguidelines-owning-memory` (mapped 401,
low, fires once per raw pointer on flawed and correct functions alike — a
*guideline*, by the repo's own test) and `kordon-manual-ownership-flag`. The
CLAUDE.md rule: a guideline check filed under a defect CWE inflates raw recall
and FP and never reaches the reader → CWE-398 tier 0, still enabled. Check
whether `owning-memory` has any exclusive coverage first (the bad column).

### 6. CWE-415's 24.2% false positives under `--ctu --multifile`

Name the check. Double-free reported in a `good` function across units is
either an inlining artefact worth a note or a real mapping problem.

### 7. The ownership-summary pass — design, not code

The oldest open item in `CLAUDE.md`. Write `docs/design/ownership-summary.md`:
what a per-class summary holds (owning raw-pointer members, release sites,
the flag pattern), how it is computed from the AST (clang-query cannot; this
is a small libTooling pass or a clang-tidy plugin), how it feeds
`kordon-reinit-without-free`/`manual-ownership-flag`, and what it would close
(672's container case, `fco_vector.h`'s flag, the Rule-of-Five double free).
Two pages, with the fixtures it would be measured on. Do not start the code
in this lane cycle.

## Fixtures

Marked: none yet. To mark (yours): `basic` (leaks.cpp), `ownership_flag`,
`reinit_leak`, `unowned_transfer`. To build: `uaf_after_loop`, `free_alloca`,
`delete_placement_new`, `stream_leak`, `invalidated_iterator`.

## Don't

- Build a leak check that pairs `new` with `delete` in one function; that is
  the false-positive class the ownership summary exists to replace.
- Report the dynamic layer's 775 result as static coverage.

## For CLAUDE.md

(fill in — the loop-budget measurement belongs here whatever it shows)

## State

not started
