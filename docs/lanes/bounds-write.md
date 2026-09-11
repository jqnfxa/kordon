# Lane `bounds-write` — CWE-121, 122, 124 (and 787, 788, 119, 129, 131, 120)

branch `lane/bounds-write` · worktree `.claude/worktree/bounds-write` · skills: `kordon-lane` first

## Scope

Out-of-bounds *writes*: stack overflow, heap overflow, underwrite, and the
generic ids the engines report them under. Reads (125/126/127) are the
`bounds-read` lane, but the two share machinery: the alpha checkers in
`src/tools/clang_sa.rs`, the index checks in `src/tools/clang_query.rs`
(`kordon-one-sided-index-guard`, `kordon-unchecked-negative-index`,
`kordon-index-used-before-check`, `kordon-unchecked-constant-index`,
`kordon-unchecked-parallel-extent`). Any check that covers both directions
is built here and consumed there.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | dynamic | multi-file no-ctu → ctu (FP) | tier |
|---|---|---|---|---|---|---|
| 121 stack overflow | 20/44 = 45.5% (45.5) | 0/112 | +45.5 | 16/24 | 9.5% → 23.8% (5.7) | C |
| 122 heap overflow | 15/48 = 31.2% (31.2) | 0/116 | +31.2 | 12/25 | 33.3% → 38.1% (**27.8**) | D |
| 124 underwrite | 34/45 = 75.6% (75.6) | 2/117 | +73.8 | 11/25 | 26.1% → 43.5% (12.8) | C |

Already settled, do not re-derive (all in `CLAUDE.md`): the three alpha
checkers are the only route to the library-call shapes and run only in the
`clang --analyze` pass; `ArrayBoundV2` is medium by design; the one-sided index
checks exist and report zero positions on 169 real translation units; the
`pro-bounds-*` guideline checks are tier 0; `alpha.unix.cstring.NotNullTerminated`
never fires and was removed.

## Shapes and verdicts (from `scripts/explain-misses.py <cwe>`)

### CWE-121

| shape (source · sink) | found | verdict | note |
|---|---|---|---|
| Set/Point · memcpy/memmove/strncpy (CWE805: length from dest size) | 12/14 | B | `cstring.OutOfBounds` |
| rand/socket · index sign-checked only (CWE129) | 2/2 | C | `kordon-one-sided-index-guard` |
| **Initialize · copy *data* into a 50-byte dest** with strcpy / memcpy / memmove / strncpy / strncat / loop / swprintf / wcscat / wcsncat (CWE806: bound taken from the *source*) | **0/15** | triage first | see TODO 1 — diff `goodG2B` before building anything |
| Set · wcscpy / wcsncpy / strcat | 0/3, 1/2 | engine gap | wide and concatenating functions are not modelled by `CStringChecker` |
| Set · twoIntsStruct array memcpy | 0/2 | ? | struct-typed copy; check whether the checker computes the extent |
| fscanf · index | 0/1 | ceiling | `_41`+ variant: the index arrives as a parameter, see below |
| Initialize · placement new | 0/1 | E | one case; leave |

### CWE-122

| shape | found | verdict | note |
|---|---|---|---|
| Allocate · memcpy/memmove/strcpy/strncpy/loop | 12/15 | B | |
| Allocate · **strcat** ×4, wcscpy ×4, snprintf, swprintf, wcsncat, wcsncpy | **0/13** | engine gap | concatenation needs the current length, not the capacity; wide unmodelled |
| Allocate · copy **loop** (`for (i<100) data[i] = source[i]` into `malloc(50)`) | 0/2 (+1 found) | **C-narrow** | two literals in one function — TODO 2 |
| Initialize · copy data to string (loop/memmove/snprintf/strncat/wcscat/wcscpy) | 0/8 | as 121 row 3 | |
| fgets/listen_socket/large · index | 0/5 | ceiling / verify | `_41`+ parameter variants; `large` is a constant — TODO 5 |

### CWE-124

| shape | found | verdict | note |
|---|---|---|---|
| Set (`data = dataBuffer - 8`) · strcpy/loop/memmove/strncpy/memcpy | 27/32 | B | `pointerOutOfBounds` (cppcheck) + alpha |
| Set · wcscpy / wcsncpy | 1/7 | engine gap | wide again |
| any source · index bounded above, never sign-checked (CWE839) | 7/7 | C | `kordon-unchecked-negative-index` |

The **parameter ceiling**: in flow variants `_41` and above the sink is a
separate function that receives `data` as a parameter, so the "filled from a
call" clause of the index checks cannot fire. Extending them to parameters is
the loop-counter flood in another form (callers validate). Record it as the
ceiling for the index rows; do not build it.

## TODO — in order

### 1. The CWE806 family (`Initialize · copy data …`), 0/15 on 121 — triage before building

The flawed line is `strncpy(dest, data, strlen(data))` / `memcpy(dest, data,
strlen(data) * sizeof(char))` with `dest[50]` and `data` holding 99 chars: the
length is taken from the **source**. That is a real-world bug shape. But
**diff `goodG2B` first**: if the corrected function keeps the identical line and
only shrinks `data`, this is the CWE-126 lesson again and a matcher
discriminates zero → verdict D, and `--ikos` is the answer (measure it:
`scripts/explain-misses.py 121 -- --ikos`). If `goodG2B` instead bounds the
length by the destination, a matcher keyed on "length argument derived from
the source argument, destination a fixed-size local" is C, medium, and
covers 121/122/124/126/127 at once. Fixture either way.

### 2. Literal-bound copy loop, both directions — build here, `bounds-read` reuses it

    data = (char *)malloc(50 * sizeof(char));      // or char data[50]
    for (i = 0; i < 100; i++) data[i] = source[i]; // 100 > 50

Two literals in one function; no value analysis needed. Two check ids because
the claim differs: `kordon-copy-loop-overwrites` (dest extent < loop bound →
787) and `kordon-copy-loop-overreads` (source extent < loop bound → 125).
Clauses: the subscript's base is a local array with a literal extent or a
pointer assigned from `malloc(<literal> * sizeof)` / `new T[<literal>]`; the
loop condition compares the index against a larger literal; the index is the
loop's own counter. Good twins: equal literals; a bound taken from
`sizeof(dest)`; a runtime bound. Spot-check `rtklib_mod` — terse C with many
fixed loops is exactly where this would flood.

### 3. Wide-string and concatenation sinks (`wcscpy`, `wcsncpy`, `wcscat`, `wcsncat`, `strcat`, `swprintf`)

An engine gap, shared with `bounds-read` and `init`. Two honest options: a
narrow matcher for the literal-extent case (dest is a fixed local array, the
source is a literal or a local array with a larger literal extent) — build the
fixture `wide_copy_overflow` and measure discrimination; or a verdict D with
the `--ikos` number attached. Do not model string semantics in a matcher.

### 4. The `hoisted_guard` false positive — a shipped check penalising the fix

`testdata/hoisted_guard/` (unmarked; mark it, it is yours):
`kordon-unchecked-parallel-extent` fires on all five functions, including the
three that hoist the precondition into `const bool condition = …; assert(condition);
if (!condition) return;`. The exemption looks for an `ifStmt` whose condition
*mentions the subscripted parameter*; the hoisted form names the local. Fix:
follow the local — an `ifStmt` whose condition names a variable whose
initialiser mentions the parameter. `add_unrelated_bool` is the control that
must survive. Full write-up in `docs/acl-report-findings.md` § Fixtures.

### 5. `_large_`: a constant index with no call involved

`data = 10; if (data >= 0) buffer[data] = 1;` (121 `CWE129_large`, 122
`large`). No call, so the index checks skip it by design — but cppcheck's
`arrayIndexOutOfBounds` and `ArrayBoundV2` should both see a constant 10 into
`buffer[10]`. Build the three-line fixture and find out which engine is silent
and why (`-Warray-bounds` is another candidate; the `misc` lane's diagnostic
sweep may hand you the answer).

### 6. Multi-file: 122's 27.8% false positives under `--ctu`

`scripts/score-juliet.py third_party/juliet/C --multifile --kordon-arg=--ctu
--cwe 122 --by-check` — name the check. If it is `ArrayBoundV2` seeing across
units, the confidence is right and the note is what changes; if it is a
mapping, fix it.

### 7. Mark the existing fixtures

`assert_validation`, `index_order`, `parallel_extent`, `hoisted_guard`,
`zero_length_tu_gate` (the content is yours; the 8-unit CTU ceiling in
`zero_length_ctu/README.md` is the `infra` lane's). `one_sided_index` and
`zero_length_ctu` are already marked.

## False-positive work

124's two flagged correct functions: `scripts/score-juliet.py … --cwe 124
--by-check` names the check. Everything else in this lane is at 0% FP on the
single-file sample; keep it there — every new clause above is measured on the
whole baseline and spot-checked on `rtklib_mod`.

## Don't

- Extend the index checks to function parameters (see the ceiling).
- Add `alpha.unix.cstring.NotNullTerminated` back; it never fired.
- Chase the value-range rows with a matcher; the good twin has the same line.

## For CLAUDE.md

(fill in: measured facts only, dated, terse)

## State

not started
