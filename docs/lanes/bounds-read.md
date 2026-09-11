# Lane `bounds-read` — CWE-125, 126, 127 (and 170)

branch `lane/bounds-read` · worktree `.claude/worktree/bounds-read` · skills: `kordon-lane` first

## Scope

Out-of-bounds *reads*: over-read past the end, under-read before the start,
and the loop-counter-after-the-loop shape (`kordon-loop-index-escape`, CWE-125,
built from the rtklib `ddidx` crash). CWE-170 (missing terminator, then a read
runs off the end) is here because its consequence is a read.

Shared with `bounds-write`: the alpha checkers and the direction split of
`alpha.unix.cstring.OutOfBounds` (write text → 787, read text → 125). The
copy-loop check is **built in `bounds-write`** (its TODO 2) with a read-side id
you consume; coordinate through the briefs rather than building it twice.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | dynamic | `--ikos` | multi-file ctu (FP) | tier |
|---|---|---|---|---|---|---|---|
| 126 over-read | 5/44 = 11.4% (11.4) | 0/121 | +11.4 | 17/25 | **86.2%** at 44.6% FP | 35.0% (**20.5**) | D |
| 127 under-read | 18/45 = 40.0% (40.0) | 0/117 | +40.0 | 10/25 | — | 21.7% (10.3) | C |

Settled (in `CLAUDE.md`): CWE-126's dominant shape `memcpy(dest, data,
strlen(dest))` has the identical line in the corrected twin — value-range, IKOS
reports it precisely; IKOS's findings there are *warnings* and belong in the
unproven tier. CWE-127's `data = dataBuffer - 8` is caught by cppcheck's
`pointerOutOfBounds` and the alpha checker.

### Multi-file cases with `--ctu` (survey 2026-09-11, 25 cases per CWE)

126: **0/59** · 127: 7/56. 126 is zero with CTU on the split cases; the value-range verdict holds across units too. Per-shape tables and the missed functions are in `docs/lanes/survey-2026-09-11.md`.

## Shapes and verdicts

### CWE-126

| shape | found | verdict | note |
|---|---|---|---|
| fgets/fscanf/large/socket · index sign-checked only | 4/8 | C | the misses are `_41`+ parameter variants — ceiling |
| Set/Use · memcpy / memmove / loop reading `data` for `strlen(dest)` | **0/30** | **D** | identical line in `goodG2B`; `--ikos` → 86% |
| direct · copy without null termination, then read (CWE-170 shape) | 0/5 | triage | `bugprone-not-null-terminated-result` is mapped 170 medium — does it fire? `NotNullTerminated` never did |

### CWE-127

| shape | found | verdict | note |
|---|---|---|---|
| Set (`dataBuffer - 8`) · memcpy / memmove | 12/15 | B | `pointerOutOfBounds` |
| Set · **loop / strcpy / strncpy / wcscpy / wcsncpy** | **5/24** | investigate | same arithmetic, different sink, three quarters missed — TODO 1 |
| negative · index bounded above only | 1/1 | C | `kordon-unchecked-negative-index` |
| rand/fgets/fscanf/socket · index | 0/5 | ceiling | parameter variants |

## TODO — in order

### 1. Why does the sink decide whether `dataBuffer - 8` is reported?

The pointer arithmetic is identical in every 127 case; with `memcpy` as the
sink it is found 80%, with `strcpy`/`strncpy`/`wcscpy`/a loop 20%. Either
cppcheck reports the arithmetic only when it can see the access size (memcpy
has one), or the finding lands on a line the scorer attributes elsewhere.
Build `testdata/underread_string_copy/` with the five sinks and one good twin
(`dataBuffer + 0`), run with `-v`, and look at which engine fires where. If it
is a mapping or an anchor problem, fix it; if cppcheck genuinely needs the
size, `ArrayBoundV2` should still see the `strcpy` read — check whether the
finding exists at low confidence or not at all.

### 2. Make `--ikos` legible for CWE-126, not default

86% recall at 44.6% FP belongs in the unproven tier, which is where it is.
Two things are still open: (a) the report's skip message says what `--ikos`
is worth — verify the text on a run without it; (b) IKOS has several numeric
domains (`ikos -d interval|dbm|var-pack-dbm|gauge|…`). Measure two or three on
`scripts/explain-misses.py 126 -- --ikos` (the domain needs a Kordon flag or an
env var — add one in `src/tools/ikos.rs`, append-only) and record whether any
cuts the false-positive rate enough to move these findings to medium. A
negative result is a result; write it down.

### 3. The copy loop, read side

When `bounds-write` lands `kordon-copy-loop-overreads` (source extent < loop
bound, CWE-125), add the read-side fixture here
(`for (i<100) dest[i] = data[i]` with `data` 50 bytes) and measure 126's
`Set/Use · loop` rows (0/9). Until then, record the dependency in `## State`.

### 4. CWE-170: un-terminated copy then read

`strncpy(dest, src, n)` without `dest[n] = 0`, then `strlen(dest)` / print.
Check `bugprone-not-null-terminated-result` on the Juliet `direct` cases and
on a fixture; if it fires, the accept set for 126 may legitimately include 170
(*with the reason written in `EQUIVALENT`*). If nothing fires, a matcher for
"`strncpy(d, s, sizeof d)` / `strncpy(d, s, n)` with no later `d[...] = 0` in
the function" is C-narrow; measure its discrimination on the `goodG2B` twins
before keeping it.

### 5. `kordon-loop-index-escape`: the confidence split that was designed but not built

`CLAUDE.md` records the design: a loop with **no** `break` always exits at the
bound, so the read is unconditional → high; with a `break` it is one path →
medium. Today it is one id at medium. Two ids (`…-escape` / `…-escape-guarded`),
with `testdata/loop_index_escape/` already marked and covering both — extend
the fixture's expectations rather than its cases.

### 6. Multi-file: 126's 20.5% FP under `--ctu`

Name the check with `--multifile --kordon-arg=--ctu --cwe 126 --by-check`.

## False-positive work

Both CWEs are at 0% FP on the single-file sample. The multi-file rates (20.5%
and 10.3%) are the open items; the IKOS rate is the deliberate one.

## Don't

- Move IKOS's CWE-126 warnings out of the unproven tier without a domain that
  measurably earns it.
- Build a matcher for the `memcpy(dest, data, strlen(dest))` family.

## Fixtures

Marked: `loop_index_escape`. To build: `underread_string_copy`,
`unterminated_read`, the read-side copy-loop twin.

## For CLAUDE.md

(fill in)

## State

not started
