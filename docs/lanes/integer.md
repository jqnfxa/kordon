# Lane `integer` — CWE-190, 191, 197, 680, 369

branch `lane/integer` · worktree `.claude/worktree/integer` · skills: `kordon-lane` first

## Scope

Arithmetic: overflow, underflow, truncation, overflow-into-allocation, and
divide by zero. Kordon's own checks here: `kordon-unsigned-subtraction` (191,
low), `kordon-unsigned-addition` (190, low), `kordon-extent-underflow` (191,
medium), `kordon-unchecked-divisor` (369, error) and
`kordon-unchecked-float-divisor` (369, advice). IKOS is the only engine that
*proves* any of this.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | dynamic | `--ikos` | tier |
|---|---|---|---|---|---|---|
| 190 overflow | 9/49 = 18.4% (**2.0**) | 24/178 = **13.5%** | +4.9 | 4/25 | 31.2% | D |
| 191 underflow | 16/50 = 32.0% (**0.0**) | 24/176 = **13.6%** | +18.4 | 4/25 | 52.9% | F |
| 197 truncation | 24/47 = 51.1% (**0.0**) | 0/106 | +51.1 | — | — | F |
| 680 overflow → alloc | 32/48 = 66.7% (54.2) | 20/109 = **18.3%** | +48.3 | — | — | D |
| 369 divide by zero | 28/50 = 56.0% (56.0) | 2/182 | +54.9 | — | — | C |

Settled (in `CLAUDE.md`): no Clang SA checker covers integer overflow; IKOS
proves the constant cases; ~71% of 190/191 cases take their value from
`rand`/`fscanf`/sockets and are unprovable; the `char`/`short` `_max_` cases
are not CWE-190 (promotion) and are deliberately left in; 369's `float_`
families are excluded with the reason printed; float division is Advice. This
lane holds **three of the four worst false-positive rates in the baseline**.

### Multi-file cases with `--ctu` (survey 2026-09-11, 25 cases per CWE)

190: 8/62 · 191: 12/59 · 197: 15/56 · 680: 20/56 · 369: 3/37. 369 drops to 8% on split cases: the divisor is always a parameter of the sink unit — the ceiling, measured. Per-shape tables and the missed functions are in `docs/lanes/survey-2026-09-11.md`.

## Shapes and verdicts

### CWE-190 / 191

| shape | 190 found | 191 found | verdict |
|---|---|---|---|
| socket/fgets · `++`, `+1`, `*2` | 4/5 | 8/10 | mixed — see TODO 4 |
| rand · any sink | 0/12 | 10/13 | ? 191 finds what 190 misses on the same source — TODO 4 |
| fscanf · any sink | 1/17 | 0/14 | D (unprovable) — IKOS says "cannot prove" |
| max / min · constant then `+1`/`-1`/square | 4/14 | 1/15 | D — IKOS proves; cppcheck `integerOverflow` gets some |

### CWE-197

| shape | found | verdict |
|---|---|---|
| socket/fgets/rand · `(char)data`, `(short)data` | 24/31 | F — `bugprone-narrowing-conversions`, low; the good twin has the identical cast |
| fscanf · same | 0/10 | F |
| large · `short data = CHAR_MAX + 1; (char)data` | 0/6 | F — a constant through an explicit cast; no diagnostic fires (probed) |

### CWE-680

| shape | found | verdict |
|---|---|---|
| connect_socket / fgets / listen_socket · `malloc(data * sizeof(int))` then fill | **25/25** | which check? — TODO 1 |
| rand · same | 3/6 | |
| fscanf · same | **2/11** | the same sink at 100% for `fgets` and 18% for `fscanf` — TODO 1 |
| fixed · `data = INT_MAX / 4 + 1` | 2/6 | D — IKOS |

### CWE-369

All sources 33–75%; the misses are `_41`+ variants where the divisor arrives
as a **parameter**, which the "from a call" clause deliberately does not cover
(callers validate; extending it is the loop-counter flood). Record the
ceiling; do not build.

## TODO — in order

### 1. CWE-680: find the asymmetry, then build the allocation-size check

Same sink, `fgets` 100% and `fscanf` 18%. `fgets` sources go through
`atoi(inputBuffer)` — a call assigned to `data`; `fscanf(stdin, "%d", &data)`
fills an out-parameter. Some check is firing on the first and not the second:
`scripts/explain-misses.py 680 --found` and `-v` on one of each will name it.
Then the check this CWE needs, which nothing has: **an allocation whose size is
an external value never bounded above**:

    data = atoi(buf);               // or fscanf(…, &data), rand(), recv()
    buffer = malloc(data * sizeof(int));   // or new int[data]
    for (i = 0; i < data; i++) buffer[i] = 0;

`kordon-unbounded-allocation-size`, CWE-680, medium, error. Reuse the
three-spelling "from a call" fragment from `one_sided_index_guard_matcher()`
(copy the string; do not refactor that function — another lane may be in it).
Good twins: `if (data > 0 && data < 100)` before the allocation; a `size_t`
bounded by `sizeof`; a constant size. Spot-check `rtklib_mod`.

### 2. Tier F into the Advice band — 191, 197, and the low 190 checks

`CLAUDE.md` says this is the next step and it has not been done. Unsigned
wraparound and narrowing are *defined*; the same shape is a bug or a technique
by intent. Decide, per rule in `data/cwe_map.toml`: `severity = "style"` for
`bugprone-narrowing-conversions`, `cppcoreguidelines-narrowing-conversions`,
`bugprone-signed-char-misuse`, `kordon-unsigned-subtraction`,
`kordon-unsigned-addition`; keep `kordon-extent-underflow` as an error (an
extent of −1 is never a technique). Then check the report text: a tier-F CWE
reading "0% surfaced" must read "reported, as advice" instead — that is a
`docs/progress.md`/`progress.py` change, which is the integrator's; write the
wording in `## For CLAUDE.md`.

### 3. The false positives: 13.5%, 13.6%, 18.3%

`scripts/score-juliet.py third_party/juliet/C --cwe 190 --cwe 191 --cwe 680
--by-check --limit 40` — the good-side column names the checks. Suspects:
`kordon-unsigned-addition`/`-subtraction` firing on the guarded twin
(`if (data < INT_MAX) data++` still contains `data++`), and
`bugprone-implicit-widening-of-multiplication-result` (190, medium) on
`malloc(data * sizeof(int))` in the *corrected* 680 functions. For each: does
the check find anything nothing else finds (`--by-check` bad column)? If not,
tier 0 or drop; if yes, is the noise surfaced? A low check's noise costs a
reader nothing — the decision rule is in `CLAUDE.md` under CWE-457.

### 4. 190 vs 191 on the `rand` source: 0/12 against 10/13

Same source, mirror sinks (`data++` vs `data--`), and only one direction is
found. Whatever reports the decrement — find it with `--found` — is either not
reporting the increment or reporting it under a CWE the 190 accept set
(`{190, 680}`) rejects. Fixture with both directions.

### 5. `saturating_overflow` — two mechanical shapes from a real codebase

`testdata/saturating_overflow/` (unmarked; yours; measured 1 of 3 found, 2
false positives — see `docs/acl-report-findings.md` § Fixtures):

- **a negative error return stored unsigned**: `size_t n = ftell(f);` with no
  `< 0` test before use — `ftell`, `ftello`, `lseek`, `read`, `recv`, `sscanf`
  returns assigned to an unsigned type. Narrow, mechanical, should cost no
  false positives. New check, CWE-195 (add it to the catalog, tier 1; it is
  the signed-to-unsigned conversion class) or 190 — argue the choice in the
  rule comment.
- **saturate then unsaturate**: a callee that clamps to a type maximum, whose
  caller immediately adds to the result. Cross-function; probably a verdict E
  rather than a check — but the fixture must stop flagging the *lockstep*
  twin (`pyramid_index`, two expressions that wrap together), which is the
  vendor's false positive reproduced by `kordon-unsigned-addition`.

### 6. `masked_underflow` — 5 of 7, one false positive, one twin problem

`testdata/masked_underflow/` (unmarked; yours). The false positive is the
*correct* clamp `std::max(w, 1) - 1`, flagged like its defective sibling
`std::max(w - 1, 1)`. Exempt a left operand that is a `max`/`std::max` call
with a positive literal — measure that it does not exempt the sibling. The
twin problem: three overloads carry the identical `&&`-for-`||` guard and only
the first is flagged; find out why the matcher stops.

### 7. Record the 369 ceiling and mark `unchecked_divisor`

Already marked and green. Write the parameter ceiling into `## For CLAUDE.md`
with the count of `_41`+ cases in the sample.

## Don't

- Build a matcher that fires on `data + 1` — it fires on the guarded twin too
  (`bugprone-narrowing-conversions` read 64% where detection was zero).
- Extend the divisor or index "from a call" clauses to parameters.
- Loosen `kordon-extent-underflow`'s early-exit clause; the defect's own `if`
  is what it protects against.

## Fixtures

Marked: `unchecked_divisor`. To mark: `unsigned_underflow` (two files),
`masked_underflow`, `saturating_overflow`. To build: `unbounded_alloc_size`,
`negative_return_unsigned`, `overflow_direction_pair`.

## For CLAUDE.md

(fill in)

## State

not started
