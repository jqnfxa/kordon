# Juliet coverage inventory

What the NIST Juliet C/C++ 1.3 suite holds, what Kordon is measured on, and what is
left to do. Counts regenerate with `scripts/juliet-inventory.py`.

The suite has **118 CWE directories and 101,231 source files**. **26** of those CWEs are tier 1 — the classes Kordon claims — holding 62,066 files.

## Reading the columns

- **files** — single-file cases, then multi-file ones (`_54a.c`..`_54e.c`, `_81`..`_84`)
  whose defect crosses translation units. The scorers sample; they never run all of it.
- **static** — `scripts/score-juliet.py`, default flags, 40 files per CWE. The bracketed
  figure is *surfaced* recall: high and medium confidence only, which is what the report
  shows without `--all`.
- **dynamic** — `scripts/score-juliet-dynamic.py`, 25 cases per CWE, as a fraction of
  cases that actually built and ran.
- **The two columns are not comparable and must not be added.** Different samples,
  different denominators, different questions. See the open question at the end.

## Tier 1 — measured

| CWE | name | files (single / multi) | static | dynamic |
|---|---|---|---|---|
| 122 | Heap-based Buffer Overflow | 3,508 / 6,144 | 29.2% (29.2%) | 48.0% |
| 121 | Stack-based Buffer Overflow | 3,057 / 4,832 | 40.9% (40.9%) | 66.7% |
| 190 | Integer Overflow or Wraparound | 2,462 / 3,996 | 18.4% (2.0%) | 16.0% |
| 762 | Mismatched Memory Management Routines | 2,110 / 3,996 | 84.8% (84.8%) | 100.0% |
| 191 | Integer Underflow (Wrap or Wraparound) | 1,870 / 2,862 | 32.0% (0.0%) | 16.0% |
| 590 | Free of Memory not on the Heap | 1,685 / 2,546 | 42.2% (42.2%) | 60.0% |
| 124 | Buffer Underwrite (Buffer Underflow) | 1,235 / 2,084 | 71.1% (71.1%) | 44.0% |
| 127 | Buffer Under-read | 1,235 / 2,084 | 40.0% (40.0%) | 40.0% |
| 401 | Missing Release of Memory after Effective  | 1,042 / 1,668 | 86.7% (73.3%) | 56.0% |
| 126 | Buffer Over-read | 917 / 1,380 | 2.3% (2.3%) | 68.0% |
| 415 | Double Free | 568 / 1,080 | 93.0% (93.0%) | 64.0% |
| 457 | Use of Uninitialized Variable | 825 / 258 | 57.5% (57.5%) | 100.0% |
| 563 | Assignment to Variable without Use (Dead S | 372 / 384 | 77.3% (70.5%) | — |
| 476 | NULL Pointer Dereference | 238 / 294 | 84.1% (84.1%) | — |
| 416 | Use After Free | 402 / 120 | 50.0% (50.0%) | 84.0% |
| 775 | Missing Release of File Descriptor or Hand | 86 / 150 | 16.3% (16.3%) | 100.0% |
| 562 | Return of Stack Variable Address | 5 / 0 | 50.0% (50.0%) | 100.0% |

## Tier 1 — not yet measured (the work queue)

None of these appear in `TARGETS` in `scripts/score-juliet.py`, so no baseline exists
for them at all.

| CWE | name | files (single / multi) | why it matters |
|---|---|---|---|
| 197 | Numeric Truncation Error | 508 / 900 | narrowing conversions; `bugprone-narrowing-conversions` already emits these |
| 252 | Unchecked Return Value | 632 / 0 | unchecked return value — the first half of the CWE-690 chain |
| 369 | Divide By Zero | 508 / 972 | divide by zero; `kordon-query` already has a guard check for it |
| 483 | Incorrect Block Delimitation | 22 / 0 | incorrect block delimitation; moved to tier 1 on 2026-08-17 |
| 665 | Improper Initialization | 116 / 200 | improper initialisation — the fallible-constructor class `--ctu` was built for |
| 672 | Operation on a Resource after Expiration o | 29 / 54 | operation after release; overlaps CWE-416 |
| 680 | Integer Overflow to Buffer Overflow | 338 / 600 | integer overflow *leading to* buffer overflow — the 190→122 chain |
| 690 | Unchecked Return Value to NULL Pointer Der | 564 / 1,000 | null deref from an unchecked return; CLAUDE.md classifies this chain explicitly |
| 843 | Access of Resource Using Incompatible Type | 52 / 76 | type confusion |

## Not tier 1 — 92 directories, 39,165 files

Injection, path traversal, access control, the web-specific classes. Deliberately out
of scope per CLAUDE.md. Not worth scoring: measuring a promise Kordon never made would
only make the numbers worse for no reason.

Largest, for reference: CWE-78 (7,813), CWE-134 (4,929), CWE-23 (3,907), CWE-36 (3,907), CWE-194 (1,876), CWE-195 (1,876).

## The open question this inventory exists to answer

**Kordon is the union of its engines, and nothing measures it that way yet.** The two
baselines are separate runs over separate samples, so a defect ASan catches still reads
as a miss in the static table — CWE-122 is the clearest case, 29.2% static against
85.7% dynamic on the same class.

The measurement worth having asks one question per case — *did any layer catch it* —
with everything enabled (`--ctu --ikos --dynamic`). That number is the one to quote,
and the per-layer tables above become diagnostics for where each layer earns its cost.

