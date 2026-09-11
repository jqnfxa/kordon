---
name: kordon-triage
description: How to read Juliet (and the ACL notes) for a Kordon CWE and decide, shape by shape, what an analyzer would need to see the defect — the seven verdicts, the corrected-sibling diff, the wrapper ceiling, and the shape table that goes in a lane brief. Use before building any check or fixture, and whenever a Juliet number needs explaining.
---

# Triage: name the shapes before touching anything

The step that pays. On CWE-126 the corrected function contained the *identical*
`memcpy` line — only a buffer size differed — so any matcher would have
discriminated exactly zero. One diff saved building the wrong thing.

## Where the cases are

    third_party/juliet/C/testcases/CWE<n>_<Name>/[s01..sNN/]<case>.c|.cpp
    third_party/juliet/C/testcasesupport/     std_testcase.h, io.c

A case is named `CWE<n>_<Name>__<type>_<source>_<sink>_<variant>.c`. The type,
source and sink are the *shape*; the variant is control-flow scaffolding:

| variant | means |
|---|---|
| `01` | baseline, straight-line |
| `02`–`22` | the same shape behind `if(1)`, `if(globalTrue)`, `while`, `switch`, `goto`, … |
| `31`–`34` | data flows through a local copy, an array, a pointer |
| `41`–`45` | through a function call in the same file |
| `51`–`54` | across files: `_54a.c` … `_54e.c` — the CTU cases |
| `61`–`68` | through a return value, out-parameter, struct, array of pointers |
| `81`–`84` | C++ class hierarchy, virtual dispatch, split as `_82_bad.cpp` / `_82_goodG2B.cpp` |

Every file's header says `BadSource:` and `BadSink :` — that pairing, not the
CWE, decides whether any engine can see the defect. Every file holds `..._bad`
(or a bare `bad()` in a namespace) and `goodG2B` / `goodB2G` — good source
into the bad sink, and bad source into a good sink — plus `main()` behind
`INCLUDEMAIN`. The C++ variants name functions bare `bad`/`good*`.

## The commands

    scripts/explain-misses.py <cwe>                 # detection rate per shape, 40 files
    scripts/explain-misses.py <cwe> --misses        # + the missed functions, file:line
    scripts/explain-misses.py <cwe> --multifile -- --ctu   # the split cases, with CTU
    scripts/explain-misses.py <cwe> -- --ikos       # what abstract interpretation adds

Read the shape table top to bottom. A shape at 0% with ten cases is the item;
a shape at 0% with one case is noise until you have read it.

Then **read three or four missed `_01` cases and one high-numbered variant**,
and for each, diff the flawed function against its sibling:

    f=third_party/juliet/C/testcases/CWE126_Buffer_Overread/s01/CWE126_..._01.c
    diff <(sed -n '/_bad()/,/^}/p' $f) <(sed -n '/goodG2B()/,/^}/p' $f)

If the only difference is a size, a range or a value — the verdict is
value-range or runtime, and no matcher will separate them. If the difference is
a missing comparison, a missing call, a different function — a shape rule may.

## The seven verdicts

Give every shape one, and write it down even when it is "nothing we can build".

| | verdict | what it needs | what to do |
|---|---|---|---|
| **A** | the compiler already knows | a `clang-diagnostic-*` name in the check set | name it (three for three so far) |
| **B** | a default checker does it | a Clang SA / cppcheck check that is on | check the mapping: right CWE, right confidence, message discriminated |
| **C** | syntactic | a shape rule with a "where did the value come from" clause | build a clang-query check |
| **D** | value-range | a bound on an expression | `--ikos`, or a rule that flags the *missing guard*; never a matcher that fires on the guarded twin too |
| **E** | cross-TU / ownership | the sink and the value in different units, or who-owns-what | `--ctu`; a CTU fixture; not piecemeal |
| **F** | defined behaviour | intent | **Advice** band at the same confidence; not recall |
| **G** | application semantics | which union member is live, which downcast is intended | written verdict; leave |

Two more outcomes are legitimate and must be recorded rather than chased:

- **Not an instance of the CWE.** Juliet files `char data = CHAR_MAX; data + 1`
  under CWE-190 (promotes to `int`, nothing overflows) and `double / 0` under
  CWE-369 (defined: an infinity). The bar for `EXCLUDED` in `score-juliet.py`
  is that the defect is *absent, checkable from the standard* — never that
  Kordon happens to miss it. Print the count.
- **A wrapper labelled bad.** `..._bad()` that only calls `helperBad()` or
  `badSink()` contains no defect; a detector reports at the flaw. CWE-562's
  ceiling is 50% for exactly this. Say so.

## Common shapes and what they resolved to (do not re-derive)

- `data = RAND32()` / `fscanf` / `fgets` / socket → **unprovable statically**;
  ~71% of the integer and index CWEs. The honest outputs: a rule that flags
  the *missing guard* (`kordon-one-sided-index-guard`, `kordon-unchecked-divisor`
  exist), IKOS's "cannot prove safe", the dynamic layer.
- `memcpy(dest, data, strlen(dest))` with the identical line in the good twin →
  value-range; IKOS takes CWE-126 from 11% to 86%.
- hand-written copy loops, `strcat`/`wcsncat` → no engine models them; loops
  are a matcher candidate only if the bound is visible.
- `_54a`..`_54e`, `_81`..`_84` → CTU; measured 17% → 29% with `--ctu`.
- constructor leaves a member unassigned → `optin.cplusplus.UninitializedObject`,
  needs the call site in the same TU or `--ctu`.

## The second source: the ACL notes

`docs/acl-report-findings.md` adjudicates 45 positions from a vendor report on a
real C++ codebase, each ending in what a detector would have needed. The
fixtures under `testdata/` named there (`hoisted_guard`, `allocator_fallibility`,
`empty_container_signal`, `masked_underflow`, `saturating_overflow`,
`fill_initialises`, `zero_length_*`) are synthetic reductions of them. **Never
copy or quote ACL source** — it has no licence. Model the shape, rename
everything, and describe the origin generically in the fixture header.

## The output: a shape table in the brief

    | shape (source | sink) | cases | found | verdict | note |
    |---|---|---|---|---|---|
    | alloca | free | 13 | 0 | B | unix.Malloc reports it; message not discriminated -> filed 401 |
    | placement_new | delete | 4 | 0 | B | NewDelete "not memory allocated by" has no rule |
    | static | free | 14 | 10 | B | 4 misses are `_41` wrappers |

Cases and found come from `explain-misses.py`; the verdict and note are yours.
