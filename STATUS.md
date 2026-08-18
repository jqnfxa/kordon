# Kordon — working state

Session notes. Where things stand and what to pick up next.

## What works today

`kordon <dir> [-p <build-dir>] [--ctu]` — walks a directory, runs cppcheck +
clang-tidy (+ Clang SA under CTU), maps every finding to a CWE, merges what the
engines agree on, and reports the gaps. 60 tests green.

| Piece | File | Notes |
|---|---|---|
| Finding schema | `src/finding.rs` | everything normalizes into this |
| CWE mapping table | `data/cwe_map.toml`, `src/cwe.rs` | message-discriminated; tool-independent fallback on check id |
| Cross-tool dedup | `src/dedup.rs` | keyed `file+line+CWE`; confidence +1 step on independent agreement |
| CTU index + call graph | `src/ctu.rs` | AST serialization + extdef map; edges from analyzer imports |
| CTU analyzer | `src/tools/clang_sa.rs` | `clang --analyze`, `plist-multi-file` |
| Report | `src/report.rs` | confidence-tiered, explicit coverage gaps |
| Compile database | `src/compile_db.rs` | parsed once; decides which files are in the build |
| Kordon's own checks | `src/tools/clang_query.rs` | AST matchers via clang-query; CWE-191 |

## Measured results

Ground truth: `/home/shard/VsCode/acl/report/problems.md` — **280 confirmed
positions** (`(CWE, file, line)`), 104 excluded as false positives. Parsed to
`tmp/confirmed.json`. Raw list is 714 records → 384 unique.

**Full ACL tree**, current: **162/280 = 57.9%** (`tmp/cov_raw.json`, ~12 min,
274 units analyzed + 212 skipped as not-in-build, CTU + kordon-query on).

| CWE | recall | | CWE | recall |
|---|---|---|---|---|
| 563 | 46/49 (94%) | | 119 | 16/59 (27%) |
| 191 | 49/52 (94%) † | | 401 | 9/66 — mostly FP, see below |
| 190 | 17/19 (89%) ‡ | | 763/415 | 0/5 |
| 457 | 17/19 (89%) | | 369 | 2/3 |
| 476 | 5/7 (71%) | | 416 | 1/1 |

† specificity verified against `acl_fix` — corrected sites go quiet.
‡ specificity **not** verified: reports fixed code identically to broken code,
because the fix idiom is a precondition validated by an early throw. Treat as
"can overflow if unvalidated", not "is unvalidated".

A full `acl_fix` run was in progress when this was written; when
`tmp/cov_fix.json` completes, compare per-CWE finding counts against
`tmp/cov_raw.json` (counts, not line numbers — the fixes shift lines).

History: 11.4% (no compile db) -> 24.6% (db) -> 34.3% (CTU + checks re-enabled
+ build-membership filter) -> 51.8% (CWE-191 check) -> 57.9% (CWE-190 check). Older logs `tmp/acl_log.txt`,
`tmp/acl_log_db.txt` predate all three and understate badly.

Compile failures are now **5 of 274**, down from 159 of 486 — almost all of
that was files outside the build, not broken code.

**modules/math subset** (22 TUs, 75 confirmed positions):

| config | recall | CWE-119 | CWE-401 |
|---|---|---|---|
| no CTU, checks disabled | 13% | 0/27 | 1/35 |
| CTU, checks disabled | 17% | 0/27 | 2/35 |
| **CTU + checks re-enabled** | **39%** | **11/27** | **7/35** |
| CodeChecker `--enable extreme` | 39% | 11/27 | 7/35 |

Kordon now equals CodeChecker's best profile on recall, while deduping and
CWE-mapping. CodeChecker emitted 42 `UninitializedObject` reports for 2 distinct
defects (`vector.cpp:15` reported 41×, once per constructing TU).

## CWE-401 is mostly the reference tool's false positives

Confirmed with the codebase author. The 66 recorded CWE-401 positions are not
66 defects: nearly all sit at a closing brace, the scope exit of an unrelated
function that merely held a `Matrix` or `Vector` local. Nothing in those
functions is wrong. They are the classic RAII false positive CLAUDE.md predicts
— a tool that cannot pair `new` in a constructor with `delete` in a destructor
and flags it anyway.

**So Kordon's low CWE-401 recall is largely correct behaviour, not a gap.**
Chasing it would mean reproducing another tool's false positives. Read the
numbers accordingly:

| metric | value |
|---|---|
| headline recall | 162/280 = **57.9%** |
| recall excluding CWE-401 | 153/214 = **71.5%** |

What Kordon reports instead is the *cause*: `kordon-manual-ownership-flag`
matches a `delete` of a pointer member gated on a bool member — 5 findings on
the broken tree, **0 on the corrected tree**, where the fix deleted the flag and
moved ownership into a member smart pointer. Five actionable class-level
findings replace 66 unactionable site reports, and fixing them removes all 66.

This will not move a line-keyed recall score, because the ground truth records
effects and the check finds causes. That is a property of the measurement.

**Remaining non-401 misses: 61, of which CWE-119 is 43 (70%).** That is now the
whole game, and it is precisely what abstract interpretation addresses.

## The precision problem — the biggest thing left

Comparing a full run on the broken tree against one on the corrected tree
(`tmp/cov_raw.json` vs `tmp/cov_fix.json`), where ~226 defects were fixed:

| tier | broken | corrected | change |
|---|---|---|---|
| high confidence | 227 | 195 | **-14%** |
| medium | 13 | 12 | -8% |
| low | 6628 | 6307 | -5% |

Low confidence is **96.5% of all in-scope findings**, and it barely notices that
the code was fixed. Broken down by check:

| check | findings | change on fixed tree |
|---|---|---|
| `cppcoreguidelines-pro-bounds-pointer-arithmetic` | 2326 | -1% |
| `bugprone-narrowing-conversions` | 1184 | -0% |
| `cppcoreguidelines-init-variables` | 659 | **-33%** |
| `pro-bounds-constant-array-index` | 534 | +0% |
| `pro-bounds-array-to-pointer-decay` | 481 | +0% |
| `kordon-unsigned-subtraction` | 383 | -8% |

The `pro-bounds-*` family is 3341 findings — **49% of everything Kordon reports**
— and is essentially inert: it cannot distinguish corrected code from broken
code at all. It fires on every pointer arithmetic and every array subscript.

It cannot simply be deleted, though: removing it costs 16 matched positions,
11 of them CWE-119. That is the tension to resolve. Kordon currently emits 6868
in-scope findings to cover 162 real positions — a 42:1 ratio. Replacing
`pro-bounds-*` with a range-analysis answer for CWE-119 would cut roughly half
the total volume *and* raise recall, which makes it the highest-value work left.

Note what does respond: `init-variables` (-33%) and the path-sensitive analyzer
findings. Responsiveness to fixes is a better quality signal than recall, and
cheap to measure — always run both trees.

## Specificity: always test against fixed code

`acl_fix/` is a corrected copy of `acl_raw/` and is the only way to tell a
detector from a shape-counter. Compile db: `tmp/db-fix`.

The first CWE-191 matcher scored 94% recall and reported **the fixed code
identically to the broken code** — because the fix was
`if (dataIn.width() > 0)` on a class *member*, and the guard exemption only
understood plain locals. Recall alone would have hidden that completely: a
matcher flagging every `unsigned - 1` scores 94% too.

After adding the member-call guard, on the 52 CWE-191 positions:

| tree | flagged |
|---|---|
| `acl_raw` | 49/52 (recall preserved) |
| `acl_fix` | 7/52 — and all 7 verified byte-identical between trees, i.e. never fixed |

So specificity is effectively 100% on that sample.

**CWE-190 has not cleared this bar.** Its fix idiom is a precondition validated
by an early throw:

```cpp
if ((roi.left() > roi.right()) || roi.right() > header._width)
    ACL_THROW(bad_option, "Check bounds for ROI, X dimension");
...
rsz._xSize = roi.right() - roi.left() + 1;   // now safe
```

The expression is byte-identical in both trees (19 occurrences each), so the
check reports fixed code identically to broken code. No AST matcher can close
this: the subtraction is not inside the guard, the guard compares a different
pair of expressions, and it depends on the throw not returning. It is a
dataflow fact. Treat CWE-190 findings as "can overflow if unvalidated", not as
"is unvalidated" — and this is the concrete argument for IKOS.

## Things learned the hard way — do not re-derive

- **clang-tidy has no SARIF** (LLVM 18). `--export-fixes` YAML uses *byte
  offsets* and carries no CWE. It also cannot represent cross-file paths, which
  is why CTU needs its own runner.
- **`plist-multi-file` is mandatory for CTU.** Plain `plist` and text silently
  drop every cross-file diagnostic. Looks exactly like CTU not working.
- **The extdef map must point at serialized ASTs**, not sources, relative to the
  CTU dir. `clang-extdef-mapping` emits source paths; rewrite them.
- **cppcheck's native `cwe=` is often the parent class** — `operatorEqToSelf`
  says 398, is 416. Override list is in the table.
- **A file can look analyzed and not be.** Without a compile db, AST-matcher
  checks still fire on a broken TU while Clang SA silently skips it.
  `coord_convertion.cpp` showed 36 findings and zero analyzer findings.
- **`optin.*` checkers are not in `clang-analyzer-*`** — must be named.
- **Do not judge a check by output volume on a toy corpus.** Disabling
  `owning-memory` and `pro-bounds-*` cost more than half the recall on real
  code. Noise is a *reporting* problem; fix it with confidence tiering.
- **Fixture leak cases need `_static` and `_runtime` forms.** A sanitizer needs
  the pointer to escape; a static analyzer needs it not to.
- AST JSON is not viable for a call graph: **176 MB for one ACL file**.
- **Recall without specificity is meaningless.** Always run a new check against
  `acl_fix/` as well as `acl_raw/`; a check that cannot tell them apart is
  counting syntax, not finding defects.

## Known limitations

Grouped by whether they can be engineered away.

### Fundamental — no amount of tooling fixes these

- **`#ifdef` is invisible.** Code in an inactive configuration never reaches the
  AST, so no engine can see it. ACL has 272 `#if`-family directives and its
  analyzed build leaves `INIT_LIBBPG`, `USE_OPENCV` and `NUMBERTURN` undefined.
  Only remedy: analyze each configuration as a separate run and merge. Not done.
- **Intent is undecidable.** For CWE-190/191 no layer can tell a deliberate
  wraparound from a bug — not the matcher, not IKOS, and not the sanitizer,
  which flags a textbook FNV-1a hash. These stay permanently low confidence.
- **Absence of findings is never proof of safety.** Every clean report means
  "these engines did not flag it", nothing more.
- **Dynamic analysis needs execution.** Whatever line coverage the tests reach
  is the hard ceiling of that layer, and it is not wired up at all yet.

### Detection gaps, with known causes

- **CWE-119: 16/59.** The remainder are `vector::operator[]` where proving the
  container can be empty needs interprocedural range reasoning. No configured
  engine reaches it — IKOS was the hope and contributed nothing unique.
- **CWE-401: 9/66**, but mostly moot — the corpus positions are largely the
  reference tool's RAII false positives. Kordon targets the cause instead
  (`kordon-manual-ownership-flag`, 5 class-level findings, silent on the fixed
  tree). This will never score well against a line-keyed ground truth.
- ~~CWE-763 0/4~~ **— resolved, it was a mapping choice, not a miss.** All four
  positions are detected at the exact line by
  `clang-analyzer-unix.MismatchedDeallocator`; Kordon labelled them 762. The
  code is `x = new bbf_data; ... free(x)`, which both classes describe: 762 is
  the narrow one, 763 the broader one that also covers calling the wrong
  release function. Requirements in this domain name 763, and the ground truth
  records them as 763, so that is now the default. `--cwe-map` flips it back in
  one rule.
- ~~CWE-415 0/1~~ **— confirmed false positive by the codebase author**, with
  sanitizers agreeing. Not a gap; the correct behaviour is to stay silent.
- **CWE-369 2/3** — small tail, uninvestigated.
- **Guard shapes the CWE-191 matcher cannot see**: a precondition validated by
  an early exit (`if (a > b) throw; ... b - a`). Needs dataflow. IKOS was tested
  on exactly this and still warns, under both `interval` and `dbm`.
- **CWE-190 fails the specificity test.** It reports corrected code identically
  to broken code, because the corpus fixes it with precondition-and-throw.
  Treat those findings as "can overflow if unvalidated", not "is unvalidated".

### Precision — the largest practical problem

Visible in-scope findings on the reference corpus: **6 877 for 162 real
positions, a 42:1 ratio.**

| confidence | findings |
|---|---|
| high | 227 |
| medium | 846 |
| low | 5 804 |

The low tier moves only −5% on a tree where ~226 defects were fixed, while the
high tier moves −14%. `pro-bounds-*` alone is ~3 300 findings and is completely
inert between the two trees — but removing it costs 16 real positions, so it
cannot simply be deleted.

### Tooling constraints

- **A compile database is effectively required.** Without one, AST-matcher
  checks still fire on a broken TU while the path-sensitive engine silently
  skips it, so a file can show dozens of findings and never have been analyzed.
- **clang-tidy has no SARIF** (LLVM 18); its YAML uses byte offsets and carries
  no CWE, and it cannot express cross-file paths — hence a separate CTU runner.
- **IKOS needs clang-14 bitcode, `-O0`, and `fneg` lowering**, and its "error"
  verdict is only a proof when it names a concrete allocation.
- **Dedup is line-exact.** Two engines reporting one defect on adjacent lines
  stay separate.

### Unresolved

- pkta shows 51 files failing under clang-tidy in batch that compile cleanly
  individually with their exact database flags. Cause not established.
(The 762-vs-763 question is settled — see the detection-gaps section.)

## Next steps, roughly in order

1. ~~Re-run the full ACL tree with CTU.~~ **Done** — 34.3%, see above.
2. ~~Fix the 159/486 failing TUs.~~ **Done.** They were 212 sources absent from
   `compile_commands.json` (186 under `tests/`), compiled with no flags. Kordon
   now analyzes only what the build compiles and reports the rest as skipped.
   Genuine failures: 5 of 274. Note the old "misses are in unanalyzed files"
   proxy is no longer valid — with 5 failures, essentially all 184 remaining
   misses are real analysis gaps.
3. ~~CWE-191 is 0% and will stay 0%.~~ **Done — 49/52 (94%)** via
   `kordon-unsigned-subtraction`, a clang-query AST matcher
   (`src/tools/clang_query.rs`). Permanently low confidence: no layer resolves
   intent, the sanitizer included (it flags a correct FNV-1a hash). Next for
   this class is IKOS, which can close the two guard shapes the matcher
   cannot see (early return, guarded call) because they need dataflow.
4. **CWE-401 is 9/66 and is now the biggest addressable class** (57 misses).
   Confirmed to be the manual-ownership-flag RAII pattern: `clear()` frees only
   `if (m_data && m_flgAllocMemory)`, so a wrong flag skips the free —
   the mirror image of the uninitialized-flag defect. `matrix.cpp:41` is the
   destructor itself. Needs the per-class ownership summary from CLAUDE.md
   (which raw-pointer members own, where they are released, when release can be
   skipped). Not reachable by more inlining.
5. **CWE-119 is 16/59** (43 misses), up from 0. Remaining are
   `vector::operator[]` where proving the container can be empty needs
   interprocedural range reasoning.
6. Ingest CodeChecker output as an alternative runner — its cppcheck
   integration prefixes ids (`cppcheck-arrayIndexOutOfBounds`) and its clangsa
   ids are bare (`core.NullDereference`); the table's tool-independent fallback
   already handles both.
7. Dedup is line-exact; two engines reporting one defect on adjacent lines stay
   separate. Consider a small line window.

## Macros and other hiders — measured

`testdata/macros/hiders.cpp` pairs every macro form with a plain-code twin and
requires the same verdict for both. **All pairs match.** Analysis runs on the
post-preprocessing AST, so macros are transparent:

| hider | result |
|---|---|
| defect inside a macro body | flagged, at the **expansion site** not the `#define` |
| guard written as a macro (`IF_POSITIVE(k) {...}`) | correctly suppressed |
| only the comparison in a macro (`if (IS_POSITIVE(k))`) | correctly suppressed |
| macro-declared variable | flagged, same as plain |
| macro-generated member function | flagged, at expansion site |
| one macro expanded 3× | 3 separate findings, not collapsed |
| guard + control flow in a macro (`THROW_IF`) | flagged — same as its plain twin, so no regression |

Clang SA is equally transparent (use-after-free through a `FREE_IT(p)` macro is
reported normally).

**The real blind spot is `#ifdef`, not macros.** Code in an inactive
configuration never reaches the AST, so no engine can see it and no check
improvement will change that. Verified: `k - 1` under `#ifdef` gives 5 matches
without the define and 6 with it. ACL has 272 `#if`-family directives; its
analyzed build defines `INIT_QT5`, `INIT_ZLIB`, `INIT_LIBJPEG/PNG/TIFF/WEBP`
but **not** `INIT_LIBBPG`, `USE_OPENCV` or `NUMBERTURN`. Everything behind those
is permanently invisible. The only fix is to analyze each configuration as a
separate run and merge — worth doing, and not yet done.

### The bug this fixture caught

Building it exposed a live regression that no ACL measurement could reveal. The
guard exemption had stopped matching a bare `if (k > 0)`: the condition matcher
was `hasCondition(hasDescendant(cmp))`, and `hasDescendant` does not match the
node itself. Only the nested form `if (a && k > 0)` still worked — and ACL uses
only that form, so recall, specificity and the raw-vs-fix comparison all looked
clean while the common case was broken.

Now `anyOf(cmp, hasDescendant(cmp))`, with a regression test on both arms, and
guards built from an operand descriptor rather than three hand-written copies.
CWE-191 recall after the fix is unchanged at 49/52 = 94%.

**Lesson worth keeping: a corpus can only falsify what it happens to contain.**
Paired synthetic fixtures test the axis directly; corpus measurements cannot.

## Prerequisites for IKOS and for sanitizers — scoped

Both need Kordon to *drive a build*, which it has never done: today it consumes
someone else's `compile_commands.json`. That is the shared piece of work.

### IKOS — everything checked, nothing blocking

IKOS v3.5 requires **LLVM/Clang 14.0.x** and cannot use 18. APRON is optional.

| need | status |
|---|---|
| `clang-14`, `llvm-14-dev`, `libclang-14-dev` | available via apt, coexists with 18 |
| gmp, boost, sqlite3, tbb, mpfr, cmake, python3 | already installed |
| `libppl-dev` | available; only needed for polyhedra |
| IKOS itself | source build, cmake, no package |

Input pipeline is already proven: emitting bitcode from the existing compile db
works (`clang++ -emit-llvm -c -g -O0` + the db's flags), and `llvm-link` merges
per-TU bitcode into one whole-program module — which gives **cross-TU analysis
at IR level for free**, cleaner than the AST-based CTU we built.

Two things that will bite if missed:
- Bitcode must be produced by **clang-14**, not 18 — LLVM 14 cannot read 18 bitcode.
- Use `-O0`. Measured: at `-O1` clang folded `n - 1` into the address computation
  (`getelementptr ... i64 -1`) and the debug info collapsed to a single line,
  losing the line the subtraction was written on. Optimization erases the
  expressions we want to report.

IR keeps `!DILocation(line:, column:)`, so IR-level findings map back to source
positions and fit the existing finding schema.

### Sanitizers — viable, with one hard part

| need | status |
|---|---|
| runnable tests | **11 ctest tests exist and the binaries run** |
| dependency libs | built `.so` resolves everything, 0 missing |
| `_GLIBCXX_ASSERTIONS` | already in the build's `-D` flags — needed for the `vector::operator[]` CWE-119 class |
| conan | **missing**, cache empty — but all include paths resolve, so a rebuild looks plausible without it |

Separate build trees are required: ASan+UBSan combine (plus
`-fsanitize=unsigned-integer-overflow` for CWE-191), MSan does not — and MSan
additionally needs every dependency instrumented, which is the hard part.

Also needed: an ignorelist for intentional wraparound, or the CWE-191 sanitizer
will flag correct code (verified: it reports a textbook FNV-1a hash).

**Ceiling to check first:** sanitizers only see what those 11 tests execute.
Measure line coverage before expecting much from this layer.

## IKOS — built and measured

`scripts/setup-ikos.sh` builds IKOS v3.5 into `third_party/ikos` (gitignored).
Working: `ikos 3.5`. `scripts/ikos-bitcode.sh` produces input it can read.

### On ACL it contributed nothing to the visible report

Measured on the full tree with everything enabled (12m32s, 274 units):

| | findings | matched |
|---|---|---|
| visible report | 7 582 | 162/280 = **57.9%** |
| including the hidden unproven bucket | 22 155 | 187/280 = 66.8% |

**IKOS proved nothing: `proved: 0`.** Its entire contribution — 14 869
findings — landed in the unproven bucket, of which 25 happen to sit on a real
defect line. A hit rate of 25 in 14 869 is not a detector, it is a list of
everything the analyser could not decide, which on library code is everything.

The cause is structural, not a tuning problem. A library function analysed as a
synthetic entry point has pointer parameters backed by no allocation, so IKOS
can prove neither that an access is in bounds nor that it is out of them. The
792-safe-checks result that motivated this work came from a *self-contained* C
file whose arrays were local and whose sizes were literals.

So the CWE-119 hope did not survive contact: 16/59 visible, unchanged from
before IKOS. Whole-program analysis from a real `main` would be a different
experiment; analysing a library this way is not.

### What it gives that nothing else does

Three-valued verdicts. On a real float-heavy C file (pkta `refraction.c`):

```
Total checks: 861    safe: 796 (92.5%)    definite unsafe: 0    warnings: 65
```

796 accesses **proved** in bounds. Every other engine Kordon drives can only
fail to flag something; none can say "safe". That is the property that makes it
a candidate to replace `pro-bounds-*`, which emits 3341 findings on ACL without
distinguishing corrected code from broken.

### Guard handling: closes one documented gap, not both

| guard shape | AST matcher | IKOS |
|---|---|---|
| `if (k > 0) { k - 1 }` | exempt | proved safe |
| `if (k == 0) return; k - 1` | **flagged (limitation)** | **proved safe** |
| `if (lo > hi) return; hi - lo` | **flagged (limitation)** | **still warns** |

So IKOS resolves the early-return guard, which is a real win. It does **not**
resolve the relational precondition — tested under `interval` and under `dbm`,
which is relational and built in without APRON. That is the exact idiom the
reference corpus uses to fix its CWE-190 sites, so that specificity failure
survives the IKOS layer.

### Three input constraints, all measured

1. **Bitcode must come from clang-14.** IKOS links LLVM 14 and rejects an
   LLVM 18 module outright. Verified both ways.
2. **Must be `-O0`.** At `-O1` clang folds `n - 1` into the address computation
   and the debug location collapses, so findings lose the line they belong to.
3. **`fneg` must be lowered.** IKOS 3.5's importer does not implement it
   ("unsupported llvm instruction fneg") and clang emits it for every
   floating-point negation. This is fatal for numerical code — the only kind
   worth running an interval analyser over. It blocked **10 of 40** sampled ACL
   units and the first pkta file tried.

   `scripts/ikos-bitcode.sh` rewrites `fneg x` to `fsub -0.0, x`, which is how
   the operation was expressed before LLVM 8 added the instruction. With that,
   the previously-fatal file analyzes completely.

### Entry points: solved — use call-graph roots

`scripts/ikos-entry-points.sh` prints the entry points for a `.bc`. Both
problems have the same answer.

**Which names.** Read them out of IKOS's own AR, after `ikos-pp` then
`ikos-import`, rather than from `llvm-nm`. Exact by construction, and it avoids
the C++ constructor aliases (`_ZN3acl3AnyC1EOS0_`) that `llvm-nm` reports and
IKOS rejects as "could not find function". Note `ikos-import` must run on
*preprocessed* bitcode — on raw bitcode it fails with "llvm select instructions
are not supported" even where a full `ikos` run succeeds.

**How many.** Only the roots — functions no other function in the unit calls.
An entry point's parameters are unconstrained, so naming every function fills
the report with artifacts of that choice. Measured on one real unit
(13 functions, 1 root):

| entry points | checks | safe | warnings |
|---|---|---|---|
| all 13 functions | 1419 | 1316 | 103 |
| call-graph roots only | 1338 | 1271 | **67** |

The 36 warnings that vanish are exactly the artifacts — "variable might be
uninitialized" 35 → 7, "memory access might be invalid" 8 → 0 — while "possible
buffer overflow" stays at 60. Nothing real is lost.

Validated on a second unrelated file: 581 checks, 511 safe, 70 warnings, entry
point derived automatically.

### Still open before it can be a Kordon runner

- Wire it up as a runner: emit bitcode per TU, derive entry points, run with
  `-f json`, map analyses to CWEs (`boa`→119, `uio`→190/191, `dbz`→369,
  `nullity`→476, `uva`→457, `dfa`→415).
- Decide how to report the **safe** verdict. It is the one genuinely new piece
  of information — no other engine can say it — and the report has nowhere to
  put "this was proved" today.
- 25% of translation units still need the `fneg` rewrite; that is handled, but
  any other unsupported instruction will surface the same way.

## Engine audit — what each one actually earns

Measured on the full reference corpus, counting only what reaches the visible
report. "Unique" means no other engine found that position.

| engine | positions found | unique | raw findings | verdict |
|---|---|---|---|---|
| clang-tidy | 90 | 9 | 10 948 | keep — broadest reach |
| clang-sa-ctu | 74 | 5 | 363 | keep — best signal-to-noise by far |
| **kordon-query** | 66 | **66** | 5 162 | **keep — every position is unique** |
| cppcheck | 29 | **0** | 1 106 | keep, but for corroboration only |
| ikos | 21 | **0** | 52 269 | **not earning its place** |

Reading it:

- **Kordon's own checks are the single largest unique contributor.** All 66
  positions — CWE-191 (49) and CWE-190 (17) — are found by nothing else. That
  is the whole justification for writing custom checks rather than only
  orchestrating.
- **clang-sa-ctu has the best ratio in the set**: 74 positions from 363 raw
  findings. Everything else is one to two orders of magnitude noisier.
- **cppcheck finds nothing unique here.** Its value is corroboration — a second
  independent engine agreeing raises confidence a step — and different blind
  spots on other codebases. Cheap enough to keep on those grounds, but it is
  not pulling detection weight on this corpus.
- **IKOS is not earning its place.** 52 269 raw findings, 14 869 of them
  unproven, 21 positions found and **none of them unique**. It costs the
  largest share of runtime and contributes nothing no other engine already
  had. Leave it opt-in and off by default; revisit only for whole-program
  analysis from a real `main`, where its proofs can actually ground.

## Environment

- CodeChecker 6.28.2 at `~/.venv/codechecker/bin/CodeChecker` (add to PATH).
  Detects clangsa, clang-tidy, cppcheck, gcc. `infer` absent.
- `clang-extdef-mapping-18` present; unversioned name is not.
- clang 18.1.3, cppcheck 2.13.0, 20 cores.
- Retargeted compile dbs: `tmp/db` (full tree), `tmp/db-math` (math only).
  Built by rewriting paths from `/home/shard/VsCode/acl/tmp/build-cwe-clang`.

## Provenance constraint

`acl/analysis/repro/*.cpp` quote real ACL source in comments and ACL has no
LICENSE file — do not copy them into this repo. `testdata/` is synthetic only.
ACL stays an external validation target.
