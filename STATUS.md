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

## Early-exit guards: the limitation is closed (2026-08-21)

```cpp
if (in.width() == 0) { return false; }
...
r = in.width() - 1;        // cannot underflow here
```

`guard_clause` only understood a condition that *encloses* the use, so this
shape -- at least as common, since it is how preconditions are usually written
-- was reported anyway. It was carried in the fixture as a known false
positive.

**The clause that makes it safe** is requiring the subtraction not to be inside
the exempting condition. Without it the check exempts a defect using the
defect's own `if`:

```cpp
if ((x_begin > (width_in - 1)) || ...) { return; }
```

`width_in - 1` is evaluated *by* the guard, so a zero `width_in` underflows
before anything can protect it. Measured: the naive form suppressed 11
positions of which **2 were real defects the maintainers had fixed**; with the
clause it suppresses 6 and none of them are.

Ordering is not checked -- AST matchers cannot express "this statement precedes
that one" -- so any early exit naming the operand exempts every use of it in
the function. A use before the guard is wrongly exempted, erring toward
silence.

**The payoff was much larger than the suppression count suggests**, because it
let two checks confirm fixes they previously could not:

| check | before | after |
|---|---|---|
| `kordon-extent-underflow` | 45 -> 41, **-9%** | 44 -> 17, **-61%** |
| `kordon-unsigned-subtraction` | -2% | -8% |

Zero acted-on defects lost. The recorded CWE-190/191 limitation -- "treat these
as *can* overflow, not *is* unvalidated" -- was partly a gap in the guard
vocabulary rather than a fact about the defect class.

## Widening parallel-extent beyond parameters: rejected (2026-08-21)

The remaining CWE-119 "two containers" misses (13) subscript locals and members
rather than parameters. Both relaxations were measured and both fail:

| trigger | positions | specificity | new acted-on defects |
|---|---|---|---|
| parameters (shipped) | 181 | -17% | -- |
| + locals | 592 | **-4%** | +2 |
| members only | 234 | **+0%** | +4 |

Locals cost 411 findings for two defects and land near
`pro-bounds-pointer-arithmetic` territory; member containers are perfectly
inert. A local's extent is usually established by its own construction in the
same function, which is why subscripting it under an unrelated bound is normal
rather than suspicious. That cluster is not reachable by widening this shape.

## The dynamic layer (2026-08-21)

Built as a separate layer from `src/tools`, with its own report section above
the static findings and `Proof::Refuted` on every finding. Three profiles:
`asan` (ASan + LSan + UBSan in one instrumented build), `msan`, `valgrind`.

Verified end to end against `testdata/dynamic/`, a small CTest project where
each program commits exactly one defect. ASan observes CWE-401/416/787/190;
valgrind observes CWE-401/416/125/457 -- including the uninitialised read that
ASan structurally cannot see, since it tracks addressability rather than
definedness.

### Things measurement forced

- **Frames are `FILE:LINE:COL` at -O0 and `FILE:LINE` at -O1.** Requiring the
  column dropped every ASan frame in an optimised build, and a report whose
  frames are all dropped is discarded as frameless -- so the defect vanished
  while the run looked clean.
- **Both output streams must be read.** A sanitizer writes to the child's
  stderr; `ctest --output-on-failure` captures that and re-prints it on its own
  stdout. Reading stderr alone finds nothing.
- **valgrind needs `--trace-children=yes`.** Wrapping a test harness without it
  traces the harness, reports nothing, and reads exactly like a clean run.
- **UBSan ids must be curated, not derived.** Its messages embed addresses, so
  an id built from the text differs every run and nothing dedups or maps.
  `UBSAN_PHRASES` is the same curation the cppcheck CWE overrides are.
- **The leak fixture needs `opaque_malloc`.** At -O1 clang deletes a malloc
  whose result is unused, and the fixture then reports nothing. It must also
  *not* store the pointer in a global -- still-reachable memory is not a leak
  to either engine. The static leak fixtures need the opposite, which is the
  `_static`/`_runtime` split already recorded here, seen from the other side.

### MSan is unreliable on this host, and that is reported not hidden

It hangs symbolizing its own report: reliably with
`-fsanitize-memory-track-origins` (now removed from the profile), and
intermittently without -- the same binary completed one run and hung the next.
Every run therefore has a deadline, and a timeout produces a FAILED line naming
it. A hung sanitizer is indistinguishable from a slow test suite, and both are
indistinguishable from a clean result if nothing watches the clock.

**Pinning clang is done only for MSan**, which has no g++ equivalent. Pinning it
for ASan too also switched the symbolizer, and LLVM's hangs here where GCC's
addr2line path does not -- turning a working profile into a timeout. That is
the second time in this project that forcing a toolchain choice changed
something other than the thing intended; the first was the clang-specific
compile database breaking gcc's analyzer.

### Classification

valgrind's `InvalidRead` covers both CWE-125 and CWE-416 and only its
`<auxwhat>` says which, so that text is carried into the message and the table
discriminates on it -- the same mechanism the cppcheck overrides use.

`--require-cwe` now spans both layers. The dynamic layer is deliberately kept
out of the static findings list, and leaving it out of the selftest as well
would have reintroduced exactly the failure that flag exists to prevent.

## Coverage as of 2026-08-21

Two denominators, because they disagree and both matter. "Reported" is every
position the reference tool listed; "acted on" is the subset whose site or
immediate context changed between the broken and corrected trees.

| basis | coverage |
|---|---|
| vs everything the reference tool reported | **245/379 = 65%** |
| vs defects the maintainers actually fixed | **131/176 = 74%** |
| function level (within 25 lines) | 343/379 = 91% |

| CWE | reported | acted on |
|---|---|---|
| 763 | 4/4 100% | 4/4 100% |
| 369 | 3/3 100% | 3/3 100% |
| 416 | 1/1 100% | 1/1 100% |
| 191 | 59/60 98% | 31/32 97% |
| 190 | 28/30 93% | 6/7 86% |
| 457 | 25/27 93% | 10/12 83% |
| 476 | 11/12 92% | 5/6 83% |
| 563 | 69/74 93% | 53/56 95% |
| **119** | **44/86 51%** | 20/33 61% |
| **401** | **6/86 7%** | 2/25 8% |
| 415 | 0/1 | 0/1 -- confirmed false positive, silence is correct |

Everything except CWE-119 and CWE-401 is at or above 83% against acted-on
defects. Those two are the whole remaining gap, and they are not the same kind
of gap:

- **CWE-401's 7% is largely correct and will not move.** Its ground truth is
  dominated by positions on a closing brace -- leak-at-end-of-scope for locals
  of RAII classes that free in their destructors. Confirmed false positives.
  The real defects in that class are found, but reported per-class rather than
  per-line, so a line-keyed score cannot see them.
- **CWE-119's 51% is a real gap.** Breakdown of the 42 remaining misses:
  constant index on `operator[]` 25, two containers 13, single subscript 10,
  and one non-subscript. The `operator[]` constant-index family is the largest
  and was measured and rejected: including it doubled ground-truth reach and
  took specificity from -81% to -13%.

Report shape at these numbers: **441 detailed findings covering 104 acted-on
defects (4.2:1)**, with 6669 summarized low-confidence findings behind them.

## Measured results

Ground truth: `/home/shard/VsCode/acl/report/problems.md` — **280 confirmed
positions** (`(CWE, file, line)`), 104 excluded as false positives. Parsed to
`tmp/confirmed.json`. Raw list is 714 records → 384 unique.

**Full ACL tree**, current (`tmp/now2.json`, CTU on, IKOS off per the audit).
Three numbers, because one does not describe it honestly:

| measured against | result |
|---|---|
| the full 280-position list | 167/280 = **59.6%** |
| excluding the two classes the author confirms are mostly false positives (401, 415) | 157/213 = **73.7%** |
| the 52 positions the author's own triage lists as *still open real defects* | **49/52 = 94%** at function level, 26/52 = 50% at the exact line |

The third is the one that answers "does it find real bugs". The gap between 94%
and 50% is anchoring, not detection: the reference tool reports many defects at
the enclosing function's header while Kordon reports them at the offending
statement. Window sensitivity, for honesty:

| window | matched |
|---|---|
| ±3 lines | 26/52 (50%) |
| ±10 | 37/52 (71%) |
| ±20 | 41/52 (79%) |
| ±40 | 47/52 (90%) |
| ±60 | 49/52 (94%) |

Only 3 of the 52 are missed outright: one CWE-190 and two CWE-191.

Per-class against the still-open list: CWE-119 7/7, CWE-457 13/13, CWE-563
29/29, CWE-190 0/1, CWE-191 0/2.

**Precision is the counterweight**: 7 422 visible in-scope findings — 228 high,
96 medium, 7 098 low. Roughly 44 findings per real position.

**The CWE-415 "1/1" is a false match, not a detection.** The code there is

```cpp
Image& Image::operator=(const Image& other) {
    if (d == other.d) return *this;   // self-assignment IS handled
```

`bugprone-unhandled-self-assignment` recognises only the `this != &other`
idiom, so it reports this pimpl-comparison guard anyway. Independently verified,
and it agrees with the maintainers having already dismissed the position. Six of
that check's fifteen findings on this corpus are guarded code. Count real recall
as **166/280**, not 167.

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

## Loop-shaped false positives — fixed, and worth little on this corpus

Four shapes were reported as defects and are not:

```cpp
while (k > 0)  { use(k - 1); --k; }              // guard is a while condition
while (k != 0) { use(k - 1); --k; }
for (std::size_t i = n; i > 0; --i) use(i - 1);  // guard is a for condition
for (std::size_t i = 1; i < n; ++i) use(i - 1);  // guard is the initialiser
for (std::size_t i = 0; i + 1 < v.size(); ++i) use(v[i + 1]);  // counter + 1
```

`do`/`while` is deliberately still reported: its condition runs after the body,
so the first iteration is genuinely unguarded.

All confirmed to cost nothing — CWE-191 stays 49/52, CWE-190 stays 17/19.

**But the whole-tree effect is negligible: 7 422 visible findings to 7 395,
about -0.4%.** The per-file measurements taken while developing these looked
much larger and were comparing against a guard-blind matcher, not against the
shipped one. On this corpus the noise lives almost entirely in `pro-bounds-*`
and the other prolific checks, and loop idioms are a rounding error against it.

They mattered elsewhere: on a Qt project two of the three findings in the
project's own code were exactly these shapes. Worth having for correctness, not
as a route to a quieter report on a numerical library.

## The 42:1 ratio was measuring the wrong thing

Splitting it by what the report actually shows:

| tier | findings | positions found | ratio |
|---|---|---|---|
| **detailed in the report** | 324 | 78 | **4.2:1** |
| summarized low tier | 7 098 | +89 more | — |

The detailed report is not noisy. What is true instead is that **89 real
positions are only reachable through the summarized tier** — including every
CWE-191 (49) and every CWE-190 (17), because Kordon's own checks are low
confidence by design: intent is undecidable, so they can never be promoted.

So the problem is not "too much noise in the report", it is "more than half the
detections are in the part nobody reads". Cutting checks would make it worse:
the only source of those 49 CWE-191 positions is a check that emits 1 868
findings.

What does help is that the low tier is heavily **clustered**: half of its 7 098
findings sit in 17 of 401 files, and the largest single contributor is
`dcraw_loader.cpp` with 1 107 — a vendored raw-image decoder. The report now
says so, because "7 000 findings" is a number to despair at while "half are in
17 files, the biggest of which is third-party" is two or three decisions.

Per-check yield, measured, for anyone tempted to prune:

| check | findings | positions | covers still-open defects |
|---|---|---|---|
| `clang-analyzer-deadcode.DeadStores` | 144 | 46 | 29 |
| `unreadVariable` | 121 | 26 | 7 |
| `kordon-unsigned-subtraction` | 1 868 | 49 | 0 |
| `kordon-unsigned-addition` | 3 265 | 17 | 0 |
| `pro-bounds-pointer-arithmetic` | 3 798 | 15 | 7 |
| `cppcoreguidelines-init-variables` | 1 500 | 3 | 7 |
| `cppcoreguidelines-special-member-functions` | 985 | **0** | **0** |

`special-member-functions` is the one clear candidate for removal — 985 findings,
nothing matched, nothing covered — but it is also the only check for the
Rule-of-Five double-free class, which this corpus happens not to contain. That
is the general difficulty with pruning on one corpus.

## The precision problem — measured properly (2026-08-20)

### The 42:1 headline was measuring against the wrong ground truth

The reference tool's report is not a list of defects; it is a list of one
tool's warnings. Scoring against it rewards agreeing with another
shape-counter. A better basis is available: **the defects the maintainers
actually acted on**, found by checking whether the site or its immediate
context changed between `acl_raw` and `acl_fix`.

Of 384 ground-truth positions, **176 were acted on and 203 were not.** The
context window matters -- comparing the statement alone misses fixes made by
adding a guard around it, which is how the whole `vector.cpp` family was
corrected. Sanity-checked against `vector.cpp:327`, a known guard-added fix.

Against that basis the tool looks very different, and much better:

| tier | findings | defects actually fixed | ratio |
|---|---|---|---|
| detailed by default (high+medium) | 339 | 81 | **4.2:1** |
| summarized (low) | 7091 | 47 | **150:1** |

**The default report was never the problem.** 4.2:1 is good. The problem was
that 47 real defects were invisible behind 7091 low-confidence findings.

### What does not work, measured

Generic ranking of the low tier fails. Three signals were tested:

| signal | lift |
|---|---|
| number of distinct checks stacked on one position | 2.2% -> 2.6% -> 0.0% (none) |
| within 15 lines of a high/medium finding | 1.8% -> 4.1% (real, but on a hopeless base rate) |
| how few findings the file has | 57:1 -> 26:1 for the sparsest bucket only |

There is no metadata signal to rank on. Suppressing the noisiest file
(`dcraw_loader.cpp`, 1106 low findings) would have cost 19 real positions.

**Responsiveness splits cleanly by engine kind, and the existing tiering already
tracks it.** Path-sensitive engines: DeadStores -82%, `unix.Malloc` -100%,
`NullDereference` -58%, `UninitializedObject` -62%, but volumes of 12-173.
AST matchers: pointer-arithmetic -3%, unsigned-addition -0%, narrowing -0%,
array-to-pointer-decay 0%. The one responsive matcher is `init-variables` at
-29%. The low tier is inert *by construction*; it is a risk register, and no
tuning turns it into a defect list.

### What does work: narrow a shape until its precision changes tier

`x.width() - 1` and `n - 1` are the same expression and different propositions.
An empty container reports 0, and 0 - 1 unsigned is the type maximum; a
variable named `n` carries no such invariant. Splitting on that:

| left operand | positions | defects actually fixed | ratio |
|---|---|---|---|
| a container-extent accessor | 46 | 21 | **2:1** |
| anything else | 332 | 8 | 41:1 |

Twentyfold, and 2:1 beats the entire high-confidence tier. Shipped as
`kordon-extent-underflow` at medium confidence, excluded from the general
check so no site is reported twice.

### Net effect

| | before | after |
|---|---|---|
| detailed report | 339 findings, 81 real | **404 findings, 103 real** |
| ratio | 4.2:1 | **3.9:1** |
| real defects buried in the low tier | 47 | **26** |
| total in-scope findings | 7430 | 7001 (-6%) |

More real defects visible and a better ratio at the same time -- because the
gain came from re-tiering 21 defects that were already found, not from adding
volume. `pro-bounds-array-to-pointer-decay` was also removed outright: 622
findings, zero acted-on defects, zero exclusive coverage, 0% responsiveness.

### What is left, and what it would cost

The 26 still-buried defects sit behind these checks:

| check | buried defects | low-tier volume | cost each |
|---|---|---|---|
| `pro-bounds-pointer-arithmetic` | 8 | 3782 | 472 |
| `kordon-unsigned-addition` | 7 | 3191 | 455 |
| `bugprone-narrowing-conversions` | 3 | 1623 | 541 |
| `pro-bounds-constant-array-index` | 2 | 716 | 358 |

`kordon-unsigned-addition` is ours and the obvious next target, but the
narrowing that worked for subtraction does not transfer: restricting it to
memory-relevant contexts (subscripts, allocation arguments) cut volume 90% and
kept only 3 of its 26 exclusive ground-truth positions. Its remaining hits are
`roi.right() - roi.left() + 1`, where the `+ 1` is incidental and the real
hazard is the subtraction -- and 20 of those 26 positions were never acted on
by the maintainers at all.

## The precision problem — earlier framing, superseded above

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

## CWE-119: the parallel-extent check (2026-08-20)

The ground truth's 86 CWE-119 positions break down by shape:

| shape | count | example |
|---|---|---|
| constant index | 29 | `w[0] = (R(2,1) - R(1,2)) / 2.0;` |
| single subscript | 22 | `while (m_ptrack[m_end] == NULL && m_end >= 0)` |
| two containers, same index | 20 | `m_data[i] += v[i];` |
| operator() on two objects | 8 | `res(i,m) += a(k,i) * blc(k,m);` |
| mixed indices | 5 | `res[i] += m_data[i * m_col + j] * v[j];` |

`kordon-unchecked-parallel-extent` targets the third and part of the fourth.
The defect and its fix, both from the reference tree:

```cpp
// broken                                fixed
assert(m_length == v.m_length);          assert(m_length == v.m_length);
                                         if (v.m_length < m_length) return;
for (int i = 0; i < m_length; i++)       for (int i = 0; i < n; ++i)
    m_data[i] += v[i];                       m_data[i] += v[i];
```

Measured across 452 TUs: **52 positions broken / 27 corrected (-48%)**, against
`pro-bounds-pointer-arithmetic`'s 2326 findings moving -1%. Responsiveness is
the quality signal, and this is the first bounds check to show it.

Recall against the line-keyed ground truth is only 8/86 exact, because it
targets one of five shapes. That understates it: it also found
`Vector::operator-=` (the twin of a listed defect, unlisted) and
`SparseVector::colMult`, where the index written into the caller's vector comes
from stored data (`pos = m_ppos[i]`) and is bounded by nothing at all.

**The exemption that carries the precision** is dropping loops bounded by the
same object being subscripted. `for (i = 0; i < v.size(); ++i) v[i]` is safe by
construction, and without that clause one file of `push_back(list[i])` loops
contributed 55 findings on its own -- more than the whole check now emits.

### Measured end to end, not just standalone (full CTU run, 452 TUs)

The standalone clang-query scan and the integrated run agree closely: 52
positions scanning alone, **48 in the full run** (57 raw findings). What the
integrated run adds is the honest recall delta:

| | exact hits on the 86 CWE-119 positions |
|---|---|
| without the new check | 18/86 |
| with it | **20/86** |

**+2.** Six of the eight ground-truth positions it finds -- the whole
`vector.cpp` family -- were already covered by `pro-bounds-*`. So the check's
value is not recall. It is that those positions are now also held by something
that moves -48% between the broken and corrected trees, instead of only by
something that moves -1%.

It did **not** displace `pro-bounds-*`. Re-measured with the new check in
place, 16 ground-truth positions are still covered by `pro-bounds-*` and
nothing else -- the same 16 as before, none of them overlapping the new check.
3341 findings for 16 exclusive positions, a 209:1 ratio on its own. The
precision problem is unchanged; this check does not solve it, it just shows the
shape of a check that could.

Note on ground-truth quality: **76 of the 86 statements are byte-identical in
the corrected tree.** For the vector/matrix family the class was rewritten
around them, but a line-keyed recall score against this list is measuring
something noisier than it looks.

## CWE-119: the constant-index check (2026-08-20)

Targets the largest remaining shape, 29 of the 86 ground-truth positions. The
defect and its fix:

```cpp
void Rotation::fromRotationToAxisAngle(Matrix &R, Vector &w)
{
    w.init(3);                          // w's extent is guaranteed -- fine
    ...
    w[0] = (R(2,1) - R(1,2)) / 2.0;     // R's extent is not -- the hazard
}
// fix adds:  if (R.getRows() < 3 || R.getCols() < 3) { return; }
```

Two exemptions: the function *read* the parameter's extent in a condition, or
*set* it. Both must name the bound parameter.

**Exempting any `if` that mentions the parameter is far too loose.** The first
version did, and reported nothing on the very file it was written for, because
`if (R(2,1) < 0) y = -y;` -- a test of the stored value -- silenced all 25
findings. Requiring an extent accessor is the whole check.

Measured across 452 TUs: **21 positions broken / 4 corrected (-81%)**, the
sharpest discrimination of any bounds check here.

Restricted to `operator()` deliberately. Adding `operator[]` doubled
ground-truth reach (3 to 6) but took specificity to -13% and volume from 21 to
129, nearly all of it inert -- a fixed subscript on a one-dimensional container
is usually a real constant, not an assumption. That is recall bought by
shape-counting, which is the thing this project keeps rejecting.

## CWE-401: what the ground truth actually contains (2026-08-20)

Of the 86 CWE-401 positions, only 25 were acted on, and the list is dominated
by positions on a closing brace `}` -- the reference tool reporting "leak at
end of scope" for locals of RAII classes that free in their destructors. Those
are the false positives already recorded here and confirmed by the codebase
author. A line-keyed recall score against this class will stay low regardless
of what Kordon does, and that is the right outcome.

Two clusters in it are real, and they are different defects:

**The manual ownership flag** (`matrix.cpp:41,59,157`, `vector.cpp:94,203`,
all acted on). Ownership is tracked by a bool that can disagree with reality:

```cpp
void Vector::clear() {
    m_length = 0;
    if (m_data && m_flgAllocMemory) { delete[] m_data; }   // frees only if the flag agrees
    m_data = NULL;
    m_flgAllocMemory = false;
}
```

while `init(double *data, int n, hardcopy=false)` sets `m_data = data;
m_flgAllocMemory = false;`, aliasing memory the object does not own. A wrong
flag is either a leak or a free of someone else's buffer. The corrected tree
deletes the scheme entirely and holds a `unique_ptr`. Already covered by
`kordon-manual-ownership-flag`, which reports it once per class rather than
once per line -- which is why it scores zero against a line-keyed ground truth.

**Reinit without free** -- shipped today as `kordon-reinit-without-free`, and
the one CLAUDE.md predicted would need custom code. That prediction held:
nothing in clang-tidy, Clang SA or cppcheck reports these sites, and Clang SA
structurally cannot, because the leak requires two calls to the same method
while it reasons about one path at a time.

26 findings at 10 positions across 452 TUs. Four sampled, four genuine:
`SparseVector::init`, `BmpImage::init`, `Tracker::make_sets`, and a guided
filter's `init`, none of which release before allocating.

The exemption had to match release-method names **as a substring**. With an
exact list, `cmatchingcorner.cpp:35` -- `if (m_pPolinom) clearPolinom();`
followed by the allocation, which is correct code -- was reported as a defect.

### A matcher bug worth not repeating

`allOf(binaryOperator(...), hasAncestor(...))` silently matches nothing.
Written as direct arguments, `binaryOperator(..., hasAncestor(...))`, the same
matcher works. It cost a full tree scan to notice, because the failure mode is
a clean zero rather than an error, and a check that reports nothing looks
exactly like a codebase with no defects. There is now a test asserting the
assembled matcher contains no `allOf(`.

## The fallible-init chain: three formulations, none shipped (2026-08-20)

Target was CWE-252 -> 476 -> 690, currently at zero coverage. Three matchers
were built and measured; all are recorded here so they are not rebuilt.

**1. Caller-side, constructor body as the fallibility signal.** A local of a
class whose constructor contains `new (std::nothrow)`, subscripted with no
bool-returning query called on it. Works exactly on the fixture. **Zero
findings on the reference corpus** -- the constructor is defined in
`vector.cpp`, so from every other translation unit only the declaration is
visible and `hasDescendant(cxxConstructorDecl(...))` has no body to see. This is
the CTU boundary again, and clang-query has no CTU.

**2. Caller-side, class signature as the signal.** Fallibility inferred from
what the header shows: a raw-pointer member, a bool-returning method, a
destructor. **1227 findings, -0.7% between trees** -- a pure shape-counter,
because on this codebase nobody checks these queries anywhere, so "did not
check" is endemic rather than diagnostic. Narrowing to runtime-sized
constructions (`Vector v(n)`, not `Vector v(4)`) cut it to 89 positions and 5
acted-on defects, 18:1 -- better, still not tier-worthy.

**3. Class-internal: a method dereferencing its own raw-pointer member**,
linked to a fallible constructor *of the same class in the same TU*, with no
null test on that member in the method. This one is well targeted: **73
positions, 0 on the corrected tree (-100%)**, confined entirely to
`vector.cpp`/`matrix.cpp` -- the two genuinely fallible classes -- and silent
on the corrected tree because the rewrite replaced nothrow-new with
`unique_ptr`. Best responsiveness of anything measured here.

**Not shipped, because it adds nothing.** All 73 positions are already reported
by Kordon at the exact line, under CWE-119. It would add 73 findings and zero
detections, taking the detailed tier from 3.9:1 to 4.6:1 -- a precision loss
for a relabelling. Its claim (CWE-690, the fallible-init chain) is more
accurate than CWE-119 for those lines, so it is worth revisiting if the report
ever grows a way to correct a finding's class rather than add a second one.

**Why formulation 3 is still the right shape**: the reference corpus's actual
CWE-476 defects are not callers misusing a local. They are
`res[i] += m_data[i * m_col + j]` -- a class dereferencing its own member,
which may be null because its constructor failed quietly. The caller-side model
was simply the wrong picture of this defect class.

## A guard deleted by a semicolon — the highest-precision check in the tool

Found while investigating why formulation 3 exempted `matrix.cpp:219`:

```cpp
void Matrix::vecMult(const Vector &v, Vector &res) const
{
    if(v.m_length == m_col && m_data && v.m_data);   // <-- the guard is gone
    {
        ...  res[i] += m_data[i * m_col + j] * v[j];
    }
}
```

The precondition is written correctly -- non-null buffers, matching extents --
and then discarded by the semicolon. `Matrix::trVecMult` has the same defect.

`bugprone-suspicious-semicolon` catches both, mapped to CWE-483, and **Kordon
was discarding them as out of scope.** Two findings across 452 translation
units, both genuine, and both fixed by the maintainers -- the corrected tree
carries the identical conditions without the semicolon. A 1:1 ratio, the best
in the tool, in a class where the absence of a memory-safety guard is provable
rather than suspected.

CWE-483 is now tier 1. The CWE itself is a control-flow class, which is why it
was excluded; what makes it in scope is the consequence, since the guard being
deleted is the one protecting a subscript of a possibly-null buffer.

## Clang SA does not model allocation failure (2026-08-20)

Measured on clang 18.1.3, with each masking bug removed in turn:

| case | reported |
|---|---|
| `int *p = nullptr; *p = 1;` | yes, `core.NullDereference` |
| `p = malloc(4); *p = 1;` | **no** |
| `p = new (std::nothrow) int; *p = 1;` | **no** |
| `p = malloc(4); if (p == nullptr) { *p = 1; }` | yes |

The analyzer knows the pointer can be null -- it follows the branch when the
code forces it -- but never proactively splits state on allocation failure. So
an unchecked allocation and a correctly guarded one are indistinguishable, and
the CWE-252/476/690 fallible-init chain is unreachable by the configured
engines. Silence on a guarded `if (v.isNullPointer()) return;` is not the guard
being understood.

Getting this took three fixtures: the first reported an uninitialized read and
the second a leak, each masking the null path, because Clang SA stops at the
first bug on a path.

## CodeChecker: evaluated, not wired (2026-08-20)

Installed 6.28.2 in `.venv-cc/` (`pip install codechecker`). It works, and
`CodeChecker parse -e json` gives a clean schema: `checker_name`,
`analyzer_name`, `file.path`, `line`, `message`, `report_hash`. No CWE, so the
mapping table still does that work. Check ids are as predicted: clangsa bare
(`core.NullDereference`), cppcheck prefixed (`cppcheck-noCopyConstructor`).

Three of its four analyzers are the ones Kordon already drives directly. The
one addition is **gcc `-fanalyzer`**, and it has two problems:

- **The compile database is clang-specific.** It carries
  `-fsanitize=unsigned-integer-overflow`, `-fsanitize-ignorelist=` and
  `-fsanitize-recover=`, none of which g++ accepts, so every TU fails to
  compile. Stripping those three makes it work. Any future non-clang engine
  will hit this, so flag filtering belongs in the orchestrator, not in a script.
- **It is slow**: 438 s for 22 translation units, roughly 2.5 h extrapolated to
  the full tree.

What it earns, measured on `modules/math/src`: 20 reports, 13 in-tree
positions, **9 of them not reported by Kordon**, all in the uninit family
(CWE-457/908) -- the class with the weakest static story. Against that, its
messages are often `use of uninitialized value '<unknown>'`, and one of the
nine (`vect3d.cpp:138`) points at a function that is genuinely broken for a
different reason than gcc states: `operator-` performs `tmp += v2`.

Verdict: worth wiring as an opt-in runner for the uninit class specifically,
not as a default engine. Its unique contribution is real but narrow and
expensive.

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
