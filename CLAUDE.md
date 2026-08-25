# Kordon

## What this is

An open-source static+dynamic analysis orchestrator for C/C++, scoped like "Coverity/PVS-Studio, but smaller" — aimed at generic memory/value-safety bugs, not the full commercial-tool surface area.

Name: "Kordon" (Cyrillic Кордон = border checkpoint/perimeter). Deliberately spelled the transliterated way, not "Cordon" — plain "cordon" collides with `kubectl cordon` and an existing GitHub security-gateway project of the same name; "Kordon" had no collisions and still reads naturally in English. License for Kordon's own code: **Apache 2.0** (explicit patent grant + retaliation clause matters for a multi-contributor security tool; MIT doesn't offer this).

## Scope: what Kordon actually targets

Deliberately **not** trying to be a general SAST tool. Three tiers were identified; only Tier 1 is in scope:

- **Tier 1 (in scope)** — generic memory/value-safety bugs: bounds/OOB (CWE-119 class: 125/787/121/122/120/129/786/788), use-after-free/double-free/dangling (416/415/590/762/825/562), uninitialized reads (457/824/908), integer over/underflow (190/191/680/192-197), resource leaks (401/772), NULL deref (476), misc (369 div-by-zero, 563 dead store, 843 type confusion).
- **Tier 2 (explicitly out of scope)** — injection/taint class (CWE-78/89/22/94/502/918/77/770). Real and catchable with a taint engine, but ruled out: "we don't care about SQL injection or something like that, it's out of scope of kordon."
- **Tier 3 (explicitly out of scope, and not realistically solvable generically)** — authorization/access-control CWEs (862/863/284/306/639/200) and web-specific ones (79/352/434). Confirmed via research: these require the user to annotate application-specific privilege semantics — "no automated means to verify access control" without that. Even Coverity/PVS-Studio don't meaningfully solve this class.

Rationale for the split: see conversation history (2026-08-14) for the full CWE Top 25 walkthrough and MISRA C:2025 cross-reference.

## Ground truth already established (don't re-derive)

**MISRA C:2025 Addendum 5** (official MISRA↔CWE mapping, misra.org.uk) gives per-CWE coverage classification. Key takeaways for our CWE list:
- Strong static coverage: CWE-119/125/787/788 (via MISRA R.18.1 pointer-arithmetic restriction + R.21.6/17/18 stdlib guards) — this is the tractable core.
- "Partial/Restrictive but Strong": CWE-401/415/416 — MISRA's approach here is banning risky patterns outright, not precisely detecting the defect. Matches our own finding that leak/UAF/double-free need whole-class ownership analysis, not function-local new/delete pairing.
- Weak/Implicit only: CWE-190 (overflow) and CWE-476 (null deref) — MISRA punts to Directive 4.1 ("avoid UB generally"), not a targeted rule.
- Not mapped at all (as of this MISRA edition): CWE-191 (unsigned underflow), CWE-457 (general uninit read — though the pointer-specific sibling CWE-824 *is* covered), CWE-563 (dead store).

**Precise CWE classification matters** — don't default to CWE-119 for every bad-memory-access bug:
- Custom container with fallible init (nothrow-alloc, null-check via a method's return value, no throw) → **CWE-252 (unchecked return) + CWE-476 (null deref)**, chain-classified as **CWE-690**. Not CWE-119 — there's no real buffer being mis-bounded, there's no buffer at all.
- Same bug but the fallible logic is in a **constructor** (no return value to ignore) → root cause is **CWE-665 (Improper Initialization)**, not CWE-252, because a constructor can only fail by throwing — an early `return;` leaves a "zombie" object that looks valid. Consequence is still CWE-476 at the point of use.
- The self-inflicted nature of the constructor case is worth flagging as a design recommendation whenever detected: if the constructor threw instead of silently returning, the entire bug class is structurally impossible (no partially-constructed object can ever exist to misuse).

## Architecture: orchestrator over existing engines, not a rebuilt analyzer

Repeated conclusion across every sub-problem discussed: **don't rebuild symbolic execution, CTU orchestration, or abstract interpretation from scratch** — mature open engines already exist; Kordon's value-add is wrapping them, filling specific gaps, and producing one coherent CWE-mapped report.

### Static layer
- **clang-tidy** — cheap AST-matcher-level checks (dead stores, div-by-zero, some unsigned-subtraction patterns). Also directly useful: `cppcoreguidelines-special-member-functions` (Rule-of-Five enforcement — see RAII section below).
- **Clang Static Analyzer, via CodeChecker** — path-sensitive symbolic execution, no execution of the target program required. Catches the CFG-reachability family (bounds, null-deref, leak/UAF-shape) without needing tests. **Must run with Cross-Translation-Unit (CTU) analysis enabled** — by default Clang SA only sees one TU and treats external function calls (e.g. a constructor defined in a different .cpp) as opaque, so it silently can't reason about them. Manual CTU setup is "error-prone and not scalable" per LLVM's own docs — use **CodeChecker** (`CodeChecker analyze --ctu compile_commands.json`), which already automates AST emission, the extdef-mapping index, and the CTU flags. This is itself an orchestrator we build on top of, not around.
- **cppcheck** — second opinion, different engine/blind spots, cheap to include. License is GPL-3.0, but invoked as a subprocess (not linked into Kordon), so it doesn't affect Kordon's own Apache 2.0 licensing or impose anything on analyzed user code (GPL copyleft doesn't propagate through mere tool invocation — FSF's own position: output of a program is not covered by the program's license, and using a GPL tool on your code is not a derivative work).
- **IKOS** (NASA, LLVM-based, open source, actively maintained) — abstract interpretation, the only technique that can *soundly prove* absence of overflow/OOB for the provable subset, entirely statically, no execution needed. This is the honest answer to "CWE-190/191 need more than heuristics." License is NASA Open Source Agreement — OSI-approved but not FSF/GPL-compatible; **needs a licensing review before embedding**, given the goal of unrestricted downstream use.
- Deliberately **excluded**: CodeQL. Its CLI license requires a separate commercial license to analyze closed-source code — directly conflicts with "everyone can use this on any project" without forcing them into GitHub Advanced Security.

### Dynamic layer (only meaningful if tests/fuzz harnesses exist — see note below)
- ASan + UBSan (combinable in one build) for bounds/UAF/double-free ground truth and signed+unsigned overflow traps (`-fsanitize=unsigned-integer-overflow` is opt-in, separate from the default UB group, since wraparound is often intentional).
- MSan (separate build — doesn't combine with ASan) for uninitialized reads — the family with the weakest static story.
- LSan (bundled with ASan) for leak confirmation.
- TSan (separate build, future work) for races, not yet in scope.
- **Directed/targeted fuzzing as the handoff mechanism**: static analysis identifies *what* might be wrong (e.g. "this exit path might not free X" or "this array access has unprovable bounds"); a directed fuzzer (AFLGo-style, biased toward reaching the flagged line) generates a concrete triggering input automatically — no human writes a test. This is how "code paths with 0% test coverage" get covered without demanding new tests: the CFG-reachability class (leaks on untested branches) doesn't need this at all (provable by pure static CFG analysis, see below); the value-dependent class (overflow, OOB with runtime-dependent bounds) does need it, seeded specifically by IKOS's "cannot prove safe" output rather than fuzzed blindly.
- Sanitizers fundamentally require the target to *execute* — no tests/harness means no dynamic layer, full stop. Static-only is a legitimate reduced-scope mode, not a broken one; see per-family confidence table in conversation history.

### The RAII/leak false-positive problem (CWE-401 specifically)
Diagnosed root cause: existing tools (including paid ones) try to pair `new` with a `delete` *within traceable scope*, and fall back to "flag it anyway" when the delete lives in a destructor reached via a different function/virtual dispatch. This is genuine open research territory, not tool laziness. Fix: stop pairing at the statement level, build **one ownership summary per class** (which raw-pointer members are owning, where are they released) — this simultaneously:
1. Suppresses the false leak alarm at every constructor/init site.
2. Unlocks Rule-of-Five violation detection almost for free — if a class frees an owning pointer in its destructor but doesn't explicitly define/delete copy ctor/copy assignment, the compiler-generated shallow copy creates two owners of the same pointer → eventual **double-free (CWE-415)**, actually more dangerous than the leak originally suspected. Already shipped as `clang-tidy`'s `cppcoreguidelines-special-member-functions` (implements C++ Core Guidelines C.21) — no custom code needed for this part.
3. Unlocks reinit-without-free as its own tractable, function/class-local check (calling `init()` twice, overwriting the owning pointer without freeing the old one first) — needs custom implementation, no off-the-shelf check found for this specific pattern.

### Teaching the analyzer about custom fallible-init types
For classes where the analyzer can't inline (opaque, virtual, cross-TU without CTU), the real mechanism is Clang's existing **typestate/consumed-analysis attributes** (`-Wconsumed`: `[[clang::consumable]]`, `callable_when`, `set_typestate`, `test_typestate`, `return_typestate`). `return_typestate` is specifically designed for functions with no return value to check (i.e. constructors) — exactly the CWE-665 constructor case above. Less mature/battle-tested than mainstream Clang SA checkers; budget extra validation. Practical implication: adopting Kordon on a codebase with lots of custom RAII/container types (matches ACL's own Matrix/Vector types) means incrementally annotating those core types, similar to how projects adopt `_Nullable`/`_Nonnull`.

### Aggregation layer (this is real, novel Kordon code)
- Normalize every tool's native output (Clang SA plist/SARIF, cppcheck XML, IKOS output, sanitizer crash reports) into one schema: `{tool, native-id, CWE, file:line, severity, confidence}`.
- A curated tool-check-id → CWE mapping table (own IP, analogous to what MISRA published for their own rules).
- Cross-tool dedup (multiple tools flagging the same root bug).
- Explicit "not fully analyzed" / "unproven" reporting for anything Clang SA gave up on (complexity budget) or IKOS couldn't bound — no silent caps; a clean report must not imply full coverage when it isn't.

## Do we need to write code at all?

Yes, but not the kind originally assumed. Nearly every "hard" sub-problem in this conversation resolved to "wrap an existing engine," not "build one." What's actually novel Kordon engineering:

- The orchestrator/runner (build-matrix management: separate ASan+UBSan / MSan / TSan builds, compile_commands.json wiring, CTU index generation via CodeChecker).
- The aggregation layer above (schema, CWE-mapping table, dedup, gap reporting) — this is probably the largest real chunk of original code.
- A handful of custom checkers for confirmed gaps with no existing equivalent: reinit-without-free, the unsigned-subtraction-without-guard heuristic for CWE-191 (prior art found was an unmerged LLVM patch, not a shipped check — needs verification before relying on it), the static-finding→directed-fuzz-target handoff.
- Tooling/docs to help users annotate their own types with typestate/nullability attributes.
- The report generator itself.

What does *not* need new code: the symbolic execution engine (Clang SA), CTU orchestration (CodeChecker), abstract interpretation (IKOS), sanitizer instrumentation (LLVM compiler-rt), Rule-of-Five checking (clang-tidy already has it). Kordon's job is gluing these together correctly, filling the specific identified gaps, and presenting one coherent, honestly-scoped, CWE-mapped report — not reimplementing program analysis theory.

## Ground truth measured while building (2026-08-17) — don't re-derive

Implementation decisions settled: orchestrator is **Rust** (single crate, `src/`), license switched **MIT → Apache 2.0** (LICENSE + NOTICE in place). Two engines wired up, `cargo test` green, `kordon <dir>` works end to end.

**Tool output formats (clang 18 / cppcheck 2.13):**
- **clang-tidy has no SARIF export.** Only structured output is `--export-fixes` YAML, which despite the name lists *all* diagnostics, not just fixable ones. It locates them by **byte offset**, not line:col — hence `src/offsets.rs`. It reports **no CWE at all**, which is why the mapping table is mandatory rather than a nicety.
- **cppcheck emits `cwe=` natively but frequently the *parent* class.** Verified: `operatorEqToSelf` → claims 398, is 416; `containerOutOfBounds` → claims 398, is 119; `deallocret` → claims 672, is 416. Taking the attribute at face value silently drops real findings out of scope. Override list ported into `data/cwe_map.toml`.
- One check id covers several defect classes: `unix.Malloc` is leak + UAF + double-free + free-of-non-heap. Mapping rules therefore discriminate on **message substring**, not check id alone.
- cppcheck `--enable=all` is wrong for this purpose — it adds `information` and `unusedFunction` noise. Use `warning,style,portability`.

**The escape-sink trap in test fixtures (measured both ways):** a sanitizer needs the allocated pointer to escape the function or the optimizer deletes the allocation at -O1; a static analyzer needs it to *not* escape, because once written to an opaque global both Clang SA and cppcheck conclude ownership transferred and stop reporting the leak. Adding one `sink = p;` line silently removes the `unix.Malloc` and `memleak` findings. **One fixture function cannot serve both layers** — leak cases must exist in `_static` and `_runtime` form.

**`optin.cplusplus.UninitializedObject` is the checker for the CWE-665 constructor case**, and it has two gotchas:
- It is **not included in `clang-analyzer-*`** — `optin.*` checkers must be named explicitly. Now in Kordon's `DEFAULT_CHECKS`.
- It only fires when the constructor's **call site is in the same TU**. Same file: reports the exact field (`uninitialized field 'this->m_owns'`). Split header/.cpp: reports nothing even when enabled. This is the concrete, measured cost of not having CTU — `testdata/uninit_owner/` is the fixture, kept deliberately failing until CTU lands.

**Check families that are mapped but off by default:** `cppcoreguidelines-owning-memory` and `pro-bounds-*` fire once per raw pointer / subscript / cast. On the test corpus they produced 8 low-confidence CWE-401/119 findings that buried the single genuine leak. Mappings retained so opting in still yields classified results.

**Prior art to reuse, not re-derive:** `/home/shard/VsCode/acl/` holds a working shell+Python prototype of this exact pipeline (`scripts/cwe_summary.py`, `run-cppcheck.sh`, `run-codechecker.sh`, `analysis/cwe_map.json`) plus a 714-finding report from a real run. Two ideas ported: the curated cppcheck override list, and `--require-cwe` selftesting (a config regression is indistinguishable from clean code unless you assert what *must* be found). Cross-tool dedup was **absent** there — it is Kordon's actual value-add. **ACL itself has no LICENSE file: treat as proprietary.** `analysis/repro/*.cpp` quote real ACL source in comments and must not be copied into this repo; `cwe_probe.cpp` is synthetic and safe to adapt. ACL is intended later as an *external* validation target — run Kordon on it and diff against the existing report.

## Ground truth measured while building (2026-08-24) — don't re-derive

**clang-tidy's "Error while processing" is a cumulative counter, not a per-unit verdict.** It asks "have I seen an error yet" after each unit, so once one unit in an invocation fails, every unit processed *after* it is named too. Measured directly: `clang-tidy good.c bad.c` names only bad.c; `clang-tidy bad.c good.c` names both. Since Kordon shards files across jobs, one broken header inflated 26 real failures to 51. The names are now treated as suspects and confirmed with a syntax-only parse. That count is the report's single most important note, so its accuracy matters more than most.

**`--checks='-*,clang-diagnostic-error'` (and `-*,clang-diagnostic-*`) silently analyzes nothing** — clang-tidy exits with "no checks enabled" and reports zero errors even on a file that genuinely fails to parse. Never use a `-*`-only check set to probe whether a unit compiles; ask the compiler, or use `clang-check -p <db>`.

**`LD_PRELOAD` is inherited by every descendant.** With `--run "ctest ..."` the shell, the runner and the program all ran under the fault interposer, sharing one count file with last-writer-wins — so the "1051 allocations" the sweep planned around were `sh`'s. The program made 21, ctest 4491. The interposer is now scoped to executables inside the build tree.

**valgrind replaces `malloc` itself and beats an `LD_PRELOAD` interposer.** Injection that drives a program down its error path when run directly is ignored entirely under the valgrind wrapper; `--soname-synonyms=somalloc=NONE` does not help. This is why the `fault` profile cannot currently do both jobs in one run — see the open questions below.

**Qt projects need a *build*, not just a configure, before analysis.** AUTOUIC/AUTOMOC generate `ui_*.h` and moc sources at build time; analyzing a configured-but-unbuilt tree failed 26 of 28 TUs. Build first, then analyze.

**A cmake project with both a shared and a static target lists every source twice** in `compile_commands.json` (159 files, 318 entries here). Kordon walks the filesystem for sources rather than the database, so this does not double the work — but it does double clang-tidy's raw diagnostic counts and its per-compile-command error lines.

## Measured against labelled ground truth (2026-08-25) — don't re-derive

Kordon is now scored against the **NIST Juliet C/C++ suite 1.3** — the only labelled corpus of any size for this defect class. Every case ships a flawed function and a corrected counterpart in one file, so a finding inside a `_bad` function is a hit and one inside a `good*` function is unambiguously wrong. `scripts/setup-juliet.sh` fetches it, `scripts/score-juliet.py` scores it, baseline in `data/juliet-baseline.json`.

Baseline over 40 files per CWE: **45.5% recall, 16.9% false positives — 34.8% / 2.0% counting only the high- and medium-confidence tiers the report details without `--all`.**

| strong | weak | absent |
|---|---|---|
| 457 (100%), 476 (93%), 415 (80%), 762 (77%), 401 (69%), 563 (64%) | 416 (49%), 775 (39%) | 121/124/126/127 (5%), 122 (10%), 590 (0%), 562 (0%) |

Three things this measured that were previously assumed:

- **The bounds class is not the tractable core.** CLAUDE.md called CWE-119/125/787/788 "the tractable core"; measured, CWE-121/122/124/126/127 score 5-10%. The dominant Juliet shape is an index from an unbounded source guarded only against negative — `if (data >= 0) buffer[data] = 1;` with `data = RAND32()` — 228 of 628 files in one subdirectory alone. Kordon emits 21 findings on such a file and none of them is the overflow. cppcheck even reports `Condition 'data>=0' is always true` without connecting it. **This is a syntactic shape and the clearest next check to build.**
- **CWE-190/191 are detected but never shown.** 64% recall, 0% surfaced — every overflow finding is low-confidence, so a default report contains none of them. Either the confidence is wrong or the tier is.
- **The confidence tiers earn their keep.** Restricting to surfaced tiers cuts false positives 16.9% → 2.0% while costing 45.5% → 34.8% recall. CWE-457 is the extreme: 100% recall at a 75.6% raw FP rate, but only 5.7% surfaced.

**Juliet is synthetic and its scores do not transfer.** The flow-variant scaffolding looks like nothing anyone writes, and the defects this project actually found by comparing a function against a correct sibling have no analogue in the suite. Use it for per-CWE coverage of mechanical cases; keep the ACL raw/fixed pair for realism.

Two harness traps already paid for, both of which read as real results: the C++ variants name the flawed function bare `bad()` inside a namespace rather than `<case>_bad`, so testing only the underscore form scored every C++ flaw as a *correct* function — CWE-762 read 0% until fixed, then 76.7%. And the corrected code lives in `goodG2B`/`goodB2G`, which carry no underscore either, so requiring one shrank the false-positive denominator to a third of its real size.

## Working plan: close the Juliet gaps, CWE by CWE

The standing plan. Work one CWE at a time, in the order below, and record the
verdict in the table so the next session starts where this one stopped.

### The loop, per CWE

1. **Read the cases before running anything.** `ls testcases/CWE<n>_*/s01/` and
   read three or four `_01` variants plus one high-numbered flow variant. The
   goal is to name the *shapes* the CWE is made of, not to count them.
2. **Triage each shape into one of five verdicts**, and write the verdict down.
   This is the whole point of the exercise -- deciding what is out of reach is
   as valuable as building a check, and far cheaper than rediscovering it:
   - **syntactic** -- a shape a matcher can express. Build the check.
   - **value-range** -- needs to bound an expression (`data = RAND32()`).
     IKOS territory, or a heuristic that flags the *missing guard* rather than
     proving the overflow.
   - **cross-TU** -- the source and sink are in different files (`_54a.c` ..
     `_54e.c`). Blocked on CodeChecker; do not attempt piecemeal.
   - **runtime** -- only decidable by executing. Dynamic layer, and honestly
     reported as unreachable statically.
   - **out of scope** -- injection, access control, or a Juliet artifact that
     no real code contains. Record and skip; do not chase the score.
3. **Run the scorer for that CWE alone**:
   `scripts/score-juliet.py <root> --cwe <n> --limit 40`
4. **Fix what the triage marked syntactic.** New checks follow the existing
   discipline: validate the matcher by hand with `clang-query` first (a
   malformed matcher returns 0 matches, not an error), add a `testdata/`
   fixture with both a positive and the corrected form, and assert the
   matcher's invariants in a Rust test.
5. **Re-run the *whole* baseline, not just that CWE.** A check built for one
   class routinely adds false positives to another; `data/juliet-baseline.json`
   is the regression record. Update it only when the change is understood.
6. **Check the fix against real code too.** Juliet is synthetic; a check that
   scores well there and floods a real project is not an improvement. The
   corpora already wired up: `~/VsCode/pkt-astronomia` (159 TUs, C and C++),
   `~/VsCode/Satellite/rtklib_mod` (10 TUs, terse C), the ACL raw/fixed pair.

### Order of work, by value rather than by number

| # | CWE | now | verdict | state |
|---|---|---|---|---|
| 1 | 190/191 overflow | 64% recall, **0% surfaced** | tiering decision, no new code | **not started** |
| 2 | 121/122/124/126/127 bounds | 5-10% | dominant shape is syntactic (see below) | **not started** |
| 3 | 590 free-of-non-heap | 0% | unknown -- triage first | **not started** |
| 4 | 416 use-after-free | 49% | unknown -- triage first | **not started** |
| 5 | 775 fd leak | 39% | unknown -- triage first | **not started** |
| 6 | 563 unused/dead store | 64% | partly ours already | **not started** |
| 7 | 401/415/762/457/476 | 69-100% | working; revisit last | **not started** |

**Start with 190/191**: it is the cheapest thing on the list and needs no new
code. 64% of the flawed functions are already found and none reach the report,
because every overflow finding is low-confidence. The question is whether the
confidence is wrong or the tier is, and answering it is a mapping-table change.

**Then the bounds class**, where the dominant shape is already identified: an
index from an unbounded source, guarded only against negative --
`data = RAND32(); if (data >= 0) buffer[data] = 1;`. Kordon has neighbouring
checks (`INDEX_USED_BEFORE_CHECK`, `UNCHECKED_CONSTANT_INDEX`) but nothing that
matches "tested for one side of the range only".

### What "should catch" means here

A case is worth catching when the defect is visible in the code as written.
`buffer[data]` with only a lower-bound test is such a case: no value analysis is
needed to see that one side is unchecked. `buffer[i]` where `i` came through
three function calls in two files is not -- that is the CTU gap, already
recorded, and pretending a matcher can reach it produces a check that fires on
shape alone and floods real code.

Resist raising recall by loosening a guard. Every exemption removed is a real
project's false positive, and this session already has three worked examples of
an exemption that looked correct and silently matched nothing.

## Open questions for next session
- **Missed detection to close: a loop variable used as an index after the loop ran to completion.** Reported from `~/VsCode/Satellite/rtklib_mod` (`ddidx` in `sat/pkt_sputnik_prcpos.c`): `ssat[i-k]` is read with `i-k == MAXSAT`, one past the end. The loop finishes without taking its `break`, so the index holds the bound, and the read happens after the loop. **Not flagged by any of the five engines, with CTU on; UBSan caught it in seconds.**
  - This is worth building because it is *purely syntactic* — no runtime values, no path sensitivity, no cross-TU reasoning. And it is **not** the ordering problem that blocked three earlier checks: this needs "is this reference outside the loop that bound the variable", which `hasAncestor`/`unless(hasAncestor(forStmt(equalsBoundNode(...))))` can express, not statement precedence, which matchers cannot.
  - Kordon already reports the *same defect class* when an engine happens to see it: `ura_value[15]` in `pkt_sputnik_eph.c:36` (cppcheck) and `pulkovo85_gamma[li]`/`[ri]` in pkt-astronomia's `refraction.c:188`, where the loops reach 1219 and −1. Those arrived from cppcheck's value analysis, not from a shape rule, which is why they are hit-and-miss.
  - Confidence split to design for: a loop with **no** `break` always exits at the bound, so the out-of-range read is unconditional — high confidence. A loop **with** a `break` only reaches the bound on one path — medium.
  - Two sibling defects in the same investigation are fair misses, worth recording so they are not chased: `obs.data == NULL` (depends on how many observations survive a runtime constellation filter — no static engine can bound that, and the report said so) and a missing `iobsr = obs.n - 1` before a backward sweep.
  - What actually solved that investigation: reading the code and diffing against stock RTKLIB, then UBSan/ASan for confirmation with an exact stack. Diffing a modified vendor library against upstream is a detection strategy Kordon does not have at all.
- **The `fault` profile cannot inject under valgrind** (measured, see above). Direction: drop the valgrind wrapper from the sweep, detect defects from the target's exit status and stderr, and recover a stack with `gdb -batch -ex run -ex bt` on abnormal termination — that worked by hand. Needs a gdb-backtrace → `RuntimeReport` parser; note `RuntimeReport::anchor` returns `None` for a frameless report, so a finding with no frames cannot be emitted at all.
- **CTU via CodeChecker is the highest-value next step** — it is the measured blocker for the whole fallible-init class (`testdata/uninit_owner/`). CodeChecker is not installed on this machine (`pip install codechecker` in a venv).
- **CWE-762 vs 763 for `unix.MismatchedDeallocator`.** Kordon maps it to 762 (literally "mismatched memory management routines"); prior ACL work mapped it to 763 because their requirements list named 763. Both are in the catalog. Confirm which the requirements actually want.
- Dedup is keyed on `file + line + CWE`, so two engines reporting one defect on *adjacent* lines stay separate (seen: clang-analyzer flags a dead store at the initialization line, cppcheck at the overwrite line). Consider a small line window.
- Licensing review of IKOS's NASA Open Source Agreement before committing to embed it.
- Whether the CWE-191 unsigned-subtraction-without-guard check needs to be written from scratch (LLVM patch D71607 was found via search but not confirmed merged/shipped).
- Concrete design of the per-class ownership-summary pass (data structure, how it's computed, how it plugs into Clang SA's checker API).
- Concrete design of the aggregation schema and CWE-mapping table format.
- Build-matrix tooling design (how Kordon manages N separate sanitizer builds without becoming its own build system).
