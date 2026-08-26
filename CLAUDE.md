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

Kordon is scored against the **NIST Juliet C/C++ suite 1.3**, the only labelled corpus of any size for this defect class. Every case ships a flawed function and a corrected counterpart in one file, so a finding inside a `_bad` function is a hit and one inside a `good*` function is unambiguously wrong. `scripts/setup-juliet.sh` fetches it, `scripts/score-juliet.py` scores it, baseline in `data/juliet-baseline.json`.

**Baseline, 40 files per CWE, default flags: 52.1% recall at 4.6% false positives — 47.6% / 1.6% counting only the high- and medium-confidence tiers the report details without `--all`.** (`--ikos` and `--ctu` add substantially more; see the per-CWE notes.)

Read the **discrimination** column (recall − FP), not recall. A check that fires on every arithmetic line scores high recall and detects nothing.

| CWE | recall | FP | discrim | note |
|---|---|---|---|---|
| 415 double free | 93.0% | 3.5% | **+89.5** | |
| 762 mismatched free | 84.8% | 0.0% | **+84.8** | |
| 476 null deref | 84.1% | 4.5% | **+79.6** | |
| 563 dead store | 77.3% | 2.3% | **+75.0** | |
| 401 leak | 86.7% | 17.9% | **+68.8** | |
| 124 underwrite | 75.6% | 1.7% | **+73.8** | |
| 416 use-after-free | 51.2% | 0.0% | +51.2 | `--ctu` takes the split cases 0% → 30% |
| 121 stack overflow | 45.5% | 0.0% | +45.5 | was 2.8% |
| 590 free non-heap | 42.2% | 0.0% | +42.2 | |
| 122 heap overflow | 31.2% | 0.0% | +31.2 | |
| 127 underread | 40.0% | 0.0% | +40.0 | surfaced doubled |
| 457 uninit | 57.5% | 4.7% | **+52.8** | now means *reads* of uninitialised values |
| 191 underflow | 32.0% | 13.6% | +18.4 | |
| 775 fd leak | 16.3% | 0.9% | +15.4 | dynamic gets 96%; valgrind `--track-fds` |
| 126 overread | 11.4% | 0.0% | +11.4 | `--ikos` takes it to 86% |
| 190 overflow | 18.4% | 13.5% | +4.9 | IKOS's job |
| 562 stack addr return | 50.0% | 0.0% | +50.0 | was 0%; see below |

### CWE-190/191 — settled: this is IKOS's job, not a matcher's

- **No Clang SA checker covers integer overflow.** Tested directly: `alpha.core.Conversion`, `alpha.security.ArrayBound`, `core.UndefinedBinaryOperatorResult` and all of `alpha.core.*` report nothing on `data = INT_MAX; int result = data + 1;`. This confirms the MISRA note above rather than contradicting it.
- **IKOS proves it, and Kordon's integration works.** On that case it reports `signed integer overflow` as a *definite* result, and Kordon merges it with cppcheck's `integerOverflow` into one CWE-190 finding at high confidence. Enabling `--ikos` lifts CWE-190 from 12.5% to 31.2% recall and CWE-191 from 41.2% to 52.9% on a matched sample.
- **The `char` and `short` `_max_` cases are not CWE-190 at all.** `data + 1` promotes to `int`, so nothing overflows; what happens is a narrowing conversion back to `char`. IKOS correctly calls them SAFE. Juliet files them under 190 anyway.
- **The `rand`/`fscanf`/`socket`/`fgets` families — about 71% of the suite — are unprovable statically.** They need a bound on external input. The honest output is IKOS's "cannot prove safe", which is what `--show-unproven` and the directed-fuzz handoff exist for. Do not build a matcher to chase them.
- **Consequence for the baseline: it must always record whether `--ikos` was on.** The default report understates CWE-190 badly.

### Two harness bugs that read as results, both now fixed

Both produced plausible numbers rather than errors, and both invalidated a published baseline:

- **Crediting a check that does not discriminate.** The scorer's equivalence table counted CWE-197 as detecting CWE-190. `bugprone-narrowing-conversions` fires on `data + 1` narrowing back to `char` — a different observation on the same line — and fires *identically* on the guarded `goodB2G`. CWE-190 read 64% recall where real detection was zero. Hence the discrimination column.
- **Sampling a prefix instead of a spread.** Juliet names cases `<type>_<source>_<operation>`, so `--limit N` over a sorted list took one type and one source. The first 20 CWE-190 files are all `char_*`, the corner where no overflow exists. Fixing it to an even stride moved CWE-124 from 5% to 53%, CWE-127 from 5% to 47%, and CWE-590 from 0% to 38%.

**Juliet is synthetic and its scores do not transfer.** The flow-variant scaffolding looks like nothing anyone writes, and the defects this project found by comparing a function against a correct sibling have no analogue in the suite. Use it for per-CWE coverage of mechanical cases; keep the ACL raw/fixed pair for realism.

Earlier harness note, still true: the C++ variants name the flawed function bare `bad()` inside a namespace rather than `<case>_bad`, and the corrected code lives in `goodG2B`/`goodB2G` with no underscore either.

## The dynamic layer, measured the same way (2026-08-25) — don't re-derive

`scripts/score-juliet-dynamic.py` scores the sanitizers against the same suite. Every Juliet case has a `main()` calling the flawed and corrected functions behind their own guards, so building twice separates them: `-DOMITGOOD` leaves only `bad()` (recall), `-DOMITBAD` leaves only `good()` (false positives). Baseline in `data/juliet-dynamic-baseline.json`.

**Dynamic baseline, 25 cases per CWE: 57.8% of *runnable* cases caught, and 0 false positives out of 277 correct functions.**

Zero is not luck: a sanitizer reports a defect that happened, so the only way to flag correct code is to report the wrong class of defect. Which is exactly what it did before class matching was added — see below.

| CWE | static recall / FP | dynamic caught / FP | |
|---|---|---|---|
| 562 stack addr return | 0% / 0% | **100% / 0%** | static misses the class entirely |
| 762 mismatched free | 64% / 2.1% | **100% / 0%** | |
| 457 uninit | 100% / 68.9% | **100% / 0%** | MSan strictly dominates |
| 416 use-after-free | 57% / 0% | **88% / 0%** | |
| 590 free non-heap | 38% / 0% | **67% / 0%** | |
| 126 overread | 19% / 14.0% | **62% / 0%** | |
| 121 stack overflow | 2.8% / 1.1% | **60% / 0%** | the static layer's worst gap |
| 122 heap overflow | 36% / 23.7% | **57% / 0%** | |
| 124 / 127 | 53% / 47% | 56% / 50% | comparable |
| 415 double free | **90%** / 6.1% | 68% / 0% | static wins |
| 401 leak | **78%** / 19.7% | 57% / 0% | static wins |
| 191 underflow | **43%** / 18.6% | 18% / 0% | |
| 190 overflow | 12% / 8.8% | 9% / 0% | neither; IKOS's job |
| 775 fd leak | 13% / 0% | — | 12 of 25 would not build |

**The two layers are complementary, and the numbers say so per class.** Static wins where the defect is on a path the run does not take (leaks, double free). Dynamic wins where the defect depends on a value (bounds, use-after-free, uninitialised reads). CWE-562 and CWE-121 are the clearest cases for running both.

`unreached` is the honest ceiling: 80 of 355 cases never executed their flawed path, because the flaw sits behind `fscanf`, a socket peer, or a `rand()` that came back negative. That is not a miss — "the sanitizer did not fire" and "the code never ran" mean opposite things and the scorer keeps them apart.

### This host hangs ASan's symbolizer — and it cost a whole measurement

A one-line `int a[4]; return a[5];` under ASan never returns. `symbolize=0` returns in 5 ms; `llvm-symbolizer` works standalone. The sandbox breaks the symbolizer subprocess, so it is not Kordon's bug and not Kordon's to fix — but it has two consequences worth knowing:

- **Kordon lost findings to it.** The deadline path discarded the child's output before reading it, so a stack-buffer-overflow ASan had already named came back as "timed out -- nothing it would have found is in this report". Fixed: output is read first, complete reports are kept with a note that the run was killed. A frameless report still cannot become a finding — there is no location to anchor it — but the class it named now reaches the report, because silence there is indistinguishable from a clean run.
- **The scorer sets `symbolize=0` deliberately**, and Kordon does not. Scoring asks only "did the sanitizer detect this", which needs the banner; Kordon needs frames to place a finding at a line. With the default options CWE-401 scored **0%**, because LeakSanitizer produced *zero bytes* before hanging; with symbolization off it scores 57%.

### Two more scorer traps, same family as the static ones

- **Crediting the wrong defect class.** CWE-416 read 96% false positives until reports were matched against the CWE under test. Its `goodG2B` deliberately never frees — that is what makes it a good *use-after-free* case — so it leaks, and LeakSanitizer correctly reported a real leak in a function labelled good for a different defect.
- **Treating a deadline as a clean run.** Before the partial-output fix, CWE-121 read 50% of 4 runnable cases; it is 60% of 20.

## CWE-775 and CWE-121, worked (2026-08-25) — don't re-derive

### CWE-775 — 0% to 96%, and none of it was a detection problem

Two causes, neither a gap in Kordon's reasoning:

- **The wrong instrument.** File descriptors are not allocations, so LeakSanitizer does not track them and no engine Kordon ran could see an unclosed `fopen`/`open`. valgrind can, given `--track-fds`, which the profile did not pass. It now does.
- **The scorer counted unportable cases as failures.** 8 of 25 CWE-775 cases are `w32CreateFile` (Windows API) and 5 more are the 81-84 class variants split as `_82_bad.cpp`, which have no `main()`. Both are excluded now.

The fd report does not look like valgrind's others: a bare `<stack>` after `<status>FINISHED</status>`, with no `<error>` wrapper, no `<kind>` and no `<what>`. The parser keyed on the error envelope every other report has, so it saw nothing. Mapped to CWE-775 at high confidence — the descriptor was observed open at exit, which is a fact about the run.

### CWE-121 — the alpha checkers are the whole story, and only `--ctu` can reach them

The shape breakdown corrects an earlier note in this file. CWE-129 (an index from an unbounded source, guarded only against negative) is **6%** of the suite, not the dominant shape — that reading came from one subdirectory. The bulk is library calls: **CWE805 36%** (`memcpy` with a length that overruns the destination), **CWE806 23%** (`strncpy(dest, data, strlen(data))` — a bound taken from the source), **CWE193 17%** (off-by-one, a buffer one byte short of its terminator).

Measured on those shapes:

- **IKOS reports the program SAFE** for CWE805/806/193. It does not model `strcpy`/`strncpy`/`memcpy` bounds. It *does* catch CWE129, as a warning ("accessing index between 0 and 2147483647 of local variable 'buffer' of 10 elements") — the unprovable-input case, which is what it is for.
- **Three `alpha` checkers cover the library-call shapes**: `alpha.unix.cstring.OutOfBounds` ("Memory copy function overflows the destination buffer"), `alpha.security.ArrayBoundV2`, `alpha.unix.cstring.NotNullTerminated`.
- **clang-tidy cannot enable an alpha checker at all.** `--checks=clang-analyzer-alpha.*` in every spelling yields "No checks enabled", and no config option reaches them. Only a direct `clang --analyze -analyzer-checker` does — which is what the `--ctu` pass already is, so they live there.

With `--ctu`, on 25 cases per CWE:

| CWE | was | now | discrim |
|---|---|---|---|
| 121 | 2.8% | **31.6%** | +19.8 |
| 124 | 53% | **73.7%** | +46.6 |
| 126 | 18.8% | **42.1%** | +22.4 |
| 127 | 46.9% | 42.1% | +21.8 |
| 122 | 35.7% | 46.4% | +22.8 |

Raw false positives rise to 21.9% and **surfaced false positives are 1.1%** — the tiering absorbs the alpha noise, which is what it is for.

Two things to hold onto:

- **CWE-122 does *not* discriminate negatively** — that reading was small-sample noise and is retracted. At 25 cases it measured −10.2; at 40 it is **+22.8 raw and +25.0 surfaced**, and `--ctu` and a default run give byte-identical numbers for it. **Per-CWE figures below roughly 30 cases can flip a discrimination sign**, so compare only at matched `--limit`, and do not read a single small run as a finding.
- **`ArrayBoundV2` is mapped medium, not high**, and the distinction is the checker's own. `cstring.OutOfBounds` says "this copy overflows the destination" and has both sizes. `ArrayBoundV2` says "I cannot show this index is in range" — on rtklib_mod it flags `obs[i].L[f]` for `f < rtk->opt.nf`, where the bound holds by an invariant it cannot see. On 10 real translation units it produced 3 findings, not a flood.
- **It runs without `--ctu` now.** The analyzer pass takes `Option<&CtuIndex>`; with `None` it drops the cross-TU config and runs *only* the three alpha checkers, reporting as `clang-sa-bounds`. Everything else in `CTU_CHECKERS` is already covered by clang-tidy under `clang-analyzer-*`, so running the full set without an index would pay for a second path-sensitive analysis to learn what Kordon already knows. A default run went from 2.8% to 31.6% on the 25-case sample, and the whole-baseline total from 49.1% to 51.5% recall with false positives flat.

## `--ctu` is worth its cost — measured (2026-08-25)

An earlier note here observed that `--ctu` added nothing over a default run for CWE-122 and left its value an open question. That reading was an artifact of the sample: **`scripts/score-juliet.py` excluded every multi-file case**, which is precisely what CTU exists for. A single-translation-unit corpus cannot give cross-TU analysis any credit.

`--multifile` scores only the split cases — `_54a.c`..`_54e.c` and the `_81`..`_84` class variants — where the entry function is in one unit and the sink holding the defect is several units away. All parts of a case go into the database together, or the analyzer never sees the unit with the sink.

**On those cases: recall 17.4% → 28.8%, false positives 11.7% → 11.9%.** That is 39 more flawed functions found out of 344, at a cost of one additional flagged correct function out of 750.

Three classes go from **literally nothing to detectable**, because the allocation and its misuse sit in different files:

| CWE | no `--ctu` | `--ctu` |
|---|---|---|
| 476 null deref | **0%** | 33.3% |
| 762 mismatched free | **0%** | 36.4% |
| 416 use-after-free | **0%** | 30.0% |
| 457 uninit | 55.0% | 75.0% |
| 124 underwrite | 26.1% | 43.5% |
| 121 stack overflow | 9.5% | 23.8% |
| 415 double free | 40.0% | 50.0% |
| 401 leak | 23.1% | 34.6% |

Kordon's own fixture agrees and is the cheapest check of all: `testdata/uninit_owner/` fails `--require-cwe 665` without the flag and passes with it. That is the fallible-init class this file has called the measured CTU blocker since the start — **plain clang CTU already closes it, with no CodeChecker involved.**

Two things follow:

- **Recommend `--ctu` for any real run.** It is not a marginal flag; for three defect classes it is the difference between coverage and none.
- **Never compare CTU on a single-file corpus.** It will read as free cost, which is how the earlier note went wrong.

## CWE-126 — the triage step earning its keep (2026-08-25)

The plan's second step is to name each shape and decide what it needs *before* writing anything. On CWE-126 that decision came within one command of going the wrong way.

The dominant family looks perfectly syntactic:

    memcpy(dest, data, strlen(dest) * sizeof(char));   // length from the DESTINATION

408 files share it, and reading `data` for `strlen(dest)` bytes is exactly the over-read. It is the mirror of the CWE-806 shape (`strncpy(dest, data, strlen(data))`), which is a real defect, so a matcher looked obvious.

**The corrected function contains the identical line.** `goodG2B` differs only in `data = dataGoodBuffer` (100 bytes) instead of `data = dataBadBuffer` (50). The copy call is character-for-character the same. Any matcher on that shape fires on both and discriminates exactly zero — the verdict is **value-range, not syntactic**, and only comparing against the corrected variant reveals it.

**IKOS handles it, precisely.** On the flawed variant: *"possible buffer overflow, pointer 'data' accesses up to 99 bytes at offset 0 bytes of local variable 'dataBadBuffer' of size 50 bytes"*. On the corrected one: SAFE.

| CWE-126 | recall | FP | discrim |
|---|---|---|---|
| default | 17.2% | 8.1% | +9.1 |
| `--ikos` | **86.2%** | 44.6% | **+41.6** |

Five times the recall, and the best discrimination measured for this CWE — but at a 44.6% false-positive rate, which is why those findings belong where Kordon already puts them: the **unproven** tier, counted and summarized, listed on `--show-unproven`. Reporting them at medium would put a coin-flip beside a proof. The gap is not the classification, it is that nothing told the user what `--ikos` is worth; the skip message now says so.

**`alpha.unix.cstring.NotNullTerminated` was removed.** It never fired — not on Juliet's CWE-170 family, which is 108 files of nothing but un-terminated `strncpy` results, and not on a hand-written canonical case. It was added on the strength of its name, which is exactly the mistake this file exists to stop.

**Scorer fix, and it moved the numbers:** the truth extractor only recognised functions ending in `_bad`, so it missed `..._54e_badSink` and the whole multi-file naming. Classifying on the substring instead raised the flawed-function count per CWE (CWE-121: 36 to 43). Baselines taken before this are not comparable to ones taken after.

## CWE-457: the guideline and the defect are different questions (2026-08-25)

`cppcoreguidelines-init-variables` reported **127 of 170 correct functions** on CWE-457 — the worst false-positive rate of any check here, and the entirety of that CWE's noise. Two wrong conclusions were available and both were avoided by measuring.

**It is not a check to delete.** Removing it takes recall from 100% to 57.5% and discrimination from +25.3 to +52.8, which reads as an improvement until the surfaced columns are compared: **57.5% recall at 4.7% false positives, identical either way**, because it is low-confidence and never reaches the detailed report. It costs a reader nothing, and it is the only thing that finds 17 of those 40 flawed functions. Contrast `cppcoreguidelines-pro-bounds-array-to-pointer-decay`, removed earlier for having *zero* exclusive coverage. **A high false-positive rate is not by itself grounds for removal; the questions are what a check finds that nothing else does, and whether its noise reaches the reader.**

**It was, however, filed under the wrong CWE.** The check implements the *guideline* — "always initialise an object", so every declaration without an initialiser is a violation. CWE-457 is the *defect*: a value read before it was ever assigned. `int data; data = 5; use(data);` violates the first and is not an instance of the second, and Juliet's corrected functions are full of exactly that. Filed under 457 the count meant two things at once.

It now maps to **CWE-398, tier 0** — a code-quality indicator, not a defect class Kordon claims — so it is counted out of scope rather than inflating a defect count. The path-sensitive `clang-analyzer-core.uninitialized.*` checkers still carry CWE-457, and that number now means reads of uninitialised values and nothing else:

| | recall | FP | discrim |
|---|---|---|---|
| CWE-457 before | 100% | 74.7% | +25.3 |
| CWE-457 after | 57.5% | 4.7% | **+52.8** |

Whole-baseline effect: raw false positives **12.7% → 7.5%**, raw recall 57.0% → 54.6%, **surfaced numbers unchanged** at 45.1% / 1.6%. No detection was lost — the check still runs and still reports; it is no longer *credited* with finding a defect class it was not finding.

## Every check, scored on one question (2026-08-25)

`scripts/score-juliet.py --by-check` drops the per-CWE question and asks each native check only this: **how much more often does it land in a flawed function than in a corrected one?** A check that fires equally on both implements a guideline rather than detecting a defect, whatever its name says. Output kept in `data/juliet-by-check.txt`.

Run over 465 flawed and 1448 correct functions, restricted to checks that reach an **in-scope** CWE and land in 10 or more functions:

**Every in-scope check discriminates positively.** Nothing Kordon reports as a defect fires more on correct code than on flawed code. That is the configuration health check this table exists for, and it is the first time it has been run.

The strongest are the ones with a zero good-side: `unix.MismatchedDeallocator` (23/0), `alpha.security.ArrayBoundV2` (17/0), `autovarInvalidDeallocation` (13/0), `doubleFree` (12/0), `invalidLifetime` (11/0), `pointerOutOfBounds` (10/0). The weakest at high confidence is `core.NonNullParamChecker` (5 flawed, 15 correct, +0.0%).

**Two limits, and the second is the sharper one:**

- **Small counts say nothing.** A check landing in two functions can show any discrimination at all; that is how the CWE-122 claim went wrong. The table drops anything under 10.
- **The good side is weaker evidence than a per-CWE score.** A function labelled `good` is only correct *with respect to its own CWE* — Juliet's CWE-416 `goodG2B` deliberately leaks, and LeakSanitizer is right to say so. On top of that, this mode compiles both halves into one translation unit and attributes findings by line range. `NonNullParamChecker`'s 15 good-side hits do not reproduce at all when the corrected half is compiled alone, so they are not yet evidence of anything. **Treat this table as a ranking, and confirm anything actionable per-CWE.**

## CWE-562 — 0% to 50%, and neither cause was detection (2026-08-25)

The only complete hole left in the static baseline. Both causes were bookkeeping.

**A default compiler warning was not in the check set.** clang reports `-Wreturn-stack-address` on `return charString;` with no flags at all, and it is not reachable through any `clang-analyzer-*` checker, so naming it was the whole fix. Same shape as `-Wunused-variable` earlier: **a `clang-diagnostic-*` check does nothing unless it is named, and Kordon names only two.** Worth a sweep for others.

**The scorer could not see the functions holding the defect.** CWE-562 keeps its flaw in `static const int *helperBad()`, and `FUNC_RE` listed return types starting with `void|int|char|...` — `const` is not among them, so those functions were never in the ground truth. Findings landed in no known range and were discarded. Two engines had been reporting the flaw the whole time: Clang SA's `core.StackAddressEscape`, already enabled and already mapped to CWE-562, and cppcheck's `returnDanglingLifetime`.

Matching any definition and gating on the name instead lifted CWE-562 from 0% to **50% at 0% false positives**. That is also the ceiling here: of the 6 functions Juliet labels flawed, only 3 contain a defect — the others are wrappers that call `helperBad()`, and a detector reports at the flaw, not the call.

**Fourth scorer bug in this file, and they share a shape:** every one was a pattern that looked exhaustive and silently matched less than it claimed — `_bad` missing `_badSink`, lowercase `bad` missing `helperBad`, a sorted prefix standing in for a sample, a return-type list missing `const`. Each read as a Kordon gap. **When a CWE reads 0%, check the instrument before the tool.**

## CWE-127 and CWE-122 (2026-08-25)

Two fixes, and neither was a missing detection.

### CWE-127 — an out-of-bounds *read* was being filed as a *write*

`alpha.unix.cstring.OutOfBounds` covers both directions and says which in its message:

- `"Memory copy function overflows the destination buffer"` — a write
- `"Memory copy function accesses out-of-bound array element"` — a read, observed on `memcpy` *source* overruns

It was mapped wholesale to **CWE-787**, so every buffer under-read was filed as an out-of-bounds write. A question about reads could not be answered by a 787. Splitting on the message — 787 for the write text, **125** for the read — took CWE-127's *surfaced* recall from 20.0% to **40.0%**, and left CWE-121 untouched, since writes still map where they did.

The dominant CWE-127 shape (`data = dataBuffer - 8;`) was already caught, by cppcheck's `pointerOutOfBounds` and the alpha checker. Nothing needed building.

### CWE-122 — its false positives were a guideline check in a defect CWE

CWE-122 had the worst false-positive rate of any CWE, 22.4%, and it was almost entirely `cppcoreguidelines-pro-bounds-pointer-arithmetic`: 25 of 116 correct functions. That check flags **all** pointer arithmetic — `p[i]`, `p + 1` — because the guideline is to use a span. It never claims an access is out of range.

Filed under CWE-119 it made the bounds count mean "out of range **or** merely written with a pointer". Both `pro-bounds-*` checks now map to **CWE-398, tier 0**, exactly as `init-variables` did, and stay enabled.

**Every surfaced number is unchanged** — 121 at 40.9%, 122 at 29.2%, 126 at 2.3%, 127 at 40.0% — because these checks are low-confidence and never reach the report. What moved is the raw count, which now means what it says. Whole baseline: raw false positives **7.6% → 4.6%**, and surfaced recall **45.1% → 46.4%** from the CWE-127 split.

**It also deflated a number I had believed.** CWE-126's 25.6% was mostly `pro-bounds` noise correlating with flawed code; its real detection was 2.3% all along. That matches the earlier finding that its shape needs value analysis — `--ikos` still takes it to 86%.

**The pattern, now three times:** `init-variables`, `pro-bounds-pointer-arithmetic`, `pro-bounds-constant-array-index`. A guideline check mapped to a defect CWE inflates that CWE's raw recall *and* its false positives, and the surfaced report never sees either. **When a CWE's false-positive rate is the outlier, look for a guideline check in its accept set before suspecting the detectors.**

## Why recall is not 100% — the misses, bucketed (2026-08-25)

`scripts/explain-misses.py <dir> <cwe> <n>` groups every flawed function by the shape Juliet declares in its header (`BadSource:` / `BadSink :`) and prints the detection rate per shape. That pairing, not the CWE, is what decides whether any engine can see a defect. **Six causes account for essentially every miss, and only one of them is a gap in Kordon rather than a property of the problem.**

**1. The length is a runtime string length.** The largest bucket. `memcpy(dest, data, wcslen(data)*sizeof(wchar_t))` with `dest[50]` and `data` holding 99 characters — the bound is not a constant, so nothing syntactic can compare it to the destination. Default engines: 0%. IKOS: reports it (`potentially UNSAFE`). ASan: catches it. This is the value-range class, and the answer already exists in `--ikos` and the dynamic layer.

**2. Hand-written copy loops.** `alpha.unix.cstring.OutOfBounds` models known string functions only. "Copy data to string using a loop" is 0/4, 0/3, 0/2 wherever it appears, while the same defect through `memcpy` is 100%.

**3. Concatenation.** `strcat`, `wcscat`, `strncat` need the destination's *current* length, not its capacity. Consistently 0%.

**4. The value comes from outside the program.** `rand`, `fgets`, `fscanf`, `connect_socket`. Not a limitation to fix — the value genuinely is not knowable statically. The honest outputs are IKOS's "cannot prove safe" and the dynamic layer, which catches 57-100% of these at 0% false positives.

**5. The defect is in another translation unit.** Measured separately: `--ctu` takes the split cases from 17.4% to 28.8%.

**6. The function labelled flawed contains no defect.** Juliet marks `..._bad()` as flawed even when it only calls `helperBad()`, and a detector reports at the flaw rather than the call. For CWE-562 this alone caps recall at 50% — 3 of its 6 flawed functions are wrappers.

**So 100% is not the target, and a per-layer number read alone is misleading.** The clearest case is CWE-122: the static layer scores 29.2%, and the shapes it misses — runtime lengths, loops, concatenation — are exactly the ones ASan catches, at **85.7% of runnable cases with zero false positives**. The layers are complementary by construction, which is the argument for running both and the reason both baselines are kept.

## Two checks for an index nobody bounded (2026-08-26)

The `rand`/`fscanf` families are ~71% of Juliet's integer and index CWEs, and the dynamic layer cannot be relied on for them: the flawed branch is taken only on the runs where the value happens to land in range, so a sanitizer reports nothing on the others. **The code is wrong either way, which is what static analysis is for.** Neither shape was reported by any engine Kordon runs.

| | shape | id | CWE |
|---|---|---|---|
| overflow | `if (data >= 0) buffer[data]` — sign tested, range never | `kordon-one-sided-index-guard` | 129 |
| underwrite | `if (data < 10) buffer[data]` — range tested, sign never | `kordon-unchecked-negative-index` | 124 |

Effect on the bounds family, 40 files per CWE: **121 40.9→45.5%, 122 29.2→31.2%, 124 71.1→75.6%, 126 2.3→11.4%**, 127 unchanged. Nine more flawed functions, **false positives unchanged at 2 of 583**, and **zero across 169 real translation units** (pkt-astronomia's 159 and rtklib_mod's 10).

**The discriminator is the operand, not the operator.** `i >= 0` and `i < 0` are both sign checks — one guards a block, the other exits early — and `i < 10` and `i >= 10` are both bounds. Keying on the operator catches the guard idiom and misses the early-exit one, which is how real code usually writes it.

**Three clauses, and the second is what makes them usable:**
- the index is filled from a call — an external value;
- **without that clause the checks fire on every loop counter ever compared to zero: 160 positions across the two real projects, 56 of them in vendored SOFA**;
- nothing tests the other side.

### The two directions are not mirror images, and both differences were measured

- **Signedness.** A `size_t` cannot be negative, so the underwrite check requires a signed index. Without it, every bounded loop over an unsigned counter matches.
- **"Bounded by its own call" exempts the upper bound only.** `n = read(fd, buf, sizeof buf - 1); buf[n] = 0;` is safe from overflow — the bound is the argument handed to `read`, which no comparison-based check can see — and it is a *genuine underwrite*, because `read` returns **-1** on error. The same idiom is an exemption in one direction and the defect in the other. A test asserts the clause is present in one matcher and absent from the other.

### `hasDescendant` does not match the node itself — the third time

`hasRHS(hasDescendant(callExpr()))` missed `data = atoi(buf)`, where the call **is** the right-hand side, and matched `data = RAND32()` only because that macro expands to a call nested in an expression. So the check worked on one Juliet source family and silently missed the rest; CWE-126 read 2.3% instead of 11.4%. The same trap has now cost a measurement three times — `hasCondition(hasDescendant(...))` in the loop-index check, and twice here. **Write `anyOf(ignoringParenImpCasts(X), hasDescendant(X))` by default.**

`fscanf(stdin, "%d", &data)` needed a third spelling again: the value arrives through an out-parameter and is never assigned.

### Scorer bug #5: a relative Juliet root measures one engine

The compile database carries `-I <support>` while its `directory` field is the source file's own folder, so a relative root makes the include resolve against *that* directory and every unit dies with `'std_testcase.h' file not found`. **The scorer still prints numbers, because cppcheck needs no includes** — so the run looks fine and quietly measures one engine instead of four. Measured: CWE-121 reads 40.9% that way and 45.5% correctly. Both scorers now `abspath` the root.

This one also produced a *false conclusion* before it was found: the numbers reverted to baseline after an exemption was added, and the exemption got the blame. It was the path.

## Nine CWEs that had no baseline at all (2026-08-26)

`scripts/score-juliet.py` matched Juliet directories by full name, and `CWE369_Divide_By_Zero` does not match the suite's `CWE369_Divide_by_Zero`. The scorer printed "not present in this suite" and moved on, so that CWE never appeared in any baseline. It now matches on the **number**, which is the only stable part of the name, and all 26 in-scope directories resolve.

First measurement of the nine, 40 files each:

| CWE | recall | FP | discrim | |
|---|---|---|---|---|
| 483 block delimitation | **95.0%** | 0.0% | **+95.0** | was 0%; see below |
| 680 overflow → buffer overflow | 66.7% | 18.3% | +48.3 | |
| 665 improper initialisation | 36.0% | 4.5% | +31.5 | the `--ctu` class |
| 369 divide by zero | 56.0% | 1.1% | +54.9 | was 8.5%; float cases excluded, see below |
| 252 unchecked return | 70.0% | 0.0% | +70.0 | was 0%; 20.0% surfaced |
| 672 use after release | **0%** | 0.0% | 0 | |
| 690 null deref from return | **0%** | 0.0% | 0 | |
| 843 type confusion | **0%** | 0.0% | 0 | |

### CWE-483 — 0% to 95%, and a third `clang-diagnostic-*` win

`-Wmisleading-indentation` reports exactly this and nothing else does: `if (x) a; b;` where the indentation says `b` belongs to the `if` and the language says it does not — the goto-fail shape. **Not on by default**, so Kordon turns it on itself, the same as `-Wunused-variable` and `-Wreturn-stack-address`. That is three for three: **every `clang-diagnostic-*` check named so far has closed a real gap, and Kordon names only three of them.** The rest of that namespace is unexplored.

95.0% recall at **0% false positives**, the best discrimination of any CWE here, and **zero findings across 169 real translation units**.

### It read 100% before the check existed

The first measurement of CWE-483 reported 100% recall — with the check not yet enabled. The accept set was `{483, 398, 561}`, and 398 is the tier-0 style bucket, so any unrelated style finding landing in a flawed function was credited. Narrowed to `{483}` the honest number appeared.

**Third time an over-wide accept set has flattered a result** — CWE-197 crediting CWE-190, the by-check good side, and now this. **An equivalence entry is a claim that the other CWE means the same defect; write the narrow set and widen only with a reason.**

## CWE-369 — 8.5% to 40.4%, and float division is not the defect (2026-08-26)

`core.DivideZero` is a default Clang SA checker, already enabled, already mapped, and it works: it reports Juliet's `_zero_` family exactly. That family is where the whole 8.5% came from. What it cannot do is bound a divisor that arrived from `rand`, `fscanf` or a socket — five of the suite's six source families — and the corrected sink is simply `if (data != 0)`.

`kordon-unchecked-divisor` reports an **integer** divisor that came from a call and is never compared to zero. Same three-clause shape as the index checks. **8.5% → 40.4%**, discrimination **+8.5 → +39.8**, at 0.6% false positives, and **zero across 169 real translation units**.

**The integer restriction is the whole story on precision, and it is not a technicality.** Dividing a double by zero is not undefined behaviour — it yields an infinity. Without the restriction the check reported **62 positions across pkt-astronomia and rtklib_mod**, and every one inspected was floating point: `r = sqrt(r2); ppr[i] = p[i]/r;` in vendored SOFA. With it, zero.

**Six of the eighteen source families are `float_`, and those are not defects.** IEEE 754 makes division of a double by zero *defined*: it raises the divide-by-zero flag and yields an infinity. It may still be a logic error, but it is not the undefined behaviour CWE-369 names, and nothing will trap it. Juliet files them under 369 anyway — the same mislabelling as the `char` cases under CWE-190, where `data + 1` promotes to `int` and nothing overflows.

The scorer now has an `EXCLUDED` table for exactly this, and **the count and the reason are printed on every run** so a reader can put them back. Over the 168 excluded float cases the number is 40.4%; over the integer cases where the defect is real it is **56.0% at +54.9 discrimination**.

**The bar for that table is that the defect is absent, checkable from the standard — never that Kordon happens to miss it.** The CWE-190 `char` cases are left in for the same reason in reverse: the boundary there is less clear-cut, so removing them would be closer to score-gaming than to accuracy.

Any comparison against zero is accepted as the guard, including `d == 0` used to skip. Deliberately generous: accepting a weak guard costs a missed defect, rejecting a real one costs a false positive on code that did check.

## CWE-252 — 0% to 70%, and a curated list beats the standard one 12:1

`cert-err33-c` reports this and discriminates perfectly on Juliet, and it was simply not enabled. Turning it on takes CWE-252 from **0% to 70.0% recall at zero false positives, +70.0 discrimination**.

But it treats the whole standard library alike, and on real code that shows: 12 positions on pkt-astronomia, of which **9 are `fclose` and 2 are `fprintf`**. Ignoring those is near-universal and almost never matters. So `cert-err33-c` is mapped **low** — counted, not detailed.

`bugprone-unused-return-value` takes a function list, which is Kordon's to write, and one is now in `CHECKED_FUNCTIONS` at **medium**. The rule for adding a name: **ignoring the result must leave the program using a value it did not compute.** Parsers and readers qualify; things whose failure only means "output did not appear" do not.

Measured, that list reports **one** position on pkt-astronomia where `cert-err33-c` reports twelve — and the one is a real defect: `sscanf(columns[idx_v_rad], "%lf", &entry.v_rad);` with the result discarded, so a failed parse silently leaves the field at whatever it held.

**`snprintf` failed that rule and was removed rather than tolerated.** With it on the list, 19 of 20 surfaced positions on pkt-astronomia were `snprintf` inside one error-reporting macro. Removing it cost 2.5 points of surfaced recall on Juliet and removed 19 real-code false positives — 20 surfaced down to 1.

This is the first time the two tiers have been used to split one defect class by *which function* is involved rather than by which check found it, and it is the shape to reuse: the broad check counts, the curated one reports.

## Severity and confidence are different questions (2026-08-26)

The report grouped findings by confidence alone, and severity came from the *tool's* diagnostic level — cppcheck's `severity="style"`, clang-tidy's `Warning`. That is the engine describing its own diagnostic, not the defect.

Two axes, and a reader needs both:

- **confidence** — how sure Kordon is that this is real. From the check.
- **severity** — how bad it is if it is real. From the **defect class**.

The motivating case is CWE-369. `data = rand(); 100 / data` and `100.0 / data` are the same shape with the same certainty, and different consequences: the integer form is undefined behaviour, and the float form is *defined* — IEEE 754 yields an infinity. Reporting the second as an error overstates it; not reporting it at all is worse, because an infinity propagates silently into every later result and surfaces as a nonsensical number rather than a crash.

So the report now bands the findings:

```
  ── Errors ──   undefined behaviour, or memory the program has no right to touch
  ── Warnings ── defined behaviour that is very likely not what was meant
  ── Advice ──   defined, harmless at run time, and usually a sign of something else
```

`kordon-unchecked-divisor` (integer) is an error; `kordon-unchecked-float-divisor` is advice at the same confidence. **Two check ids rather than one, because a check id carries one severity** and the claim genuinely differs.

Severity resolves from the rule, then the CWE, then the tier: tier 1 is an error by default, everything else advice. `[[cwe]]` and `[[rule]]` both take an optional `severity`.

**This immediately corrected a misfiling nobody had noticed.** cppcheck reports `operatorEqToSelf` as `severity="style"` with `cwe="398"`. The table already corrected the CWE to 416 — a use after free — but the severity still came from cppcheck, so a memory-corruption defect was filed as style. A test now pins that both follow the class.

On pkt-astronomia the split is 214 errors and 16 advice, the advice being float divisions that were previously either invisible or, before the integer restriction, indistinguishable from real defects.

**Recall still excludes the float cases**, because they are not instances of the defect CWE-369 names and crediting them would be crediting Kordon for flagging non-defects. They are reported, in the band that says what they are.

## Start of session: read docs/NEXT-SESSION.md

Three generated or maintained documents carry the state, and re-deriving any
of it is wasted work:

- **`docs/NEXT-SESSION.md`** — the loop, the setup, and every trap that has
  cost a measurement. Read first.
- **`docs/progress.md`** — generated by `scripts/progress.py` from the stored
  baselines. Every CWE with found/total and what would move it. **Never
  hand-edited**: a stale coverage number is worse than none, because the whole
  method is change one thing and see whether the count moved.
- **`docs/cwe-difficulty.md`** — why each CWE is easy or hard, in seven tiers
  from "the compiler already knows" to "needs semantics no analyzer has".
- **`docs/juliet-inventory.md`** — what the corpus holds and what is
  deliberately out of scope.

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
| 1 | 190/191 overflow | 12%/43% | **IKOS's job, not a matcher's** | **done — see verdict above** |
| 2 | 121 stack overflow | 2.8% -> 31.6% with --ctu | alpha checkers, reachable only via --ctu | **done** |
| 3 | 126 overread | 17% -> 86% with --ikos | value-range, not syntactic | **done** |
| 4 | 775 fd leak | 0% -> 96% dynamic | valgrind --track-fds | **done** |
| 5 | 122 heap overflow | 35.7% | triage first | not started |
| 6 | 590 free non-heap | 37.9% | triage first | not started |
| 7 | 124/127 under-read/write | 47-53% | triage first | not started |
| 8 | 457 uninit | 100% / 74.7% FP | noise is real, correctly tiered, and earns its place | **done — keep as is** |
| 9 | 401/415/416/476/563/762 | 57-90% | working; revisit last | not started |

**Start with CWE-121**, where the dominant shape is already identified: an
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

## ESBMC measured properly (2026-08-26) — see `docs/esbmc-evaluation.md`

**14/15 of decided cases found at 0 false positives, 9 of 24 undecided**, on
CWE-121 and CWE-122 at 12 cases each. Kordon's static layer is 45.5% and 31.2%
on the same classes. Bounded model checking is a genuinely different class of
answer on the cases it can decide, and it returns a counterexample.

**Every false positive was the harness. Four causes, three of them new traps:**

- **`VIOLATION_RE` contained a bare `assertion` alternative**, and ESBMC spells
  giving up as "unwinding **assertion**". Every bound-too-small was scored as a
  defect, inflating recall and false positives together and making the gave-up
  branch unreachable. **Scorer bug #6, same shape as the other five: a pattern
  that looked exhaustive and silently matched more than it claimed.**
- **A declared-but-bodiless function is havoc, not abstraction.** ESBMC models
  the narrow string functions and none of `wchar.h`. Declaring the wide ones
  parses; the run then prints `WARNING: no body for function wcslen` and
  reports confidently on a state nothing in the program produced.
  `scripts/esbmc-shim/wchar_model.c` gives them loop bodies — after which the
  same case reports the overflow *inside* `wcsncat`, where it is.
- **`alloca` is not declared by ESBMC's `<stdlib.h>` model** and Juliet never
  includes `<alloca.h>`, so every `ALLOCA(n)` was an implicit declaration
  returning `int` — a truncated pointer, then `invalid pointer freed` at the
  closing brace of a *corrected* function. **A prototype alone does not fix
  it**: glibc's header also routes the call to `__builtin_alloca`, and the
  builtin is what ESBMC models.
- **A missing translation unit.** `GLOBAL_CONST_FIVE` is `extern`, defined in
  `io.c`. Not passing it left the value unknown, so exploring the branch Juliet
  marks dead was *correct*. Same class as Kordon's own CTU gap.

**`--no-library` is the wrong workaround** and was the earlier one. It makes
the header clash go away by disabling the string models, so no bound derived
from `strlen` can be proved either — the false-positive rate then measures the
configuration rather than the engine.

**Cost, and it is real:** the wide-string models are symbolically executed, so
`--unwind` must exceed the longest string (Juliet's are 100), which is why the
default here is 128 against ESBMC's 16. Of the 9 undecided, 6 fail to build on
`sys/socket.h: redefinition of 'iovec'` — ESBMC's frontend mixing its header
tree with the system's, mostly on the C++ variants — and 3 time out.

## Open questions for next session
- **Missed detection to close: a loop variable used as an index after the loop ran to completion.** Reported from `~/VsCode/Satellite/rtklib_mod` (`ddidx` in `sat/pkt_sputnik_prcpos.c`): `ssat[i-k]` is read with `i-k == MAXSAT`, one past the end. The loop finishes without taking its `break`, so the index holds the bound, and the read happens after the loop. **Not flagged by any of the five engines, with CTU on; UBSan caught it in seconds.**
  - This is worth building because it is *purely syntactic* — no runtime values, no path sensitivity, no cross-TU reasoning. And it is **not** the ordering problem that blocked three earlier checks: this needs "is this reference outside the loop that bound the variable", which `hasAncestor`/`unless(hasAncestor(forStmt(equalsBoundNode(...))))` can express, not statement precedence, which matchers cannot.
  - Kordon already reports the *same defect class* when an engine happens to see it: `ura_value[15]` in `pkt_sputnik_eph.c:36` (cppcheck) and `pulkovo85_gamma[li]`/`[ri]` in pkt-astronomia's `refraction.c:188`, where the loops reach 1219 and −1. Those arrived from cppcheck's value analysis, not from a shape rule, which is why they are hit-and-miss.
  - Confidence split to design for: a loop with **no** `break` always exits at the bound, so the out-of-range read is unconditional — high confidence. A loop **with** a `break` only reaches the bound on one path — medium.
  - Two sibling defects in the same investigation are fair misses, worth recording so they are not chased: `obs.data == NULL` (depends on how many observations survive a runtime constellation filter — no static engine can bound that, and the report said so) and a missing `iobsr = obs.n - 1` before a backward sweep.
  - What actually solved that investigation: reading the code and diffing against stock RTKLIB, then UBSan/ASan for confirmation with an exact stack. Diffing a modified vendor library against upstream is a detection strategy Kordon does not have at all.
- **The `fault` profile cannot inject under valgrind** (measured, see above). Direction: drop the valgrind wrapper from the sweep, detect defects from the target's exit status and stderr, and recover a stack with `gdb -batch -ex run -ex bt` on abnormal termination — that worked by hand. Needs a gdb-backtrace → `RuntimeReport` parser; note `RuntimeReport::anchor` returns `None` for a frameless report, so a finding with no frames cannot be emitted at all.
- ~~CTU via CodeChecker is the highest-value next step~~ — **done, and CodeChecker turned out to be unnecessary.** Plain `clang --analyze` with `experimental-enable-naive-ctu-analysis` and an `externalDefMap` index closes the fallible-init class: `testdata/uninit_owner/` passes `--require-cwe 665` with `--ctu`. Measured value across Juliet's multi-file cases is above. CodeChecker would still be worth having for its build interception, but it is no longer on the critical path.
- **CWE-762 vs 763 for `unix.MismatchedDeallocator`.** Kordon maps it to 762 (literally "mismatched memory management routines"); prior ACL work mapped it to 763 because their requirements list named 763. Both are in the catalog. Confirm which the requirements actually want.
- Dedup is keyed on `file + line + CWE`, so two engines reporting one defect on *adjacent* lines stay separate (seen: clang-analyzer flags a dead store at the initialization line, cppcheck at the overwrite line). Consider a small line window.
- Licensing review of IKOS's NASA Open Source Agreement before committing to embed it.
- Whether the CWE-191 unsigned-subtraction-without-guard check needs to be written from scratch (LLVM patch D71607 was found via search but not confirmed merged/shipped).
- Concrete design of the per-class ownership-summary pass (data structure, how it's computed, how it plugs into Clang SA's checker API).
- Concrete design of the aggregation schema and CWE-mapping table format.
- Build-matrix tooling design (how Kordon manages N separate sanitizer builds without becoming its own build system).
