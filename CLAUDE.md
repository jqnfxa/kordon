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

**Baseline, 40 files per CWE, default flags: 51.5% recall at 14.6% false positives — 38.5% / 1.9% counting only the high- and medium-confidence tiers the report details without `--all`.** (`--ikos` and `--ctu` add more; see the per-CWE notes.)

Read the **discrimination** column (recall − FP), not recall. A check that fires on every arithmetic line scores high recall and detects nothing.

| CWE | recall | FP | discrim | note |
|---|---|---|---|---|
| 415 double free | 89.7% | 6.1% | **+83.6** | working |
| 563 dead store | 76.9% | 5.3% | **+71.7** | working |
| 762 mismatched free | 64.0% | 2.1% | **+61.9** | working |
| 476 null deref | 65.6% | 4.6% | **+61.0** | working |
| 401 leak | 78.1% | 19.7% | **+58.4** | working |
| 416 use-after-free | 57.1% | 0.0% | **+57.1** | working |
| 590 free non-heap | 37.9% | 0.0% | +37.9 | half the cases missed |
| 457 uninit | 100% | 68.9% | +31.1 | all found; noise buried in low tier (2.8% surfaced) |
| 124 underwrite | 65.6% | 22.7% | +42.9 | was 53.1% |
| 127 underread | 46.9% | 18.2% | +28.7 | |
| 191 underflow | 42.9% | 18.6% | +24.3 | 0% surfaced |
| 775 fd leak | 12.9% | 0.0% | +12.9 | 13 of 40 units failed to compile |
| 122 heap overflow | 46.4% | 23.7% | +22.8 | was 35.7% |
| 126 overread | 18.8% | 14.0% | +4.7 | |
| 190 overflow | 12.1% | 8.8% | +3.3 | see verdict below |
| 121 stack overflow | 16.7% | 1.1% | +15.6 | was 2.8%; alpha checkers |
| 562 stack addr return | 0% | 0% | 0 | only 3 cases sampled |

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
| 3 | 126 overread | 18.8% | probably same shape as 121 | not started |
| 4 | 775 fd leak | 0% -> 96% dynamic | valgrind --track-fds | **done** |
| 5 | 122 heap overflow | 35.7% | triage first | not started |
| 6 | 590 free non-heap | 37.9% | triage first | not started |
| 7 | 124/127 under-read/write | 47-53% | triage first | not started |
| 8 | 457 uninit | 100% / 69% FP | works; the FP tier may be worth trimming | not started |
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
