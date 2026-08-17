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

## Open questions for next session
- Licensing review of IKOS's NASA Open Source Agreement before committing to embed it.
- Whether the CWE-191 unsigned-subtraction-without-guard check needs to be written from scratch (LLVM patch D71607 was found via search but not confirmed merged/shipped).
- Concrete design of the per-class ownership-summary pass (data structure, how it's computed, how it plugs into Clang SA's checker API).
- Concrete design of the aggregation schema and CWE-mapping table format.
- Build-matrix tooling design (how Kordon manages N separate sanitizer builds without becoming its own build system).
