# Kordon

Static analysis orchestrator for C/C++. Point it at a directory; get one
CWE-mapped report from several engines.

Kordon does not implement program analysis. Mature open engines already exist —
Kordon drives them, normalizes their mutually incompatible output into one
schema, maps every finding to a CWE, merges what the engines independently
agree on, and reports honestly on what none of them covered.

**Status: early but working end to end.** Five static engines, cross-translation-unit
analysis, abstract interpretation, and a dynamic layer (sanitizers and valgrind)
are wired up.

## Engines

| Engine | What it contributes | Flag |
|---|---|---|
| clang-tidy | AST-matcher checks: dead stores, narrowing, Rule-of-Five, bounds patterns | on by default |
| Clang Static Analyzer | Path-sensitive symbolic execution | on by default |
| Clang SA with CTU | The same, but a function defined in another `.cpp` stops being opaque | `--ctu` |
| cppcheck | Second opinion with different blind spots | on by default |
| clang-query | Kordon's own AST matchers, for gaps with no off-the-shelf check | on by default |
| IKOS | Abstract interpretation — the only engine that can *prove* an access safe | `--ikos` |

The dynamic layer is separate, because it makes a different kind of claim — not
"this shape is risky" but "the program did this":

| Profile | What it observes | Build |
|---|---|---|
| `asan` | out-of-bounds, use-after-free, double free, leaks, undefined behaviour | ASan+LSan+UBSan in one instrumented build |
| `msan` | uninitialised reads — the family with the weakest static story | separate build; cannot combine with ASan |
| `valgrind` | an independent engine with different blind spots | no instrumentation needed |

```bash
kordon path/to/src --dynamic --run "ctest --output-on-failure"
kordon path/to/src --dynamic --profiles asan,valgrind,msan
```

It only sees what the command executes: whatever line coverage `--run` reaches
is the hard ceiling, and silence means "not exercised" at least as often as it
means "correct". Every run has a deadline — a sanitizer that hangs is not
hypothetical, and a hang is indistinguishable from a clean result if nothing is
watching the clock.

Kordon's own checks are `kordon-unsigned-subtraction` (CWE-191),
`kordon-unsigned-addition` (CWE-190), `kordon-manual-ownership-flag` (CWE-401),
`kordon-assert-only-validation` (CWE-754) and `kordon-index-used-before-check`
(CWE-119).

A missing engine is reported as skipped rather than silently ignored.

Engines that are not distribution packages are built into a local, gitignored
prefix under `third_party/`; nothing is installed system-wide:

```bash
scripts/setup-ikos.sh --check          # abstract interpretation
scripts/setup-codechecker.sh --check   # optional: adds gcc -fanalyzer
```

Run either without `--check` to install. `third_party/` is disposable — delete
it and re-run the script.

## Scope

Kordon targets generic memory- and value-safety defects, and deliberately
nothing else:

| In scope (tier 1) | Examples |
|---|---|
| Bounds / OOB | CWE-119, 125, 787, 120, 129, 788 |
| Use-after-free, double free, dangling | CWE-416, 415, 590, 762, 825, 562 |
| Uninitialized reads | CWE-457, 824, 908, 665 |
| Integer over/underflow | CWE-190, 191, 197, 680 |
| Resource leaks | CWE-401, 772 |
| Null deref and fallible init | CWE-476, 252, 690 |
| Misc | CWE-369, 563, 843 |

Out of scope, on purpose: the injection/taint class (CWE-78/89/22/…) and the
authorization/access-control class (CWE-862/863/284/…). The latter is not
generically solvable — it needs the user to annotate application-specific
privilege semantics, which no tool does for you.

## Usage

```bash
kordon path/to/src                       # analyze a directory recursively
kordon path/to/src -p build/             # use compile_commands.json
kordon path/to/src -p build/ --ctu       # cross-TU analysis (slower, much deeper)
kordon path/to/src -p build/ --ikos      # add abstract interpretation
kordon path/to/src --all                 # detail low-confidence findings too
kordon path/to/src --show-unproven       # list what no engine could decide
kordon path/to/src --json                # machine-readable output
kordon path/to/src --fail-on-finding     # non-zero exit if anything in scope
```

**A compile database is effectively required.** Without one, the AST-matcher
checks still fire while the path-sensitive engine silently skips the file — so
a file can show dozens of findings and never actually have been analyzed.

## What makes the report different

**Nothing is dropped silently.** A finding Kordon cannot classify appears as a
gap in the mapping table. An engine that failed to run appears as an engine
that failed to run. Findings outside the analyzed tree are dropped and counted,
not quietly included. Every report ends with the limits that hold even when it
is empty.

**Cross-tool agreement is surfaced.** The same defect found by two engines with
different blind spots is stronger evidence than either alone, so findings are
merged on `file + line + CWE` and confidence is raised one step when
independent engines agree. Two low-confidence pattern matchers agreeing never
reaches high confidence — they may share a blind spot.

**CWEs are corrected, not just copied.** cppcheck reports a CWE itself, but
frequently the parent class: `operatorEqToSelf` comes back as CWE-398
("Indicator of Poor Code Quality") when the defect is a CWE-416 use after free,
and `deallocret` as CWE-672. Taking those at face value drops real findings out
of scope. `data/cwe_map.toml` overrides them, and the report records whether
each CWE was native, mapped, or overridden.

**"Proved safe" is distinguished from "not flagged".** IKOS can refute a
defect; the other engines can only stay quiet. Findings carry that distinction,
and what no engine could decide either way is reported separately under
`--show-unproven` rather than being rounded down to clean.

## Honest limits

These are measured on a real 486-file codebase, not estimated.

- **Precision is the open problem.** Kordon emits roughly 42 in-scope findings
  per real defect position. The low-confidence tier is ~96% of output and moves
  only −5% on a tree where ~226 defects were fixed, while the high tier moves
  −14%. The `cppcoreguidelines-pro-bounds-*` family alone is ~49% of all output
  and cannot distinguish fixed code from broken code — but deleting it costs 16
  real positions, so it is tiered down rather than removed.
- **CWE-190 findings mean "can overflow if unvalidated", not "is
  unvalidated".** The common fix idiom is a precondition validated by an early
  throw, which no AST matcher can see; those findings read identically on fixed
  and broken code.
- **Intent is undecidable for CWE-190/191.** No layer distinguishes deliberate
  wraparound from a bug — not the matcher, not IKOS, and not a sanitizer, which
  flags a correct FNV-1a hash. These stay permanently low confidence.
- **`#ifdef` is invisible.** Code in an inactive configuration never reaches the
  AST, so no engine can see it. The only remedy is analyzing each configuration
  as a separate run and merging; Kordon does not do this yet.
- **Allocation failure is not modelled.** Clang SA assumes `malloc` and
  `new (std::nothrow)` succeed, so an unchecked allocation and a correctly
  guarded one are currently indistinguishable to Kordon.
- **Absence of findings is never proof of safety.** A clean report means these
  engines did not flag it, and nothing more.
- **The dynamic layer is bounded by test coverage.** It reports defects that
  actually happened, which is the strongest evidence Kordon produces, but only
  along the paths the run command reached.

## Test corpus

`testdata/` holds synthetic fixtures only — every function is a minimal,
self-contained reproduction of one CWE. Nothing is derived from any real
codebase.

The corpus doubles as a configuration check:

```bash
kordon testdata/basic --require-cwe 369,401,415,416,476,563,763
```

This exits non-zero if any listed class stops being detected. Without it, a
configuration regression looks exactly like clean code.

The dynamic layer has its own, and it guards the whole pipeline — instrumented
build, execution, report parsing, CWE mapping:

```bash
kordon testdata/dynamic --dynamic --profiles asan --require-cwe 190,401,416,787
```

Two measured constraints the fixtures encode:

*Leak cases appear twice*, in `_static` and `_runtime` form. A sanitizer needs
the allocated pointer to escape the function or the optimizer deletes the
allocation outright; a static analyzer needs it *not* to escape, because once
the pointer is stored in an opaque global both Clang SA and cppcheck conclude
ownership transferred and stop reporting the leak. One function cannot serve
both layers.

*Every new check is tested against corrected code, not just defective code.* A
matcher that flags every `unsigned - 1` scores 94% recall and is worthless. The
only way to tell a detector from a shape-counter is to run it on a fixed tree
and confirm the findings disappear.

## Building

```bash
cargo build --release
cargo test
./scripts/check-fixtures.sh     # verify every fixture still compiles
```

## License

Apache 2.0. See [LICENSE](LICENSE).

cppcheck (GPL-3.0) is invoked as a subprocess and never linked, so its licence
does not reach Kordon's own code or the code you analyze.
