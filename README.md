# Kordon

Static analysis orchestrator for C/C++. Point it at a directory; get one
CWE-mapped report from several engines.

Kordon does not implement program analysis. Mature open engines already exist —
Kordon drives them, normalizes their mutually incompatible output into one
schema, maps every finding to a CWE, merges what the engines independently
agree on, and reports honestly on what none of them covered.

**Status: early.** Two engines wired up (clang-tidy / Clang Static Analyzer,
cppcheck). No cross-TU analysis, no sanitizer layer yet.

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
kordon path/to/src --json                # machine-readable output
kordon path/to/src --verbose             # include each finding's event path
kordon path/to/src --fail-on-finding     # non-zero exit if anything in scope
```

Requires `clang-tidy` and/or `cppcheck` on `PATH`. A missing engine is reported
as skipped rather than silently ignored.

## What makes the report different

**Nothing is dropped silently.** A finding Kordon cannot classify appears as a
gap in the mapping table. An engine that failed to run appears as an engine
that failed to run. Every report ends with the limits that hold even when it is
empty — single-TU only, static only, and no claim that the code is safe.

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

## Test corpus

`testdata/` holds synthetic fixtures only — every function is a minimal,
self-contained reproduction of one CWE. Nothing is derived from any real
codebase.

The corpus doubles as a configuration check:

```bash
kordon testdata/basic --require-cwe 369,401,415,416,476,563,762
```

This exits non-zero if any listed class stops being detected. Without it, a
configuration regression looks exactly like clean code.

One measured constraint the fixtures encode: leak cases appear twice, in
`_static` and `_runtime` form. A sanitizer needs the allocated pointer to
escape the function or the optimizer deletes the allocation outright; a static
analyzer needs it *not* to escape, because once the pointer is stored in an
opaque global both Clang SA and cppcheck conclude ownership transferred and
stop reporting the leak. One function cannot serve both layers.

## Building

```bash
cargo build --release
cargo test
```

## License

Apache 2.0. See [LICENSE](LICENSE).

cppcheck (GPL-3.0) is invoked as a subprocess and never linked, so its licence
does not reach Kordon's own code or the code you analyze.
