---
name: kordon-fixture
description: How to write a Kordon testdata/ fixture — a minimal synthetic reproduction of one defect shape with its corrected twin, marked with @kordon/@bad/@good/@expect/@silent so scripts/check-fixtures.py can assert detection and silence, including cross-translation-unit (--ctu) fixtures. Use when reducing a Juliet or ACL case to a regression test, or when converting an unmarked fixture.
---

# Fixtures: the defect, its twin, and what Kordon must say about each

A fixture is one directory under `testdata/`. It is the regression test for one
defect shape, and it has to be able to **fail**: it fails before the fix and
passes after, and its corrected twin must stay silent throughout. A check that
fires on both has found nothing — that sentence appears in this repo more
than any other, because it kept being true.

## Layout

    testdata/<shape_name>/
        <one>.c or <one>.cpp            single-TU form
        README.md                        only when the reasoning is not obvious from the source

    testdata/<shape_name>_ctu/           the same defect across units, when the real
        thing.hpp  thing.cpp  app.cpp    shape crosses a boundary (see zero_length_ctu)

Names describe the shape, not the CWE: `one_sided_index`, `reinit_leak`,
`zero_length_ctu`. All code is **synthetic** — modelled on Juliet or on the ACL
notes, never copied from either.

The harness generates a compile database per fixture (one entry per source,
`-I <fixture dir>`, `-std=c11` for `.c`, `-std=c++17` for `.cpp`), so headers
in the directory resolve and every engine runs. Without a database clang-tidy
and the bounds analyzer fail on a `.c` file and report nothing.

## Markers

In any comment, anywhere in the fixture:

    // @kordon cwe: 129, 124        the class(es) this fixture is about  (required)
    // @kordon flags: --ctu          extra kordon flags                   (optional)
    // @kordon confidence: low       floor: low | medium (default) | high (optional)

Per function — on the signature line or a comment line just above it:

    // @bad            body must draw >= 1 finding in the class, at or above the floor
    // @good           body must draw none
    // @bad 787        override the class for this function

Per line:

    buf[n] = 0;   // @expect 124    a finding of this class exactly here
    buf[n] = 0;   // @silent 124    none here

**Naming convention instead of markers:** once `cwe:` is declared, any function
whose name contains `bad` or `good` (Juliet's convention, any casing) is
classified implicitly. `guard_form_bad` / `guard_form_good` needs no markers
at all. C++ methods (`Buffer::init`) take explicit `@bad`/`@good`.

The class is accepted through the same `EQUIVALENT` table the Juliet scorer
uses, so a stack overflow reported as CWE-787 satisfies `@bad 121`. Silence is
per class: a `@good 457` function that draws a genuine CWE-120 is reported as a
note, not a failure — the same distinction the by-check table in `CLAUDE.md`
records about Juliet's `good` functions.

The default floor is **medium**, because that is what the report shows without
`--all`. If the check you are building is low confidence by design (a risk
pattern rather than a logic error), declare `confidence: low` — and know that
it will never reach a reader.

## Run it

    scripts/check-fixtures.py --only <name> -v     # -v lists every in-scope finding
    scripts/check-fixtures.py                      # everything; also lists unmarked fixtures
    scripts/check-fixtures.py --flags=--ctu        # add a flag to every fixture

Exit status is non-zero on any failure. **Run it before the fix and confirm the
`bad` side fails.**

## Writing the good twin

The twin is the check's specification. Write the *remediation someone would
actually apply*, in the idiom real code uses:

- the guard as written in practice: an early `return`, not only an enclosing `if`
- both spellings of a bound: `i < n` and `n > i`; `if (p == NULL) return;` and `if (!p)`
- the exemptions the check claims: a loop counter, a value bounded by its own
  call (`n = read(fd, buf, sizeof buf - 1); buf[n] = 0;`), a signed vs unsigned
  operand, a float vs integer divisor
- the *fixed* shape from the corpus, when the fixture comes from one

And write the **near-miss twin** that must still be flagged: `if (i >= 0)` alone
when the check is about a missing upper bound; `&&` where `||` was needed.

## Traps that produced a passing fixture that proved nothing

All measured in this repo. Read `testdata/zero_length_ctu/README.md` for the
long form of the first two.

- **A concrete value manufactured next to the sink.** A defensive
  `if (n < 0) n = 0;` one hop from the write gave the analyzer the zero it
  needed, and deleting the file that was supposed to supply it changed nothing.
  For a CTU fixture, the ablation *is* the test: remove the entry unit, and the
  finding must disappear.
- **An accessor that reads the buffer on both paths.** The good twin failed for
  a reason unrelated to the guard. Make the two chains differ in exactly one
  thing.
- **The wrong defect firing on both sides.** `use(v[0])` on `new double[n]`
  reports the *uninitialised contents* — a real defect, but not the null
  question the fixture asked, and it fires identically on the safe container.
  Write-then-read isolates the null; the read keeps the write from being a dead
  store.
- **Reinit-without-free on both variants.** A method that reassigns an owning
  member without `delete[]` first is a genuine CWE-401 on the good twin too.
  Release first, unless the leak is what the fixture is about.
- **The escape-sink trap.** A sanitizer needs the allocation to escape or the
  optimizer deletes it; a static analyzer needs it *not* to escape or it
  concludes ownership transferred. One function cannot serve both layers —
  leak fixtures exist in `_static` and `_runtime` form.
- **Findings in headers are dropped when the target is a `.cpp`.** Always run
  Kordon on the directory. The harness does.
- **A fixture that does not compile still produces findings.** The harness
  syntax-checks first; a fixture with its later functions appended outside the
  namespace had its parameters typed `int&` and was judging nonsense.
- **`assert` expands to nothing under `NDEBUG`.** The harness passes
  `-UNDEBUG`; if the check is about what a build removes, say so in the
  fixture header.

## The CTU form

When the real shape crosses a translation unit — a public method whose only
callers live in test files, a constructor in one `.cpp` and its users in
another — build it that way:

- one header, N sources, an entry function that supplies the value, the sink
  several hops away (`zero_length_ctu` is four hops and documents the 8-unit
  `ctu-import-cpp-threshold` ceiling)
- `@kordon flags: --ctu`; mark the sink `@bad`, its guarded twin `@good`
- state in a README what a run *without* `--ctu` must report (usually nothing),
  so the fixture doubles as the regression test for CTU itself
