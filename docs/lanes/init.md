# Lane `init` — CWE-457, 665, 824, 908

branch `lane/init` · worktree `.claude/worktree/init` · skills: `kordon-lane` first

## Scope

Reads of values never assigned: uninitialised locals and buffers (457),
objects handed back half-constructed (665 — the fallible-constructor class
`--ctu` was built for), uninitialised pointers (824), uninitialised resources
(908). Engines: `core.uninitialized.*` (457, high),
`optin.cplusplus.UninitializedObject` (665, high; needs the constructor's call
site in the TU or `--ctu`), cppcheck `uninitvar`/`uninitdata`/
`uninitMemberVar`, MSan in the dynamic layer (100% on Juliet, 0 FP).
`cppcoreguidelines-init-variables` is deliberately **tier 0** — it is the
guideline, not the defect; do not move it back.

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | dynamic (MSan) | multi-file no-ctu → ctu (FP) | tier |
|---|---|---|---|---|---|---|
| 457 uninit | 23/40 = 57.5% (57.5) | 8/170 = 4.7% | +52.8 | **25/25** | 55.0% → 75.0% (**48 → 50%**) | B |
| 665 improper init | 18/50 = 36.0% (36.0) | 5/112 = 4.5% | +31.5 | — | not in the multi-file baseline (200 files exist) | E |

Settled (in `CLAUDE.md`): the guideline/defect split for 457; `testdata/
uninit_owner/` passes `--require-cwe 665,457,476` with `--ctu` and reports
nothing without it (now marked, green); `testdata/fill_initialises/` shows the
vendor's "fill functions not modelled" false positive does **not** reproduce
in Kordon — the engines already model `fread`/`memset`/`memcpy`/`strcpy` as
initialising.

## Shapes and verdicts

### CWE-457

| shape | found | verdict |
|---|---|---|
| no_init · use data | 22/25 | B |
| **partial_init** · loop fills half of a malloc'd/stack array, second loop reads all | **0/14** | D / runtime — per-element tracking through a 10-iteration loop; MSan catches all of them |
| Don't · use | 1/1 | B |

### CWE-665

| shape | found | verdict |
|---|---|---|
| `char data[100];` (never written) · `strcat(data, …)` / `strncat` / `wcsncat` | 18/38 | B, half — which engine, and why half? TODO 1 |
| same · **`wcscat`** | **0/12** | wide-string modelling gap (shared with the bounds lanes) — TODO 1 |

The shape is a string appended to a buffer nothing ever terminated; the
corrected twin writes `data[0] = '\0'` first.

## TODO — in order

### 1. CWE-665: append into a never-written buffer, narrow and wide alike

Find what reports the 18 (`scripts/explain-misses.py 665 --found`, then `-v`
on one): if it is `core.uninitialized`/cstring reading `data` before
`strcat`, the wide half is the `CStringChecker` not modelling `wcs*`. Then
build the matcher that does not care which function it is:

    call to strcat / strncat / wcscat / wcsncat / strlen / wcslen
      whose first argument is a local array declared without an initialiser
      and the function contains no write to it before — approximated as:
      no memset / strcpy / wcscpy / `arr[…] =` / `= {…}` of that array anywhere

`kordon-append-to-uninitialised-buffer`, CWE-665, medium (statement order
cannot be expressed; the "anywhere in the function" exemption errs toward
silence). Fixture `append_uninit_buffer` with the `data[0] = '\0'` twin, a
`memset` twin, and a `char data[100] = ""` twin. Measure 665, then the whole
baseline: this shape appears in the bounds CWEs too and must not add false
positives there.

### 2. CWE-457 under `--ctu --multifile`: 50% false positives

Half the corrected functions flagged. `scripts/score-juliet.py … --multifile
--kordon-arg=--ctu --cwe 457 --by-check` names the check. If it is
`core.uninitialized.*` after CTU inlining, this is an analyzer precision loss
worth a fixture and a note; if it is `cppcoreguidelines-init-variables` being
counted through the accept set `{457, 824, 908}`, the accept set is right and
the tier-0 mapping already excludes it — check that the scorer honours
`in_scope`.

### 3. CWE-665 multi-file baseline

200 split files exist and no baseline covers them; the class is *the* CTU
class. `scripts/explain-misses.py 665 --multifile -- --ctu` and record the
number with and without `--ctu` in the brief; the integrator adds it to the
multi-file baseline.

### 4. `partial_init` — write the verdict, point at the dynamic layer

No static engine tracks which of ten elements a loop initialised. Record D /
runtime with MSan's 100%; add a runtime fixture only if `testdata/dynamic/
uninitialised.cpp` does not already cover the half-initialised array shape
(check; extend that CMake project rather than adding a second one).

### 5. Mark the existing fixtures

`fill_initialises` (2 must-flag, 6 silent — all currently correct),
`uninit_switch` (geodesy.cpp: a `switch` without `default` leaves a struct
field unassigned), `fallible_init` (container.cpp: the nothrow constructor
alone — decide with the `null-chain` lane which class it asserts; 665 is the
root cause, 476 the consequence). `uninit_owner` is marked.

### 6. `optin.cplusplus.UninitializedObject` on real code

It reports every constructor that leaves a field unassigned, intended or not.
One run on `~/VsCode/pkt-astronomia` (its C++ parts; note the `api.h` typo in
memory) with the count of positions and how many are defects; if it floods,
the answer is the checker's `Pedantic`/`IgnoreRecordsWithField` options, not a
lower confidence.

## Don't

- Re-file `cppcoreguidelines-init-variables` under 457.
- Build a per-element initialisation tracker.

## Fixtures

Marked: `uninit_owner`. To mark: `fill_initialises`, `uninit_switch`,
`fallible_init`. To build: `append_uninit_buffer`.

## For CLAUDE.md

(fill in)

## State

not started
