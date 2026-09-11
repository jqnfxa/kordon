---
name: kordon-measure
description: How to measure a Kordon change honestly — per-CWE Juliet scoring, the whole-baseline regression with compare-baselines, the fixture harness, multi-file/CTU and dynamic scoring, the by-check discrimination table, a bounded real-code spot check — and how to read the numbers (discrimination, surfaced vs raw, sample size, flags). Use after any change to a check, mapping or check set, and before any claim that a number moved.
---

# Measuring: did the count move, and did anything else?

The method of this repo is *change one thing and see whether the count moved*.
Every number below is meaningless without the flags and the `--limit` it was
taken at, so record both every time.

## The instruments

| question | command | time |
|---|---|---|
| does the fixture detect and discriminate | `scripts/check-fixtures.py --only <f> -v` | seconds |
| all fixtures still pass | `scripts/check-fixtures.py` | ~1 min |
| this CWE, single-file cases | `scripts/score-juliet.py third_party/juliet/C --cwe <n> --limit 40` | ~8 s |
| **everything**, default flags | `scripts/baseline.sh` → diff vs `data/juliet-baseline.json` | ~4 min |
| everything, with a flag | `scripts/baseline.sh --ctu` (compare against a baseline taken with the same flag) | longer |
| why not 100% | `scripts/explain-misses.py <n> --misses` | ~8 s |
| the split cases (what CTU is for) | `scripts/score-juliet.py … --multifile --kordon-arg=--ctu --cwe <n>` | minutes |
| which checks discriminate at all | `scripts/score-juliet.py … --by-check --limit 40` | ~4 min |
| the sanitizers on the same cases | `scripts/score-juliet-dynamic.py third_party/juliet/C --cwe <n>` | minutes |
| two JSON results, per CWE | `scripts/compare-baselines.py a.json b.json` | instant |
| the Rust invariants | `cargo test --release` | ~1 min |

`baseline.sh` never writes `data/juliet-baseline.json`; it writes to a scratch
path and prints the diff. Only the integrator updates the committed baseline.

## Reading the numbers

- **Discrimination = recall − FP**, per CWE. Read that column, not recall. A
  check that fires on every arithmetic line scores high recall and detects
  nothing; `bugprone-narrowing-conversions` read 64% recall on CWE-190 where
  real detection was zero.
- **Surfaced vs raw.** Surfaced counts high and medium only — what a user sees
  without `--all`. A low-confidence check can have a 75% false-positive rate
  and cost the reader nothing; whether to keep it is decided by what it finds
  that nothing else does, not by its raw FP rate.
- **Samples below ~30 flip signs.** CWE-122 read −10 discrimination at 25 cases
  and +23 at 40. Compare only at matched `--limit`; never read one small run
  as a finding.
- **The dynamic column is a different question** (did the flawed path execute
  and did the sanitizer fire) over a different sample. Never add it to the
  static one; `unreached` is not a miss.
- **Wrappers labelled bad** cap recall below 100% by construction.
- **`--ikos` and `--ctu` change the answer** (CWE-126: 11% → 86%; the split
  cases: 17% → 29%). A baseline must say which flags were on.

## What to record in the brief

    | CWE | before (recall / surfaced / FP / discrim) | after | flags | limit |

plus the `TOTAL` line from `compare-baselines.py` and any `REGRESSED` CWE with
an explanation. A regression in another lane's CWE is still yours to explain
in the commit; fixing it there is not.

## Traps — every one printed a plausible number instead of an error

When a CWE reads 0%, or suspiciously well, **check the instrument before the
tool.**

- **A relative Juliet root** makes every include fail while cppcheck keeps
  reporting, so the scorer measures one engine instead of four. Both scorers
  `abspath` now; `explain-misses.py` too. Watch for `FAILED TO COMPILE` notes
  in any output.
- **An over-wide accept set.** `EQUIVALENT` credited CWE-197 for CWE-190; the
  tier-0 398 bucket credited CWE-483 at 100% before the check existed. An
  entry there is a claim that the two CWEs mean the same defect.
- **A prefix is not a sample.** Cases are named `type_source_sink`; the
  scorer strides. Do not `head`.
- **A pattern that looked exhaustive**: `_bad` missing `_badSink`, lowercase
  `bad` missing `helperBad`, a return-type list missing `const`, a directory
  name with the wrong casing, a bare `assertion` alternative matching
  "unwinding assertion". Six scorer bugs, one shape.
- **`--checks='-*,clang-diagnostic-…'`** analyses nothing and reports zero.
- **clang-tidy's "Error while processing" is cumulative** — every unit after
  the first failure is named too.
- **A deadline read as a clean run.** A killed sanitizer with no output is not
  "nothing found".
- **A fixture that passes before the fix** is measuring nothing.

## Real code, bounded

Juliet is synthetic. Before believing a new check, count its positions on a
real tree — but as a spot check, not a loop step:

    kordon ~/VsCode/Satellite/rtklib_mod -p <its build dir> --json --all \
      | python3 -c 'import json,sys; r=json.load(sys.stdin); \
        print(sum("<check-id>" in f["native_ids"] for f in r["findings"]))'

`rtklib_mod` is 10 terse C units and runs in well under a minute; the existing
index checks report **zero** there and the divisor check reported 62 before its
integer restriction — that is the kind of signal this step exists for.
`~/VsCode/pkt-astronomia` is 159 units, C and C++, several minutes; use it once
per check, at the end. Note `pkta/src/api.h:71` may carry a stray edit that
breaks 26 units (see memory). Do not run the ACL trees in a lane; they are the
integrator's external validation.
