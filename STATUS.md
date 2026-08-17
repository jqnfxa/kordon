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

## Measured results

Ground truth: `/home/shard/VsCode/acl/report/problems.md` — **280 confirmed
positions** (`(CWE, file, line)`), 104 excluded as false positives. Parsed to
`tmp/confirmed.json`. Raw list is 714 records → 384 unique.

**Full ACL tree**, current: **145/280 = 51.8%** (`tmp/acl_q.json`, 12m19s,
274 units analyzed + 212 skipped as not-in-build, CTU + kordon-query on).

| CWE | recall | | CWE | recall |
|---|---|---|---|---|
| 563 | 46/49 (94%) | | 119 | 16/59 (27%) |
| 191 | 49/52 (**94%**) | | 401 | 9/66 (14%) |
| 457 | 17/19 (89%) | | 190 | 0/19 |
| 476 | 5/7 (71%) | | 763/415 | 0/5 |
| 416 | 1/1 | | 369 | 2/3 |

History: 11.4% (no compile db) -> 24.6% (db) -> 34.3% (CTU + checks re-enabled
+ build-membership filter) -> 51.8% (kordon-query CWE-191 check). Older logs `tmp/acl_log.txt`,
`tmp/acl_log_db.txt` predate all three and understate badly.

Compile failures are now **5 of 274**, down from 159 of 486 — almost all of
that was files outside the build, not broken code.

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
