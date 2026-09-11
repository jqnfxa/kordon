# Lane `null-chain` — CWE-476, 252, 690

branch `lane/null-chain` · worktree `.claude/worktree/null-chain` · skills: `kordon-lane` first

## Scope

Null dereference, unchecked return values, and the chain that joins them:
an allocation or open whose result is used without a null test (690). Also
the ACL family of *fallible containers*: `init(n)` that can leave a container
empty, signalled only by a `bool` nobody reads or by the container being
null. Engines: `core.NullDereference`, `core.NonNullParamChecker`,
`unix.cstring.NullArg` (476), `bugprone-unused-return-value` with Kordon's
`CHECKED_FUNCTIONS` (252, medium), `cert-err33-c` (252, low).

## Where it stands (2026-09-11, default flags, 40 files/CWE)

| CWE | recall (surfaced) | FP | discrim | multi-file no-ctu → ctu (FP) | tier |
|---|---|---|---|---|---|
| 476 null deref | 37/44 = 84.1% (84.1) | 7/156 = 4.5% | +79.6 | **0% → 33.3%** (0) | B |
| 252 unchecked return | 28/40 = 70.0% (**20.0**) | 0/109 | +70.0 | no split cases | C |
| 690 null deref from return | **4/40 = 10.0% (0.0)** | 6/100 = 6.0% | +4.0 | — | E |

Settled (in `CLAUDE.md`): the curated `CHECKED_FUNCTIONS` list beats
`cert-err33-c` 12:1 on real code and the rule for adding a name is "ignoring
the result leaves the program using a value it did not compute"; `snprintf`
failed it and was removed. 252's 70% raw / 20% surfaced is therefore **by
design**: Juliet's ignored `fprintf`/`putc`/`fputs` results are counted low
and never detailed.

### Multi-file cases with `--ctu` (survey 2026-09-11, 25 cases per CWE)

476: 18/54 · 252: no split cases · 690: not sampled. 476 at 33% across units is the CTU win recorded in CLAUDE.md, re-measured at a larger sample. Per-shape tables and the missed functions are in `docs/lanes/survey-2026-09-11.md`.

## Shapes and verdicts

### CWE-690

| shape | found | verdict |
|---|---|---|
| fopen / w32_wfopen · use without null check | 4/4 | B (which engine? note it) |
| **malloc / calloc / realloc · `strcpy(data, …)` / `data[0] = …` without null check** | **0/36** | **C — nothing reports it** — TODO 1 |

Probed on `char_malloc_01.c`: cppcheck with `--inconclusive` reports nothing
(`nullPointerOutOfMemory` does not exist in 2.13); Clang SA with
`core,unix,alpha.core,optin.portability` reports nothing — `malloc` *may*
return non-null, so the null path is not a definite dereference.

### CWE-476

| shape | found | verdict |
|---|---|---|
| direct · check after deref / deref after check | 10/10 | B |
| Set · `data->a` | 4/4 | B |
| Set · print `data` | 23/30 | B; the misses are flow variants |

### CWE-252

29 of 31 shapes are 100%; the misses are Windows APIs (`CreateMutex`,
`ImpersonateSelf` — 5 units fail to compile; the `infra` lane's `UNPORTABLE`
item) and `puts`/`putchar`/`putwchar`/`fgetws`, which fail the rule for the
curated list and are correctly low or absent.

## TODO — in order

### 1. `kordon-unchecked-allocation-result` — the check CWE-690 needs

    data = (char *)malloc(100 * sizeof(char));     // calloc, realloc, strdup,
    strcpy(data, "…");                              // aligned_alloc, fopen,
                                                    // new (std::nothrow) T[n]
    …and no comparison of `data` against NULL / nullptr / 0, and no `if (!data)`
    / `if (data)`, anywhere in the function

Same three-clause shape as `kordon-unchecked-divisor`: the pointer is
assigned from one of a named list of fallible producers; it is then
dereferenced (`*p`, `p[i]`, `p->f`) or passed to a function in a short list
that dereferences (`str*`, `mem*`, `wcs*`, `fread`/`fwrite`/`fclose`); nothing
tests it. CWE-690, medium, error. Good twins: `if (data == NULL) exit(-1);`,
`if (!data) return;`, the ternary `data ? … : …`, a `new` without `nothrow`
(**must stay silent** — it throws; this is `testdata/allocator_fallibility/`'s
whole point, and the check's producer list is what discriminates).

Then the decision the number forces: on `~/VsCode/Satellite/rtklib_mod`
(C, `malloc` everywhere) count the positions. An unchecked `malloc` is CWE-690
by definition and a policy in much of C; if the count is large, the answer is
not to drop the check but to say what it claims — medium for a *dereference*
in the same function, low for a pass-through to a callee. Write the count and
the decision in `## For CLAUDE.md`.

### 2. `allocator_fallibility` and `empty_container_signal` — mark them, close the gap

Both unmarked, both yours (`docs/acl-report-findings.md` § Fixtures has the
measurements). `allocator_fallibility` has **no detection at all** today for
`new (std::nothrow)` written through unchecked, and its infallible twin must
stay silent — TODO 1's producer list is the fix; the fixture is the test.
`empty_container_signal` finds 2 of 3: the miss is an early `return` from a
`void` function leaving a container unsized, indexed by the caller — a
two-function property; record E unless `--ctu` plus `ArrayBoundV2` sees it
(try, with `@kordon flags: --ctu` on a copy).

### 3. The 252 → 119 chain the ACL notes asked for

`bool init(int n)` whose result is discarded, then the object is indexed in
the same function: "an ignored return value whose loss enables an
out-of-bounds access downstream is a stronger signal than either finding
alone, and both halves are mechanically detectable." A matcher: a call to a
`bool`/pointer-returning method named `init`/`resize`/`allocate`/`reserve`
whose value is unused (`hasParent(compoundStmt())`), followed anywhere in the
function by `obj[…]` / `obj.at(…)` / `obj.data()` on the same object. CWE-252,
medium, with the message naming the consequence. Fixture from
`empty_container_signal`'s `Vector::init`.

### 4. 476's seven false positives and `core.NonNullParamChecker`

`--by-check --cwe 476`. `CLAUDE.md` records `NonNullParamChecker` at +0.0
discrimination in the by-check table with the caveat that its good-side hits
did not reproduce compiled alone. Settle it per-CWE: if the 7 are this
checker, decide medium vs high with the evidence; if they are a mapping
through the accept set `{476, 690, 252}`, narrow the set with the reason.

### 5. Write the 252 verdict

The 20% surfaced is the design. Put the sentence in `## For CLAUDE.md` so the
progress table stops reading it as a gap, and list the Windows cases for the
`infra` lane's exclusion.

## Fixtures

Marked: none yet. To mark: `unchecked_return`, `allocator_fallibility`,
`empty_container_signal`. To build: `unchecked_alloc_result` (C, Juliet
shape, all producers), `ignored_init_then_index`.

## Don't

- Add `fprintf`/`fclose`/`snprintf`/`puts` to `CHECKED_FUNCTIONS`.
- Report an unchecked `new` without `nothrow`.

## For CLAUDE.md

(fill in)

## State

not started
