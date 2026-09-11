# What the ACL report positions actually were

Notes from adjudicating 45 of the 67 confirmed positions in the ACL "mosaic"
report against `comparison/acl`. Written for kordon: each class ends with what a
detector would have needed to get the answer right.

Source: `acl/report/acl_report_v1_filtered.xlsx` (67 confirmed, false positives
already stripped by the vendor). Verdicts below are mine, from reading the code
plus the report's own `codeflow` traces.

---

## CWE-563 — dead store (2 positions, both real)

* `exif_info.cpp:2784` — last `DirIndex += 12` of 11 identical tag writes; the
  next block reassigns `DirIndex` unconditionally.
* `inout_reader_image_tiff.cpp:952` — `angle_course` computed, then clobbered by
  `angle_course = angle_track` 20 lines later.

**Kordon found both.** For the tiff one it anchored on `:973` (the write that
kills) where the report anchored on `:952` (the write that dies).

> **Lesson.** Both ends of a dead store are legitimate anchors. Reporting the
> pair — "written here, killed there" — is strictly more useful than either
> alone, and would have made this position self-evident without reading.

---

## CWE-476 — null deref (2 positions, both false positives)

* `kdtree.cpp:491` — `nbrs[n-1]->feature_data`. Slots `0..n-1` are always
  filled, but the invariant spans a function boundary and a `goto`.
* `dcraw_loader.cpp:338` — `A[i][i]`. `calloc` is checked, `A[i]` points into
  the same block, and **both call sites pass literal constants** (9 and 19).

> **Lesson.** Constant propagation from call sites is worth real money here. A
> single-caller / literal-argument analysis would have dropped the dcraw finding
> outright. Separately: `calloc(n, 0)` returning a non-null zero-size block that
> passes an `if (!p)` check is a concrete hazard class deserving its own check —
> it is what makes `len == 0` genuinely unsafe in that function.

---

## CWE-457 — uninitialised read (2 positions, both false positives)

* `vector.cpp:298` — trace shows the analyzer losing precision through
  `clear()`, whose body is `m_own.reset(); m_data = nullptr; m_length = 0;`. It
  treats the `unique_ptr::reset()` as opaque and marks the whole object's fields
  unknown afterwards.
* `hgt_internal.cpp:96` — trace jumps from `malloc` straight to the read,
  **never visiting the `fread` that fills the buffer**.

> **Lesson (high value).** Model the standard fill functions — `fread`,
> `memcpy`, `memset` — as initialising their destination. Without that, every
> "read from a malloc'd buffer" is noise, and this family is large. Second:
> do not invalidate an object's fields on a call whose body is visible.

Both were FP *as reported*, but `hgt` sat on a real leak — `malloc` with no
`free` anywhere in the file, losing the buffer on the success path too.

---

## CWE-401 — leak (20 positions, all one container)

All 20 traces named `CVector` (`matching/src/fco_vector.h`); none named
`CMatrix`. Kordon reported **0 CWE-401 in those files** with a working compile
database, LSan was silent across 418 calls, and the destructors do free.

The real latent bug is the ownership flag:

```cpp
void CVector<Type>::clear() {
    if (m_AllocMemory) { delete[] m_pData; ... }   // frees ONLY under the flag
}
bool CVector<Type>::init(int n) {
    m_pData = new Type[n];
    if (!m_pData) return false;                    // returns BEFORE setting the flag
    ...
    m_AllocMemory = true;
}
```

> **Correction — the check works; the invocation was wrong.** `kordon` reported
> 0 CWE-401 only because it was pointed at the `.cpp` files. The defect lives
> entirely in `fco_vector.h`, and findings in headers are classified as outside
> the analyzed tree and dropped: `external_findings_dropped: 234` on that run.
>
> Re-run with the header inside the analyzed path, on the **original** code:
>
> ```
> :226  owning pointer member is released only when a bool member permits it
> :194  this assigns a fresh allocation to an owning member without releasing it
> :179  assigning newly created 'gsl::owner<>' to non-owner 'Type *'
> ```
>
> On the **corrected** header (flag deleted, ownership moved into
> `std::unique_ptr<Type[]>`): **0 CWE-401**. So the check discriminates fixed
> code from broken code on a real container, not just on the fixture — which is
> the property `testdata/ownership_flag/ownership.cpp` exists to assert.
>
> The `ownership_flag` fixture already covers this shape, and it also fires on a
> class **template** with out-of-line member definitions (verified separately),
> so templates are not the gap.

---

## CWE-191 — unsigned underflow (9 positions: 3 real, 2 FP, 1 already fixed, 2 out of scope)

Real:
* `image_functions_operators.cpp` — `if (width == 0 && height == 0)` guarding
  `Data2DROI(0, width - 1, 0, height - 1)`. Must be `||`. **Three identical
  overloads; the report caught one.**
* `image_service_data_relief.cpp:424` — `static_cast<double>(m_matrix.width() - 1)`.
  At width 0 this is ~1.8e19, so the range check stops rejecting anything: the
  overflow *disables a bounds check* rather than crashing.
* `bmp_image.cpp:1079` — `bits + (height-1)*non_al_bpl`, `uint32_t height`, no
  dimension validation anywhere in the function.

False positives:
* `dcraw_loader.cpp:352` — `len - 2` where `len`, `i`, `j` are all `int`.
  Signed; `-1` is just `-1`. **Type-check before flagging underflow.**
* `algorithm_layer_data.cpp:23` — already guarded on the line above.

> **Lesson.** Two distinct patterns worth separating:
> 1. `unsigned_expr - 1` **inside a cast to a wider signed/floating type** — the
>    wrap silently neuters a comparison. Higher severity than a plain wrap
>    because it fails open. (Playbook calls this "masked overflow" and rates it
>    above a crash.)
> 2. **Twin detection.** `&&`-vs-`||` appeared in 3 of 3 overloads of one
>    function; `width() - 1` appeared at 5 sites in one file. When a guard is
>    wrong once, check its siblings — highest-yield single addition here.

A tree-wide sweep found **50 occurrences** of `X() - 1` on unsigned accessors,
~25 with no nearby guard. The report listed 9. Two clear unreported ones:
`image_functions_transform.cpp:394` (`Data2DROI(0, image_out.width() - 1, ...)`)
and `parallel_runner.h:54` (`std::fmax(1, cols_bounds.size() - 1)` — the clamp
is on the wrong side of the subtraction).

---

## CWE-190 — overflow (9 positions: 2 real, 4 FP, 3 already fixed)

* `disparity.cpp:240` — `calcDisparityRange` deliberately saturates at
  `SIZE_MAX`, then the caller does `+ 2 * disparityExpansion` and wraps it to 1.
* `webp:164` — `ftell` returns `-1` into a `size_t`; `file_size + 1` wraps to 0,
  which makes the sanity check on the *next line* (`size() != file_size + 1`)
  pass vacuously and lets the failure reach `fread(..., SIZE_MAX, 1, in)`.
* `sift_cl.cpp:185,187` — FP. `nOctaveLayers + 2` and `+ 3` wrap in lockstep, so
  `max index = nOctaves*L - 1 <= pyr.size() - 1` holds. `L == 0` is a division
  by zero, not an overflow.

> **Lesson.** Two checkable rules:
> 1. **Saturate-then-unsaturate**: a function that clamps to `MAX` whose result
>    immediately feeds unguarded arithmetic. The author already understood the
>    hazard one line away — that proximity makes it a strong signal, not a weak one.
> 2. **`ftell`/`ftello` assigned to an unsigned type without a `< 0` check.**
>    Narrow, mechanical, no false positives.

---

## CWE-119 — bounds (22 rows / 18 unique positions; triage in progress)

Three shapes, and one of them is a kordon false positive worth fixing first.

### A. Failure signalled only by an empty container — real, and reachable

`image/src/image_transform_coord_adapter.cpp:248`.

```cpp
CornerCoord findKadrInImage(...)          // returns two acl::Vector by value
{
    Vector xCords, yCords;
    xCords.init(4); yCords.init(4);
    if (xCords.isNullPointer() || yCords.isNullPointer())
        return {xCords, yCords};          // ONLY failure signal: the vectors are null
    ... fills [0..3] ...
}

void Matrix3x3Adapter::calcBounds(...)
{
    CornerCoord corner = findKadrInImage(width, height);
    minX = corner.xCords[0];              // no check; operator[] is `return m_data[j];`
}
```

Reachable, not theoretical: `acl::Vector::allocate` uses `new (std::nothrow)`, so
the null path is a real allocation failure rather than a branch that can only be
taken if a throwing `new` returned null. Two callers in the same file share the
defect (`calcBounds`, `defaultFindScale`), and only one was reported.

> **Check to implement.** A function that returns a container with an early-exit
> path leaving it empty/null, whose callers index it unchecked. It is a
> two-function property, so it needs CTU or at least same-TU interprocedural
> reach — but the "failure reported only by returning an empty container" idiom
> is common in C++ codebases without exceptions, and worth the cost.

### B. Already guarded — a detector must not re-report these

`rotation.cpp:103,121` carries three separate guards before the flagged line:
`w.init(3)`, `if (w.isNullPointer()) return;`, and
`if (R.getRows() < 3 || R.getCols() < 3) return;`. Same for
`epipolar_model.cpp:36` (`params_out.init(6)` + `isNullPointer`) and
`preconditioner.cpp:311` (`n <= 0 || cols != n || r.getLength() < n ||
z.getLength() < n` → return, then `w.init(...)` + `isNullPointer`).

> Recognising `init(n)` followed by `isNullPointer()` as establishing an extent
> is the single change that would silence this whole group.

### C. kordon false positive — `assert` followed by a real check

`matrix.cpp:1253`, `kordon-unchecked-parallel-extent`, low confidence:

> "…nothing in this function establishes that the subscripted parameter is at
> least as long; **an assert does not count, it expands to nothing under NDEBUG**"

The code, however, is:

```cpp
const bool condition = a.getRows() == blc.getRows()
                    && !blc.isNullPointer() && !a.isNullPointer();
assert(condition);
if (!condition) { return; }          // the real check the message says is absent
...
if (size <= 0 || bcols % size != 0 || bcols > blc.getRows()) { return; }
```

The matcher appears to stop at the `assert` and never see the branch on the next
line. **This FP is distributed in the worst possible way**: commit `b0e277fa`
("Заменить assert настоящими проверками входа в matrix.cpp") introduced exactly
the `assert(x); if (!x) return;` shape across this codebase — so the check fires
precisely on the sites where someone already did the right thing, and stays
quiet on the ones still relying on `assert` alone.

> **Fix.** When the asserted expression is re-tested in a real branch that
> returns or throws, treat the property as established. Worth doing before the
> check is trusted, since `assert` + real check is the documented remediation
> in this project's own playbook (§2.2).

### D. Same syntax, opposite verdicts — the allocator decides

Two vector classes in this codebase, indistinguishable at the call site:

```cpp
// matching/src/fco_vector.h : CVector   -- plain new, throws on failure
m_pData.reset(new Type[mElement]);

// math/src/vector.cpp       : Vector    -- nothrow, returns null on failure
m_own.reset(new (std::nothrow) double[n]);
```

Both are then used as `container.init(N); ... container[0]` with no length
check, and the report flagged both. The verdicts are opposite:

* `cpolinom2Daffine.cpp:74` — `m_DirectX` is `CVector`. `InitVector(3, PP_ROW)`
  either yields three elements or propagates an exception, so the indexing is
  **unreachable with an empty vector**. False positive.
* `image_transform_coord_adapter.cpp:248` — `corner.xCords` is `Vector`.
  `init(4)` can genuinely leave it null, the producing function signals that
  *only* by returning the empty vector, and two callers index it. **Real.**

> **Lesson.** This family cannot be adjudicated syntactically. Deciding it
> requires resolving which allocation the container ultimately performs —
> `new` vs `new (std::nothrow)` vs `malloc`. A detector without that will
> either miss the real one or flood on the safe one, and here the two classes
> live three directories apart in the same module tree.
>
> Cheap approximation if full resolution is out of reach: classify container
> types once by their allocation call, treat `nothrow`/`malloc`-backed ones as
> fallible and plain-`new` ones as infallible, and **state which assumption the
> finding rests on**, so a reader can overrule it in one step.

> **Second lesson — pair this with CWE-252.** The fix was not a length check.
> `InitVector` already returns `bool` and the caller discarded it; honouring
> that return closes the bounds issue at its source. An ignored return value
> whose loss enables an out-of-bounds access downstream is a stronger signal
> than either finding reported alone, and both halves are mechanically
> detectable.

### E. `new T[n]` where `n` can be runtime-zero — caught in isolation,
   missed in the wild, and the reason is provable

`math/src/sparseblockmatrix.cpp`, two sibling overloads of `initStructure`,
same shape:

```cpp
int SparseBlockMatrix::initStructure(int height, int size)
{
    ...
    m_msize = size;                    // caller-supplied, can be 0
    mp_indexes = new int[m_msize];     // new int[0]: legal, zero elements
    mp_indexes[0] = 0;                 // index 0 of a zero-length array — UB
}

void SparseBlockMatrix::initStructure(AdjacentMatrix& graph)
{
    m_msize = 0;
    for (ii = 0; ii < rows; ii++) m_msize += ...;   // rows == 0 -> loop skipped
    m_msize += rows;                                // still 0
    mp_indexes = new int[m_msize];                  // new int[0]
    mp_indexes[0] = 0;                              // same defect, reached differently
}
```

One overload reaches `m_msize == 0` through a caller-supplied parameter, the
other through an accumulation loop that degenerates to zero. The report caught
the second (confirmed by trace: the accumulation loop executes zero times —
`rows == 0` — immediately before the flagged write) but not the first; both
are the same defect and both needed the identical one-line guard.

**kordon result on the real file: 0 CWE-119/787 findings, before and after the
fix, on either overload.**

**First hypothesis — wrong, corrected here.** The initial read of this was
"kordon has no check for this shape at all." That is false, and a three-line
isolated fixture disproves it immediately:

```cpp
class BadInit {
public:
    void init(int size) {
        m_size = size;
        m_ptr = new int[m_size];   // size == 0 -> new int[0]
        m_ptr[0] = 1;              // index 0 of a zero-length array
    }
    ...
};
void use() { BadInit a; a.init(0); }
```

`clang-sa-bounds` (`clang-analyzer-alpha.security.ArrayBoundV2`) catches this
outright, with a full call-path trace:

```
CWE-787  medium  "Out of bound access to memory after the end of the heap area"
  Calling 'BadInit::init'
  Entered call from 'use'
  Access of the heap area at index 0, while it holds only 0 'int' element
CWE-416  high    "Use of memory allocated with size zero"
```

A `GuardedInit` sibling with `if (m_size > 0) { m_ptr[0] = 1; }` is correctly
silent — the check discriminates fixed from broken.

**So why does the real file miss it?** Isolated three ways to find out:

| Fixture | `clear()` before alloc? | Call site *in the same TU* reaching `size == 0`? | Caught? |
|---|---|---|---|
| `BadInit` | no | yes (`a.init(0)`) | ✅ CWE-787 |
| `testA` (adds `clear()` + a second sibling array, mirroring `mp_matr`/`mp_indexes`) | **yes** | yes | ✅ CWE-787 |
| `testB` (same body, no `clear()`) | no | **no** | ❌ nothing |

`clear()`, the sibling array, and the extra ownership bookkeeping are not what
defeats the checker — `testA` has all of that and is still caught. The single
variable that flips the result is **whether the translation unit being
analyzed contains a call site that reaches the zero-size path.** Both real
`initStructure` overloads are public API; every caller found in this repo lives
in a *different* translation unit (`tests/math/*.cpp`, and for the
`AdjacentMatrix&` overload, plugin code entirely outside `acl/`) — and none of
those callers pass `0` in any case. Without `--ctu`, clang-sa analyzes each TU
independently, so a public method with no exercising call in its own TU never
gets the path explored, regardless of how simple the defect is once you're
looking at the right five lines.

> **Correction of the earlier verdict.** This is not "no check exists" — it is
> "a check that works, gated on TU-local reachability that a public library
> method routinely fails to have." That is a much more specific, and more
> fixable, problem statement.
>
> **What would actually close this gap.** `--ctu` is the documented remedy for
> cross-function reasoning, but it should be evaluated specifically against
> this shape: a *zero-argument-cost* defect (five lines, no recursion, no
> pointer aliasing) that a single-TU run misses purely because the exercising
> call lives in a sibling TU. If `--ctu` recovers it, that is a concrete,
> reproducible justification for defaulting it on for library code with a
> test suite in a separate TU — which describes most of this codebase. (Not
> verified end-to-end in this session: a hand-built two-file `--ctu` compile
> database failed at the indexing step here, which reads as a fixture/tooling
> gap in how I built the compile database — worth someone getting a real CTU
> index built with the project's actual toolchain and re-running exactly this
> three-fixture comparison.)
>
> Absent `--ctu`, the cheap partial fix is a syntactic check that does not need
> path-sensitivity at all: `new T[n]` assigned to a member, immediately
> followed (no intervening `n > 0`/`n != 0` test) by an unconditional
> `member[0]` in the *same function*, regardless of whether any in-TU caller
> ever constrains `n`. That would have caught both real positions without
> needing a symbolic call path at all.

## Cross-cutting

1. **Traces are decisive.** The `codeflow` column reversed two of my verdicts
   (`vector.cpp:298`, `hgt:96`). Kordon's `events` field was empty on every
   finding in these runs — populating it is worth more than more findings.
2. **The flagged line is not always the defect.** Several positions marked an
   expression adjacent to the real issue; one comment described a different line
   entirely. Anchor confidence should be reported separately from finding
   confidence.
3. **A guard can create a bug.** `SiftClCache::sync_images` returns early from a
   `void` function when its overflow check trips, skipping `_gpu_pyr.resize()` —
   and the caller then indexes that vector with `operator[]`. Candidate check:
   *early return from a void function leaves a container unsized that a caller
   indexes unchecked.*
4. **Absence of findings needs the compile database.** The first kordon run had
   274 of 278 TUs failing to compile; its 62 "misses" were meaningless. The note
   kordon prints about this is correct and load-bearing — keep it prominent.
4b. **Header findings are dropped when the target is a `.cpp` — this is the
   single biggest usability trap found here.** Analyzing
   `matching/src/cpolinom2Dnormal.cpp` dropped **234** findings as external,
   among them every finding for the `CVector` defect that the whole CWE-401
   group was about. In C++ the class-level defects that matter most live in
   headers, so the default invocation hides exactly the findings worth having.
   `external_findings_dropped` is reported, but as a bare integer it reads as
   noise rather than "the thing you were looking for is in here". Suggestions,
   in order of value: include the dropped findings' *files* in the report;
   treat headers reachable from the analyzed TU as in-tree by default; or warn
   when the count is large relative to the reported findings.
   Directory targets reduce but do not remove this: analyzing `modules/math/src`
   still dropped **216** findings, because the headers live in `math/api/acl/`.
5. **Vendored code needs a scope flag.** `dcraw_loader.cpp` is imported dcraw
   with no tests; the project's rule is minimal local edits only. A per-path
   severity or suppression concept would match how teams actually triage.

---

## Measurement corpus — three trees, already on disk

Under `acl/comparison/` (trees are nested one level, e.g. `acl_raw/acl/`):

| Marker | `acl_raw` | `acl_fix` | `acl` |
|---|---|---|---|
| `rotation.cpp` guards (`isNullPointer` / `getRows() < 3`) | 0 | 3 | 4 |
| `matrix.cpp` real check after assert (`if (!condition)`) | 0 | 14 | 14 |
| `fco_vector.h` ownership flag / `unique_ptr` | 7 / 0 | 7 / 0 | 1 / 3 |

`acl_raw` is pre-fix and defective; `acl_fix` carries the globus-batch
remediations; **99 files differ** between them. This is very likely the pair
behind the README's "−5% low tier, −14% high tier on a tree where ~226 defects
were fixed".

`acl` (branch `certification_borisov`) is a third point: it has the globus fixes
*plus* the mosaic-report work, and it is the only tree where `fco_vector.h` was
converted. Note **`fco_vector.h` is byte-identical in `acl_raw` and `acl_fix`** —
both still carry the manual ownership flag — so the existing pair cannot measure
the CWE-401 ownership-flag check at all. The `acl` tree supplies that missing
before/after, and the isolated header pair used in §CWE-401 above (3 findings →
0) is the minimal version of it.

Practical note for any measurement run: target **directories, not `.cpp` files**,
or header findings are dropped as external — see cross-cutting item 4b.

---

# Fixtures — the ACL positions, reproduced in `testdata/`

Six fixtures, one per distinct shape above. All synthetic: no ACL source is
copied or quoted, and the origin of each is described generically in its header
comment. Every one carries both the defect and its corrected twin, because a
check that fires on both has found nothing.

Measured 2026-09-10, `kordon <dir> --all`, default flags, no `--ctu`, no
`--ikos`. This table is the only place the results live — the fixture headers
point here rather than repeating them.

| fixture | ACL section | must flag | found | must stay silent | wrongly flagged |
|---|---|---|---|---|---|
| `hoisted_guard/` | CWE-119 §C | 2 | **2** | 3 | **3** |
| `allocator_fallibility/` | CWE-119 §D | 2 | **0** | 3 | 0 |
| `empty_container_signal/` | CWE-119 §A, §B | 3 | **2** | 3 | 0 |
| `masked_underflow/` | CWE-191 | 7 | **5** | 6 | **1** |
| `saturating_overflow/` | CWE-190 | 3 | **1** | 3 | **2** |
| `fill_initialises/` | CWE-457 | 2 | **2** | 6 | 0 |

Counts are of positions the fixture's own comments mark, judged on the CWE the
fixture is about. Low-confidence `cppcoreguidelines-owning-memory` and
`special-member-functions` findings are excluded throughout: they fire once per
raw pointer on flawed and corrected functions alike, so they carry no verdict
either way — the same tier-0 noise `CLAUDE.md` records for `pro-bounds-*` and
`init-variables`.

One finding outside those two is excluded and should not be: `fill_initialises/`
draws a correct CWE-120 on `length_of_strcpy`, which copies from an unbounded
source into a 64-byte buffer. That is a real defect about bounds, and the
fixture is about initialisation — a reminder that "must stay silent" is only
ever silent *with respect to one class*, which is the same distinction the
by-check table in `CLAUDE.md` records about Juliet's `good` functions.

## The one confirmed bug: `hoisted_guard/`

**Reproduces exactly, and discriminates zero.** All five functions are flagged
by `kordon-unchecked-parallel-extent`, including all three that enforce the
precondition properly.

The cause is precise. The exemption is

    unless(hasAncestor(functionDecl(hasDescendant(
        ifStmt(hasCondition(hasDescendant(<the subscripted parameter>)))))))

— it requires an `ifStmt` whose condition *mentions the subscripted parameter*.
Hoisting the precondition into a `const bool` and writing `if (!condition)`
names the local and not the parameter, so the exemption never fires.
`testdata/parallel_extent/extent.cpp` covers the direct form and is already
exempt; the difference between the two files is the entire bug.

This matters more than its low confidence suggests, because of *where* it
fires: the commit that introduced this shape across the real codebase was the
remediation commit. The check is quiet on the functions still relying on a bare
assert and loud on the ones already fixed.

**Fix direction.** Follow the local: when an `ifStmt` condition names a
variable whose initialiser mentions the parameter, treat the property as
established. `add_unrelated_bool` is the control that must survive it — a local
bool that is branched on but says nothing about the operand's extent — so the
exemption has to key on what the condition establishes, not on the presence of
a bool.

## The one class with no detection at all: `allocator_fallibility/`

`image_corners` writes through a pointer that `new (std::nothrow)` may have
left null, and **nothing reports it** — no CWE-476, no CWE-119. The
`calloc(n, 0)` sibling, where the null check passes for a zero-element block,
is equally undetected.

Two things were learned building this one, and the second cost a measurement:

- The fixture originally read `use(v[0])` rather than writing. That fires on
  the array's *uninitialised contents* — `new double[n]` does not zero — which
  is a real defect, but a different one, and it fires identically on the
  infallible container. Measured: all three functions flagged, discrimination
  exactly zero. **The fixture looked like it was working.** This is the same
  trap `testdata/zero_length_ctu/README.md` records twice.
- Writing instead then produced a dead store, since nothing read the value
  back. The write-then-read pair is what isolates the null question.

So the `new` vs `new (std::nothrow)` discrimination the ACL notes call
un-adjudicable syntactically is not currently adjudicated at all, in either
direction. That is a cleaner problem statement than the notes had: there is no
false positive to fix here, only an absent check.

## Where Kordon is already right: `fill_initialises/`

**The vendor's false positive does not reproduce.** Not one of the six
correct functions draws a CWE-457 — not the `fread` case, not `memset`,
`memcpy` or `strcpy`, and not the object whose fields are set by a visible
`clear()`. The genuine uninitialised read beside them is reported at high
confidence by `core.uninitialized.Assign`, and the leak underneath the original
false positive is reported too.

This retires a work item. The ACL notes list "model the standard fill functions
as initialising their destination" as high value; Kordon's engines already do,
and the item was written from another tool's behaviour rather than from
Kordon's. **A lesson taken from a vendor report is a hypothesis about Kordon,
not a finding about it, until it is run.**

## Partial, with a specific gap named

**`masked_underflow/`** is the strongest of the six: 5 of 7, one false
positive. Both masked forms — the wrap widened to `double` and to `int64_t`,
where the comparison silently stops rejecting anything — are caught at medium.
The signed twins are correctly silent, so the type test works.

Two things it pins:

- **The twin problem reproduces.** Three overloads carry the identical
  `&&`-for-`||` guard bug; only the first is flagged. This is the shape the
  ACL notes call the highest-yield single addition, and here it is, measured:
  a defect found once and missed twice in the same file.
- **One false positive**, and it is the correct code: `std::max(w, 1) - 1`,
  the clamp applied to the operand rather than the result, is flagged. The
  defective sibling `std::max(w - 1, 1)` is flagged too, so this pair also
  discriminates zero.

**`empty_container_signal/`** finds both callers that index a container whose
emptiness is its only failure signal, and stays silent on all three correctly
defended forms — including the `init(n)` + `isNullPointer()` pair whose absence
produced a whole group of vendor false positives. The miss is the third shape:
an early return from a `void` function leaving a container unsized
(`resize_pyramid` / `build_pyramid`).

Worth noting for anchor quality: one finding lands inside `Vector::operator[]`
rather than at the caller that failed to check. That is cross-cutting item 2
above — the flagged line is not always the defect — showing up in Kordon's own
output.

## The weakest: `saturating_overflow/`

Both real shapes are essentially undetected and both silence cases are flagged,
so this fixture currently has no discrimination to speak of.

- `ftell` failure stored in a `size_t` is not reported as such. `load_whole_file`
  draws CWE-190 and CWE-252 at low confidence, but the CWE-252 is about the
  discarded `fseek`/`fread` results, not the negative return. `stream_length`,
  which is the defect on its own with nothing else in the function, draws only
  the CWE-252.
- Saturate-then-unsaturate (`padded_range`) draws **nothing at all**.
- `load_whole_file_checked`, which tests `n < 0` before widening, is flagged
  anyway.
- `pyramid_index` reproduces the vendor's own false positive: two expressions
  that wrap in lockstep preserve the relation between them, so no index goes
  out of range, and it is flagged three times.

The ACL notes call the `ftell` rule "narrow, mechanical, no false positives".
That remains plausible and is now testable — this fixture is the test.

## What is not here

`kordon-unchecked-parallel-extent` is unchanged, and so is every other check.
These are fixtures and a measurement, not a fix. In the repo's order of work
that is the correct first step — the check discipline is to pin the behaviour
before changing it — but the table above is a list of open items, not closed
ones. The `hoisted_guard` false positive is the one that should not wait: it is
a shipped check penalising code that was already repaired.
