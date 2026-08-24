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

## Early-exit guards: the limitation is closed (2026-08-21)

```cpp
if (in.width() == 0) { return false; }
...
r = in.width() - 1;        // cannot underflow here
```

`guard_clause` only understood a condition that *encloses* the use, so this
shape -- at least as common, since it is how preconditions are usually written
-- was reported anyway. It was carried in the fixture as a known false
positive.

**The clause that makes it safe** is requiring the subtraction not to be inside
the exempting condition. Without it the check exempts a defect using the
defect's own `if`:

```cpp
if ((x_begin > (width_in - 1)) || ...) { return; }
```

`width_in - 1` is evaluated *by* the guard, so a zero `width_in` underflows
before anything can protect it. Measured: the naive form suppressed 11
positions of which **2 were real defects the maintainers had fixed**; with the
clause it suppresses 6 and none of them are.

Ordering is not checked -- AST matchers cannot express "this statement precedes
that one" -- so any early exit naming the operand exempts every use of it in
the function. A use before the guard is wrongly exempted, erring toward
silence.

**The payoff was much larger than the suppression count suggests**, because it
let two checks confirm fixes they previously could not:

| check | before | after |
|---|---|---|
| `kordon-extent-underflow` | 45 -> 41, **-9%** | 44 -> 17, **-61%** |
| `kordon-unsigned-subtraction` | -2% | -8% |

Zero acted-on defects lost. The recorded CWE-190/191 limitation -- "treat these
as *can* overflow, not *is* unvalidated" -- was partly a gap in the guard
vocabulary rather than a fact about the defect class.

## Widening parallel-extent beyond parameters: rejected (2026-08-21)

The remaining CWE-119 "two containers" misses (13) subscript locals and members
rather than parameters. Both relaxations were measured and both fail:

| trigger | positions | specificity | new acted-on defects |
|---|---|---|---|
| parameters (shipped) | 181 | -17% | -- |
| + locals | 592 | **-4%** | +2 |
| members only | 234 | **+0%** | +4 |

Locals cost 411 findings for two defects and land near
`pro-bounds-pointer-arithmetic` territory; member containers are perfectly
inert. A local's extent is usually established by its own construction in the
same function, which is why subscripting it under an unrelated bound is normal
rather than suspicious. That cluster is not reachable by widening this shape.

## Scoping a run to one directory (2026-08-21)

`kordon <subdir> -p <db>` works and is the fast way to iterate: `modules/math`
takes **28s against ~10 minutes** for the full tree, with the compile database
still supplying every flag. The findings filter to the subtree exactly as they
filter to the analysis root for a whole project.

One caveat: `--ctu` under a subdirectory indexes only that subdirectory's
translation units, so a call into another module stays opaque. Directory
scoping is for iterating on a check; whole-tree runs are for measuring.

### What the first scoped comparison found

Running `modules/math` raw against fixed immediately surfaced two results that
pointed the wrong way, and both were real:

**The fix traded uninitialised variables for dead stores.**
`cppcoreguidelines-init-variables` drops 96% (213 -> 9) because the maintainers
added initialisers, and cppcheck then reports those initialisers as dead
stores: `unreadVariable` goes 15 -> 108, **+620%**. Both observations are
correct, and the trade is obviously worth it -- an uninitialised read is a
defect, a redundant initialiser is not.

**`unreadVariable` was mapped high confidence, and that was wrong.** It made
all 59 high-confidence findings on the corrected tree defensive initialisers,
so the detailed report inverted: high went **up** 119% on fixed code. Demoted
to low, and every signal agreed:

| | before | after |
|---|---|---|
| high | 27 -> 59 (**+119%**) | 15 -> 0 (**-100%**) |
| medium | 49 -> 9 | 49 -> 9 |
| detailed tier on fixed code | 68 | 9 |

Zero positions and zero acted-on defects lost. The check earns nothing by being
loud: across the whole tree it reaches 36 acted-on defects and is the only
check reaching **none** of them, while `clang-analyzer-deadcode.DeadStores`
covers the same ground at 9:1 and responds -82% to fixes.

The general lesson is the one this project keeps relearning: confidence has to
track whether the finding is a *defect*, not only whether the underlying fact
is certain. A dead store is certainly a dead store; that is not the same claim.

## Fault injection: shipped, and it did not find the defect that motivated it

Error paths are the least-tested code in most programs and no sanitizer reaches
them, because a sanitizer observes what a program does rather than changing
what it is asked to do. The `fault` profile changes that: an `LD_PRELOAD`
interposer fails the *n*th allocation and passes every other through, run once
per *n*, under valgrind.

Design points worth keeping:

- **Count first, then sweep.** A clean run is measured for how many
  allocations it makes, and the budget is sampled evenly across that range.
  Taking the first N would exercise only startup on a program that allocates a
  thousand times before doing any work.
- **A non-zero exit is not a finding.** Most injected failures make the program
  stop deliberately -- GMP aborts with "Cannot allocate memory" -- and that is
  the program working. Only what valgrind reports counts.
- **Attribution.** Each finding says which allocation had to fail, because
  otherwise it cannot be reproduced.
- **The interposer has its own bootstrap arena**, since `dlsym` allocates on
  some libcs and would otherwise recurse into the interposer during init.

### The honest result

Run against `lastbit`, whose `split_vector_ozaki` returns `void` and bails out
of a failed `malloc` without filling its caller's buffer: **a full sweep of all
1051 allocations, six minutes, found nothing.**

The mechanism is verified working -- the interposer compiles, counts 1051,
fails on demand, and valgrind XML is produced per run. Two hypotheses for the
miss were tested and both were wrong:

- *memcheck cannot see uninitialised floating point.* It can; verified on a
  minimal program where uninitialised `double` arithmetic reaching `printf`
  produces reports.
- *the error path is never reached.* It is; a size-targeted interposer fires
  six times on the relevant allocation. But that test was itself invalid --
  failing every `malloc(40)` also fails the caller's own buffer, which
  `dot_ozaki` null-checks, so the buggy path is skipped.

A third hypothesis was tested and also wrong: that `LD_PRELOAD` injection has
no effect under valgrind. It does -- forcing the first allocation to fail
changes the program's exit status and output under the wrapper, which is now
asserted before every sweep. What *does* shift under valgrind is the ordinal of
a given *size*: `malloc(24)` call number two is a different call site with
valgrind in the process than without, which is what made an earlier
size-targeted experiment look like proof that injection was inert.

**Why the full sweep misses this defect is still not established.** Recording
that as an open question rather than a conclusion: the mechanism is verified,
the error path is verified reachable, the detector is verified capable, and the
sweep still finds nothing. One of those is wrong and it is not yet known which.

### The safeguard that came out of it

A sweep that injects nothing reports zero findings, which reads exactly like a
program with no error-path defects -- the same failure mode as an uninstrumented
sanitizer build, and the same answer: check rather than assume. Before
sweeping, the profile runs the command once cleanly and once with allocation
one forced to fail. Failing the first allocation is close to guaranteed to
change *something* in any program that allocates at all, so no observable
difference means the injection is not reaching the program, and that is
reported as a failure instead of a clean result.

## Suppressions: keeping an engine's judgement, removing one wrong case (2026-08-21)

`bugprone-implicit-widening-of-multiplication-result` reported
`const std::ptrdiff_t defaultL1CacheSize = 32*1024;` as a potential overflow.
Both operands are literals, the product is 32768, and nothing about it depends
on input. Five such findings survived into Eigen's medium tier.

**Replacing the check was measured and rejected.** A `kordon-` matcher covering
the same ground -- an integer multiplication in a widening or pointer-offset
context, minus literal-times-literal -- scored exactly right on a probe (three
genuine cases, both false positives excluded) and then produced **326 positions
on the reference corpus against clang-tidy's 90, moving 0.3% between the broken
and corrected trees.** Trading 3 false positives for 236 inert findings is a
worse report.

The reason is worth stating: clang-tidy is right about the hard part. Deciding
*which* multiplications are implicitly widened is fiddly type reasoning, and it
does that correctly. It is wrong about exactly one narrow shape.

So Kordon gained a **suppression**: a matcher that removes another engine's
finding at a position, declared with the reason and counted in the report.

```
target:  bugprone-implicit-widening-of-multiplication-result
shape:   binaryOperator("*", hasLHS(integerLiteral), hasRHS(integerLiteral))
reason:  the product is fixed at compile time; a constant that genuinely
         overflows is reported by the compiler as -Winteger-overflow, which
         Kordon already ingests
```

That last clause is what makes it safe. `const long long x = 100000 * 100000;`
really does overflow, and clang diagnoses it independently -- verified -- so
suppressing the constant case loses nothing.

On Eigen's blas module: **medium 5 -> 2, nine raw findings suppressed**, and the
two survivors are genuine -- `(*n-1)*(*incx)` in `level1_impl.h`, runtime times
runtime used as a pointer offset. The reference corpus is unchanged.

### Two traps this hit on the way

`isIntegerConstantExpr()` would have been the natural matcher and **is not
registered in clang-query**: using it fails the whole matcher to parse and
returns zero, which reads as "nothing to suppress". There is now a test
asserting no suppression uses it.

And the suppression silently did nothing at first because its positions were
not canonicalized. clang-query reports the path as the compile database spells
it -- `blas/../Eigen/src/...` -- while findings are canonicalized on the way
into the report, so the keys never matched. Same class of bug as the cJSON
duplicate-path defect, in the opposite direction.

## Eigen blas: machine-generated code is a false-positive factory (2026-08-21)

64 TUs, 2 minutes, 816 in-scope findings -- and **24 of the 24 high-confidence
findings were false positives from a single structural cause.**

All of them landed in `blas/f2c/drotmg.c` and `srotmg.c`, reported by
`clang-analyzer-core.uninitialized.Assign` as reads of uninitialised values.
The variable in question, `dh11`, is assigned at three separate places and on
every path that reaches the use. What defeats the analyzer is how f2c
translates Fortran's assigned-`GOTO`:

```c
    igo_fmt = fmt_120;
    goto L70;          /* L70 assigns dh11, then dispatches back to L120 */
L120:
    dh11 /= gam;       /* reported uninitialised */
```

The dispatch runs through a state variable, so path-sensitive analysis cannot
follow it and explores paths that cannot happen. There are **18 f2c-translated
files** in that tree.

### Findings in generated code are now demoted

Not dropped -- the code compiles and runs, so a real defect there is still a
defect -- but demoted out of the tiers a reader acts on, because the fix
belongs in the generator or its input and the file is regenerated over any
edit. Detected from the banner every generator writes (`translated by f2c`,
`automatically generated`, `DO NOT EDIT`, and similar), read from the first 20
lines and cached per path.

Effect on the module: **high 24 -> 0, nothing lost**, 816 in-scope either way.
Zero files in the reference corpus carry such a banner, so the measured
baselines there are unaffected.

This is the third distinct concentration problem the same shape has produced --
`dcraw_loader.cpp` vendored into ACL, `qcustomplot.cpp` vendored into
GA_Practice, and now f2c output in Eigen. Code the author did not write and
cannot fix dominates the report unless something separates it out.

### The remaining 5 medium findings are also false

`bugprone-implicit-widening-of-multiplication-result` on
`const std::ptrdiff_t defaultL1CacheSize = 32*1024;` -- compile-time constants
nowhere near overflowing `int`. The check is syntactic and does not look at
operand values. Worth knowing before trusting that check on numeric code.

## Eigen: the static layer had no deadline (2026-08-21)

637 headers, 1310 translation units, and the hardest shape Kordon has been
pointed at -- header-only, heavily templated, where every TU instantiates an
enormous tree.

**The finding is a Kordon defect, not an Eigen one.** Measured on one test TU:

| | |
|---|---|
| plain `clang++ -c` | **11.5 s** |
| `clang-tidy` with Kordon's check set | **exceeded 9 minutes**, killed |

And nothing was stopping it taking nine hours. The dynamic layer has had a
deadline since MSan hung; the static layer -- the default path, the one that
always runs -- had none at all. On a project this size an unbounded per-unit
cost is not a slow run, it is a run that never returns, produces no output, and
gives no way to tell which unit was responsible.

`--tool-timeout` now bounds every clang-tidy invocation, defaulting to 600s.
A killed shard is reported, never silently dropped: clang-tidy writes its fixes
file only at the end, so a timeout loses that shard's findings entirely and the
report has to say so.

### The template explosion is real and mostly absorbed

| module | TUs | raw clang-tidy | in-scope | high | medium |
|---|---|---|---|---|---|
| demos | 6 | 5780 | 474 | 3 | 5 |
| bench | 3 | 7256 | 1537 | 3 | 4 |

Three translation units producing 7256 raw findings is what "header-only and
templated" does. Scoping and tiering absorb almost all of it -- 7 actionable
out of 7256 -- which is the tiering working as designed rather than a problem.

### Triage of what surfaced

- `GeneralBlockPanelKernel.h:29-31`, `bugprone-implicit-widening-of-multiplication-result`:
  **false positive**. The expression is `const std::ptrdiff_t defaultL1CacheSize = 32*1024;`
  -- compile-time constants nowhere near overflowing `int`. The check is
  syntactic and does not consider operand values.
- `BiCGSTAB.h:175`, `ConjugateGradient.h:178`, `SuperLUSupport.h:119`,
  `optin.cplusplus.UninitializedObject`: 4, 5 and 8 uninitialised fields at
  constructor exit. Almost certainly deliberate -- Eigen's solvers defer
  initialisation to `compute()` -- but it is exactly the CWE-665 shape
  CLAUDE.md targets, and a solver used before `compute()` reads them.
- `MatrixMarketIterator.h:219`, **our** `kordon-extent-underflow`: correct about
  the underflow, mild in consequence. `filename.substr(0, filename.length()-4)`
  underflows for names shorter than four characters; `substr` clamps the count,
  so the result is silently the whole string rather than a crash.

## The reachability gap is not closable by AST matching — measured (2026-08-21)

Prompted by the `parser.cpp:52` miss, an "unguarded container access" check was
prototyped and **abandoned on measurement**, not on taste. The result is worth
keeping so it is not attempted again.

The check: flag `top()`/`front()`/`back()`/`pop()` on a container member where
the enclosing function contains no `empty()`/`size()` call on that same member.
Same shape as every other `kordon-` check here.

On the one file it was written for:

| form | matches |
|---|---|
| trigger alone | **16** in a 200-line file |
| with the function-scope exemption | **0** |

Both numbers are useless, and the reason they are useless is the same fact.
`construct_node` *does* call `operands.size()` and `operations.size()` -- at
line 61, **after** the unguarded uses at 49 and 52. A function-scope exemption
cannot distinguish "checked before the use" from "checked after it", so it
exempts the very function containing the defect. Removing the exemption leaves
16 findings in 200 lines.

This is the ordering problem that has now blocked three separate checks
(`kordon-index-used-before-check` solved it only *within one expression*, where
short-circuit order is visible in the AST). AST matchers have no predicate for
"this statement precedes that one", and every workaround so far has been to
widen to function scope and accept erring toward silence. Here that erring
silences everything.

**So the remaining CWE-119/476 misses need a different mechanism, not a better
pattern.** The options are a real Clang SA checker plugin, which sees a CFG and
can answer reachability, or accepting the gap. What they do not need is another
matcher.

## PropositionalCalculusSolver: a found bug, and the one next to it (2026-08-21)

2820 lines of C++ AST/parser code. 19 in-scope findings, 4 high and 1 medium.
Two results matter, and they point in opposite directions.

### Kordon found a real bug

`parser.cpp:63`, via cppcheck's `containerOutOfBounds` mapped to CWE-119:

```cpp
if (operands.size() < 2 || operations.size() < 1)
{
    if (operations.top() == Token::OpenBracket ||    /* empty stack when the
        operations.top() == Token::CloseBracket)        right disjunct fired */
```

The guard fires *because* `operations` may be empty, and the body then calls
`top()` on it. `std::stack::top()` on an empty stack is undefined behaviour.

### And missed the one eleven lines above it

Built with `-fsanitize=address,undefined -D_GLIBCXX_ASSERTIONS` and fed one
character, the program aborts:

```
$ echo '!' | ./task1
stl_stack.h:232: std::stack<Expression>::top(): Assertion '!this->empty()' failed.
```

The backtrace lands in `construct_node`, and the failing call is **line 52**:

```cpp
if (operations.top() == Token::Negation)
{
    auto operand = operands.top();     /* line 52 -- operands is empty for "!" */
```

Kordon reported line 63 and nothing else in the file. Input `()` reaches the
same line. The project's real build is `-O3` with no assertions, where this is
silent UB rather than an abort.

### Why the gap is exactly where it is

cppcheck catches line 63 because the *guard contradicts the use*: a condition
saying "the stack may be empty" sits directly above a call requiring it not to
be. That is a syntactic contradiction, and detecting it needs no reasoning
about reachability.

Line 52 has no guard at all. Establishing that `operands` can be empty there
requires knowing that `parse` calls `construct_node` whenever `operations` is
non-empty, regardless of what `operands` holds -- interprocedural reasoning
about a loop in another function.

So the shape Kordon detects is **"a guard that contradicts its own body"**, and
the shape it misses is **"no guard, and emptiness is reachable from a caller"**.
The second is both more common and more dangerous, since nothing in the source
looks wrong at the use site. It is the same wall CWE-119 keeps hitting: the
remaining misses need range and reachability reasoning, not better patterns.

Worth noting the two-line fix for the project: hoist a
`if (operations.empty() || operands.empty()) throw` to the top of
`construct_node`, which closes both lines at once.

### Also: task2 does not compile

`src/task2.cpp:38` uses `binary_function_t`, which is defined nowhere in the
tree. Both g++ and clang reject it, so `make -f Makefile2` fails; the `task2`
binary in the working tree is a stale artefact from Nov 2024 that predates the
breakage. Kordon reported it honestly as "3 of 9 translation unit(s) FAILED TO
COMPILE and were not analyzed -- findings for them are absent, not clean".

## What the CP_practice sweep did and did not teach us (2026-08-21)

Worth being blunt about, because the honest answer is "less than the previous
two projects". DMP and cJSON each broke Kordon in a new way -- a GCC toolchain,
a build with several executables. These 17 are the same shape as each other:
small numerical C/C++, one author, similar habits. They exercised paths that
already worked.

**Kordon did not "find all the errors" there, and that is not a claim this
exercise can support.** The findings it made were verified; nothing was done to
look for defects it missed. Static silence is not evidence.

### Trying to falsify it produced the one real result

The single high-confidence defect -- `split_vector_ozaki` returning `void` and
bailing out of a failed `malloc` without filling its caller's buffer -- sits on
an **allocation-failure path**. Sanitizers cannot reach it, so:

- ASan + UBSan on the `--demo` path: **clean**.
- valgrind, `--track-origins=yes`: **0 errors from 0 contexts**.
- A `LD_PRELOAD` malloc interposer failing the *n*th allocation, swept across
  the full range of 79 allocations the run makes, under valgrind: **no runtime
  witness produced**.

So the static layer found a defect the dynamic layer structurally cannot reach,
and an ad-hoc fault injector could not reach either. That inverts the usual
story, where dynamic evidence confirms what static analysis suspects, and it is
the concrete argument for the fault-injection item CLAUDE.md lists: reaching
error paths needs deliberate failure injection wired into the runner, not a
better sanitizer.

### A gap the sweep did surface

**`--dynamic` requires CMake.** 4 of these 17 projects are Makefile-only, and
for those the dynamic layer skips every profile. The message is accurate and
the reason is real -- the layer builds its own instrumented variants -- but it
means an entire common build system gets no dynamic coverage at all. Supporting
it means either driving `make` with overridden `CC`/`CFLAGS`, which is what the
manual runs above did successfully, or requiring the user to supply a build
command.

## CP_practice: 17 projects, 175 TUs, 2 actionable findings (2026-08-21)

A sweep across one directory of numerical/computational practice projects, all
C or C++. 314 in-scope findings, of which **1 high and 1 medium** -- the rest
low-confidence risk patterns.

That ratio is the point. On code written by one author to one set of habits,
the detailed report stays nearly empty, which is what a tool that reports
honestly should do on mostly-correct code. The comparison worth making is with
`pro-bounds-*` on the reference corpus, where 3341 findings said nothing about
whether the code was right.

**The one real defect**, `lastbit/src/dotprod.c:171`, found by
`clang-analyzer-core.UndefinedBinaryOperatorResult` with a full path:

```c
static void split_vector_ozaki(const double* x, size_t n, size_t K, double* layers)
{
    ...
    double* rem = malloc(n * sizeof(double));
    if (!rem) { return; }        /* returns without filling `layers` */
```

The function returns `void`, so on allocation failure it leaves the caller's
output buffer completely uninitialized and has no way to say so. `dot_ozaki`
then reads `x_layers[i*n + k]` and multiplies garbage. The caller does check
its own two allocations -- there is simply no channel for this third failure to
travel back through.

This is the CWE-252 -> CWE-457 shape from CLAUDE.md seen in C: a fallible
operation with no way to report failure. Worth noting that the path-sensitive
engine found it and none of the pattern matchers could have, because nothing
about the syntax at line 171 is unusual.

**The one medium**, `n_body/gold.cpp:197`, is `cmd.erase(cmd.size() - 2)`,
flagged by `kordon-extent-underflow`. Correct as a claim and not a bug: `cmd`
is initialised to `"plot "` so it is never shorter than 5. The check cannot see
the initialiser, which is exactly what "no guard that the container is
non-empty" means.

### A noise source worth knowing about

`clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling` fires on
every `printf`, `fprintf`, `snprintf` and `fscanf`, recommending the C11 Annex K
`_s` variants that essentially only MSVC implements. It produced most of the
428 out-of-scope findings in this sweep. It is unmapped, so Kordon already
keeps it out of the report -- but it inflates the raw counts and the coverage-gap
list on any C project.

## AvlTree: a validation datapoint for transfer-to-non-owner (2026-08-21)

2500-line header-heavy C++ template project. 25 in-scope findings, 2 high and 1
medium, all three in test code rather than the library.

The useful result is what stayed quiet. `cppcoreguidelines-owning-memory` fires
**13 times** on `tree.insert(new AvlTreeNode<int>(value))` -- syntactically
identical to the GA_Practice defect that motivated
`kordon-transfer-to-non-owner`. Our check fires **zero** times, correctly:
`AvlTreeBase` declares `~AvlTreeBase()` and releases its nodes through
`safe_delete`, so there is a release path and no claim to make. That is the
distinction the check was built on, holding up on code it was not tuned against.

The three findings triaged:

- `TestAvlTree.cpp:69` `'tree' used after it was moved` -- **intentional**. The
  test asserts the moved-from tree has a null root, which is a legitimate use
  of a moved-from object whose post-move state is specified.
- `TestAvlTree.cpp:89` and `:113` null-pointer calls -- mild and real. The test
  dereferences `tree.root_` without checking it, so a regression in `insert`
  would segfault the suite instead of failing a test cleanly.

### The compile failure was the real find

Kordon reported "1 of 5 translation unit(s) FAILED TO COMPILE and were not
analyzed -- findings for them are absent, not clean", and that was accurate:
`AvlTreeImplementation.hpp` uses `std::exchange` four times and never includes
`<utility>`. The four test units compile only because gtest pulls it in
transitively; `src/core/main.cpp` does not, and fails.

Worth recording against the **pkta open question** ("51 files failing in batch
that compile cleanly individually"). The individual check that produced that
observation may have been run the way this one initially was -- with
`--checks='-*'`, which makes clang-tidy exit with "no checks enabled" before
compiling anything and report zero errors. A file that never gets parsed looks
exactly like a file that parses cleanly.

## A confirmed crash found on CompensationSum (2026-08-21)

23-file mixed C/C++ numerical project. Kordon produced 64 in-scope findings, 62
low and **2 medium** -- and both medium findings are the same real defect, in
`exact_sum.c:32` and `exact_dot.c:37`:

```c
int max_exp = -1074;                 /* sentinels: lowest/highest double exponent */
int min_exp = 1023;
for (size_t i = 0; i < size; ++i) {
    if (array[i] == 0.0) continue;   /* zeros never update the sentinels */
    ...
}
mp_bitcnt_t range = (mp_bitcnt_t)(max_exp - min_exp + 53);
```

An array of all zeros passes the `size == 0 && array == NULL` guard, skips
every iteration, and leaves the sentinels untouched. The arithmetic then runs
in `int`: `-1074 - 1023 + 53 = -2044`, cast to a 64-bit unsigned bit count as
**18446744073709549572**, and handed to `mpf_init2`. The `if (precision <
65536)` floor does not catch it -- the value is enormous, not small.

Reproduced, not inferred:

```
$ ./zsum          # exact_sum(double[4]{0,0,0,0}, 4)
GNU MP: Cannot allocate memory (size=2305843009213693736)
Aborted (core dumped)
```

2.3 exabytes. `exact_dot` is easier to trigger still, since its skip condition
is `x[i] == 0.0 || y[i] == 0.0` -- either vector being all zeros suffices.

Found by `bugprone-misplaced-widening-cast`, mapped to CWE-190. Worth noting
which checks did *not* find it: `kordon-unsigned-subtraction` does not fire
because the subtraction is on `int`, not an unsigned type, so the underflow
happens at the cast rather than in the arithmetic. The mapping table earning
its keep -- a clang-tidy check nobody would call a memory-safety check
producing the only real defect on the project.

## Two CTU bugs found by running on open source (2026-08-21)

Running Kordon on cJSON (23 TUs) and tinyxml2 surfaced two defects in Kordon
itself. Both were found the same way: a number that looked plausible and was
not. `clang-sa-ctu ok, 0 raw findings` on a 5000-line C parser is believable
right up until you run the same checkers by hand and get ten.

### 1. One ambiguous symbol silently voided the entire CTU pass

`externalDefMap.txt` had 135 entries for 116 distinct keys, and `9:c:@F@main`
appeared **20 times** -- cJSON builds 20 test executables. Given a duplicated
key clang does not skip the entry: it rejects the whole index, prints
`multiple definitions are found for the same key in index`, writes no output at
all, and **exits 0**.

The index builder did call `dedup()`, which removes identical lines only. A USR
pointing at two *different* units survives that, which is exactly the `main`
case. Now grouped by USR, and any symbol with more than one definition is
dropped and counted -- an ambiguous key carries no information anyway, since
nothing can say which definition a call resolves to, and `main` is never a CTU
target because nothing calls it.

Effect on cJSON: **0 findings -> 13**, and 0 plists -> 23. Any project building
more than one executable was affected, which is most of them.

### 2. A total analysis failure was reported as a clean run

Kordon said `clang-sa-ctu ok, 0 raw findings` for a pass that produced nothing.
The runner counted findings, and zero findings from zero output is
indistinguishable from zero findings from a clean project.

The analyzer writes one plist per translation unit even when it has nothing to
say, so no plists at all is a reliable signal that it never ran. That is now a
`Failed` outcome naming the unit count, not a `Ran` with an empty list.

This one matters more than the first. The index bug cost findings; this bug is
the failure mode the whole reporting design exists to prevent, and it was
sitting in the engine that produces the highest-confidence results.

**What the pair says about method**: both bugs were invisible from the inside.
The fixture corpus passes, the ACL corpus produces hundreds of CTU findings,
and 99 unit tests are green -- because the reference codebase happens to build
one executable. Only an unfamiliar project shaped differently exposed it.

## GCC-built projects: the compile database needed normalizing (2026-08-21)

Kordon's static engines are clang frontends, but plenty of projects build with
GCC -- every out-of-tree kernel module, for a start. Their compile databases
carry flags clang has no equivalent for, and clang does not skip them: it
errors, so **every** translation unit fails and the run looks like a broken
project rather than an incompatible database.

Measured on a 217-line kernel module: **20 GCC-only flags**, including
`-mpreferred-stack-boundary=3`, `-mindirect-branch=thunk-extern`,
`-fno-allow-store-data-races`, `-fconserve-stack`, `-fsanitize=bounds-strict`
and a dozen `-Wno-` options clang does not know. Removing them takes clang from
"unknown argument" on every unit to a clean parse.

`CompileDb::load` now strips them and, when it strips anything, writes a
rewritten copy for the tools that read the database themselves. The dropped
flags are named in the report -- the analysis ran on slightly different flags
than the build did, and that is the reader's business. An already-clang
database is passed through untouched.

Deliberately a deny-list rather than an allow-list: dropping a flag clang would
have accepted changes what gets analysed, so the conservative error is to keep
too much and let clang complain about one unit.

This is the mirror of a problem already recorded here from the other side --
a clang-generated database breaking gcc's analyzer under CodeChecker. Compile
databases are not compiler-neutral, in either direction.

## A real defect Kordon missed, and why (2026-08-21)

The same kernel module contains two serious bugs that Kordon reported nothing
about:

```c
struct dm_dev *device = kmalloc(sizeof(struct dm_dev), GFP_KERNEL);
if (device == NULL) { ... return -ENOMEM; }
const int status = dm_get_device(ti, argv[0], mode, &device);   /* overwrites */
...
ti->private = device;
```

`dm_get_device(..., struct dm_dev **result)` is an out-parameter; the
device-mapper core allocates and owns the `dm_dev`. So the `kmalloc` result is
overwritten and leaked (CWE-401), and worse, the destructor does
`dm_put_device(ti, device); kfree(device);` -- calling `kfree` on memory the
core owns and the module never allocated (CWE-590). That is allocator
corruption, not a leak.

Clang SA cannot see it: `dm_get_device` is declared in a header and defined in
the kernel, so passing `&device` to an opaque function makes it assume the
pointer escapes and stop reasoning.

**A check for the shape was prototyped and not shipped.** "A local initialised
from an allocator whose address is then passed to a function, with no release
in between" works exactly on a clean C probe -- flags the defect, stays silent
on both the correct version and the freed-first version. It reaches **zero** of
the real cases, because `kmalloc` in kernel 6.14 expands through macros that
`ignoringParenCasts` does not see through, and the initialiser never matches.
Shipping a check that misses the defect that motivated it would be worse than
not having it.

Two matcher traps cost time here and are worth not repeating:
`matchesName` matches the **qualified** name, so `^malloc$` never matches
`::malloc` -- anchors silently disable the clause. And an unbalanced paren in a
matcher makes clang-query return zero rather than an error, which is
indistinguishable from a clean codebase.

## kordon-transfer-to-non-owner: the Qt-noise gap (2026-08-21)

Running Kordon on a small Qt/genetic-algorithm project produced 13 CWE-401
findings that were **all** Qt parent-child false positives -- `new QAction(this)`
and friends, which Qt reparents and owns correctly -- while missing the one
real leak in the same file:

```cpp
GeneticAlgorithm algorithm(
    initial_size, max_generations, mut_p, cross_p,
    new RouletteWheel,
    new MixerCrossover(0.5, left, right),
    new SubstanceMutation(left, right),
    new PolynomialEvaluator(polynomial),
    left, right, polynomial);
```

`GeneticAlgorithm` stores all four in raw pointer members and declares no
destructor. Four objects leak per construction, and the construction is a
button-click handler. Verified by reading the class: no `~GeneticAlgorithm`, no
`delete` anywhere, and the same project's `Generation` class *does* hold
`std::unique_ptr`, so the author knew the idiom and did not apply it here.

**Two engines should have caught it and structurally cannot:**

- `cppcoreguidelines-owning-memory` fires on a `new` *assigned* to a non-owner.
  These are constructor arguments, never assigned. It was silent here while
  producing five findings on Qt widgets in the same file that are correct.
- `cppcoreguidelines-special-member-functions` fires when a class declares
  *some* special member and omits the rest. This class declares none at all --
  the worse case, and the invisible one.

The check keys on a structural fact rather than a heuristic: not "this pointer
looks owned" but "this class has no release path, and was just handed something
that needs one". `unless(isImplicit())` on the destructor is load-bearing --
clang synthesises one for every class, so without it the matcher matches
nothing and the check never fires.

Measured: **2 findings on the project that motivated it, both genuine**, the
same defect reached from the GUI and the CLI entry point. **Zero across 452
translation units of the reference corpus**, where the shape does not occur --
so it costs nothing to run.

Not covered: a class that declares a destructor which frees some members and
forgets this one. That needs the release path matched per field; this answers
the cruder question first.

## kordon-dead-store: work computed and thrown away (2026-08-21)

Written because `clang-analyzer-deadcode.DeadStores` misses the shape that
matters most, verified rather than assumed: it reports a plain
`v = compute();` that is never read, and says nothing about

```cpp
int var = 0;
for (int i = 0; i < n; ++i) { sum += i * 10.0; var += i; }
return sum;                      // var never used: every += is dead
```

because the compound assignment reads `var` and its liveness analysis stops
there.

**Defining "read" is the whole check.** The obvious definition -- a reference
wrapped in an lvalue-to-rvalue `ImplicitCastExpr` -- works and is wrong. Inside
an uninstantiated template the expression is type-dependent and carries no
cast, so *every accumulator in every template header reads as dead*. It was
caught by checking a finding rather than trusting the number:
`filter_convolution.hpp` had `sum` reported, and `sum` is consumed two lines
later by `line_data.dataOut[x] = sum;`.

The formulation that works needs no cast and behaves identically in both
contexts: **a read is any reference that is not the left side of an assignment
to that same variable.** The left side of `sum += x` is deliberately not a
read -- a compound assignment does read, but only to feed the same variable, so
a value that never leaves that cycle was still never used.

One more exclusion, also from a checked finding: the assignment's own value
must not be consumed. `while ((len -= 8) >= 0)` reads the result through the
comparison.

Measured across 452 translation units: **46 positions on the broken tree, 12 on
the corrected one (-74%)**, reaching 34 defects the maintainers acted on --
**1.4:1, the sharpest ratio of any check here**, and the strongest
responsiveness.

### The best find is a shape nobody was looking for

```cpp
inline void KrenTangage_to_TiltKursN(TYPE tangage, TYPE kren,
                                     double Tilt, double KursN)
{
    Tilt  = radian_to_angle(asin(...));
    KursN = radian_to_angle(atan2(...));
}
```

Both outputs are taken **by value**. The function computes two results,
discards them, and returns void; every caller gets nothing. Somebody meant
`double &`. No other engine reports it, and it is why parameters are
deliberately *included* rather than excluded -- a reference parameter is not
matched, because `hasType(builtinType())` does not match a reference type, so
the correct idiom stays silent while the missing `&` does not.

## Uninitialised variables: the split already exists, one level down

Promoting `cppcoreguidelines-init-variables` to high was considered and
rejected on measurement: **1500 findings on the reference corpus, reaching zero
acted-on defects, zero of them exclusively.** It would have quadrupled the
detailed tier for no gain.

The reason is that it does not report the defect. `int x;` on its own is not
one -- `int x; if (c) x = 1; else x = 2;` is correct -- and flagging every
uninitialised declaration is a style rule. The actual defect is *reading*
before writing, which is path-sensitive, and those checks are already high:
`clang-analyzer-core.uninitialized.{Assign,Branch,UndefReturn,ArraySubscript}`.

So the tiering the ask wants is in place, just drawn one level lower than the
name suggests: declaration-without-initialiser is low, read-before-write is
high.

## CWE-563: splitting dead stores by what the store cost (2026-08-21)

Measured on clang 18 rather than assumed. `clang-analyzer-deadcode.DeadStores`
already discards the case that is idiomatic rather than wrong:

| form | reported |
|---|---|
| `double w = 0.0;` overwritten | **no** |
| `double w = 3.14159;` overwritten | **no** |
| `int n = 0;` overwritten | **no** |
| `double w = compute();` overwritten | yes, "during its initialization" |
| `v = compute();` never read | yes, plain message |

So the analyzer's own distinction is better than the syntactic one it is
tempting to write. A rule keying on "does a type appear in front" would demote
`double w = compute();` -- a genuinely wasted call -- purely for being a
declaration, and would have to special-case constant initialisers back out
again. Clang already asks the question that matters: was work thrown away.

Mapped accordingly:

- plain "Value stored to 'x' is never read" -> **high**. A value produced and
  discarded, with no benign reading.
- "during its initialization" -> **medium**. A wasted call, which may be a
  deliberate default that a branch usually replaces.
- `cppcheck redundantInitialization` -> **low**. The defensive-initializer case
  by name.
- `cppcheck unreadVariable` -> **low**, as before.

On `modules/math` the detailed tier now moves **64 -> 9, -86%**, with high
going to zero on corrected code.

### `double w{}` is not a fix for this

Value-initialisation and `= 0.0` are the same thing for a double, and neither
is reported. `{}` is better style -- it refuses narrowing conversions and reads
the same in generic code -- but it has no bearing on dead-store analysis. The
only thing that removes the store is not writing it: declare at first use.

### What the demotion of `unreadVariable` costs

cppcheck uniquely catches the accumulator shape:

```cpp
for (int i = 0; i < 10; ++i) { sum += i * 10.0; var += i; }   // var never read
return sum;
```

Clang reports nothing here; `unreadVariable` reports both the declaration and
the compound assignment. That is a genuine defect and it now sits in the low
tier. The trade is still right on measurement -- across the whole tree
`unreadVariable` reaches 36 acted-on defects and is the only check reaching
none of them exclusively, and it rises 72% on corrected code -- but the cost is
real and worth recording rather than discovering later.

## The dynamic layer (2026-08-21)

Built as a separate layer from `src/tools`, with its own report section above
the static findings and `Proof::Refuted` on every finding. Three profiles:
`asan` (ASan + LSan + UBSan in one instrumented build), `msan`, `valgrind`.

Verified end to end against `testdata/dynamic/`, a small CTest project where
each program commits exactly one defect. ASan observes CWE-401/416/787/190;
valgrind observes CWE-401/416/125/457 -- including the uninitialised read that
ASan structurally cannot see, since it tracks addressability rather than
definedness.

### Things measurement forced

- **Frames are `FILE:LINE:COL` at -O0 and `FILE:LINE` at -O1.** Requiring the
  column dropped every ASan frame in an optimised build, and a report whose
  frames are all dropped is discarded as frameless -- so the defect vanished
  while the run looked clean.
- **Both output streams must be read.** A sanitizer writes to the child's
  stderr; `ctest --output-on-failure` captures that and re-prints it on its own
  stdout. Reading stderr alone finds nothing.
- **valgrind needs `--trace-children=yes`.** Wrapping a test harness without it
  traces the harness, reports nothing, and reads exactly like a clean run.
- **UBSan ids must be curated, not derived.** Its messages embed addresses, so
  an id built from the text differs every run and nothing dedups or maps.
  `UBSAN_PHRASES` is the same curation the cppcheck CWE overrides are.
- **The leak fixture needs `opaque_malloc`.** At -O1 clang deletes a malloc
  whose result is unused, and the fixture then reports nothing. It must also
  *not* store the pointer in a global -- still-reachable memory is not a leak
  to either engine. The static leak fixtures need the opposite, which is the
  `_static`/`_runtime` split already recorded here, seen from the other side.

### MSan is unreliable on this host, and that is reported not hidden

It hangs symbolizing its own report: reliably with
`-fsanitize-memory-track-origins` (now removed from the profile), and
intermittently without -- the same binary completed one run and hung the next.
Every run therefore has a deadline, and a timeout produces a FAILED line naming
it. A hung sanitizer is indistinguishable from a slow test suite, and both are
indistinguishable from a clean result if nothing watches the clock.

**Pinning clang is done only for MSan**, which has no g++ equivalent. Pinning it
for ASan too also switched the symbolizer, and LLVM's hangs here where GCC's
addr2line path does not -- turning a working profile into a timeout. That is
the second time in this project that forcing a toolchain choice changed
something other than the thing intended; the first was the clang-specific
compile database breaking gcc's analyzer.

### Classification

valgrind's `InvalidRead` covers both CWE-125 and CWE-416 and only its
`<auxwhat>` says which, so that text is carried into the message and the table
discriminates on it -- the same mechanism the cppcheck overrides use.

`--require-cwe` now spans both layers. The dynamic layer is deliberately kept
out of the static findings list, and leaving it out of the selftest as well
would have reintroduced exactly the failure that flag exists to prevent.

## Coverage as of 2026-08-21

Two denominators, because they disagree and both matter. "Reported" is every
position the reference tool listed; "acted on" is the subset whose site or
immediate context changed between the broken and corrected trees.

| basis | coverage |
|---|---|
| vs everything the reference tool reported | **245/379 = 65%** |
| vs defects the maintainers actually fixed | **131/176 = 74%** |
| function level (within 25 lines) | 343/379 = 91% |

| CWE | reported | acted on |
|---|---|---|
| 763 | 4/4 100% | 4/4 100% |
| 369 | 3/3 100% | 3/3 100% |
| 416 | 1/1 100% | 1/1 100% |
| 191 | 59/60 98% | 31/32 97% |
| 190 | 28/30 93% | 6/7 86% |
| 457 | 25/27 93% | 10/12 83% |
| 476 | 11/12 92% | 5/6 83% |
| 563 | 69/74 93% | 53/56 95% |
| **119** | **44/86 51%** | 20/33 61% |
| **401** | **6/86 7%** | 2/25 8% |
| 415 | 0/1 | 0/1 -- confirmed false positive, silence is correct |

Everything except CWE-119 and CWE-401 is at or above 83% against acted-on
defects. Those two are the whole remaining gap, and they are not the same kind
of gap:

- **CWE-401's 7% is largely correct and will not move.** Its ground truth is
  dominated by positions on a closing brace -- leak-at-end-of-scope for locals
  of RAII classes that free in their destructors. Confirmed false positives.
  The real defects in that class are found, but reported per-class rather than
  per-line, so a line-keyed score cannot see them.
- **CWE-119's 51% is a real gap.** Breakdown of the 42 remaining misses:
  constant index on `operator[]` 25, two containers 13, single subscript 10,
  and one non-subscript. The `operator[]` constant-index family is the largest
  and was measured and rejected: including it doubled ground-truth reach and
  took specificity from -81% to -13%.

Report shape at these numbers: **441 detailed findings covering 104 acted-on
defects (4.2:1)**, with 6669 summarized low-confidence findings behind them.

## Measured results

Ground truth: `/home/shard/VsCode/acl/report/problems.md` — **280 confirmed
positions** (`(CWE, file, line)`), 104 excluded as false positives. Parsed to
`tmp/confirmed.json`. Raw list is 714 records → 384 unique.

**Full ACL tree**, current (`tmp/now2.json`, CTU on, IKOS off per the audit).
Three numbers, because one does not describe it honestly:

| measured against | result |
|---|---|
| the full 280-position list | 167/280 = **59.6%** |
| excluding the two classes the author confirms are mostly false positives (401, 415) | 157/213 = **73.7%** |
| the 52 positions the author's own triage lists as *still open real defects* | **49/52 = 94%** at function level, 26/52 = 50% at the exact line |

The third is the one that answers "does it find real bugs". The gap between 94%
and 50% is anchoring, not detection: the reference tool reports many defects at
the enclosing function's header while Kordon reports them at the offending
statement. Window sensitivity, for honesty:

| window | matched |
|---|---|
| ±3 lines | 26/52 (50%) |
| ±10 | 37/52 (71%) |
| ±20 | 41/52 (79%) |
| ±40 | 47/52 (90%) |
| ±60 | 49/52 (94%) |

Only 3 of the 52 are missed outright: one CWE-190 and two CWE-191.

Per-class against the still-open list: CWE-119 7/7, CWE-457 13/13, CWE-563
29/29, CWE-190 0/1, CWE-191 0/2.

**Precision is the counterweight**: 7 422 visible in-scope findings — 228 high,
96 medium, 7 098 low. Roughly 44 findings per real position.

**The CWE-415 "1/1" is a false match, not a detection.** The code there is

```cpp
Image& Image::operator=(const Image& other) {
    if (d == other.d) return *this;   // self-assignment IS handled
```

`bugprone-unhandled-self-assignment` recognises only the `this != &other`
idiom, so it reports this pimpl-comparison guard anyway. Independently verified,
and it agrees with the maintainers having already dismissed the position. Six of
that check's fifteen findings on this corpus are guarded code. Count real recall
as **166/280**, not 167.

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

## CWE-401 is mostly the reference tool's false positives

Confirmed with the codebase author. The 66 recorded CWE-401 positions are not
66 defects: nearly all sit at a closing brace, the scope exit of an unrelated
function that merely held a `Matrix` or `Vector` local. Nothing in those
functions is wrong. They are the classic RAII false positive CLAUDE.md predicts
— a tool that cannot pair `new` in a constructor with `delete` in a destructor
and flags it anyway.

**So Kordon's low CWE-401 recall is largely correct behaviour, not a gap.**
Chasing it would mean reproducing another tool's false positives. Read the
numbers accordingly:

| metric | value |
|---|---|
| headline recall | 162/280 = **57.9%** |
| recall excluding CWE-401 | 153/214 = **71.5%** |

What Kordon reports instead is the *cause*: `kordon-manual-ownership-flag`
matches a `delete` of a pointer member gated on a bool member — 5 findings on
the broken tree, **0 on the corrected tree**, where the fix deleted the flag and
moved ownership into a member smart pointer. Five actionable class-level
findings replace 66 unactionable site reports, and fixing them removes all 66.

This will not move a line-keyed recall score, because the ground truth records
effects and the check finds causes. That is a property of the measurement.

**Remaining non-401 misses: 61, of which CWE-119 is 43 (70%).** That is now the
whole game, and it is precisely what abstract interpretation addresses.

## Loop-shaped false positives — fixed, and worth little on this corpus

Four shapes were reported as defects and are not:

```cpp
while (k > 0)  { use(k - 1); --k; }              // guard is a while condition
while (k != 0) { use(k - 1); --k; }
for (std::size_t i = n; i > 0; --i) use(i - 1);  // guard is a for condition
for (std::size_t i = 1; i < n; ++i) use(i - 1);  // guard is the initialiser
for (std::size_t i = 0; i + 1 < v.size(); ++i) use(v[i + 1]);  // counter + 1
```

`do`/`while` is deliberately still reported: its condition runs after the body,
so the first iteration is genuinely unguarded.

All confirmed to cost nothing — CWE-191 stays 49/52, CWE-190 stays 17/19.

**But the whole-tree effect is negligible: 7 422 visible findings to 7 395,
about -0.4%.** The per-file measurements taken while developing these looked
much larger and were comparing against a guard-blind matcher, not against the
shipped one. On this corpus the noise lives almost entirely in `pro-bounds-*`
and the other prolific checks, and loop idioms are a rounding error against it.

They mattered elsewhere: on a Qt project two of the three findings in the
project's own code were exactly these shapes. Worth having for correctness, not
as a route to a quieter report on a numerical library.

## The 42:1 ratio was measuring the wrong thing

Splitting it by what the report actually shows:

| tier | findings | positions found | ratio |
|---|---|---|---|
| **detailed in the report** | 324 | 78 | **4.2:1** |
| summarized low tier | 7 098 | +89 more | — |

The detailed report is not noisy. What is true instead is that **89 real
positions are only reachable through the summarized tier** — including every
CWE-191 (49) and every CWE-190 (17), because Kordon's own checks are low
confidence by design: intent is undecidable, so they can never be promoted.

So the problem is not "too much noise in the report", it is "more than half the
detections are in the part nobody reads". Cutting checks would make it worse:
the only source of those 49 CWE-191 positions is a check that emits 1 868
findings.

What does help is that the low tier is heavily **clustered**: half of its 7 098
findings sit in 17 of 401 files, and the largest single contributor is
`dcraw_loader.cpp` with 1 107 — a vendored raw-image decoder. The report now
says so, because "7 000 findings" is a number to despair at while "half are in
17 files, the biggest of which is third-party" is two or three decisions.

Per-check yield, measured, for anyone tempted to prune:

| check | findings | positions | covers still-open defects |
|---|---|---|---|
| `clang-analyzer-deadcode.DeadStores` | 144 | 46 | 29 |
| `unreadVariable` | 121 | 26 | 7 |
| `kordon-unsigned-subtraction` | 1 868 | 49 | 0 |
| `kordon-unsigned-addition` | 3 265 | 17 | 0 |
| `pro-bounds-pointer-arithmetic` | 3 798 | 15 | 7 |
| `cppcoreguidelines-init-variables` | 1 500 | 3 | 7 |
| `cppcoreguidelines-special-member-functions` | 985 | **0** | **0** |

`special-member-functions` is the one clear candidate for removal — 985 findings,
nothing matched, nothing covered — but it is also the only check for the
Rule-of-Five double-free class, which this corpus happens not to contain. That
is the general difficulty with pruning on one corpus.

## The precision problem — measured properly (2026-08-20)

### The 42:1 headline was measuring against the wrong ground truth

The reference tool's report is not a list of defects; it is a list of one
tool's warnings. Scoring against it rewards agreeing with another
shape-counter. A better basis is available: **the defects the maintainers
actually acted on**, found by checking whether the site or its immediate
context changed between `acl_raw` and `acl_fix`.

Of 384 ground-truth positions, **176 were acted on and 203 were not.** The
context window matters -- comparing the statement alone misses fixes made by
adding a guard around it, which is how the whole `vector.cpp` family was
corrected. Sanity-checked against `vector.cpp:327`, a known guard-added fix.

Against that basis the tool looks very different, and much better:

| tier | findings | defects actually fixed | ratio |
|---|---|---|---|
| detailed by default (high+medium) | 339 | 81 | **4.2:1** |
| summarized (low) | 7091 | 47 | **150:1** |

**The default report was never the problem.** 4.2:1 is good. The problem was
that 47 real defects were invisible behind 7091 low-confidence findings.

### What does not work, measured

Generic ranking of the low tier fails. Three signals were tested:

| signal | lift |
|---|---|
| number of distinct checks stacked on one position | 2.2% -> 2.6% -> 0.0% (none) |
| within 15 lines of a high/medium finding | 1.8% -> 4.1% (real, but on a hopeless base rate) |
| how few findings the file has | 57:1 -> 26:1 for the sparsest bucket only |

There is no metadata signal to rank on. Suppressing the noisiest file
(`dcraw_loader.cpp`, 1106 low findings) would have cost 19 real positions.

**Responsiveness splits cleanly by engine kind, and the existing tiering already
tracks it.** Path-sensitive engines: DeadStores -82%, `unix.Malloc` -100%,
`NullDereference` -58%, `UninitializedObject` -62%, but volumes of 12-173.
AST matchers: pointer-arithmetic -3%, unsigned-addition -0%, narrowing -0%,
array-to-pointer-decay 0%. The one responsive matcher is `init-variables` at
-29%. The low tier is inert *by construction*; it is a risk register, and no
tuning turns it into a defect list.

### What does work: narrow a shape until its precision changes tier

`x.width() - 1` and `n - 1` are the same expression and different propositions.
An empty container reports 0, and 0 - 1 unsigned is the type maximum; a
variable named `n` carries no such invariant. Splitting on that:

| left operand | positions | defects actually fixed | ratio |
|---|---|---|---|
| a container-extent accessor | 46 | 21 | **2:1** |
| anything else | 332 | 8 | 41:1 |

Twentyfold, and 2:1 beats the entire high-confidence tier. Shipped as
`kordon-extent-underflow` at medium confidence, excluded from the general
check so no site is reported twice.

### Net effect

| | before | after |
|---|---|---|
| detailed report | 339 findings, 81 real | **404 findings, 103 real** |
| ratio | 4.2:1 | **3.9:1** |
| real defects buried in the low tier | 47 | **26** |
| total in-scope findings | 7430 | 7001 (-6%) |

More real defects visible and a better ratio at the same time -- because the
gain came from re-tiering 21 defects that were already found, not from adding
volume. `pro-bounds-array-to-pointer-decay` was also removed outright: 622
findings, zero acted-on defects, zero exclusive coverage, 0% responsiveness.

### What is left, and what it would cost

The 26 still-buried defects sit behind these checks:

| check | buried defects | low-tier volume | cost each |
|---|---|---|---|
| `pro-bounds-pointer-arithmetic` | 8 | 3782 | 472 |
| `kordon-unsigned-addition` | 7 | 3191 | 455 |
| `bugprone-narrowing-conversions` | 3 | 1623 | 541 |
| `pro-bounds-constant-array-index` | 2 | 716 | 358 |

`kordon-unsigned-addition` is ours and the obvious next target, but the
narrowing that worked for subtraction does not transfer: restricting it to
memory-relevant contexts (subscripts, allocation arguments) cut volume 90% and
kept only 3 of its 26 exclusive ground-truth positions. Its remaining hits are
`roi.right() - roi.left() + 1`, where the `+ 1` is incidental and the real
hazard is the subtraction -- and 20 of those 26 positions were never acted on
by the maintainers at all.

## The precision problem — earlier framing, superseded above

Comparing a full run on the broken tree against one on the corrected tree
(`tmp/cov_raw.json` vs `tmp/cov_fix.json`), where ~226 defects were fixed:

| tier | broken | corrected | change |
|---|---|---|---|
| high confidence | 227 | 195 | **-14%** |
| medium | 13 | 12 | -8% |
| low | 6628 | 6307 | -5% |

Low confidence is **96.5% of all in-scope findings**, and it barely notices that
the code was fixed. Broken down by check:

| check | findings | change on fixed tree |
|---|---|---|
| `cppcoreguidelines-pro-bounds-pointer-arithmetic` | 2326 | -1% |
| `bugprone-narrowing-conversions` | 1184 | -0% |
| `cppcoreguidelines-init-variables` | 659 | **-33%** |
| `pro-bounds-constant-array-index` | 534 | +0% |
| `pro-bounds-array-to-pointer-decay` | 481 | +0% |
| `kordon-unsigned-subtraction` | 383 | -8% |

The `pro-bounds-*` family is 3341 findings — **49% of everything Kordon reports**
— and is essentially inert: it cannot distinguish corrected code from broken
code at all. It fires on every pointer arithmetic and every array subscript.

It cannot simply be deleted, though: removing it costs 16 matched positions,
11 of them CWE-119. That is the tension to resolve. Kordon currently emits 6868
in-scope findings to cover 162 real positions — a 42:1 ratio. Replacing
`pro-bounds-*` with a range-analysis answer for CWE-119 would cut roughly half
the total volume *and* raise recall, which makes it the highest-value work left.

Note what does respond: `init-variables` (-33%) and the path-sensitive analyzer
findings. Responsiveness to fixes is a better quality signal than recall, and
cheap to measure — always run both trees.

## Specificity: always test against fixed code

`acl_fix/` is a corrected copy of `acl_raw/` and is the only way to tell a
detector from a shape-counter. Compile db: `tmp/db-fix`.

The first CWE-191 matcher scored 94% recall and reported **the fixed code
identically to the broken code** — because the fix was
`if (dataIn.width() > 0)` on a class *member*, and the guard exemption only
understood plain locals. Recall alone would have hidden that completely: a
matcher flagging every `unsigned - 1` scores 94% too.

After adding the member-call guard, on the 52 CWE-191 positions:

| tree | flagged |
|---|---|
| `acl_raw` | 49/52 (recall preserved) |
| `acl_fix` | 7/52 — and all 7 verified byte-identical between trees, i.e. never fixed |

So specificity is effectively 100% on that sample.

**CWE-190 has not cleared this bar.** Its fix idiom is a precondition validated
by an early throw:

```cpp
if ((roi.left() > roi.right()) || roi.right() > header._width)
    ACL_THROW(bad_option, "Check bounds for ROI, X dimension");
...
rsz._xSize = roi.right() - roi.left() + 1;   // now safe
```

The expression is byte-identical in both trees (19 occurrences each), so the
check reports fixed code identically to broken code. No AST matcher can close
this: the subtraction is not inside the guard, the guard compares a different
pair of expressions, and it depends on the throw not returning. It is a
dataflow fact. Treat CWE-190 findings as "can overflow if unvalidated", not as
"is unvalidated" — and this is the concrete argument for IKOS.

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
- **Recall without specificity is meaningless.** Always run a new check against
  `acl_fix/` as well as `acl_raw/`; a check that cannot tell them apart is
  counting syntax, not finding defects.

## Known limitations

Grouped by whether they can be engineered away.

### Fundamental — no amount of tooling fixes these

- **`#ifdef` is invisible.** Code in an inactive configuration never reaches the
  AST, so no engine can see it. ACL has 272 `#if`-family directives and its
  analyzed build leaves `INIT_LIBBPG`, `USE_OPENCV` and `NUMBERTURN` undefined.
  Only remedy: analyze each configuration as a separate run and merge. Not done.
- **Intent is undecidable.** For CWE-190/191 no layer can tell a deliberate
  wraparound from a bug — not the matcher, not IKOS, and not the sanitizer,
  which flags a textbook FNV-1a hash. These stay permanently low confidence.
- **Absence of findings is never proof of safety.** Every clean report means
  "these engines did not flag it", nothing more.
- **Dynamic analysis needs execution.** Whatever line coverage the tests reach
  is the hard ceiling of that layer, and it is not wired up at all yet.

### Detection gaps, with known causes

- **CWE-119: 16/59.** The remainder are `vector::operator[]` where proving the
  container can be empty needs interprocedural range reasoning. No configured
  engine reaches it — IKOS was the hope and contributed nothing unique.
- **CWE-401: 9/66**, but mostly moot — the corpus positions are largely the
  reference tool's RAII false positives. Kordon targets the cause instead
  (`kordon-manual-ownership-flag`, 5 class-level findings, silent on the fixed
  tree). This will never score well against a line-keyed ground truth.
- ~~CWE-763 0/4~~ **— resolved, it was a mapping choice, not a miss.** All four
  positions are detected at the exact line by
  `clang-analyzer-unix.MismatchedDeallocator`; Kordon labelled them 762. The
  code is `x = new bbf_data; ... free(x)`, which both classes describe: 762 is
  the narrow one, 763 the broader one that also covers calling the wrong
  release function. Requirements in this domain name 763, and the ground truth
  records them as 763, so that is now the default. `--cwe-map` flips it back in
  one rule.
- ~~CWE-415 0/1~~ **— confirmed false positive by the codebase author**, with
  sanitizers agreeing. Not a gap; the correct behaviour is to stay silent.
- **CWE-369 2/3** — small tail, uninvestigated.
- **Guard shapes the CWE-191 matcher cannot see**: a precondition validated by
  an early exit (`if (a > b) throw; ... b - a`). Needs dataflow. IKOS was tested
  on exactly this and still warns, under both `interval` and `dbm`.
- **CWE-190 fails the specificity test.** It reports corrected code identically
  to broken code, because the corpus fixes it with precondition-and-throw.
  Treat those findings as "can overflow if unvalidated", not "is unvalidated".

### Precision — the largest practical problem

Visible in-scope findings on the reference corpus: **6 877 for 162 real
positions, a 42:1 ratio.**

| confidence | findings |
|---|---|
| high | 227 |
| medium | 846 |
| low | 5 804 |

The low tier moves only −5% on a tree where ~226 defects were fixed, while the
high tier moves −14%. `pro-bounds-*` alone is ~3 300 findings and is completely
inert between the two trees — but removing it costs 16 real positions, so it
cannot simply be deleted.

### Tooling constraints

- **A compile database is effectively required.** Without one, AST-matcher
  checks still fire on a broken TU while the path-sensitive engine silently
  skips it, so a file can show dozens of findings and never have been analyzed.
- **clang-tidy has no SARIF** (LLVM 18); its YAML uses byte offsets and carries
  no CWE, and it cannot express cross-file paths — hence a separate CTU runner.
- **IKOS needs clang-14 bitcode, `-O0`, and `fneg` lowering**, and its "error"
  verdict is only a proof when it names a concrete allocation.
- **Dedup is line-exact.** Two engines reporting one defect on adjacent lines
  stay separate.

### Unresolved

- pkta shows 51 files failing under clang-tidy in batch that compile cleanly
  individually with their exact database flags. Cause not established.
(The 762-vs-763 question is settled — see the detection-gaps section.)

## CWE-119: the parallel-extent check (2026-08-20)

The ground truth's 86 CWE-119 positions break down by shape:

| shape | count | example |
|---|---|---|
| constant index | 29 | `w[0] = (R(2,1) - R(1,2)) / 2.0;` |
| single subscript | 22 | `while (m_ptrack[m_end] == NULL && m_end >= 0)` |
| two containers, same index | 20 | `m_data[i] += v[i];` |
| operator() on two objects | 8 | `res(i,m) += a(k,i) * blc(k,m);` |
| mixed indices | 5 | `res[i] += m_data[i * m_col + j] * v[j];` |

`kordon-unchecked-parallel-extent` targets the third and part of the fourth.
The defect and its fix, both from the reference tree:

```cpp
// broken                                fixed
assert(m_length == v.m_length);          assert(m_length == v.m_length);
                                         if (v.m_length < m_length) return;
for (int i = 0; i < m_length; i++)       for (int i = 0; i < n; ++i)
    m_data[i] += v[i];                       m_data[i] += v[i];
```

Measured across 452 TUs: **52 positions broken / 27 corrected (-48%)**, against
`pro-bounds-pointer-arithmetic`'s 2326 findings moving -1%. Responsiveness is
the quality signal, and this is the first bounds check to show it.

Recall against the line-keyed ground truth is only 8/86 exact, because it
targets one of five shapes. That understates it: it also found
`Vector::operator-=` (the twin of a listed defect, unlisted) and
`SparseVector::colMult`, where the index written into the caller's vector comes
from stored data (`pos = m_ppos[i]`) and is bounded by nothing at all.

**The exemption that carries the precision** is dropping loops bounded by the
same object being subscripted. `for (i = 0; i < v.size(); ++i) v[i]` is safe by
construction, and without that clause one file of `push_back(list[i])` loops
contributed 55 findings on its own -- more than the whole check now emits.

### Measured end to end, not just standalone (full CTU run, 452 TUs)

The standalone clang-query scan and the integrated run agree closely: 52
positions scanning alone, **48 in the full run** (57 raw findings). What the
integrated run adds is the honest recall delta:

| | exact hits on the 86 CWE-119 positions |
|---|---|
| without the new check | 18/86 |
| with it | **20/86** |

**+2.** Six of the eight ground-truth positions it finds -- the whole
`vector.cpp` family -- were already covered by `pro-bounds-*`. So the check's
value is not recall. It is that those positions are now also held by something
that moves -48% between the broken and corrected trees, instead of only by
something that moves -1%.

It did **not** displace `pro-bounds-*`. Re-measured with the new check in
place, 16 ground-truth positions are still covered by `pro-bounds-*` and
nothing else -- the same 16 as before, none of them overlapping the new check.
3341 findings for 16 exclusive positions, a 209:1 ratio on its own. The
precision problem is unchanged; this check does not solve it, it just shows the
shape of a check that could.

Note on ground-truth quality: **76 of the 86 statements are byte-identical in
the corrected tree.** For the vector/matrix family the class was rewritten
around them, but a line-keyed recall score against this list is measuring
something noisier than it looks.

## CWE-119: the constant-index check (2026-08-20)

Targets the largest remaining shape, 29 of the 86 ground-truth positions. The
defect and its fix:

```cpp
void Rotation::fromRotationToAxisAngle(Matrix &R, Vector &w)
{
    w.init(3);                          // w's extent is guaranteed -- fine
    ...
    w[0] = (R(2,1) - R(1,2)) / 2.0;     // R's extent is not -- the hazard
}
// fix adds:  if (R.getRows() < 3 || R.getCols() < 3) { return; }
```

Two exemptions: the function *read* the parameter's extent in a condition, or
*set* it. Both must name the bound parameter.

**Exempting any `if` that mentions the parameter is far too loose.** The first
version did, and reported nothing on the very file it was written for, because
`if (R(2,1) < 0) y = -y;` -- a test of the stored value -- silenced all 25
findings. Requiring an extent accessor is the whole check.

Measured across 452 TUs: **21 positions broken / 4 corrected (-81%)**, the
sharpest discrimination of any bounds check here.

Restricted to `operator()` deliberately. Adding `operator[]` doubled
ground-truth reach (3 to 6) but took specificity to -13% and volume from 21 to
129, nearly all of it inert -- a fixed subscript on a one-dimensional container
is usually a real constant, not an assumption. That is recall bought by
shape-counting, which is the thing this project keeps rejecting.

## CWE-401: what the ground truth actually contains (2026-08-20)

Of the 86 CWE-401 positions, only 25 were acted on, and the list is dominated
by positions on a closing brace `}` -- the reference tool reporting "leak at
end of scope" for locals of RAII classes that free in their destructors. Those
are the false positives already recorded here and confirmed by the codebase
author. A line-keyed recall score against this class will stay low regardless
of what Kordon does, and that is the right outcome.

Two clusters in it are real, and they are different defects:

**The manual ownership flag** (`matrix.cpp:41,59,157`, `vector.cpp:94,203`,
all acted on). Ownership is tracked by a bool that can disagree with reality:

```cpp
void Vector::clear() {
    m_length = 0;
    if (m_data && m_flgAllocMemory) { delete[] m_data; }   // frees only if the flag agrees
    m_data = NULL;
    m_flgAllocMemory = false;
}
```

while `init(double *data, int n, hardcopy=false)` sets `m_data = data;
m_flgAllocMemory = false;`, aliasing memory the object does not own. A wrong
flag is either a leak or a free of someone else's buffer. The corrected tree
deletes the scheme entirely and holds a `unique_ptr`. Already covered by
`kordon-manual-ownership-flag`, which reports it once per class rather than
once per line -- which is why it scores zero against a line-keyed ground truth.

**Reinit without free** -- shipped today as `kordon-reinit-without-free`, and
the one CLAUDE.md predicted would need custom code. That prediction held:
nothing in clang-tidy, Clang SA or cppcheck reports these sites, and Clang SA
structurally cannot, because the leak requires two calls to the same method
while it reasons about one path at a time.

26 findings at 10 positions across 452 TUs. Four sampled, four genuine:
`SparseVector::init`, `BmpImage::init`, `Tracker::make_sets`, and a guided
filter's `init`, none of which release before allocating.

The exemption had to match release-method names **as a substring**. With an
exact list, `cmatchingcorner.cpp:35` -- `if (m_pPolinom) clearPolinom();`
followed by the allocation, which is correct code -- was reported as a defect.

### A matcher bug worth not repeating

`allOf(binaryOperator(...), hasAncestor(...))` silently matches nothing.
Written as direct arguments, `binaryOperator(..., hasAncestor(...))`, the same
matcher works. It cost a full tree scan to notice, because the failure mode is
a clean zero rather than an error, and a check that reports nothing looks
exactly like a codebase with no defects. There is now a test asserting the
assembled matcher contains no `allOf(`.

## The fallible-init chain: three formulations, none shipped (2026-08-20)

Target was CWE-252 -> 476 -> 690, currently at zero coverage. Three matchers
were built and measured; all are recorded here so they are not rebuilt.

**1. Caller-side, constructor body as the fallibility signal.** A local of a
class whose constructor contains `new (std::nothrow)`, subscripted with no
bool-returning query called on it. Works exactly on the fixture. **Zero
findings on the reference corpus** -- the constructor is defined in
`vector.cpp`, so from every other translation unit only the declaration is
visible and `hasDescendant(cxxConstructorDecl(...))` has no body to see. This is
the CTU boundary again, and clang-query has no CTU.

**2. Caller-side, class signature as the signal.** Fallibility inferred from
what the header shows: a raw-pointer member, a bool-returning method, a
destructor. **1227 findings, -0.7% between trees** -- a pure shape-counter,
because on this codebase nobody checks these queries anywhere, so "did not
check" is endemic rather than diagnostic. Narrowing to runtime-sized
constructions (`Vector v(n)`, not `Vector v(4)`) cut it to 89 positions and 5
acted-on defects, 18:1 -- better, still not tier-worthy.

**3. Class-internal: a method dereferencing its own raw-pointer member**,
linked to a fallible constructor *of the same class in the same TU*, with no
null test on that member in the method. This one is well targeted: **73
positions, 0 on the corrected tree (-100%)**, confined entirely to
`vector.cpp`/`matrix.cpp` -- the two genuinely fallible classes -- and silent
on the corrected tree because the rewrite replaced nothrow-new with
`unique_ptr`. Best responsiveness of anything measured here.

**Not shipped, because it adds nothing.** All 73 positions are already reported
by Kordon at the exact line, under CWE-119. It would add 73 findings and zero
detections, taking the detailed tier from 3.9:1 to 4.6:1 -- a precision loss
for a relabelling. Its claim (CWE-690, the fallible-init chain) is more
accurate than CWE-119 for those lines, so it is worth revisiting if the report
ever grows a way to correct a finding's class rather than add a second one.

**Why formulation 3 is still the right shape**: the reference corpus's actual
CWE-476 defects are not callers misusing a local. They are
`res[i] += m_data[i * m_col + j]` -- a class dereferencing its own member,
which may be null because its constructor failed quietly. The caller-side model
was simply the wrong picture of this defect class.

## A guard deleted by a semicolon — the highest-precision check in the tool

Found while investigating why formulation 3 exempted `matrix.cpp:219`:

```cpp
void Matrix::vecMult(const Vector &v, Vector &res) const
{
    if(v.m_length == m_col && m_data && v.m_data);   // <-- the guard is gone
    {
        ...  res[i] += m_data[i * m_col + j] * v[j];
    }
}
```

The precondition is written correctly -- non-null buffers, matching extents --
and then discarded by the semicolon. `Matrix::trVecMult` has the same defect.

`bugprone-suspicious-semicolon` catches both, mapped to CWE-483, and **Kordon
was discarding them as out of scope.** Two findings across 452 translation
units, both genuine, and both fixed by the maintainers -- the corrected tree
carries the identical conditions without the semicolon. A 1:1 ratio, the best
in the tool, in a class where the absence of a memory-safety guard is provable
rather than suspected.

CWE-483 is now tier 1. The CWE itself is a control-flow class, which is why it
was excluded; what makes it in scope is the consequence, since the guard being
deleted is the one protecting a subscript of a possibly-null buffer.

## Clang SA does not model allocation failure (2026-08-20)

Measured on clang 18.1.3, with each masking bug removed in turn:

| case | reported |
|---|---|
| `int *p = nullptr; *p = 1;` | yes, `core.NullDereference` |
| `p = malloc(4); *p = 1;` | **no** |
| `p = new (std::nothrow) int; *p = 1;` | **no** |
| `p = malloc(4); if (p == nullptr) { *p = 1; }` | yes |

The analyzer knows the pointer can be null -- it follows the branch when the
code forces it -- but never proactively splits state on allocation failure. So
an unchecked allocation and a correctly guarded one are indistinguishable, and
the CWE-252/476/690 fallible-init chain is unreachable by the configured
engines. Silence on a guarded `if (v.isNullPointer()) return;` is not the guard
being understood.

Getting this took three fixtures: the first reported an uninitialized read and
the second a leak, each masking the null path, because Clang SA stops at the
first bug on a path.

## CodeChecker: evaluated, not wired (2026-08-20)

Installed 6.28.2 via `scripts/setup-codechecker.sh`, which puts it in a
virtualenv under the gitignored `third_party/`. It was originally created as
`.venv-cc/` inside the repo and committed by accident -- 9190 files, 311 MB of
binaries and `.pyc`. `.gitignore` now covers virtualenvs, and every engine that
is not a distribution package installs under `third_party/`. It works, and
`CodeChecker parse -e json` gives a clean schema: `checker_name`,
`analyzer_name`, `file.path`, `line`, `message`, `report_hash`. No CWE, so the
mapping table still does that work. Check ids are as predicted: clangsa bare
(`core.NullDereference`), cppcheck prefixed (`cppcheck-noCopyConstructor`).

Three of its four analyzers are the ones Kordon already drives directly. The
one addition is **gcc `-fanalyzer`**, and it has two problems:

- **The compile database is clang-specific.** It carries
  `-fsanitize=unsigned-integer-overflow`, `-fsanitize-ignorelist=` and
  `-fsanitize-recover=`, none of which g++ accepts, so every TU fails to
  compile. Stripping those three makes it work. Any future non-clang engine
  will hit this, so flag filtering belongs in the orchestrator, not in a script.
- **It is slow**: 438 s for 22 translation units, roughly 2.5 h extrapolated to
  the full tree.

What it earns, measured on `modules/math/src`: 20 reports, 13 in-tree
positions, **9 of them not reported by Kordon**, all in the uninit family
(CWE-457/908) -- the class with the weakest static story. Against that, its
messages are often `use of uninitialized value '<unknown>'`, and one of the
nine (`vect3d.cpp:138`) points at a function that is genuinely broken for a
different reason than gcc states: `operator-` performs `tmp += v2`.

Verdict: worth wiring as an opt-in runner for the uninit class specifically,
not as a default engine. Its unique contribution is real but narrow and
expensive.

## Next steps, roughly in order (rewritten 2026-08-21)

Items 1-3 of the old list are done and their notes have moved into the
measurement sections above. What remains, with the reason each is where it is:

1. **CWE-401 is 8% against acted-on defects and will not move by detection
   work.** Its ground truth is dominated by leak-at-end-of-scope reports for
   RAII locals -- confirmed false positives. The real defects in the class are
   found, but reported per *class* (`kordon-manual-ownership-flag`) rather than
   per line, so a line-keyed score cannot see them. The open work is the
   per-class ownership summary from CLAUDE.md, and its value is suppressing
   other engines' false leaks, not raising this number.

2. **CWE-119 is 61% against acted-on defects, and is the only real detection
   gap left.** The remaining misses are the constant-index-on-`operator[]`
   family, measured and rejected: including it doubles ground-truth reach and
   takes specificity from -81% to -13%. Anything further needs interprocedural
   range reasoning -- proving a container can be empty, or that `arows % size
   != 0`. IKOS was the hope and contributed nothing unique.

3. **The low tier is 6724 findings hiding 27 acted-on defects.** Three ranking
   signals were tested and all failed (stacked checks: no lift; proximity to a
   high finding: 1.8% -> 4.1% on a hopeless base rate; file sparsity: helps
   only the smallest bucket). The only thing that has ever worked is narrowing
   a specific shape until its precision changes tier, which is what every
   `kordon-` check here is. There is no general fix to find.

4. **Dynamic layer: no coverage-guided input generation.** It reports what the
   run command executes and nothing else. The directed-fuzzing handoff from
   CLAUDE.md -- seed a fuzzer from the static findings Kordon cannot prove --
   is unbuilt and is the only way to raise that ceiling.

5. **`#ifdef` is still invisible.** 272 `#if`-family directives in the
   reference tree, three symbols undefined in the analysed build. Needs
   analyse-per-configuration and merge.

6. Ingest CodeChecker as an alternative runner. Evaluated: three of its four
   analyzers duplicate ours, and gcc `-fanalyzer` -- the one addition --
   contributes 9 uninit positions but needs clang-only flags stripped from the
   compile database and costs ~20s per TU.

7. Dedup is line-exact; two engines reporting one defect on adjacent lines stay
   separate. Consider a small line window.

## Where the numbers stand (2026-08-21, all checks in place)

| | |
|---|---|
| coverage vs everything reported | 245/379 = **65%** |
| coverage vs defects actually fixed | 131/176 = **74%** |
| detailed report | 366 findings / 104 acted-on = **3.5:1** |
| detailed tier, broken -> corrected | 366 -> 192 = **-48%** |
| low tier | 6724 findings / 27 acted-on |

Re-verified 2026-08-21 after path canonicalization, CTU ambiguous-symbol
dropping, generated-code demotion and the first suppression -- four changes
that all touch dedup or tiering. Coverage is **unchanged at 65% / 74%**, and
the detailed tier improved from 3.7:1 to 3.5:1 carrying the same 104 acted-on
defects: 17 non-defects left, none of the real ones. Worth having checked
rather than assumed, since two of those changes alter how findings are merged.

Per CWE, against acted-on defects: 763/369/416 at 100%, 191 at 97%, 563 at 95%,
190 at 86%, 457 and 476 at 83%, **119 at 61%**, **401 at 8%**, 415 a confirmed
false positive where silence is correct.

## Macros and other hiders — measured

`testdata/macros/hiders.cpp` pairs every macro form with a plain-code twin and
requires the same verdict for both. **All pairs match.** Analysis runs on the
post-preprocessing AST, so macros are transparent:

| hider | result |
|---|---|
| defect inside a macro body | flagged, at the **expansion site** not the `#define` |
| guard written as a macro (`IF_POSITIVE(k) {...}`) | correctly suppressed |
| only the comparison in a macro (`if (IS_POSITIVE(k))`) | correctly suppressed |
| macro-declared variable | flagged, same as plain |
| macro-generated member function | flagged, at expansion site |
| one macro expanded 3× | 3 separate findings, not collapsed |
| guard + control flow in a macro (`THROW_IF`) | flagged — same as its plain twin, so no regression |

Clang SA is equally transparent (use-after-free through a `FREE_IT(p)` macro is
reported normally).

**The real blind spot is `#ifdef`, not macros.** Code in an inactive
configuration never reaches the AST, so no engine can see it and no check
improvement will change that. Verified: `k - 1` under `#ifdef` gives 5 matches
without the define and 6 with it. ACL has 272 `#if`-family directives; its
analyzed build defines `INIT_QT5`, `INIT_ZLIB`, `INIT_LIBJPEG/PNG/TIFF/WEBP`
but **not** `INIT_LIBBPG`, `USE_OPENCV` or `NUMBERTURN`. Everything behind those
is permanently invisible. The only fix is to analyze each configuration as a
separate run and merge — worth doing, and not yet done.

### The bug this fixture caught

Building it exposed a live regression that no ACL measurement could reveal. The
guard exemption had stopped matching a bare `if (k > 0)`: the condition matcher
was `hasCondition(hasDescendant(cmp))`, and `hasDescendant` does not match the
node itself. Only the nested form `if (a && k > 0)` still worked — and ACL uses
only that form, so recall, specificity and the raw-vs-fix comparison all looked
clean while the common case was broken.

Now `anyOf(cmp, hasDescendant(cmp))`, with a regression test on both arms, and
guards built from an operand descriptor rather than three hand-written copies.
CWE-191 recall after the fix is unchanged at 49/52 = 94%.

**Lesson worth keeping: a corpus can only falsify what it happens to contain.**
Paired synthetic fixtures test the axis directly; corpus measurements cannot.

## Prerequisites for IKOS and for sanitizers — scoped

Both need Kordon to *drive a build*, which it has never done: today it consumes
someone else's `compile_commands.json`. That is the shared piece of work.

### IKOS — everything checked, nothing blocking

IKOS v3.5 requires **LLVM/Clang 14.0.x** and cannot use 18. APRON is optional.

| need | status |
|---|---|
| `clang-14`, `llvm-14-dev`, `libclang-14-dev` | available via apt, coexists with 18 |
| gmp, boost, sqlite3, tbb, mpfr, cmake, python3 | already installed |
| `libppl-dev` | available; only needed for polyhedra |
| IKOS itself | source build, cmake, no package |

Input pipeline is already proven: emitting bitcode from the existing compile db
works (`clang++ -emit-llvm -c -g -O0` + the db's flags), and `llvm-link` merges
per-TU bitcode into one whole-program module — which gives **cross-TU analysis
at IR level for free**, cleaner than the AST-based CTU we built.

Two things that will bite if missed:
- Bitcode must be produced by **clang-14**, not 18 — LLVM 14 cannot read 18 bitcode.
- Use `-O0`. Measured: at `-O1` clang folded `n - 1` into the address computation
  (`getelementptr ... i64 -1`) and the debug info collapsed to a single line,
  losing the line the subtraction was written on. Optimization erases the
  expressions we want to report.

IR keeps `!DILocation(line:, column:)`, so IR-level findings map back to source
positions and fit the existing finding schema.

### Sanitizers — viable, with one hard part

| need | status |
|---|---|
| runnable tests | **11 ctest tests exist and the binaries run** |
| dependency libs | built `.so` resolves everything, 0 missing |
| `_GLIBCXX_ASSERTIONS` | already in the build's `-D` flags — needed for the `vector::operator[]` CWE-119 class |
| conan | **missing**, cache empty — but all include paths resolve, so a rebuild looks plausible without it |

Separate build trees are required: ASan+UBSan combine (plus
`-fsanitize=unsigned-integer-overflow` for CWE-191), MSan does not — and MSan
additionally needs every dependency instrumented, which is the hard part.

Also needed: an ignorelist for intentional wraparound, or the CWE-191 sanitizer
will flag correct code (verified: it reports a textbook FNV-1a hash).

**Ceiling to check first:** sanitizers only see what those 11 tests execute.
Measure line coverage before expecting much from this layer.

## IKOS — built and measured

`scripts/setup-ikos.sh` builds IKOS v3.5 into `third_party/ikos` (gitignored).
Working: `ikos 3.5`. `scripts/ikos-bitcode.sh` produces input it can read.

### On ACL it contributed nothing to the visible report

Measured on the full tree with everything enabled (12m32s, 274 units):

| | findings | matched |
|---|---|---|
| visible report | 7 582 | 162/280 = **57.9%** |
| including the hidden unproven bucket | 22 155 | 187/280 = 66.8% |

**IKOS proved nothing: `proved: 0`.** Its entire contribution — 14 869
findings — landed in the unproven bucket, of which 25 happen to sit on a real
defect line. A hit rate of 25 in 14 869 is not a detector, it is a list of
everything the analyser could not decide, which on library code is everything.

The cause is structural, not a tuning problem. A library function analysed as a
synthetic entry point has pointer parameters backed by no allocation, so IKOS
can prove neither that an access is in bounds nor that it is out of them. The
792-safe-checks result that motivated this work came from a *self-contained* C
file whose arrays were local and whose sizes were literals.

So the CWE-119 hope did not survive contact: 16/59 visible, unchanged from
before IKOS. Whole-program analysis from a real `main` would be a different
experiment; analysing a library this way is not.

### What it gives that nothing else does

Three-valued verdicts. On a real float-heavy C file (pkta `refraction.c`):

```
Total checks: 861    safe: 796 (92.5%)    definite unsafe: 0    warnings: 65
```

796 accesses **proved** in bounds. Every other engine Kordon drives can only
fail to flag something; none can say "safe". That is the property that makes it
a candidate to replace `pro-bounds-*`, which emits 3341 findings on ACL without
distinguishing corrected code from broken.

### Guard handling: closes one documented gap, not both

| guard shape | AST matcher | IKOS |
|---|---|---|
| `if (k > 0) { k - 1 }` | exempt | proved safe |
| `if (k == 0) return; k - 1` | **flagged (limitation)** | **proved safe** |
| `if (lo > hi) return; hi - lo` | **flagged (limitation)** | **still warns** |

So IKOS resolves the early-return guard, which is a real win. It does **not**
resolve the relational precondition — tested under `interval` and under `dbm`,
which is relational and built in without APRON. That is the exact idiom the
reference corpus uses to fix its CWE-190 sites, so that specificity failure
survives the IKOS layer.

### Three input constraints, all measured

1. **Bitcode must come from clang-14.** IKOS links LLVM 14 and rejects an
   LLVM 18 module outright. Verified both ways.
2. **Must be `-O0`.** At `-O1` clang folds `n - 1` into the address computation
   and the debug location collapses, so findings lose the line they belong to.
3. **`fneg` must be lowered.** IKOS 3.5's importer does not implement it
   ("unsupported llvm instruction fneg") and clang emits it for every
   floating-point negation. This is fatal for numerical code — the only kind
   worth running an interval analyser over. It blocked **10 of 40** sampled ACL
   units and the first pkta file tried.

   `scripts/ikos-bitcode.sh` rewrites `fneg x` to `fsub -0.0, x`, which is how
   the operation was expressed before LLVM 8 added the instruction. With that,
   the previously-fatal file analyzes completely.

### Entry points: solved — use call-graph roots

`scripts/ikos-entry-points.sh` prints the entry points for a `.bc`. Both
problems have the same answer.

**Which names.** Read them out of IKOS's own AR, after `ikos-pp` then
`ikos-import`, rather than from `llvm-nm`. Exact by construction, and it avoids
the C++ constructor aliases (`_ZN3acl3AnyC1EOS0_`) that `llvm-nm` reports and
IKOS rejects as "could not find function". Note `ikos-import` must run on
*preprocessed* bitcode — on raw bitcode it fails with "llvm select instructions
are not supported" even where a full `ikos` run succeeds.

**How many.** Only the roots — functions no other function in the unit calls.
An entry point's parameters are unconstrained, so naming every function fills
the report with artifacts of that choice. Measured on one real unit
(13 functions, 1 root):

| entry points | checks | safe | warnings |
|---|---|---|---|
| all 13 functions | 1419 | 1316 | 103 |
| call-graph roots only | 1338 | 1271 | **67** |

The 36 warnings that vanish are exactly the artifacts — "variable might be
uninitialized" 35 → 7, "memory access might be invalid" 8 → 0 — while "possible
buffer overflow" stays at 60. Nothing real is lost.

Validated on a second unrelated file: 581 checks, 511 safe, 70 warnings, entry
point derived automatically.

### Still open before it can be a Kordon runner

- Wire it up as a runner: emit bitcode per TU, derive entry points, run with
  `-f json`, map analyses to CWEs (`boa`→119, `uio`→190/191, `dbz`→369,
  `nullity`→476, `uva`→457, `dfa`→415).
- Decide how to report the **safe** verdict. It is the one genuinely new piece
  of information — no other engine can say it — and the report has nowhere to
  put "this was proved" today.
- 25% of translation units still need the `fneg` rewrite; that is handled, but
  any other unsupported instruction will surface the same way.

## Engine audit — what each one actually earns

Measured on the full reference corpus, counting only what reaches the visible
report. "Unique" means no other engine found that position.

| engine | positions found | unique | raw findings | verdict |
|---|---|---|---|---|
| clang-tidy | 90 | 9 | 10 948 | keep — broadest reach |
| clang-sa-ctu | 74 | 5 | 363 | keep — best signal-to-noise by far |
| **kordon-query** | 66 | **66** | 5 162 | **keep — every position is unique** |
| cppcheck | 29 | **0** | 1 106 | keep, but for corroboration only |
| ikos | 21 | **0** | 52 269 | **not earning its place** |

Reading it:

- **Kordon's own checks are the single largest unique contributor.** All 66
  positions — CWE-191 (49) and CWE-190 (17) — are found by nothing else. That
  is the whole justification for writing custom checks rather than only
  orchestrating.
- **clang-sa-ctu has the best ratio in the set**: 74 positions from 363 raw
  findings. Everything else is one to two orders of magnitude noisier.
- **cppcheck finds nothing unique here.** Its value is corroboration — a second
  independent engine agreeing raises confidence a step — and different blind
  spots on other codebases. Cheap enough to keep on those grounds, but it is
  not pulling detection weight on this corpus.
- **IKOS is not earning its place.** 52 269 raw findings, 14 869 of them
  unproven, 21 positions found and **none of them unique**. It costs the
  largest share of runtime and contributes nothing no other engine already
  had. Leave it opt-in and off by default; revisit only for whole-program
  analysis from a real `main`, where its proofs can actually ground.

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
