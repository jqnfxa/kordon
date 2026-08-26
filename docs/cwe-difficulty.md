# What makes a CWE easy or hard to detect

Rated from Kordon's measured results on Juliet, not from intuition. The
question is never "how bad is this defect" — it is **what does an analyzer
need to know to see it**, and that is what decides the cost of closing a gap.

Numbers are recall / discrimination from `data/juliet-baseline.json`, default
flags, 40 files per CWE. `docs/juliet-inventory.md` has the corpus.

---

## A · The compiler already knows — name the check

Cheapest tier by a wide margin. The detection exists in clang and is simply
not switched on. Every one of these was closed by adding a name to a list.

| CWE | | recall | discrim |
|---|---|---|---|
| 483 incorrect block delimitation | `-Wmisleading-indentation` | **95.0%** | +95.0 |
| 563 unused variable / dead store | `deadcode.DeadStores`, `-Wunused-variable` | 77.3% | +75.0 |
| 562 return of stack address | `-Wreturn-stack-address`, `core.StackAddressEscape` | 50.0% | +50.0 |

**Three for three: every `clang-diagnostic-*` check Kordon has named closed a
real gap, and it names only three.** That namespace is the cheapest remaining
seam in the whole project.

CWE-562's ceiling is 50% for a reason unrelated to detection: half the
functions Juliet labels flawed are wrappers that call the flawed helper, and a
detector reports at the flaw.

## B · A default path-sensitive checker already does it

Free, already on, and the strongest results here. What these have in common is
that the defect is **local and allocation-shaped**: one object, one function,
a path the analyzer can walk.

| CWE | recall | discrim |
|---|---|---|
| 415 double free | **93.0%** | +89.5 |
| 762 mismatched free | 84.8% | +84.8 |
| 476 null dereference | 84.1% | +79.6 |
| 401 memory leak | 86.7% | +68.8 |

## C · A syntactic shape rule Kordon writes

The defect is visible in the code as written — no values needed — but no engine
expresses it. This is where Kordon's own checks live and where most of this
session's gains came from.

| CWE | shape | recall | discrim |
|---|---|---|---|
| 252 unchecked return | curated function list, not the whole stdlib | 70.0% | +70.0 |
| 369 divide by zero | divisor from a call, never compared to zero | 56.0% | +54.9 |
| 124 buffer underwrite | index bounded above, never sign-checked | 75.6% | +73.8 |
| 121 stack overflow | index sign-checked, never bounded | 45.5% | +45.5 |
| 127 buffer underread | pointer arithmetic before the buffer | 40.0% | +40.0 |

**The recurring lesson: the discriminator is usually narrower than it first
looks.** `i >= 0` and `i < 0` are both sign checks; `i < 10` and `i >= 10` are
both bounds — the operand decides, not the operator. And a shape rule without a
"where did this value come from" clause fires on every loop counter: 160
positions across two real projects, 56 in vendored reference code.

## D · Needs a value bound — IKOS, or run it

The code is identical in the flawed and corrected versions; only a *size* or a
*range* differs. No amount of pattern matching can separate them.

| CWE | recall | with `--ikos` | note |
|---|---|---|---|
| 126 buffer overread | 11.4% | **86%** | `memcpy(dest, data, strlen(dest))` — the corrected function has the identical line |
| 122 heap overflow | 31.2% | | |
| 680 overflow → buffer overflow | 66.7% | | 18.3% FP; the widest accept set here |
| 190 integer overflow | 18.4% | 31% | IKOS *proves* the constant case; the `rand`/`fscanf` families are unprovable by construction |

**About 71% of CWE-190's cases need a bound on external input, which does not
exist.** The honest output is IKOS's "cannot prove safe", and the dynamic layer
catches what actually executes. Building a matcher to chase these buys score
and nothing else.

## E · Needs cross-TU or ownership reasoning

The defect spans a boundary one translation unit cannot see, or requires a
model of who owns what.

| CWE | recall | note |
|---|---|---|
| 416 use after free | 50.0% | `--ctu` takes the split cases from 0% to 30% |
| 590 free of non-heap | 42.2% | |
| 665 improper initialisation | 36.0% | the fallible-constructor class `--ctu` was built for |
| 690 null deref from return | 10.0% | a *chain*: CWE-252 then CWE-476, and Kordon scores 70% and 84% on the halves separately |

CWE-690 is the interesting one. Both ends are well detected in isolation;
what is missing is joining them.

## F · Defined behaviour — no tool decides this for you

**The hardest tier, and not for technical reasons.** These are legal C. The
standard says exactly what happens, no sanitizer traps by default, and the
same code is a bug or a technique depending on what the author meant.

| CWE | recall | surfaced | why |
|---|---|---|---|
| 191 unsigned underflow | 32.0% | **0%** | Wraparound is **defined**. Hashes, ring buffers and checksums rely on it. UBSan needs `-fsanitize=unsigned-integer-overflow` as an *opt-in* precisely because it is legal, and no compiler warns by default. |
| 197 numeric truncation | 51.1% | **0%** | Narrowing is defined and usually deliberate. |
| 369, float half | — | advice | IEEE 754 yields an infinity; it does not trap. |

**This is what the severity axis is for.** Reporting these as errors overstates
the claim; saying nothing is worse, because an unsigned wrap or a silent
infinity propagates into later results and surfaces as a wrong answer rather
than a crash. They belong in the **Advice** band: same confidence, lower
severity.

The dynamic layer does not rescue them either — CWE-191 is 18% there, because
the wrap has to actually happen during the run.

## G · Needs semantics no analyzer has

| CWE | recall | why |
|---|---|---|
| 843 type confusion | **0%** | Requires knowing which union member is live, or which downcast the design intends. That is application knowledge. |
| 672 operation after release | **0%** | Needs a per-resource lifetime model — the ownership-summary pass CLAUDE.md has described since the start and nobody has built. |

Both are honest zeros. Neither is closed by a matcher.

---

## Where to spend effort next, in order

1. **Sweep the rest of `clang-diagnostic-*`** — tier A is three for three and
   Kordon names three of them.
2. **CWE-690**, by joining two things already detected rather than detecting
   anything new.
3. **Make `--ikos` the default for tier D**, or say plainly in the report what
   it is worth: 11.4% to 86% on CWE-126 is not a footnote.
4. **Move tier F into Advice deliberately**, so 191 and 197 stop reading as
   0% surfaced when the truth is "reported, correctly, as not-an-error".
5. Leave tier G alone until the ownership pass exists.
