# ESBMC: what it adds, and what it costs

Evaluated 2026-08-26 against ESBMC 8.4. **This is a different kind of engine
from anything else Kordon runs** — it encodes the program as an SMT formula and
asks a solver whether a property can be violated. When it reports something it
hands back a concrete counterexample; when it finds nothing within its bound,
that is a *bounded proof* rather than an absence of evidence.

## The case that motivated looking

A tag-length-value parser where every bound on the **input** is checked and
correct, and nothing bounds the **accumulated output**:

```c
while (pos + 2 <= len) {
    uint8_t n = buf[pos + 1];
    pos += 2;
    if (pos + n > len) return -1;      /* the record fits the input */
    memcpy(out + outlen, buf + pos, n);
    outlen += n;                       /* nothing checks outlen vs OUT_MAX */
    pos += n;
}
```

The missing invariant is `sum(n) <= OUT_MAX`, which exists only across
iterations. Measured on it:

| | result |
|---|---|
| Kordon, all engines, `--all` | 2 low-confidence CWE-190 noise hits. **Missed** |
| cppcheck | nothing |
| IKOS | 4 *warnings* — "cannot prove safe", no claim |
| libFuzzer + ASan | found it in ~1 minute, with a reproducer |
| **ESBMC** | **found it, with a counterexample and CWE ids** |

And on the **fixed** version, `--k-induction` returned
`VERIFICATION SUCCESSFUL … all states are reachable (k = 15)` — a proof.
IKOS could only say it could not decide. **Nothing else Kordon runs can say
"this is safe".**

## What it needs to run

**No test and no harness, in principle.** `--function <name>` treats the
function's parameters as unconstrained and verifies it for all inputs. A file
with its own `main` needs nothing at all, which is why Juliet works so well.

**In practice, two things bite.**

*Unbounded loops.* `pktaComputeGamma` searches a 1219-entry table, so proving
anything about it needs `--unwind 1220`. At `--unwind 8` ESBMC reports
`unwinding assertion loop 41` — which means **"I gave up", not "there is a
defect"**, and arrives through the same `VERIFICATION FAILED` channel as a real
violation. Counting those as findings would be pure noise.

*Pointer parameters with no precondition.* `mathCholesky(return_t *rv, const
_matrix_t *A, matrix_t L)` reports `dereference failure: invalid pointer`,
because a nondeterministic pointer might be invalid. It is right, given what it
was told. Saying otherwise means writing a precondition — a contract, not a
test — and that is real per-API work.

Where the shape fits, it just works: `mathInRange` and `modAvg2` both verified
successfully in seconds.

*Its header models are not a superset of the system's.* ESBMC ships models for
`stdio.h`, `stdlib.h` and `string.h`, and including a system header it does not
model alongside them redefines `FILE` — `struct _IO_FILE` against
`__esbmc_file_t` — so nothing parses. Turning the models off with
`--no-library` makes it parse and silently costs the accuracy they provide.
`scripts/esbmc-shim/` is the alternative: three small files that fill the gaps
instead of disabling the models. **They are not cosmetic — the same engine on
the same cases measures 42.9% false positives without them and 0% with them.**

## Measured on Juliet

`scripts/score-juliet-esbmc.py`, scored like the sanitizers: `-DOMITGOOD` for
recall, `-DOMITBAD` for false positives. 12 cases per CWE, `--unwind 128`.

| | found | false positives | undecided |
|---|---|---|---|
| CWE-121 stack overflow | **10/10** | 0/11 | 2/12 — both timeouts |
| CWE-122 heap overflow | 4/5 | 0/5 | 7/12 — 6 do not build, 1 timeout |
| **total** | **14/15 (93.3%)** | **0/16 (0.0%)** | 9/24 |

For comparison, Kordon's static layer scores **45.5%** on CWE-121 and **31.2%**
on CWE-122 at the same 40-file discipline. On the cases ESBMC can decide it is
in a different class entirely — and it hands back a counterexample rather than
a suspicion.

**The three numbers to hold together, because any one alone misleads:**

- **93.3% of *decided* cases**, not of cases. The denominator excludes the
  9 of 24 ESBMC could not reach a verdict on, and those are not random — see
  below.
- **Zero false positives**, which is what a proof engine should look like and
  what the earlier readings did not show. Every false positive measured here
  turned out to be the harness.
- **9 of 24 undecided.** That is the real cost, and it is the number an
  integration has to plan around.

### Every false positive was the harness — four of them, in three flavours

Earlier drafts of this document published 20%, then 42.9%, then 75%. All three
were wrong, and none of the causes was ESBMC reasoning badly.

**1. A regex in the scorer that matched its own escape hatch.** `VIOLATION_RE`
carried a bare `assertion` alternative, and ESBMC's "I could not unroll this
loop far enough" is spelled *unwinding **assertion***. So every giving-up was
scored as a defect — inflating recall and false positives together, and leaving
the gave-up branch below it unreachable. This is the sixth harness bug in this
project whose symptom was a plausible number rather than an error.

**2. A missing translation unit.** `GLOBAL_CONST_FIVE` is declared `extern` in
`std_testcase.h` and defined in `io.c`, which the scorer never passed. Its
value was genuinely unknown, so ESBMC was *right* to explore the branch Juliet
marks dead. **That is the same class as Kordon's own CTU gap**, not a weakness
in the engine. See the worked proof below.

**3. `alloca` was not declared, so it returned `int`.** Two of the three
surviving reports were `dereference failure: invalid pointer freed`, raised at
the closing brace of a *corrected* function — the point where the frame is
released. glibc declares `alloca` from `<stdlib.h>`; ESBMC's model of
`<stdlib.h>` does not, and Juliet never includes `<alloca.h>`. In C that makes
every `ALLOCA(n)` an implicit declaration returning `int`, so the pointer is a
truncated integer and the release is genuinely invalid — of a pointer the
harness fabricated. Deleting one `#include <alloca.h>` from a hand-written case
flips it from `VERIFICATION SUCCESSFUL` to exactly that report.

`scripts/esbmc-shim/prelude.h` fixes it, and **a prototype alone does not**:
glibc's header also defines the macro routing the call to `__builtin_alloca`,
and the builtin is what ESBMC models. Measured both ways before writing this.

**4. Declared-but-bodiless functions are havoc, not abstraction.** ESBMC ships
models for the narrow string functions and none for `wchar.h`. Declaring the
wide ones is enough to parse, but the run then prints `WARNING: no body for
function wcslen` and assumes the call could have done anything to the memory
reachable through its arguments. The third false positive was an `array bounds
violated` raised inside ESBMC's own `__memmove_impl` on a state that nothing in
the program produced.

`scripts/esbmc-shim/wchar_model.c` gives them the obvious loop bodies. With it,
the same case reports the CWE-121 overflow **inside `wcsncat`**, which is where
it is.

**The cost of that fix is the bound.** Those loops are symbolically executed
like any other code, so `--unwind` has to exceed the longest string in the case
— Juliet's buffers are 100 wide characters. Hence a default bound of 128 where
ESBMC's own is 16, and hence the timeouts.

### The proof that settled it

The check worth repeating: **prove the code is correct first, then ask what the
engine was told.** For the flagged function

```c
data = NULL;
if (GLOBAL_CONST_FIVE != 5) { /* Juliet marks this dead */ }
else { data = malloc((10+1)*sizeof(wchar_t)); if (data == NULL) exit(-1); }
sourceLen = wcslen(source);                       /* source is L"AAAAAAAAAA" */
for (i = 0; i < sourceLen + 1; i++) data[i] = source[i];
```

1. **Arithmetic.** `SRC_STRING` is 10 wide characters plus a NUL, so
   `wchar_t source[10+1]` has valid indices 0..10. `wcslen` returns 10, the
   loop runs `i = 0..10`, and `data` holds 11 elements. In bounds, with nothing
   to spare and nothing over.
2. **Empirically.** 200 runs of the corrected half under ASan+UBSan with
   `-fno-sanitize-recover=all`: zero failures.
3. **ESBMC agrees**, once the constant is defined and `wcslen` is modelled.

### What is undecided, and why it is not noise

Nine of twenty-four, in two kinds:

- **6 do not build** — `/tmp/esbmc.*/headers/sys/socket.h: redefinition of
  'iovec'`, against the system's `struct_iovec.h`. Nothing in the suite or in
  `io.c` includes `<sys/socket.h>`; ESBMC's frontend mixes its own header tree
  with the system's. Five of the six are the C++ variants. **An integration
  wart in ESBMC, unrelated to the code under test**, and the reason CWE-122's
  denominator is 5 rather than 12.
- **3 timed out** at 120 s, all `connect_socket` cases, where the formula grows
  with the bound the wide-string models need.

Neither is a finding and neither is a clean run, which is exactly why the
scorer keeps a third column. A tool that reported these as "no defect found"
would be claiming coverage it does not have — the failure mode `--show-unproven`
exists to prevent.

CWE-190 found nothing: overflow checking is not on by default and needs
`--overflow-check`.

### The caveats on this number

- **12 cases per CWE, and 15 decided in total.** Small. `CLAUDE.md` records
  that per-CWE figures below roughly 30 cases can flip a discrimination sign;
  read this as "the engine is in this class", not as a baseline.
- **Two CWEs, both bounds.** This is where BMC should be strongest.
- **The shim is Kordon's, and it is part of the measurement.** Three files —
  a `wchar.h` that avoids the `FILE` clash, bodies for the wide-string
  functions, and a prelude declaring `alloca`. Without them the same engine
  measures 42.9% false positives on the same cases.

## Licensing — workable, but the solver must be pinned

`COPYING` opens with a warning, and it is earned. ESBMC's own code is
**Apache 2.0** and the CBMC base is BSD 4-clause, both fine. Of the solvers:

- **Z3, Boolector, Bitwuzla (MIT), CVC4 (BSD)** — no restriction
- **MathSAT (non-commercial), Yices (personal use / GPL3)** — a problem for
  any user running Kordon commercially

So `--z3` must be passed explicitly rather than trusting the default. Same
class of question as the open IKOS/NASA licence item, and Kordon invokes it as
a subprocess, so nothing propagates into Kordon's own licence.

## Verdict

Worth having, and it fills a real hole: **tier D of `docs/cwe-difficulty.md`**
— the defects that need a value bound, where pattern matching is structurally
unable to help and IKOS answers "cannot prove". It is also the only engine here
that can prove a fix correct.

It is not a drop-in. Three things have to be true before it earns its place in
a default run:

1. **Unwinding assertions and timeouts must never be reported as defects.**
   They are "could not decide", and the report already has a place for that.
   This is not a hypothetical: the scorer here counted them as findings for
   three drafts, because "unwinding **assertion**" matches a regex written for
   user asserts.
2. **A per-file time budget**, because BMC cost grows sharply with the bound —
   the same query took 8.8s at one input size and 0.05s at a slightly smaller
   one.
3. **`--function` mode needs preconditions to be useful on library APIs**, or
   every pointer parameter yields an invalid-pointer report.
4. **The header shim ships with it.** Anything ESBMC does not model is havoc,
   not abstraction, and havoc produces confident reports about states the
   program cannot reach. A missing `alloca` declaration and four missing
   `wchar.h` bodies accounted for every false positive measured here.

The honest first integration is opt-in — `--esbmc`, like `--ikos` — reporting
into the **unproven** tier by default and promoting only what carries a
counterexample.
