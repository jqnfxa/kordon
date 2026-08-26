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

## Measured on Juliet

`scripts/score-juliet-esbmc.py`, scored like the sanitizers: `-DOMITGOOD` for
recall, `-DOMITBAD` for false positives.

| sample | found | false positives |
|---|---|---|
| CWE-121, `_01` variants | 7/10 | 2/10 |
| CWE-122, `_01` variants | 6/10 | 2/10 |
| CWE-122, all flow variants | 4/10 | **4/10** |

Roughly **65% recall at 20% false positives on clean cases**, against Kordon's
current 45.5% at 0% for CWE-121. More recall, materially more noise.

### The false positives were mine, not ESBMC's — corrected

An earlier version of this document blamed ESBMC for "not folding the global
constant" in Juliet's flow-variant scaffolding. **That diagnosis was wrong**,
and the check the reader deserves is the one that found it: prove the code is
correct, then explain what the engine was actually told.

The flagged function:

```c
data = NULL;
if (GLOBAL_CONST_FIVE != 5) { /* Juliet marks this dead */ }
else { data = malloc((10+1)*sizeof(wchar_t)); if (data == NULL) exit(-1); }
...
sourceLen = wcslen(source);                       /* source is L"AAAAAAAAAA" */
for (i = 0; i < sourceLen + 1; i++) data[i] = source[i];
```

**The code is correct, three ways:**

1. **Arithmetic.** `SRC_STRING` is `L"AAAAAAAAAA"` — 10 wide characters plus a
   NUL, so `wchar_t source[10+1]` holds exactly 11 elements with valid indices
   0..10. `wcslen` returns 10, the loop runs `i = 0..10`, and `data` is
   `malloc((10+1)*sizeof(wchar_t))` — 11 elements, indices 0..10. Every access
   is in bounds, with nothing to spare and nothing over.
2. **Empirically.** 200 runs of the corrected half under ASan+UBSan with
   `-fno-sanitize-recover=all`: **zero failures**.
3. **ESBMC agrees.** Given the same logic with the two unknowns resolved — the
   constant defined locally and `wcslen` replaced by the value it provably
   returns — it reports `VERIFICATION SUCCESSFUL`.

**So what was ESBMC missing? Exactly what the invocation withheld.**

- `GLOBAL_CONST_FIVE` is declared **`extern`** in `std_testcase.h` and defined
  in `io.c`. The scorer passed only the test file, so its value was genuinely
  unknown and ESBMC was *right* to explore both branches. There was no constant
  to fold. **That is a missing translation unit — the same class as Kordon's
  own CTU gap — not a weakness in the engine.** The scorer now passes `io.c`
  and those reports disappear.
- The remaining reports come from `--no-library`, which is **not optional**
  here: ESBMC's bundled headers clash with the suite's own includes and the run
  does not parse without it. It also disables the string-function models, so
  `wcslen(source)` returns an unconstrained value and no bound derived from it
  can be proved. Again correct given what it was told.

**Neither report was ESBMC reasoning badly.** Both were the harness. The
lesson is the one this project keeps relearning in a new costume: when a tool
reports something surprising, the instrument is the first suspect, and
"prove the code is correct" is the question that settles it.

### What the numbers are worth

With `io.c` included the sample reads 7/15 found, 5/15 false positives, and
5 of 20 cases undecided — the extra unit enlarges the formula and more runs
hit the deadline. **These numbers move substantially with configuration**, so
treat them as a rough indication that the engine is in the right range and not
as a measurement of the kind `data/juliet-baseline.json` holds. A trustworthy
figure needs the header clash resolved first, so the library models can stay on.

CWE-190 found nothing: overflow checking is not on by default and needs
`--overflow-check`.

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
2. **A per-file time budget**, because BMC cost grows sharply with the bound —
   the same query took 8.8s at one input size and 0.05s at a slightly smaller
   one.
3. **`--function` mode needs preconditions to be useful on library APIs**, or
   every pointer parameter yields an invalid-pointer report.

The honest first integration is opt-in — `--esbmc`, like `--ikos` — reporting
into the **unproven** tier by default and promoting only what carries a
counterexample.
