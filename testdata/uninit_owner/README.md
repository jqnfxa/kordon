# Fixture: fallible initialization across translation units

A vector wrapper that can own or borrow its buffer, with a manual
`bool m_ownsData` flag. Both constructors leave that flag unassigned on one
path. Synthetic — the shape is a general hand-rolled-container anti-pattern,
not any codebase's code.

## The defects

| Constructor | Unassigned path | Chain |
|---|---|---|
| `Vector(int)` | nothrow `new` fails | CWE-665 → CWE-824 (`init()` reads flag) → **CWE-476** (`init()` returns early on garbage-true, leaving `m_data` null on an object reporting `size() == n`) |
| `Vector(double*, int)` | borrow path never assigns | CWE-665 → CWE-824 (`clear()` reads flag) → **CWE-590** (destructor may `delete[]` the caller's *static* array) |

Root cause is **CWE-665 (Improper Initialization)**, not CWE-252 (Unchecked
Return Value). A constructor has no return value for a caller to ignore — its
only way to report failure is to throw. Neither of these does, so each returns
an object indistinguishable from a valid one. Both defects become structurally
impossible if the constructor throws instead of returning quietly.

One counterintuitive detail: in the *owning* constructor's failure path,
`clear()` looks like it would free garbage, but `m_data != nullptr &&`
short-circuits and `m_data` is genuinely null after a failed nothrow `new`. The
uninitialized flag is harmless there and lethal in `init()`. Reading the code
quickly gets this backwards.

## What Kordon currently detects

**Detected:** CWE-415, via `cppcoreguidelines-special-member-functions`.
`Vector` defines a destructor but no copy constructor or copy assignment, so
the compiler-generated shallow copy produces two objects owning one pointer.
Low confidence, correctly — it is a latent double free, not an observed one.

**Missed: the entire CWE-665 → 824 → 476/590 chain.**

## Why it is missed — measured, not assumed

Two independent causes, established by experiment against clang 18:

**1. The relevant checker is not in `clang-analyzer-*`.**
`optin.cplusplus.UninitializedObject` is an `optin.*` checker and must be named
explicitly. Kordon now enables it by default.

**2. It needs the constructor's call site in the same translation unit.**
With the constructor and a caller in one file, the checker reports precisely:

```
warning: 1 uninitialized field at the end of the constructor call
   [optin.cplusplus.UninitializedObject]
note: uninitialized field 'this->m_owns'
```

Split as it is here — constructor in `vector.cpp`, callers in `algorithm.cpp` —
it reports nothing, even with the checker enabled. Analyzing `algorithm.cpp`,
the constructor is opaque and Clang SA assumes a function it cannot see leaves
the object valid. Analyzing `vector.cpp`, there is no call site to trigger the
check.

The defect falls in the gap between the two files. This is what
`CodeChecker analyze --ctu` exists to close, and this fixture is the concrete
measurement of what not having it costs.

## Status: resolved by CTU

CTU is now implemented (`kordon --ctu`), and this fixture detects the full
chain it was written to predict:

```
$ kordon testdata/uninit_owner --ctu
CWE-665  Improper Initialization              [2]
  vector.cpp:45  1 uninitialized field at the end of the constructor call
  vector.cpp:63  1 uninitialized field at the end of the constructor call
CWE-457  Use of Uninitialized Variable        [1]
  vector.cpp:96  Branch condition evaluates to a garbage value
CWE-476  NULL Pointer Dereference             [1]
  vector.cpp:115 Array access (via field 'm_data') results in a null pointer dereference
```

Both constructors are caught, plus the garbage branch in `init()` and the null
dereference in `at()` — CWE-665 → 824 → 476 exactly as documented above.
Without `--ctu` the same run still reports nothing but the Rule-of-Five
warning, so this doubles as the regression test for CTU itself:

```bash
kordon testdata/uninit_owner --ctu --require-cwe 665,457,476
```

Two things had to be right for this to work, and both fail silently when
wrong: the extdef map must point at serialized ASTs rather than sources, and
the diagnostic format must be `plist-multi-file` — plain `plist` and the text
format both discard any report whose path crosses a file boundary, which is
every CTU finding.
