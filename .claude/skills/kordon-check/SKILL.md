---
name: kordon-check
description: How to make Kordon detect a shape — the decision ladder from naming a compiler diagnostic, enabling an existing Clang SA or cppcheck checker, fixing a CWE mapping rule, through writing a new clang-query AST-matcher check in src/tools/clang_query.rs with its cwe_map.toml rule and Rust test. Includes the clang-query validation command and the matcher traps that cost measurements. Use when a triaged shape is verdict A, B or C.
---

# Making Kordon see a shape

Cheapest mechanism that expresses the defect wins. Most of this repo's gains
came from the first three rungs; a new matcher is the last resort before
"engine change", not the first move.

## The ladder

**1. A compiler diagnostic Kordon has not named.** clang already reports
`-Wreturn-stack-address`, `-Wmisleading-indentation`, `-Wunused-variable`.
A `clang-diagnostic-<name>` check does nothing unless it is *named* in
`DEFAULT_CHECKS` and the warning is *on*: add the name in
`src/tools/clang_tidy.rs` `DEFAULT_CHECKS`, the flag in `FORCED_WARNINGS`, and
a `[[rule]]` in `data/cwe_map.toml`. Every one named so far closed a real gap.
Find candidates with `clang -Weverything -fsyntax-only` on the fixture and
`grep` the warning name.

**2. A checker that exists and is not enabled.** clang-tidy's `clang-analyzer-*`
does *not* include `optin.*` or `alpha.*`. `optin.*` can be named in
`DEFAULT_CHECKS`; **`alpha.*` cannot be enabled through clang-tidy at all** —
they run only in the `clang --analyze` pass (`src/tools/clang_sa.rs`
`ALPHA_CHECKERS`, and `CTU_CHECKERS` for the `--ctu` pass). cppcheck runs with
`--enable=warning,style,portability`; check whether the id you need is
`inconclusive` (needs `--inconclusive`) before assuming it is absent. List what
exists: `clang -cc1 -analyzer-checker-help-alpha`, `cppcheck --errorlist`.

**3. A mapping that files the finding wrong.** Run Kordon `--json --all` on the
fixture and look at `native_ids`, `message`, `cwe`, `confidence`. Common cases:

- one check id covers several classes (`unix.Malloc` is leak, UAF, double
  free and free-of-non-heap) → a `message_contains` rule, placed **before** the
  bare rule for the same check
- cppcheck's native `cwe=` is the *parent* class (`operatorEqToSelf` says 398,
  is 416) → an override rule
- a guideline check filed under a defect CWE (`pro-bounds-*`, `init-variables`)
  → tier-0 CWE-398 at low confidence, still enabled; it inflates recall *and*
  false positives and never reaches the report
- the right CWE at the wrong confidence — see the two-axis rule below

**4. A new clang-query check.** Only for a shape no engine expresses. Below.

**5. Beyond matchers.** Statement order, value ranges, ownership across calls.
Write the verdict in the brief and stop; do not build a matcher that fires on
shape alone.

## Writing a clang-query check

Checks live in `src/tools/clang_query.rs` as `QueryCheck` constants whose
matcher is built by a function (`one_sided_index_guard_matcher()` is the model
to copy: every clause back-references one bound node, so the whole matcher is
assembled rather than base-plus-guards). Steps:

1. **Validate the matcher by hand first**, on the fixture:

       clang-query-18 -c 'match arraySubscriptExpr(...)' testdata/<f>/<file>.c -- -std=c11 -I testdata/<f>
       clang-query-18 -p <dir with compile_commands.json> -c 'match ...' file.cpp

   **A malformed matcher returns 0 matches, not an error, and so does a file
   that failed to parse.** Both look exactly like "no defects here". Check the
   positive twin matches *before* checking the good twin does not.

2. Add a `pub const <NAME>: QueryCheck` at the **end of the file**, a variant to
   `Exemption` if the matcher is assembled whole, the dispatch in
   `QueryCheck::matcher()`, and the constant at the **end of `CHECKS`**.
   Append-only: other lanes are editing the same file.

3. Add the `[[rule]]` to `data/cwe_map.toml` (tool `kordon-query`, your check
   id, CWE, confidence, optional `severity`). The test
   `every_check_is_mapped_to_a_cwe` fails otherwise.

4. Write a Rust test asserting the matcher's *invariants*, not its text: the
   clause that separates the twins is present (`assert!(m.contains(...))`), the
   exemption that must *not* apply is absent, parentheses balance. Look at
   `unchecked_negative_index_differs_from_its_mirror_deliberately` for the
   shape.

5. `cargo test --release`, then `scripts/check-fixtures.py --only <fixture>`.

## Matcher rules that each cost a measurement

- **`hasDescendant(X)` does not match the node itself.** `hasRHS(hasDescendant(callExpr()))`
  misses `data = atoi(buf)`, where the call *is* the RHS. Write
  `anyOf(ignoringParenImpCasts(X), hasDescendant(X))` by default. Three times.
- **Key on the operand, not the operator.** `i >= 0` and `i < 0` are both sign
  checks; `i < 10` and `i >= 10` are both bounds. The other side of the
  comparison decides.
- **Say where the value came from.** Without a "filled from a call" clause an
  index check fires on every loop counter compared to zero: 160 positions on
  two real projects. Three spellings: `x = f()`, `int x = f()`, `f(&x)`.
- **Type-check.** A `size_t` cannot be negative; `int - 2` is not an
  underflow; `double / 0` does not trap. Each of these was a false positive
  until the matcher consulted the type.
- **Scope the exemption to the same object.** "Bounded by its own call" must
  name the *same* array the subscript indexes.
- **Statement order is not expressible.** "This assignment precedes that use"
  cannot be matched; only nesting can (`hasAncestor`, `unless(hasAncestor(...))`).
  Design around it, or record it as the reason for medium rather than high.
- **An exemption can be satisfied by the defect's own `if`.** `if (x > w - 1)
  return;` evaluates `w - 1` *inside* the guard. Require the use not to be
  inside the exempting condition.
- Always: `unless(isExpansionInSystemHeader())`, `unless(isInTemplateInstantiation())`.

## Confidence and severity — two axes, decided per check

- **Confidence** is how sure Kordon is that this is real; it comes from the
  check. High: the tool proved it (path-sensitive, has both sizes). Medium: a
  logic error visible in the code (`&&` short-circuit order, one side of a
  range never tested). Low: a risk pattern whose intent decides (unsigned
  subtraction). Low never reaches the report without `--all`.
- **Severity** is how bad it is if real; it comes from the *class*. Tier 1
  defaults to `error`; `severity = "style"` on the rule puts a defined-behaviour
  finding in the **Advice** band. When the same shape has two consequences
  (integer vs float divisor), make **two check ids**, because an id carries one
  severity.
- Independent agreement raises confidence one step in dedup; two low matchers
  never reach high.

## Cost

Every check runs on every unit of every project. Note the clang-query run time
on `rtklib_mod` before and after (`time kordon ~/VsCode/Satellite/rtklib_mod
-p <its build>`), and prefer one assembled matcher over several passes.
