// Fixture: do C-style macros hide defects from the checks?
//
// Synthetic. Every case is a pair: a plain-code function and a twin that says
// the same thing through a macro. The requirement is that Kordon reports the
// *same* verdict for both halves of a pair. Any divergence is a hider the
// analysis cannot see through, and the pairing is what makes that visible --
// a fixture with only macro code would tell you nothing, since you could not
// tell "correctly silent" from "blind".
//
// Analysis runs on the post-preprocessing AST, so the expectation is that
// macros are transparent. That expectation is worth testing rather than
// assuming, because the guard exemptions in the CWE-191 check match on AST
// *shape*, and a macro can change the shape it expands to.
//
// Measured result: every pair matches. Macros are transparent, including ones
// that hide a guard, a condition, a declaration or a whole function body, and
// findings land on the expansion site rather than the `#define`. Building this
// fixture also caught a real bug -- the guard exemption had stopped matching a
// bare `if (k > 0)` while still matching `if (a && k > 0)`, which no measurement
// against the reference corpus could reveal, because that corpus only uses the
// second form.
//
// The one thing genuinely invisible is not a macro at all: code inside an
// inactive `#ifdef` never reaches the AST. See `never_compiled` at the bottom.

#include <cstddef>

namespace kordon_probe {

void consume(std::size_t);

// --------------------------------------------------- 1. defect inside a macro
// Expect: BOTH flagged, and the macro one reported at the *expansion* site,
// not at the `#define` line -- otherwise the finding is not actionable.

#define LAST_INDEX(x) ((x) - 1)

std::size_t plain_defect(std::size_t k)
{
    return k - 1;
}

std::size_t macro_defect(std::size_t k)
{
    return LAST_INDEX(k);
}

// ------------------------------------------- 2. the guard written as a macro
// Expect: BOTH suppressed. The guard exemption matches an `ifStmt` whose
// condition compares the operand with >, >= or !=. After expansion that is
// exactly what is there -- unless the macro changes the shape.

#define IF_POSITIVE(x) if ((x) > 0)

void plain_guard(std::size_t k)
{
    if (k > 0) {
        consume(k - 1);
    }
}

void macro_guard(std::size_t k)
{
    IF_POSITIVE(k) {
        consume(k - 1);
    }
}

// ------------------------------------ 3. only the condition hidden in a macro
// Expect: BOTH suppressed. Here the `ifStmt` is written out and only the
// comparison comes from a macro, so the exemption should still see it.

#define IS_POSITIVE(x) ((x) > 0)

void macro_condition(std::size_t k)
{
    if (IS_POSITIVE(k)) {
        consume(k - 1);
    }
}

// ------------------------------ 4. guard and control flow both inside a macro
// Expect: BOTH flagged. This is the early-exit shape the check already cannot
// see (documented in clang_query.rs), so the macro version must not look any
// better than the plain one. Modelled on a real codebase's ACL_THROW.

#define THROW_IF(cond) if (cond) throw "invalid"

void plain_early_exit(std::size_t k)
{
    if (k == 0) {
        throw "invalid";
    }
    consume(k - 1);
}

void macro_early_exit(std::size_t k)
{
    THROW_IF(k == 0);
    consume(k - 1);
}

// ------------------------------------------- 5. the declaration hidden away
// Expect: BOTH flagged. The variable is introduced by a macro, so the
// declaration and its use have different apparent origins.

#define DECLARE_ZERO(name) std::size_t name = 0

std::size_t plain_declaration()
{
    std::size_t n = 0;
    return n - 1;
}

std::size_t macro_declaration()
{
    DECLARE_ZERO(n);
    return n - 1;
}

// ---------------------------------------- 6. a whole function body generated
// Expect: BOTH flagged. A macro that expands to an entire member function is
// the hardest form of hiding short of code generation.

#define DEFINE_LAST(cls) std::size_t cls::last() const { return m_count - 1; }

struct PlainHolder {
    std::size_t m_count;
    std::size_t last() const { return m_count - 1; }
};

struct MacroHolder {
    std::size_t m_count;
    std::size_t last() const;
};

DEFINE_LAST(MacroHolder)

// ------------------------------------ 7. many expansions of one macro
// Expect: three separate findings, one per use site. If they collapsed into a
// single finding at the `#define`, two real defects would be invisible.

std::size_t use_a(std::size_t k) { return LAST_INDEX(k); }
std::size_t use_b(std::size_t k) { return LAST_INDEX(k); }
std::size_t use_c(std::size_t k) { return LAST_INDEX(k); }

// ------------------------------------------ 8. the actual blind spot: #ifdef
// Expect: NOT flagged, and that is not a bug in the check -- this code is not
// in the AST at all unless the configuration defines the macro. No engine can
// see it, and no improvement to the checks will change that. The only fix is
// to analyze the other configuration as a separate run.

std::size_t never_compiled(std::size_t k)
{
#ifdef KORDON_ENABLE_LEGACY_PATH
    return k - 1;
#else
    return k;
#endif
}

}  // namespace kordon_probe
