//! Kordon's own AST-matcher checks, run through `clang-query`.
//!
//! These cover defect classes with no off-the-shelf check. They are written as
//! Clang AST matcher expressions and executed by `clang-query`, rather than as
//! a compiled clang-tidy plugin: the matcher is the entire content of the
//! check, and running it this way needs no LLVM development headers, no plugin
//! ABI to track across releases, and no build step for the user.
//!
//! Most of these are **low confidence** on purpose. An AST matcher sees shape,
//! not intent, and for the arithmetic classes intent is exactly what decides
//! whether the shape is a defect -- so they live permanently in the
//! risk-pattern tier, summarized by count, rather than pending a better
//! analysis.
//!
//! Not all of them, though, and the distinction matters. A matcher can also
//! recognise a *logic error*, where the code does something demonstrably other
//! than what it says: an index subscripted before the condition that bounds it
//! is wrong regardless of intent, because `&&` evaluates left to right. Those
//! earn medium confidence. Each check's confidence comes from the mapping
//! table, so this is a decision recorded per check rather than a blanket rule.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::compile_db::CompileDb;
use crate::cwe::CweTable;
use crate::finding::{Confidence, Finding, Severity, Tool};
use crate::tools::{ToolOutcome, ToolRun};

pub fn tool() -> Tool {
    Tool::new("kordon-query")
}

pub struct QueryCheck {
    /// Reported as the native check id. `kordon-` marks it as our own.
    pub id: &'static str,
    /// The matcher body, without its closing parenthesis, so guard clauses can
    /// be appended. Kept split because the guards are the part that changes:
    /// each one exempts a way of writing "I already checked this".
    pub base: &'static str,
    /// Which exemptions to append. Each check has its own notion of "already
    /// handled", and using the wrong one is worse than using none.
    pub exemption: Exemption,
    /// Extra compiler flags for this check alone.
    pub extra_args: &'static [&'static str],
    /// Only run where the build defines this macro. A check about what a
    /// particular build configuration removes is meaningless anywhere else.
    pub only_if_defined: Option<&'static str>,
    /// Shown in the finding message.
    pub message: &'static str,
}

/// What counts as "the programmer already handled this" for a given check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exemption {
    /// Nothing is exempt.
    None,
    /// The operand is already known non-zero by an enclosing condition.
    ArithmeticGuard,
    /// The asserted condition is also tested by real code, so the check does
    /// survive into the shipped build after all.
    RealCheckPresent,
    /// The operand is a loop's own counter, so the arithmetic tracks the loop
    /// rather than any value that could be near the type maximum.
    LoopCounter,
    /// Not an exemption: this check's matcher is assembled whole, because its
    /// two halves have to share a binding.
    IndexOrder,
    /// Not an exemption either: assembled whole, because all three clauses have
    /// to back-reference the same subscripted parameter.
    ParallelExtent,
    /// Assembled whole for the same reason, and exempting only *extent* tests
    /// rather than any mention of the parameter.
    ConstantIndex,
    /// Assembled whole: the same guards as `ArithmeticGuard`, over a left
    /// operand narrowed to a container-extent accessor.
    ExtentUnderflow,
    /// Assembled whole, because the release must be recognised as releasing
    /// the same member that is being overwritten.
    ReinitWithoutFree,
}

impl QueryCheck {
    pub fn matcher(&self) -> String {
        if self.exemption == Exemption::IndexOrder {
            return index_order_matcher();
        }
        if self.exemption == Exemption::ParallelExtent {
            return parallel_extent_matcher();
        }
        if self.exemption == Exemption::ConstantIndex {
            return constant_index_matcher();
        }
        if self.exemption == Exemption::ExtentUnderflow {
            return extent_underflow_matcher();
        }
        if self.exemption == Exemption::ReinitWithoutFree {
            return reinit_without_free_matcher();
        }
        let mut m = String::from(self.base);
        match self.exemption {
            Exemption::None => {}
            Exemption::ArithmeticGuard => {
                append_arithmetic_guards(&mut m);
                // A container extent on the left is 20x more likely to be a
                // real defect, so it belongs to EXTENT_UNDERFLOW and is
                // excluded here rather than reported twice at two tiers.
                m.push_str(&format!(
                    ", unless(hasLHS(ignoringParenImpCasts({EXTENT_CALL})))"
                ));
            }
            Exemption::IndexOrder
            | Exemption::ParallelExtent
            | Exemption::ConstantIndex
            | Exemption::ExtentUnderflow
            | Exemption::ReinitWithoutFree => unreachable!("handled above"),
            Exemption::LoopCounter => {
                m.push_str(", unless(");
                m.push_str(LOOP_COUNTER_OPERAND);
                m.push(')');
            }
            Exemption::RealCheckPresent => {
                for shape in REAL_CHECK_SHAPES {
                    m.push_str(", unless(");
                    m.push_str(&real_check_clause(shape));
                    m.push(')');
                }
            }
        }
        m.push(')');
        m
    }
}

/// One way of naming a value inside a condition, bound and back-referenced.
struct CheckShape {
    bound: &'static str,
    back_reference: &'static str,
}

/// `a.cols` -- a member of some object.
const CHECK_MEMBER: CheckShape = CheckShape {
    bound: "memberExpr(member(fieldDecl().bind(\"af\")))",
    back_reference: "memberExpr(member(fieldDecl(equalsBoundNode(\"af\"))))",
};

/// `n` -- a plain variable or parameter.
const CHECK_VAR: CheckShape = CheckShape {
    bound: "declRefExpr(to(varDecl().bind(\"av\")))",
    back_reference: "declRefExpr(to(varDecl(equalsBoundNode(\"av\"))))",
};

const REAL_CHECK_SHAPES: &[CheckShape] = &[CHECK_MEMBER, CHECK_VAR];

/// Exempt an assert whose condition is also tested by real code.
///
/// `assert(c)` expands to the ternary `c ? (void)0 : __assert_fail(...)`, never
/// to an `if`. So any `ifStmt` in the function is code that survives NDEBUG,
/// and an assert duplicated by one is documentation rather than the only
/// defence. Written `assert(x == y); if (x != y) return;` -- which is a
/// reasonable idiom -- the check must stay quiet.
///
/// Tying the two together by the *declaration* they name is an approximation:
/// a function that asserts about one object and separately tests the same field
/// of another is exempted too. That errs toward silence, which is the right
/// direction for a check that is low confidence by construction.
fn real_check_clause(shape: &CheckShape) -> String {
    format!(
        "allOf(\
hasAncestor(conditionalOperator(hasCondition(hasDescendant({bound})))), \
hasAncestor(functionDecl(hasDescendant(ifStmt(hasCondition(hasDescendant({back})))))))",
        bound = shape.bound,
        back = shape.back_reference
    )
}


/// One guard: an operand shape plus the same shape written as a back-reference.
///
/// Guards are built rather than spelled out because the two halves must stay in
/// lockstep -- the bound form and the `equalsBoundNode` form differ by a few
/// tokens, and keeping three hand-written copies balanced across nine nesting
/// levels is how the `hasDescendant` bug below got in unnoticed.
struct GuardShape {
    /// Matches the subtraction's left operand and binds its parts.
    operand: &'static str,
    /// Matches the same thing again, by back-reference, in the condition.
    back_reference: &'static str,
}

/// Plain variable: `if (k > 0) { ... k - 1 ... }`.
const SHAPE_VAR: GuardShape = GuardShape {
    operand: "declRefExpr(to(varDecl().bind(\"v\")))",
    back_reference: "declRefExpr(to(varDecl(equalsBoundNode(\"v\"))))",
};

/// Method call on a local: `if (v.size() > 0) { ... v.size() - 1 }`.
///
/// `equalsBoundNode` on the two call expressions would never match -- they are
/// distinct AST nodes. The identity that matters is *same method on same
/// object*, so callee and object are bound separately.
const SHAPE_CALL_ON_VAR: GuardShape = GuardShape {
    operand: "cxxMemberCallExpr(callee(cxxMethodDecl().bind(\"m\")), \
on(ignoringParenImpCasts(declRefExpr(to(varDecl().bind(\"o\"))))))",
    back_reference: "cxxMemberCallExpr(callee(cxxMethodDecl(equalsBoundNode(\"m\"))), \
on(ignoringParenImpCasts(declRefExpr(to(varDecl(equalsBoundNode(\"o\")))))))",
};

/// Method call on a member: `if (dataIn.width() > 0) { ... }`.
///
/// Load-bearing rather than exotic: it is how the reference codebase actually
/// writes its fixes, and without it the check reported corrected code
/// identically to broken code.
const SHAPE_CALL_ON_MEMBER: GuardShape = GuardShape {
    operand: "cxxMemberCallExpr(callee(cxxMethodDecl().bind(\"m2\")), \
on(ignoringParenImpCasts(memberExpr(member(fieldDecl().bind(\"f\"))))))",
    back_reference: "cxxMemberCallExpr(callee(cxxMethodDecl(equalsBoundNode(\"m2\"))), \
on(ignoringParenImpCasts(memberExpr(member(fieldDecl(equalsBoundNode(\"f\")))))))",
};

const GUARD_SHAPES: &[GuardShape] = &[SHAPE_VAR, SHAPE_CALL_ON_VAR, SHAPE_CALL_ON_MEMBER];

/// Build the `unless(...)` clause exempting a subtraction whose operand is
/// already known non-zero.
///
/// The condition is matched as `anyOf(cmp, hasDescendant(cmp))`, and both arms
/// are required. `hasDescendant` does **not** match the node itself, so a bare
/// `if (k > 0)` -- where the comparison *is* the condition -- is only caught by
/// the first arm, while `if (a.empty() && k > 0)` is only caught by the second.
/// Using `hasDescendant` alone silently stopped exempting the simple form,
/// which the corpus happened not to use, so the regression measured clean.
///
/// The guard may be an `if`, a `while`, or a `for` condition. All three
/// establish the fact before the body runs, and code uses them
/// interchangeably: `while (k > 0) { use(k - 1); --k; }` and
/// `for (i = n; i > 0; --i) use(i - 1)` are as common as the `if` form and were
/// reported as defects until each was added.
///
/// `do`/`while` is deliberately absent. Its condition is evaluated *after* the
/// body, so the first iteration runs unguarded and the subtraction really can
/// underflow -- exempting it would hide a real defect.
///
/// Only `>`, `>=` and `!=` count. `if (k < n)` establishes nothing about zero,
/// and an earlier version that accepted any comparison swallowed three real
/// defects.
fn guard_clause(shape: &GuardShape) -> String {
    let cmp = format!(
        "binaryOperator(hasAnyOperatorName(\">\", \">=\", \"!=\"), \
hasLHS(ignoringParenImpCasts({})))",
        shape.back_reference
    );
    let condition = format!("hasCondition(anyOf({cmp}, hasDescendant({cmp})))");
    format!(
        "allOf(hasLHS(ignoringParenImpCasts({operand})), \
hasAncestor(stmt(anyOf(\
ifStmt({condition}), \
whileStmt({condition}), \
forStmt({condition})))))",
        operand = shape.operand
    )
}

/// A loop counter that starts above zero cannot underflow by the amount it
/// started above.
///
/// `for (std::size_t i = 1; i < n; ++i) use(v[i - 1]);` is idiomatic and safe,
/// and the guard is the loop's initialiser rather than any `if`, so none of the
/// condition-based exemptions see it. Found by running against a real project
/// where two of the three reported defects were exactly this shape.
///
/// The initialiser carries an implicit cast when the counter is wider than the
/// literal -- `std::size_t i = 1` is `int` 1 converted -- so the literal has to
/// be reached through `ignoringParenImpCasts`. Without that the clause silently
/// matches nothing, which looks identical to having no false positives to
/// remove.
///
/// Deliberately crude: any non-zero start exempts any constant subtrahend, so
/// `for (i = 1; ...) v[i - 5]` is exempted too. Erring toward silence is right
/// for a low-confidence check, and on the measured corpus this removes two
/// false positives while keeping all 49 true positives.
const LOOP_INIT_GUARD: &str = "allOf(\
hasLHS(ignoringParenImpCasts(declRefExpr(to(varDecl().bind(\"lv\"))))), \
hasAncestor(forStmt(hasLoopInit(declStmt(hasSingleDecl(varDecl(\
equalsBoundNode(\"lv\"), \
hasInitializer(ignoringParenImpCasts(integerLiteral(unless(equals(0))))))))))))";

/// CWE-191, unsigned wraparound.
///
/// Nothing else Kordon drives detects this class at all -- verified against
/// cppcheck (exhaustive), clang-tidy, Clang SA including `alpha.core`, and both
/// gcc and clang warning sets, none of which flag even a constant
/// `size_t n = 0; return n - 1;`. The reason is not tool weakness: unsigned
/// wraparound is *well-defined* C++, so it is not something a compiler may
/// warn about as erroneous. Only clang's opt-in
/// `-fsanitize=unsigned-integer-overflow` reports it, and only at runtime, on
/// executed paths.
///
/// So this matcher is the only way to reach the class statically, and it
/// cannot be precise by construction: subtracting from an unsigned value is
/// legal and often intentional (hashes, checksums, modular arithmetic). It
/// flags the shape and leaves the judgement to a human.
///
/// The `unless(allOf(...))` clause is the guard exemption: `if (k > 0) { k - 1 }`
/// is safe and must not be reported, while the bare `k - 1` must be. It fires
/// only for conditions that can actually establish the operand is non-zero --
/// `>`, `>=`, `!=` against the same variable. An earlier version suppressed on
/// *any* enclosing `if` mentioning the variable, which also swallowed
/// `if (k < n)`; that guards nothing, and it cost three real defects on the
/// measured corpus.
///
/// Recall alone is a worthless number for a check like this, and measuring it
/// alone was a mistake: a matcher that flagged every `unsigned - 1` would also
/// score 94%. What matters equally is whether the check goes quiet on *fixed*
/// code. Run against a corrected copy of the same corpus, the first version
/// reported the fixed code identically to the broken code -- because the fix
/// was written as `if (data.width() > 0)` on a class member, and the exemption
/// only understood plain locals. `GUARD_CALL_ON_MEMBER` closes that, and is
/// the reason the check distinguishes the two trees at all.
///
/// After it: 49/52 still flagged on the broken tree, and of the 52 positions in
/// the fixed tree only 7 still flag -- all 7 verified byte-identical between
/// the trees, i.e. never actually fixed. Every genuinely corrected site goes
/// quiet.
///
/// One guard shape remains unreachable, and it is not a matter of adding
/// another clause. A precondition validated by an early exit --
/// `if (a > b) throw ...;` followed later by `b - a` -- has no containment
/// relationship to exploit, compares a different pair of expressions than the
/// subtraction uses, and depends on the throw not returning. That is a
/// dataflow fact, and it belongs to the abstract-interpretation layer.
///
/// Macros are transparent to all of this, verified with paired fixtures in
/// `testdata/macros/`: a defect inside a macro body is flagged at the
/// *expansion* site, a guard written as a macro still exempts, and a macro that
/// hides only the comparison still exempts. Every macro case reports the same
/// verdict as its plain-code twin. The genuine blind spot is `#ifdef`, which is
/// not a macro problem at all -- inactive configurations never reach the AST.
///
/// Measured against a 52-position ground-truth list on a real codebase:
///
///   broad, guard-blind    541 matches, 49/52 = 94% recall
///   loose guard           503 matches, 46/52 = 88%   (over-suppressed)
///   tight guard (this)    540 matches, 49/52 = 94%
///   narrow, calls only    174 matches, 25/52 = 48%   (precision not worth it)
///
/// The tight guard costs no recall. It suppressed only one match on that
/// corpus, which barely uses the guard idiom -- consistent with it having 52
/// genuine underflows. On code that does guard properly it is what keeps the
/// check from being noise.
pub const UNSIGNED_SUBTRACTION: QueryCheck = QueryCheck {
    id: "kordon-unsigned-subtraction",
    base: "binaryOperator(hasOperatorName(\"-\"), \
hasType(isUnsignedInteger()), \
hasRHS(ignoringParenImpCasts(integerLiteral())), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation())",
    exemption: Exemption::ArithmeticGuard,
    extra_args: &[],
    only_if_defined: None,
    message: "unsigned subtraction with no guard that the left operand is large enough; \
wraps to a huge value instead of going negative",
};

/// Build the index-used-before-check matcher.
///
/// Assembled here rather than declared as a base string because the subscript
/// and the comparison must refer to the same declaration, which needs a binding
/// threaded through both halves.
fn index_order_matcher() -> String {
    let mut alternatives = Vec::new();
    for shape in REAL_CHECK_SHAPES {
        // The right operand must *compare* the index. Merely mentioning it
        // matches innocent repeated subscripting.
        let cmp = format!(
            "binaryOperator(hasAnyOperatorName(\"<\", \"<=\", \">\", \">=\", \"!=\", \"==\"), \
hasEitherOperand(ignoringParenImpCasts({back})))",
            back = shape.back_reference
        );
        alternatives.push(format!(
            "allOf(\
hasLHS(forEachDescendant(arraySubscriptExpr(hasIndex(ignoringParenImpCasts({bound}))))), \
hasRHS(anyOf({cmp}, hasDescendant({cmp}))))",
            bound = shape.bound
        ));
    }
    format!(
        "binaryOperator(hasAnyOperatorName(\"&&\", \"||\"), anyOf({}), \
unless(isExpansionInSystemHeader()), unless(isInTemplateInstantiation()))",
        alternatives.join(", ")
    )
}

/// `i + 1` where `i` is the loop's own counter.
///
/// For this to overflow the loop would have to reach the type maximum, which
/// means iterating 2^64 times. Real code writes `i + 1` constantly to look at
/// the next element, and reporting each one buries the shape that matters.
///
/// The distinction is exact rather than heuristic: the operand must be the
/// variable the enclosing `for` declares. On the reference corpus 4 of the 19
/// CWE-190 positions sit in a loop header, and every one of them adds to
/// something else -- `nOctaveLayers + 3`, `roi_out.bottom() + 1` -- so none is
/// exempted. Measured: 171 findings drop to 163 with all 17 detections kept.
const LOOP_COUNTER_OPERAND: &str = "allOf(\
hasLHS(ignoringParenImpCasts(declRefExpr(to(varDecl().bind(\"ci\"))))), \
hasAncestor(forStmt(hasLoopInit(declStmt(hasSingleDecl(\
varDecl(equalsBoundNode(\"ci\"))))))))";

/// CWE-190, integer overflow on addition.
///
/// The mirror of [`UNSIGNED_SUBTRACTION`], and unreachable by the same engines
/// for the same reason: unsigned wraparound is well-defined, so no compiler may
/// call `x + 1` erroneous. Signed overflow *is* UB and clang's default
/// `-fsanitize=undefined` does trap it, but only at runtime on executed paths.
///
/// The matcher is deliberately the addition mirror rather than something more
/// clever. Measured against the 19-position ground truth:
///
///   unsigned + literal (this)      463 matches, 17/19 = 89%
///   addition whose operand is a
///     subtraction (`a - b + 1`)    135 matches,  9/19 = 47%
///   unsigned multiplication       1228 matches,  6/19 = 32%
///
/// The subtraction-then-add variant looked like the most characteristic shape
/// -- the corpus is full of `roi.right() - roi.left() + 1` -- but it turned out
/// to be a strict subset of this one, since that expression's right operand is
/// still the literal 1. It was dropped as redundant.
///
/// Multiplication was rejected outright: 1228 further matches to gain a single
/// defect. Overflow in a multiplication used as an allocation size is a real
/// and dangerous class (CWE-680), but flagging every unsigned `*` is not a way
/// to find it. That needs the size-argument context, and is better left to the
/// abstract-interpretation layer which can bound the operands.
///
/// No guard exemption, unlike the subtraction check. `x + 1` overflows only
/// when `x` is at the type maximum, and code effectively never guards that
/// explicitly, so there is no idiom to exempt.
pub const UNSIGNED_ADDITION: QueryCheck = QueryCheck {
    id: "kordon-unsigned-addition",
    base: "binaryOperator(hasOperatorName(\"+\"), \
hasType(isUnsignedInteger()), \
hasRHS(ignoringParenImpCasts(integerLiteral())), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation())",
    exemption: Exemption::LoopCounter,
    extra_args: &[],
    only_if_defined: None,
    message: "unsigned addition with no check that the left operand is below the type maximum; \
wraps to a small value instead of growing",
};

/// CWE-401, ownership expressed as a bool instead of in the type.
///
/// Matches a `delete` of a pointer member that only runs when a *boolean
/// member* says so -- `if (m_data && m_flgAllocMemory) delete[] m_data;`. The
/// class owns memory conditionally, and the condition is a flag that ordinary
/// code can get wrong: leave it unset on one constructor path and the memory
/// leaks at every scope exit; copy the object and two owners believe they hold
/// the same pointer.
///
/// This targets the **cause**, not the symptom, and that is the whole point.
/// On the reference corpus 66 CWE-401 positions are recorded across 18 files,
/// almost all reported at a closing brace -- the scope exit of some unrelated
/// function that merely happened to hold a `Matrix` or a `Vector` local. They
/// are 66 consequences of a handful of class-level defects. Fixing the sites is
/// impossible; fixing the classes removes all of them.
///
/// Measured: 5 matches on the broken tree (3 in vector.cpp, 2 in matrix.cpp)
/// and **0 on the corrected tree**, where the fix deleted the flag outright and
/// moved ownership into a member smart pointer:
///
///   before   if (m_data && m_flgAllocMemory) { delete[] m_data; }
///   after    m_own.reset();
///
/// Consequence for scoring: this check will barely move recall against a
/// line-keyed ground truth, because it reports ~5 causes where the list records
/// 66 effects. That is a property of the measurement, not of the check.
pub const MANUAL_OWNERSHIP_FLAG: QueryCheck = QueryCheck {
    id: "kordon-manual-ownership-flag",
    base: "cxxDeleteExpr(\
hasDescendant(memberExpr(member(fieldDecl().bind(\"p\")))), \
hasAncestor(ifStmt(hasCondition(hasDescendant(\
memberExpr(member(fieldDecl(hasType(booleanType())).bind(\"flag\"))))))), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation())",
    exemption: Exemption::None,
    extra_args: &[],
    only_if_defined: None,
    message: "owning pointer member is released only when a bool member permits it; \
ownership lives in a flag rather than in the type, so any path that leaves the flag wrong \
leaks the memory or frees it twice",
};

/// Validation that exists only in debug builds.
///
/// `assert(cond)` expands to nothing when `NDEBUG` is defined, so a function
/// whose only precondition check is an assert has no check at all in the build
/// that ships. Nothing else can see this: the assert is gone before any
/// analyser looks, so every engine reports the function as unguarded-but-fine.
/// This check restores it with `-UNDEBUG` purely to find it, and reports it
/// only for units the build actually compiles with `NDEBUG`.
///
/// The reference codebase is the case in point. `matMult` validates its
/// dimensions with nothing but
///
///     assert(a.getCols() == b.getRows() && ...);
///
/// and then runs `res(i,j) += a(i,k) * b(k,j)` with the loop bounded by
/// `a.getCols()`. Under NDEBUG a mismatched pair indexes `b` past its bounds.
/// Two of the defects its maintainers list as still-open are exactly this, and
/// they were the only CWE-119 positions no engine reached.
///
/// Measured there: 448 of 448 translation units define NDEBUG, and 517 assert
/// sites disappear with them -- an order of magnitude fewer than `pro-bounds-*`
/// emits, for a hazard that is real by construction rather than by suspicion.
///
/// Low confidence, like everything else here: an assert may be documenting an
/// invariant the caller genuinely cannot violate. What the check states is a
/// fact about the build, not a claim about the code.
pub const ASSERT_ONLY_VALIDATION: QueryCheck = QueryCheck {
    id: "kordon-assert-only-validation",
    // Under -UNDEBUG, `assert(c)` becomes `c ? void(0) : __assert_fail(...)`,
    // so the call to __assert_fail is what marks the site.
    base: "callExpr(\
callee(functionDecl(hasName(\"__assert_fail\"))), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation())",
    exemption: Exemption::RealCheckPresent,
    extra_args: &["-UNDEBUG"],
    only_if_defined: Some("NDEBUG"),
    message: "this check does not exist in this build: assert() expands to nothing under \
NDEBUG, which the build defines, so whatever it validates goes unvalidated at run time",
};

/// An index is used to subscript before the condition that bounds it.
///
/// `&&` and `||` evaluate left to right and short-circuit, so in
///
///     while (m_ptrack[m_start] == NULL && m_start < m_count)
///
/// the read happens first and the bounds check never protects it. When
/// `m_start` reaches `m_count` the loop reads one past the end. The fix is to
/// swap the operands; the bug is invisible to a reader skimming for "is it
/// checked", because it is -- just too late.
///
/// This is a logic error rather than a risky shape, so it reports at medium
/// confidence rather than low. The programmer wrote the bounds check, which
/// says they believed it was needed; having it on the wrong side of the
/// operator is not a style preference.
///
/// Precision comes from insisting the right operand *compares the index
/// itself*. A looser version -- the index merely appearing on the right --
/// matched 19 sites, nearly all of them innocent repeated subscripting like
/// `hist[i] > hist[l] && hist[i] > hist[r]`. Requiring the comparison brings it
/// to **2 sites across 274 files, both genuine**, against the 3798 findings
/// `pro-bounds-pointer-arithmetic` emits to cover the same defects.
pub const INDEX_USED_BEFORE_CHECK: QueryCheck = QueryCheck {
    id: "kordon-index-used-before-check",
    base: "",   // built by matcher(); see Exemption::None arm below
    exemption: Exemption::IndexOrder,
    extra_args: &[],
    only_if_defined: None,
    message: "this index is used to subscript before the condition that bounds it; \
&& and || evaluate left to right, so the read happens first and the check comes too late",
};

/// Build the unchecked-parallel-extent matcher.
///
/// Assembled here rather than declared as a base string because the subscript
/// and both exemptions have to name the same parameter, which needs one
/// binding threaded through all three.
fn parallel_extent_matcher() -> String {
    // The subscripted object, bound so the exemptions can refer back to it.
    let param = "declRefExpr(to(parmVarDecl().bind(\"p\")))";
    let same_param = "declRefExpr(to(parmVarDecl(equalsBoundNode(\"p\"))))";
    format!(
        "cxxOperatorCallExpr(\
anyOf(hasOverloadedOperatorName(\"[]\"), hasOverloadedOperatorName(\"()\")), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation()), \
hasArgument(0, {param}), \
hasAncestor(forStmt()), \
unless(hasAncestor(forStmt(hasCondition(hasDescendant({same_param}))))), \
unless(hasAncestor(functionDecl(hasDescendant(\
ifStmt(hasCondition(hasDescendant({same_param}))))))))"
    )
}

/// A loop bounded by one object's extent subscripts another object that was
/// never checked against it.
///
/// The shape, from the reference codebase:
///
///     void Vector::operator+=(Vector &v)
///     {
///         assert(m_length == v.m_length);
///         for (int i = 0; i < m_length; i++)
///             m_data[i] += v[i];          // v may be shorter than m_length
///     }
///
/// The loop is bounded by `this` object's extent, but the body subscripts `v`,
/// whose extent nothing establishes. `assert` is not a check -- it expands to a
/// `conditionalOperator`, and to nothing at all under NDEBUG -- so under the
/// shipped build a shorter `v` is read out of bounds.
///
/// The corrected tree fixes exactly this by adding a real test, which is what
/// the second exemption looks for:
///
///     if (v.m_length < m_length) { return; }
///
/// Two exemptions carry the precision. The first drops loops bounded by the
/// *same* object being subscripted -- `for (i = 0; i < v.size(); ++i) v[i]` is
/// self-evidently safe, and without this clause a single file of
/// `push_back(list[i])` calls contributed 55 findings. The second drops any
/// function containing a real `if` that tests the subscripted parameter; since
/// `assert` never expands to an `ifStmt`, an assert cannot silence the check.
///
/// Measured across 452 translation units: **181 positions on the broken tree,
/// 151 on the corrected one (-17%)**, against `pro-bounds-pointer-arithmetic`'s
/// 2326 findings that move -1% between the same two trees. It reaches defects
/// the reference tool did not list, including `SparseVector::colMult`, where
/// the index written into the caller's vector comes from stored data
/// (`pos = m_ppos[i]`) and is bounded by nothing whatsoever.
///
/// ### Why the loop bound is not required to be a member
///
/// An earlier version required the `for` condition to contain a `memberExpr`,
/// as a proxy for "bounded by this object's own extent". That scored -48%,
/// much sharper, and missed the entire matrix-multiply family:
///
///     int arows = blc.getRows();          // extent copied into a local first
///     ...
///     for (i = 0; i < arows; i += size)
///       for (k = i; k < i + size; k++)
///         for (m = i; m < i + size; m++)
///           res(m,j) += blc(m,k) * a(k,j);   // m runs past arows
///
/// The bound is a local, so no `memberExpr` appears in any condition, and `m`
/// ranges over `[i, i + size)` which overruns `res` whenever `arows` is not a
/// multiple of `size`. Dropping the requirement takes CWE-119 recall from
/// 33/86 to 44/86 and specificity from -48% to -17%.
///
/// That trade is only acceptable because this check is low confidence and its
/// findings are summarized rather than detailed: the low tier grows 1.4% for
/// 11 more ground-truth positions. Measured against the defects the
/// maintainers actually fixed, rather than against everything the reference
/// tool reported, the gain is much smaller -- 2 more. Both numbers are real
/// and they disagree, which is itself the reason this stays out of the
/// detailed report.
///
/// Low confidence by construction: the two extents may be equal for reasons
/// no local analysis can see -- built from a common source, or fixed by an
/// invariant the caller maintains. What the check states is that nothing in
/// this function establishes it.
pub const UNCHECKED_PARALLEL_EXTENT: QueryCheck = QueryCheck {
    id: "kordon-unchecked-parallel-extent",
    base: "", // built by matcher(); see Exemption::ParallelExtent above
    exemption: Exemption::ParallelExtent,
    extra_args: &[],
    only_if_defined: None,
    message: "this loop is bounded by another object's extent, and nothing in this function \
establishes that the subscripted parameter is at least as long; an assert does not count, \
it expands to nothing under NDEBUG",
};

/// Methods that report an object's extent, and methods that establish it.
///
/// Split because they exempt for different reasons: reading the extent in a
/// condition means the code checked, setting it means the code guaranteed.
const EXTENT_READERS: &str = "\"getRows\", \"getCols\", \"rows\", \"cols\", \"size\", \
\"length\", \"width\", \"height\", \"getWidth\", \"getHeight\", \"count\"";
const EXTENT_SETTERS: &str = "\"init\", \"resize\", \"reserve\", \"assign\", \
\"allocate\", \"create\", \"setSize\", \"alloc\"";

/// Build the unchecked-constant-index matcher.
fn constant_index_matcher() -> String {
    let on_same = "on(declRefExpr(to(parmVarDecl(equalsBoundNode(\"p\")))))";
    format!(
        "cxxOperatorCallExpr(\
hasOverloadedOperatorName(\"()\"), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation()), \
hasArgument(0, declRefExpr(to(parmVarDecl().bind(\"p\")))), \
hasArgument(1, integerLiteral()), \
unless(hasAncestor(functionDecl(hasDescendant(ifStmt(hasCondition(hasDescendant(\
cxxMemberCallExpr(callee(cxxMethodDecl(hasAnyName({readers}))), {on_same})))))))), \
unless(hasAncestor(functionDecl(hasDescendant(\
cxxMemberCallExpr(callee(cxxMethodDecl(hasAnyName({setters}))), {on_same})))))\
)",
        readers = EXTENT_READERS,
        setters = EXTENT_SETTERS
    )
}

/// A parameter is indexed at a fixed position that nothing establishes it has.
///
/// The shape, from the reference codebase:
///
///     void Rotation::fromRotationToAxisAngle(Matrix &R, Vector &w)
///     {
///         w.init(3);                                  // w's extent guaranteed
///         ...
///         w[0] = (R(2,1) - R(1,2)) / 2.0;             // R's extent is not
///     }
///
/// `w` is fine -- the function sizes it before use. `R` is the hazard: it is
/// indexed at `(2,1)` on the assumption it is at least 3x3, and nothing in the
/// function says so. The corrected tree adds exactly the missing test:
///
///     if (R.getRows() < 3 || R.getCols() < 3) { return; }
///
/// So the two exemptions are "the code read this parameter's extent in a
/// condition" and "the code set this parameter's extent". Both must name the
/// bound parameter.
///
/// **Exempting any `if` that merely mentions the parameter is far too loose**,
/// and measuring caught it: the same file contains `if (R(2,1) < 0) y = -y;`,
/// a test of the stored *value*, which silenced all 25 findings in the file.
/// Requiring an extent accessor specifically is what makes the check work.
///
/// Restricted to `operator()` on purpose. Extending it to `operator[]` doubled
/// the ground-truth positions reached, from 3 to 6, but took specificity from
/// -81% to -13% and volume from 21 to 129 -- because a fixed subscript on a
/// one-dimensional container is usually a genuine constant, not an assumption.
/// Recall bought at that price is the shape-counting this project rejects.
///
/// Measured across 452 translation units: **21 positions on the broken tree,
/// 4 on the corrected one (-81%)**, the sharpest discrimination of any bounds
/// check here.
pub const UNCHECKED_CONSTANT_INDEX: QueryCheck = QueryCheck {
    id: "kordon-unchecked-constant-index",
    base: "", // built by matcher(); see Exemption::ConstantIndex above
    exemption: Exemption::ConstantIndex,
    extra_args: &[],
    only_if_defined: None,
    message: "this parameter is indexed at a fixed position, and nothing in the function \
establishes that it is that large -- neither a test of its extent nor a call that sets it",
};

/// Methods that return a container's extent.
///
/// `x.width() - 1` is a different proposition from `n - 1`: the extent of an
/// empty container is 0, and 0 - 1 on an unsigned type is the type maximum.
/// A plain variable named `n` carries no such invariant.
const EXTENT_CALL: &str = "cxxMemberCallExpr(callee(cxxMethodDecl(hasAnyName(\
\"width\", \"height\", \"bands\", \"size\", \"length\", \"rows\", \"cols\", \"count\", \
\"getWidth\", \"getHeight\", \"getRows\", \"getCols\", \"getBands\"))))";

/// Append the guards that establish an operand cannot underflow.
///
/// Shared so the general and extent-specific underflow checks cannot drift
/// apart: they must exempt exactly the same ways of writing "I checked".
fn append_arithmetic_guards(m: &mut String) {
    for shape in GUARD_SHAPES {
        m.push_str(", unless(");
        m.push_str(&guard_clause(shape));
        m.push(')');
    }
    m.push_str(", unless(");
    m.push_str(LOOP_INIT_GUARD);
    m.push(')');
}

/// Build the extent-underflow matcher: the general shape, narrowed to a
/// container-extent accessor on the left, and guarded identically.
fn extent_underflow_matcher() -> String {
    let mut m = format!(
        "binaryOperator(hasOperatorName(\"-\"), \
hasType(isUnsignedInteger()), \
hasRHS(ignoringParenImpCasts(integerLiteral())), \
hasLHS(ignoringParenImpCasts({EXTENT_CALL})), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation())"
    );
    append_arithmetic_guards(&mut m);
    m.push(')');
    m
}

/// A container's extent, minus a literal, on an unsigned type.
///
///     roiIn = Data2DROI(0, dataIn.width() - 1, 0, dataIn.height() - 1);
///
/// If the image is empty, `width()` is 0 and `0 - 1` is `SIZE_MAX`. The result
/// is passed straight into an ROI that then bounds a loop.
///
/// This is the same expression shape as `kordon-unsigned-subtraction` but with
/// the left operand narrowed to an extent accessor, and the difference in
/// precision is the reason it exists as its own check. Measured on the
/// reference corpus against the defects its maintainers actually fixed:
///
/// | left operand | positions | real defects | ratio |
/// |---|---|---|---|
/// | an extent accessor | 46 | 21 | **2:1** |
/// | anything else | 332 | 8 | 41:1 |
///
/// A twentyfold difference, and 2:1 beats the ratio of Kordon's whole
/// high-confidence tier. `n - 1` on a plain variable carries no invariant; an
/// extent has a documented one, namely that an empty container reports 0.
///
/// Reported at medium confidence rather than high because it **cannot confirm
/// a fix**: on the corrected tree the expression is still there (45 to 41,
/// -9%), since the correction is a precondition validated elsewhere in the
/// function. That is the documented CWE-190/191 limitation, not a fault in the
/// matcher -- the check is well targeted at defect *sites*, and says nothing
/// about whether the site has since been guarded at a distance.
pub const EXTENT_UNDERFLOW: QueryCheck = QueryCheck {
    id: "kordon-extent-underflow",
    base: "", // built by matcher(); see Exemption::ExtentUnderflow above
    exemption: Exemption::ExtentUnderflow,
    extra_args: &[],
    only_if_defined: None,
    message: "a container's extent minus a literal, on an unsigned type, with no guard that \
the container is non-empty; an empty container reports 0 and 0 - 1 is the type maximum",
};

/// Build the reinit-without-free matcher.
///
/// Assembled here because the release has to be recognised as releasing the
/// *same* member that is about to be overwritten, which needs one binding
/// threaded through both halves.
fn reinit_without_free_matcher() -> String {
    let field = "memberExpr(member(fieldDecl(hasType(pointerType())).bind(\"f\")))";
    let same = "memberExpr(member(fieldDecl(equalsBoundNode(\"f\"))))";
    // Names are matched as a substring, not exactly. The reference codebase
    // releases through `clearPolinom()`, and an exact-name list reported that
    // correct code as a defect until the list became a pattern.
    let released = format!(
        "anyOf(\
cxxDeleteExpr(hasDescendant({same})), \
callExpr(callee(functionDecl(hasName(\"free\"))), hasAnyArgument(ignoringParenImpCasts({same}))), \
cxxMemberCallExpr(callee(cxxMethodDecl(\
matchesName(\"(clear|free|release|reset|destroy|dealloc|cleanup|delete)\")))))"
    );
    format!(
        "binaryOperator(hasOperatorName(\"=\"), \
unless(isExpansionInSystemHeader()), \
unless(isInTemplateInstantiation()), \
hasLHS(ignoringParenImpCasts({field})), \
hasRHS(ignoringParenImpCasts(cxxNewExpr())), \
hasAncestor(cxxMethodDecl(unless(cxxConstructorDecl()), unless(hasDescendant({released})))))"
    )
}

/// An owning member is overwritten with a fresh allocation and the old one is
/// never released.
///
///     void BmpImage::init(const QString &fname, float *pProcent)
///     {
///         ...
///         data = new BmpImageData;    // whatever `data` held is now unreachable
///     }
///
/// Calling `init` twice leaks the first buffer. A constructor is exempt, since
/// there is nothing to release yet; every other method is not.
///
/// CLAUDE.md names this as one of the few gaps with no off-the-shelf
/// equivalent, and that held up: nothing in clang-tidy, Clang SA or cppcheck
/// reports these sites. Clang SA cannot, because the leak needs two calls to
/// the same method and it reasons about one path at a time.
///
/// Measured across 452 translation units: **26 findings at 10 distinct
/// positions**, and the four sampled were all genuine --
/// `SparseVector::init`, `BmpImage::init`, `Tracker::make_sets`, and a guided
/// filter's `init`, none of which release before allocating.
///
/// Recognising the release by name substring rather than exact match is what
/// makes it usable: the reference codebase releases through `clearPolinom()`,
/// and an exact list reported that correct code as a defect.
///
/// Medium confidence. The defect is real where a method is called twice, and
/// whether it ever is called twice is not a fact this check can establish.
pub const REINIT_WITHOUT_FREE: QueryCheck = QueryCheck {
    id: "kordon-reinit-without-free",
    base: "", // built by matcher(); see Exemption::ReinitWithoutFree above
    exemption: Exemption::ReinitWithoutFree,
    extra_args: &[],
    only_if_defined: None,
    message: "this assigns a fresh allocation to an owning member without releasing what it \
already held; calling this method twice leaks the first buffer",
};

pub const CHECKS: &[QueryCheck] = &[
    UNSIGNED_SUBTRACTION,
    UNSIGNED_ADDITION,
    MANUAL_OWNERSHIP_FLAG,
    ASSERT_ONLY_VALIDATION,
    INDEX_USED_BEFORE_CHECK,
    UNCHECKED_PARALLEL_EXTENT,
    UNCHECKED_CONSTANT_INDEX,
    EXTENT_UNDERFLOW,
    REINIT_WITHOUT_FREE,
];

/// Locate clang-query. Distributions ship it versioned far more often than not.
pub fn find_binary() -> Option<String> {
    for candidate in [
        "clang-query",
        "clang-query-18",
        "clang-query-17",
        "clang-query-16",
    ] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Run every check over every translation unit.
///
/// `root` bounds which matches are reported: a match inside a dependency's
/// headers is not this project's defect, and the matcher's
/// `isExpansionInSystemHeader` guard does not cover vendored third-party code
/// that lives under an ordinary include path.
pub fn run(
    binary: &str,
    sources: &[PathBuf],
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    root: &Path,
    jobs: usize,
    table: &CweTable,
) -> ToolRun {
    if sources.is_empty() {
        return ToolRun {
            tool: tool(),
            outcome: ToolOutcome::Ran,
            findings: Vec::new(),
            notes: Vec::new(),
        };
    }

    let shards = jobs.clamp(1, sources.len());
    let chunk = sources.len().div_ceil(shards);

    let per_shard: Vec<Vec<RawMatch>> = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .map(|files| {
                scope.spawn(move || {
                    let mut out = Vec::new();
                    for check in CHECKS {
                        for file in files {
                            // A check conditioned on a build macro is only
                            // meaningful where the build actually defines it.
                            if let Some(macro_name) = check.only_if_defined {
                                if !defines_macro(compile_db, file, macro_name) {
                                    continue;
                                }
                            }
                            out.extend(run_one(binary, check, file, compile_db, extra_args, root));
                        }
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut findings = Vec::new();
    for matches in per_shard {
        for m in matches {
            let check = CHECKS.iter().find(|c| c.id == m.check_id);
            let message = check.map(|c| c.message).unwrap_or("matched a Kordon pattern");
            let class = table.classify(&tool(), &m.check_id, message, None, Confidence::Low);

            findings.push(Finding {
                tool: tool(),
                native_id: m.check_id.clone(),
                cwe: class.cwe,
                cwe_source: class.source,
                file: m.file,
                line: m.line,
                column: m.column,
                severity: Severity::Style,
                // From the table, per check. Clamping everything to Low here
                // buried the one check that recognises a logic error rather
                // than a risky shape -- it reported the same two genuine
                // out-of-bounds reads as the 3798-finding pattern checks.
                confidence: class.confidence,
                message: message.to_string(),
                events: Vec::new(),
                proof: None,
            });
        }
    }

    ToolRun {
        tool: tool(),
        outcome: ToolOutcome::Ran,
        findings,
        notes: Vec::new(),
    }
}

/// Whether the build compiles this unit with `-D<macro>`.
fn defines_macro(db: Option<&CompileDb>, file: &Path, macro_name: &str) -> bool {
    let Some(db) = db else {
        // With no database there are no build flags to consult, and guessing
        // would make the finding a claim about a configuration we never saw.
        return false;
    };
    let with_value = format!("-D{macro_name}=");
    let bare = format!("-D{macro_name}");
    db.args_for(file).is_some_and(|args| {
        args.iter()
            .any(|a| a == &bare || a.starts_with(&with_value))
    })
}

pub struct RawMatch {
    check_id: String,
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
}

fn run_one(
    binary: &str,
    check: &QueryCheck,
    source: &Path,
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    root: &Path,
) -> Vec<RawMatch> {
    let mut cmd = Command::new(binary);
    for extra in check.extra_args {
        cmd.arg(format!("--extra-arg={extra}"));
    }
    cmd.arg("-c").arg(format!("match {}", check.matcher()));

    if let Some(db) = compile_db {
        cmd.arg("-p").arg(db.path());
    }
    cmd.arg(source);
    if compile_db.is_none() {
        cmd.arg("--");
        for arg in extra_args {
            cmd.arg(arg);
        }
    }

    let Ok(output) = cmd.output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_matches(&text, check.id, root)
}

/// Parse clang-query's match output.
///
/// One match prints a location line per *bound node*, not one per match: a
/// matcher that binds `p` and `flag` emits three lines, and only the one
/// labelled `"root"` is the finding. Accepting any `binds here` line multiplied
/// every finding by the number of binds. This stayed hidden until a check bound
/// names outside an `unless(...)` clause -- inside one, nothing is emitted on a
/// match, so the earlier checks never exposed it.
///
/// Matches outside `root` belong to a dependency, not this project.
pub fn parse_matches(text: &str, check_id: &str, root: &Path) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(prefix) = line.split(": note:").next() else {
            continue;
        };
        // Only the root binding is the finding; the rest are its parts.
        if !line.contains("\"root\" binds here") {
            continue;
        }
        // `<path>:<line>:<col>`; split from the right, since a path may
        // itself contain colons.
        let mut parts = prefix.rsplitn(3, ':');
        let (Some(col), Some(row), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(column), Ok(line_no)) = (col.trim().parse::<u32>(), row.trim().parse::<u32>())
        else {
            continue;
        };
        let file = PathBuf::from(path.trim());
        if !file.starts_with(root) {
            continue;
        }
        out.push(RawMatch {
            check_id: check_id.to_string(),
            file,
            line: line_no,
            column,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\nMatch #1:\n\n\
/proj/src/a.cpp:17:30: note: \"root\" binds here\n   \
17 |     roiIn = Data2DROI(0, dataIn.width() - 1);\n\n\
Match #2:\n\n\
/proj/src/b.cpp:19:55: note: \"root\" binds here\n\n\
/elsewhere/dep/x.hpp:5:1: note: \"root\" binds here\n\
2 matches.\n";

    #[test]
    fn parses_location_lines() {
        let m = parse_matches(SAMPLE, "kordon-unsigned-subtraction", Path::new("/proj"));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].file, PathBuf::from("/proj/src/a.cpp"));
        assert_eq!((m[0].line, m[0].column), (17, 30));
        assert_eq!((m[1].line, m[1].column), (19, 55));
    }

    #[test]
    fn drops_matches_outside_the_project_root() {
        // A dependency's headers are not this project's defects.
        let m = parse_matches(SAMPLE, "x", Path::new("/proj"));
        assert!(m.iter().all(|r| !r.file.starts_with("/elsewhere")));
    }

    #[test]
    fn one_match_with_several_binds_yields_one_finding() {
        // clang-query prints a line per bound node. Counting them all inflated
        // every finding by the number of binds in the matcher.
        let text = "\
/proj/a.cpp:64:5: note: \"flag\" binds here\n\
/proj/a.cpp:63:5: note: \"p\" binds here\n\
/proj/a.cpp:56:13: note: \"root\" binds here\n";
        let m = parse_matches(text, "x", Path::new("/proj"));
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].line, m[0].column), (56, 13));
    }

    #[test]
    fn ignores_non_match_output() {
        let m = parse_matches("2 matches.\nsome other text\n", "x", Path::new("/proj"));
        assert!(m.is_empty());
    }

    #[test]
    fn loop_counter_starting_above_zero_is_exempt() {
        // The guard is the loop initialiser, which no condition-based clause
        // can see. The literal sits behind an implicit cast when the counter is
        // wider than it, and missing that makes the clause match nothing --
        // indistinguishable from having nothing to exempt.
        let m = UNSIGNED_SUBTRACTION.matcher();
        assert!(m.contains("hasLoopInit"));
        assert!(m.contains("hasInitializer(ignoringParenImpCasts(integerLiteral"));
    }

    #[test]
    fn matcher_parentheses_balance() {
        // Built by concatenation across several helpers; an imbalance makes
        // clang-query reject the whole matcher and report nothing at all.
        for check in CHECKS {
            let m = check.matcher();
            assert_eq!(
                m.matches('(').count(),
                m.matches(')').count(),
                "unbalanced matcher for {}",
                check.id
            );
        }
    }

    #[test]
    fn loop_conditions_guard_as_well_as_if_conditions() {
        // `while (k > 0) { use(k - 1); }` and `for (i = n; i > 0; --i)` state
        // the same fact as the `if` form and were reported as defects until
        // each was handled.
        let m = UNSIGNED_SUBTRACTION.matcher();
        assert!(m.contains("whileStmt(hasCondition"));
        assert!(m.contains("forStmt(hasCondition"));
    }

    #[test]
    fn do_while_is_not_a_guard() {
        // Its condition runs after the body, so the first iteration is
        // unguarded and the subtraction really can underflow.
        assert!(!UNSIGNED_SUBTRACTION.matcher().contains("doStmt"));
    }

    #[test]
    fn guard_matches_both_direct_and_nested_conditions() {
        // Regression test for a real bug: switching the condition matcher to
        // `hasDescendant` alone stopped exempting a bare `if (k > 0)`, because
        // hasDescendant does not match the node itself. Only the nested form
        // `if (a && k > 0)` kept working, and the corpus happened to use only
        // that, so the regression measured clean. Both arms are required.
        let m = UNSIGNED_SUBTRACTION.matcher();
        assert!(m.contains("anyOf("), "guard must accept the condition itself");
        assert!(m.contains("hasDescendant("), "guard must accept a nested condition");
    }

    #[test]
    fn addition_exempts_only_the_loop_counter() {
        // There is no guard idiom for `x + 1` -- it overflows only at the type
        // maximum -- but a loop counter cannot get there, and real code writes
        // `i + 1` constantly.
        let m = UNSIGNED_ADDITION.matcher();
        assert!(m.contains("hasLoopInit"));
        // Not the arithmetic guards: those answer a different question.
        assert!(!m.contains("hasAnyOperatorName"));
    }

    #[test]
    fn matcher_exempts_genuine_guards_only() {
        let m = UNSIGNED_SUBTRACTION.matcher();
        // Suppression must be conditional on a comparison that can establish
        // the operand is non-zero, not on the variable merely appearing in
        // some enclosing condition.
        assert!(m.contains("equalsBoundNode"));
        assert!(m.contains("hasAnyOperatorName"));
        for op in ["\">\"", "\">=\"", "\"!=\""] {
            assert!(m.contains(op), "guard operator {op} missing");
        }
    }

    #[test]
    fn parallel_extent_exempts_self_bounded_loops_and_real_checks() {
        let m = UNCHECKED_PARALLEL_EXTENT.matcher();
        // Both exemptions must back-reference the *same* parameter that is
        // subscripted. Unbound, they would exempt any enclosing loop and any
        // `if` anywhere in the function, which silences the check entirely.
        assert_eq!(m.matches("equalsBoundNode(\"p\")").count(), 2);
        // The real-check exemption must insist on an `ifStmt`. `assert`
        // expands to a conditionalOperator and to nothing at all under NDEBUG,
        // so accepting one here would let the very shape this check exists to
        // find silence it.
        assert!(m.contains("ifStmt"));
        assert!(!m.contains("conditionalOperator"));
    }

    #[test]
    fn constant_index_exempts_extent_tests_not_value_tests() {
        let m = UNCHECKED_CONSTANT_INDEX.matcher();
        // The exemption must require reading the parameter's *extent*. A
        // looser version that accepted any `if` mentioning the parameter was
        // silenced by `if (R(2,1) < 0)` -- a test of the stored value -- and
        // reported nothing at all on the file it was written for.
        assert!(m.contains("getRows"));
        assert!(m.contains("getCols"));
        // Both exemptions must name the bound parameter.
        assert_eq!(m.matches("equalsBoundNode(\"p\")").count(), 2);
        // operator[] is deliberately out: including it doubled ground-truth
        // reach but took specificity from -81% to -13%.
        assert!(!m.contains("\"[]\""));
    }

    #[test]
    fn extent_underflow_and_general_subtraction_partition_the_shape() {
        let ext = EXTENT_UNDERFLOW.matcher();
        let gen = UNSIGNED_SUBTRACTION.matcher();
        // The specific check requires an extent accessor on the left; the
        // general one must exclude exactly that, or every extent site is
        // reported twice, at two different confidences.
        assert!(ext.contains("hasLHS(ignoringParenImpCasts(cxxMemberCallExpr"));
        assert!(gen.contains("unless(hasLHS(ignoringParenImpCasts(cxxMemberCallExpr"));
        // Both must recognise the same accessors, or sites fall between them.
        for name in ["\"width\"", "\"height\"", "\"size\"", "\"getRows\""] {
            assert!(ext.contains(name), "extent check missing {name}");
            assert!(gen.contains(name), "general check missing {name}");
        }
        // And both must exempt the same guards, or a guarded site reported by
        // neither becomes a guarded site reported by one.
        assert_eq!(
            ext.matches("equalsBoundNode").count(),
            gen.matches("equalsBoundNode").count()
        );
    }

    #[test]
    fn reinit_recognises_release_by_substring_not_exact_name() {
        let m = REINIT_WITHOUT_FREE.matcher();
        // An exact-name list reported correct code as a defect: the reference
        // codebase releases through `clearPolinom()`, which no list of whole
        // names contains. The regex is what makes the check usable.
        assert!(m.contains("matchesName"));
        assert!(!m.contains("hasAnyName"));
        // A constructor has nothing to release yet.
        assert!(m.contains("unless(cxxConstructorDecl())"));
        // The delete must name the same member being overwritten.
        assert!(m.contains("equalsBoundNode(\"f\")"));
        // `allOf` around a node matcher plus hasAncestor silently matches
        // nothing -- it cost a full tree scan to notice. Keep them inline.
        assert!(!m.contains("allOf("));
    }

    #[test]
    fn matcher_excludes_system_headers_and_instantiations() {
        // Both guards are load-bearing: without them the matcher reports
        // libstdc++ internals and template recursion base cases.
        assert!(UNSIGNED_SUBTRACTION.matcher().contains("isExpansionInSystemHeader"));
        assert!(UNSIGNED_SUBTRACTION.matcher().contains("isInTemplateInstantiation"));
    }

    #[test]
    fn every_check_is_mapped_to_a_cwe() {
        // An unmapped custom check would surface as a coverage gap in our own
        // table, which would be an odd thing to ship.
        let table = CweTable::builtin().unwrap();
        for check in CHECKS {
            let c = table.classify(&tool(), check.id, check.message, None, Confidence::Low);
            assert!(c.cwe.is_some(), "{} has no CWE mapping", check.id);
        }
    }
}
