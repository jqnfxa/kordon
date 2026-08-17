//! Kordon's own AST-matcher checks, run through `clang-query`.
//!
//! These cover defect classes with no off-the-shelf check. They are written as
//! Clang AST matcher expressions and executed by `clang-query`, rather than as
//! a compiled clang-tidy plugin: the matcher is the entire content of the
//! check, and running it this way needs no LLVM development headers, no plugin
//! ABI to track across releases, and no build step for the user.
//!
//! Everything here is deliberately **low confidence**. An AST matcher sees
//! shape, not intent, and for the classes in this file intent is exactly what
//! decides whether the shape is a defect. The report keeps these in the
//! risk-pattern tier, summarized by count, and that is the permanent home for
//! them -- not a temporary state pending a better analysis.

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
    /// Whether to append the guard exemptions. Only the subtraction check
    /// wants them: `x + 1` overflows only at the type maximum, which code
    /// effectively never guards explicitly, so there is no idiom to exempt.
    pub guarded: bool,
    /// Shown in the finding message.
    pub message: &'static str,
}

impl QueryCheck {
    pub fn matcher(&self) -> String {
        let mut m = String::from(self.base);
        if self.guarded {
            for shape in GUARD_SHAPES {
                m.push_str(", unless(");
                m.push_str(&guard_clause(shape));
                m.push(')');
            }
        }
        m.push(')');
        m
    }
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
/// Only `>`, `>=` and `!=` count. `if (k < n)` establishes nothing about zero,
/// and an earlier version that accepted any comparison swallowed three real
/// defects.
fn guard_clause(shape: &GuardShape) -> String {
    let cmp = format!(
        "binaryOperator(hasAnyOperatorName(\">\", \">=\", \"!=\"), \
hasLHS(ignoringParenImpCasts({})))",
        shape.back_reference
    );
    format!(
        "allOf(hasLHS(ignoringParenImpCasts({})), \
hasAncestor(ifStmt(hasCondition(anyOf({cmp}, hasDescendant({cmp}))))))",
        shape.operand
    )
}

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
    guarded: true,
    message: "unsigned subtraction with no guard that the left operand is large enough; \
wraps to a huge value instead of going negative",
};

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
    guarded: false,
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
    guarded: false,
    message: "owning pointer member is released only when a bool member permits it; \
ownership lives in a flag rather than in the type, so any path that leaves the flag wrong \
leaks the memory or frees it twice",
};

pub const CHECKS: &[QueryCheck] =
    &[UNSIGNED_SUBTRACTION, UNSIGNED_ADDITION, MANUAL_OWNERSHIP_FLAG];

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
                // Never above Low: see the module docs. The table may not
                // raise these, so clamp rather than trust it.
                confidence: Confidence::Low,
                message: message.to_string(),
                events: Vec::new(),
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
    fn addition_check_has_no_guard_clauses() {
        // `x + 1` overflows only at the type maximum; there is no guard idiom.
        assert!(!UNSIGNED_ADDITION.matcher().contains("equalsBoundNode"));
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
