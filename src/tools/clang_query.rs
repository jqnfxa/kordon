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
    /// Clauses wrapped in `unless(...)` and appended to `base`.
    pub guards: &'static [&'static str],
    /// Shown in the finding message.
    pub message: &'static str,
}

impl QueryCheck {
    pub fn matcher(&self) -> String {
        let mut m = String::from(self.base);
        for guard in self.guards {
            m.push_str(", unless(");
            m.push_str(guard);
            m.push(')');
        }
        m.push(')');
        m
    }
}


/// A condition that can establish the operand is non-zero: `>`, `>=` or `!=`.
/// Deliberately not `<` or `==` -- `if (k < n)` guards nothing, and an earlier
/// version that suppressed on any enclosing condition mentioning the operand
/// swallowed three real defects on the measured corpus.
/// Guard on a plain variable: `if (k > 0) { ... k - 1 ... }`.
const GUARD_VAR: &str = "allOf(\
hasLHS(ignoringParenImpCasts(declRefExpr(to(varDecl().bind(\"v\"))))), \
hasAncestor(ifStmt(hasCondition(hasDescendant(binaryOperator(\
hasAnyOperatorName(\">\", \">=\", \"!=\"), \
hasLHS(ignoringParenImpCasts(declRefExpr(to(varDecl(equalsBoundNode(\"v\"))))))))))))";

/// Guard on a method call over a local: `if (v.size() > 0) { ... v.size() - 1 }`.
///
/// `equalsBoundNode` on the two call expressions themselves would not work --
/// they are distinct AST nodes. The identity that matters is *same method on
/// same object*, so the callee and the object are bound separately.
const GUARD_CALL_ON_VAR: &str = "allOf(\
hasLHS(ignoringParenImpCasts(cxxMemberCallExpr(\
callee(cxxMethodDecl().bind(\"m\")), \
on(ignoringParenImpCasts(declRefExpr(to(varDecl().bind(\"o\")))))))), \
hasAncestor(ifStmt(hasCondition(hasDescendant(binaryOperator(\
hasAnyOperatorName(\">\", \">=\", \"!=\"), \
hasLHS(ignoringParenImpCasts(cxxMemberCallExpr(\
callee(cxxMethodDecl(equalsBoundNode(\"m\"))), \
on(ignoringParenImpCasts(declRefExpr(to(varDecl(equalsBoundNode(\"o\")))))))))))))))";

/// Guard on a method call over a member: `if (dataIn.width() > 0) { ... }`.
///
/// This one is load-bearing rather than exotic. It is how the reference
/// codebase actually wrote its fixes, and without it the check reported the
/// fixed code identically to the broken code.
const GUARD_CALL_ON_MEMBER: &str = "allOf(\
hasLHS(ignoringParenImpCasts(cxxMemberCallExpr(\
callee(cxxMethodDecl().bind(\"m2\")), \
on(ignoringParenImpCasts(memberExpr(member(fieldDecl().bind(\"f\")))))))), \
hasAncestor(ifStmt(hasCondition(hasDescendant(binaryOperator(\
hasAnyOperatorName(\">\", \">=\", \"!=\"), \
hasLHS(ignoringParenImpCasts(cxxMemberCallExpr(\
callee(cxxMethodDecl(equalsBoundNode(\"m2\"))), \
on(ignoringParenImpCasts(memberExpr(member(fieldDecl(equalsBoundNode(\"f\")))))))))))))))";

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
    guards: &[GUARD_VAR, GUARD_CALL_ON_VAR, GUARD_CALL_ON_MEMBER],
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
    guards: &[],
    message: "unsigned addition with no check that the left operand is below the type maximum; \
wraps to a small value instead of growing",
};

pub const CHECKS: &[QueryCheck] = &[UNSIGNED_SUBTRACTION, UNSIGNED_ADDITION];

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
/// Each match prints a source location line ending in `note: "root" binds
/// here`. Matches outside `root` belong to a dependency, not this project.
pub fn parse_matches(text: &str, check_id: &str, root: &Path) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(prefix) = line.split(": note:").next() else {
            continue;
        };
        if !line.contains("binds here") {
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
    fn ignores_non_match_output() {
        let m = parse_matches("2 matches.\nsome other text\n", "x", Path::new("/proj"));
        assert!(m.is_empty());
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
