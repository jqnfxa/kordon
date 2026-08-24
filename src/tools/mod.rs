//! Tool runners.
//!
//! Each runner owns one engine: how to invoke it, how to parse its native
//! output, and nothing else. Native formats never escape this module -- the
//! rest of Kordon sees only [`crate::finding::Finding`].
//!
//! Every runner returns a [`ToolRun`] rather than a bare `Vec<Finding>`,
//! because "this engine did not run" and "this engine found nothing" are
//! completely different claims and the report has to keep them apart. A clean
//! report that silently omitted a crashed analyzer would be a lie.

pub mod clang_query;
pub mod ikos;
pub mod clang_sa;
pub mod clang_tidy;
pub mod cppcheck;

use crate::finding::{Finding, Tool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    /// The engine ran to completion. `findings` is meaningful.
    Ran,
    /// The engine was not run at all (binary missing, or disabled).
    Skipped(String),
    /// The engine was invoked but failed. Any findings are partial at best.
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ToolRun {
    pub tool: Tool,
    pub outcome: ToolOutcome,
    pub findings: Vec<Finding>,
    /// Non-fatal problems worth surfacing, e.g. translation units that failed
    /// to compile and were therefore never analyzed.
    pub notes: Vec<String>,
}

impl ToolRun {
    pub fn failed(tool: Tool, reason: impl Into<String>) -> Self {
        ToolRun {
            tool,
            outcome: ToolOutcome::Failed(reason.into()),
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn skipped(tool: Tool, reason: impl Into<String>) -> Self {
        ToolRun {
            tool,
            outcome: ToolOutcome::Skipped(reason.into()),
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn ran(&self) -> bool {
        self.outcome == ToolOutcome::Ran
    }
}

/// Whether a binary is callable, so a missing engine becomes an explicit
/// `Skipped` in the report instead of a confusing spawn error.
pub fn available(binary: &str) -> bool {
    std::process::Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Wrap a command so a single translation unit cannot hang the whole run.
///
/// The dynamic layer learned this from MSan; the static layer needed it more,
/// and Eigen showed why. One template-heavy translation unit there compiles in
/// 11 seconds and takes **over nine minutes** under clang-tidy with Kordon's
/// check set -- and nothing was stopping it taking nine hours. With 1310 units
/// in that project, an unbounded per-unit cost is not a slow run, it is a run
/// that never returns, with no output and no way to tell which unit was
/// responsible.
///
/// Implemented by prefixing `timeout`, the same way the dynamic layer does it,
/// rather than by hand-rolling a wait: the child is a compiler frontend that
/// may spawn its own children, and only a process-group kill reliably stops it.
///
/// `timeout` exits 124 when it fires, which callers check to distinguish "this
/// unit was abandoned" from "this unit was clean".
pub const TIMED_OUT: i32 = 124;

pub fn with_timeout(binary: &str, secs: u64) -> std::process::Command {
    let mut cmd = std::process::Command::new("timeout");
    cmd.arg(secs.to_string()).arg(binary);
    cmd
}
