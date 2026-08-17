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
