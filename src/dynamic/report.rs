//! Parsing runtime reports into the normalized schema.
//!
//! Sanitizers and valgrind report a *defect that happened*, not a shape that
//! might be one. That difference is carried through as [`Proof::Refuted`] and
//! `Confidence::High`, and it is the whole reason this layer exists: every
//! static engine Kordon drives answers "did a pattern or path match?", while
//! these answer "did the program do this?".

use std::path::{Path, PathBuf};

use crate::cwe::CweTable;
use crate::finding::{Confidence, Event, Finding, Proof, Severity, Tool};

/// One runtime report, before it becomes a `Finding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReport {
    /// The engine, e.g. `AddressSanitizer`.
    pub engine: String,
    /// The defect class, e.g. `heap-use-after-free`. Becomes the native id and
    /// drives the CWE mapping, so it must be the tool's own vocabulary.
    pub class: String,
    pub message: String,
    /// Innermost frame first, exactly as reported.
    pub frames: Vec<Frame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub function: String,
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
}

impl RuntimeReport {
    /// The frame to anchor the finding on.
    ///
    /// Not frame zero: for a leak that is `malloc` inside the sanitizer's own
    /// interceptor, and for a bad read it is often a libc routine. The useful
    /// location is the innermost frame that lives in the code being analyzed,
    /// which is why the analysis root has to be threaded in here.
    pub fn anchor(&self, root: &Path) -> Option<&Frame> {
        self.frames
            .iter()
            .find(|f| f.file.starts_with(root))
            .or_else(|| self.frames.first())
    }

    pub fn into_finding(self, root: &Path, tool: &str, table: &CweTable) -> Option<Finding> {
        let anchor = self.anchor(root)?.clone();
        let events = self
            .frames
            .iter()
            .map(|f| Event {
                file: f.file.clone(),
                line: f.line,
                column: f.column,
                message: format!("in {}", f.function),
            })
            .collect();
        let tool_id = Tool::new(tool);
        // The sanitizer names the defect in its own vocabulary and never names
        // a CWE, so the table does that work exactly as it does for the static
        // engines. Confidence is *not* taken from the table: a runtime report
        // is an observation, and no rule should be able to weaken it.
        let class = table.classify(&tool_id, &self.class, &self.message, None, Confidence::High);
        Some(Finding {
            tool: tool_id,
            native_id: self.class,
            cwe: class.cwe,
            cwe_source: class.source,
            file: anchor.file,
            line: anchor.line,
            column: anchor.column,
            severity: Severity::Error,
            // A sanitizer did not suspect this defect, it observed it.
            confidence: Confidence::High,
            proof: Some(Proof::Refuted),
            message: self.message,
            events,
        })
    }
}
