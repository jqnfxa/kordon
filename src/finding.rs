//! The normalized finding schema every tool's output is coerced into.
//!
//! Everything downstream -- dedup, scope filtering, reporting -- works on
//! `Finding` only. Tool-native shapes (cppcheck XML, clang-tidy fix YAML,
//! sanitizer crash reports) never escape their runner module.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which engine produced a finding. Stringly-typed on purpose: adding IKOS or
/// a sanitizer runner should not require touching the core schema.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tool(pub String);

impl Tool {
    pub fn new(name: &str) -> Self {
        Tool(name.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational tool chatter (missing includes, config notes).
    Info,
    /// Style / readability / portability. Never a Kordon defect claim.
    Style,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Style => "style",
            Severity::Warning => "warning",
            Severity::Error => "error",
        })
    }
}

/// How much Kordon trusts that this finding describes a real defect.
///
/// This is about the *analysis behind the check*, not about how bad the bug
/// would be. A path-sensitive symbolic-execution result is `High`; an AST
/// pattern that merely indicates risk (a class missing copy control) is `Low`
/// even though the consequence -- a double free -- is severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

/// Where a finding's CWE id came from. Kept explicit so the report can never
/// imply Kordon classified something it merely passed through, and so an
/// `Unmapped` finding is visible as a gap in the mapping table rather than
/// silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CweSource {
    /// The tool reported the CWE itself (cppcheck does this).
    Native,
    /// Kordon's curated mapping table assigned it.
    Mapped,
    /// Kordon's table overrode a CWE the tool reported natively.
    Overridden,
    /// Neither: no CWE known for this check. Reported as a coverage gap.
    Unmapped,
}

impl fmt::Display for CweSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CweSource::Native => "native",
            CweSource::Mapped => "mapped",
            CweSource::Overridden => "overridden",
            CweSource::Unmapped => "unmapped",
        })
    }
}

/// What an analyzer was able to *prove*, as distinct from what it found.
///
/// Only abstract interpretation produces this. Every other engine Kordon drives
/// answers one question -- "did a pattern or a path match?" -- so silence from
/// them is ambiguous between "safe" and "not looked at". An interval analyser
/// answers a different question and can distinguish three outcomes, which is
/// the single most useful thing it contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proof {
    /// The analyzer proved the defect occurs on some reachable path. This is
    /// stronger evidence than any pattern match: not "this looks wrong" but
    /// "this is wrong".
    Refuted,
    /// The analyzer could prove neither safety nor error. Not a defect claim --
    /// a statement about the limits of the analysis. Reported separately and
    /// off by default, because a list of things a tool could not decide is
    /// noise to most readers and essential to a few.
    Unproven,
}

/// A single step in a tool's explanation of how it reached the defect
/// (clang-analyzer's note chain, cppcheck's secondary `<location>` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
    pub message: String,
}

/// One normalized diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub tool: Tool,
    /// The tool's own check identifier, e.g. `clang-analyzer-unix.Malloc`.
    pub native_id: String,
    pub cwe: Option<u32>,
    pub cwe_source: CweSource,
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    /// The path/trace the tool used to justify the finding. Often empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
    /// Set only by engines that reason about proofs. `None` means the engine
    /// does not work that way, not that nothing was proved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl Finding {
    /// The key two findings must agree on to be considered the same defect.
    ///
    /// Same file + same line + same CWE. Deliberately *not* keyed on column:
    /// two engines routinely anchor the same defect at different columns of
    /// one expression (cppcheck points at `q`, clang-analyzer at the `*`).
    /// Findings with no CWE fall back to their native id, so unmapped results
    /// from different tools never merge on a coincidence of position.
    pub fn dedup_key(&self) -> DedupKey {
        DedupKey {
            file: self.file.clone(),
            line: self.line,
            class: match self.cwe {
                Some(cwe) => FindingClass::Cwe(cwe),
                None => FindingClass::Native(self.native_id.clone()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FindingClass {
    Cwe(u32),
    Native(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DedupKey {
    pub file: PathBuf,
    pub line: u32,
    pub class: FindingClass,
}
