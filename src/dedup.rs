//! Cross-tool deduplication.
//!
//! Running several engines over one codebase means the same defect arrives
//! several times under different check ids. The prior Python prototype this
//! work descends from bucketed findings by CWE and never merged them, so a
//! use-after-free seen by both cppcheck and Clang SA counted twice and the
//! totals overstated the defect count.
//!
//! Merging is also where corroboration becomes usable: two independent engines
//! with different blind spots agreeing on a defect is meaningfully stronger
//! evidence than either alone, and that is exactly the signal a reviewer wants
//! to triage by.

use std::collections::HashMap;

use crate::finding::{Confidence, DedupKey, Finding, Severity};

/// One defect, with every tool report that corroborates it.
#[derive(Debug, Clone)]
pub struct MergedFinding {
    /// The report chosen to represent the defect: highest confidence, then
    /// richest event path. Its file/line/CWE are what gets reported.
    pub primary: Finding,
    /// Corroborating reports from other tools, in tool-name order.
    pub others: Vec<Finding>,
    /// Confidence after corroboration, which may exceed `primary.confidence`.
    pub confidence: Confidence,
}

impl MergedFinding {
    /// How many distinct engines reported this defect.
    pub fn agreement(&self) -> usize {
        1 + self.others.len()
    }

    pub fn severity(&self) -> Severity {
        self.others
            .iter()
            .map(|f| f.severity)
            .chain(std::iter::once(self.primary.severity))
            .max()
            .unwrap_or(self.primary.severity)
    }

    /// Every tool that reported this defect, for display.
    pub fn tools(&self) -> Vec<String> {
        let mut names: Vec<String> = std::iter::once(&self.primary)
            .chain(self.others.iter())
            .map(|f| f.tool.to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// Group findings that describe the same defect.
///
/// The grouping key is file + line + CWE (see [`Finding::dedup_key`]).
/// Deliberately *not* column: two engines routinely anchor one defect at
/// different columns of the same expression.
pub fn merge(findings: Vec<Finding>) -> Vec<MergedFinding> {
    let mut groups: HashMap<DedupKey, Vec<Finding>> = HashMap::new();
    for finding in findings {
        groups.entry(finding.dedup_key()).or_default().push(finding);
    }

    let mut merged: Vec<MergedFinding> = groups
        .into_values()
        .map(|mut group| {
            // Best representative first: highest confidence, then the one that
            // explains itself best, then a stable tie-break on tool name so
            // output does not shuffle between runs.
            group.sort_by(|a, b| {
                b.confidence
                    .cmp(&a.confidence)
                    .then(b.events.len().cmp(&a.events.len()))
                    .then(a.tool.cmp(&b.tool))
                    .then(a.native_id.cmp(&b.native_id))
            });

            let primary = group.remove(0);
            let distinct_tools = {
                let mut names: Vec<_> = std::iter::once(&primary)
                    .chain(group.iter())
                    .map(|f| f.tool.clone())
                    .collect();
                names.sort();
                names.dedup();
                names.len()
            };

            let confidence = corroborated(primary.confidence, distinct_tools);

            MergedFinding {
                primary,
                others: group,
                confidence,
            }
        })
        .collect();

    // Most serious first, then most corroborated, then by location so the
    // report is stable across runs.
    merged.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.severity().cmp(&a.severity()))
            .then(b.agreement().cmp(&a.agreement()))
            .then(a.primary.file.cmp(&b.primary.file))
            .then(a.primary.line.cmp(&b.primary.line))
            .then(a.primary.native_id.cmp(&b.primary.native_id))
    });

    merged
}

/// Raise confidence when independent engines agree.
///
/// One step only, and never past `High`. Two `Low` pattern-matchers both
/// noticing the same risky shape is not proof of a defect -- they may share
/// the same blind spot -- so agreement is treated as supporting evidence, not
/// as a substitute for a path-sensitive result.
fn corroborated(base: Confidence, distinct_tools: usize) -> Confidence {
    if distinct_tools < 2 {
        return base;
    }
    match base {
        Confidence::Low => Confidence::Medium,
        Confidence::Medium => Confidence::High,
        Confidence::High => Confidence::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{CweSource, Tool};
    use std::path::PathBuf;

    fn finding(tool: &str, id: &str, line: u32, cwe: Option<u32>, conf: Confidence) -> Finding {
        Finding {
            tool: Tool::new(tool),
            native_id: id.to_string(),
            cwe,
            cwe_source: if cwe.is_some() {
                CweSource::Mapped
            } else {
                CweSource::Unmapped
            },
            file: PathBuf::from("/src/a.cpp"),
            line,
            column: 1,
            severity: Severity::Warning,
            confidence: conf,
            message: format!("{id} at {line}"),
            events: Vec::new(),
        }
    }

    #[test]
    fn same_defect_from_two_tools_merges_into_one() {
        let merged = merge(vec![
            finding("cppcheck", "deallocuse", 26, Some(416), Confidence::High),
            finding(
                "clang-tidy",
                "clang-analyzer-unix.Malloc",
                26,
                Some(416),
                Confidence::High,
            ),
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agreement(), 2);
        assert_eq!(merged[0].tools(), vec!["clang-tidy", "cppcheck"]);
    }

    #[test]
    fn different_cwe_on_one_line_stays_separate() {
        // A leak and a null deref on the same line are two defects.
        let merged = merge(vec![
            finding("cppcheck", "memleak", 10, Some(401), Confidence::High),
            finding("cppcheck", "nullPointer", 10, Some(476), Confidence::High),
        ]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn column_difference_does_not_prevent_merging() {
        let mut a = finding("cppcheck", "deallocuse", 26, Some(416), Confidence::High);
        let mut b = finding("clang-tidy", "clang-analyzer-unix.Malloc", 26, Some(416), Confidence::High);
        a.column = 6;
        b.column = 8;
        assert_eq!(merge(vec![a, b]).len(), 1);
    }

    #[test]
    fn unmapped_findings_from_different_tools_never_merge() {
        // With no CWE there is nothing to say these describe one defect, so
        // position alone must not be enough to collapse them.
        let merged = merge(vec![
            finding("cppcheck", "someStyleThing", 10, None, Confidence::Low),
            finding("clang-tidy", "modernize-use-nullptr", 10, None, Confidence::Low),
        ]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn agreement_raises_confidence_one_step() {
        let merged = merge(vec![
            finding("cppcheck", "x", 5, Some(401), Confidence::Medium),
            finding("clang-tidy", "y", 5, Some(401), Confidence::Medium),
        ]);
        assert_eq!(merged[0].confidence, Confidence::High);
    }

    #[test]
    fn two_low_confidence_agreements_do_not_reach_high() {
        // Two pattern matchers may share a blind spot; agreement between them
        // is not equivalent to a path-sensitive proof.
        let merged = merge(vec![
            finding("cppcheck", "x", 5, Some(415), Confidence::Low),
            finding("clang-tidy", "y", 5, Some(415), Confidence::Low),
        ]);
        assert_eq!(merged[0].confidence, Confidence::Medium);
    }

    #[test]
    fn one_tool_reporting_twice_is_not_corroboration() {
        // Two checks in the same engine are not independent evidence.
        let merged = merge(vec![
            finding("cppcheck", "x", 5, Some(401), Confidence::Medium),
            finding("cppcheck", "y", 5, Some(401), Confidence::Medium),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agreement(), 2);
        assert_eq!(merged[0].confidence, Confidence::Medium);
    }

    #[test]
    fn highest_confidence_report_becomes_primary() {
        let merged = merge(vec![
            finding("cppcheck", "weak", 5, Some(416), Confidence::Low),
            finding("clang-tidy", "strong", 5, Some(416), Confidence::High),
        ]);
        assert_eq!(merged[0].primary.native_id, "strong");
    }

    #[test]
    fn output_order_is_stable() {
        let build = || {
            vec![
                finding("cppcheck", "a", 5, Some(401), Confidence::Low),
                finding("clang-tidy", "b", 9, Some(416), Confidence::High),
                finding("cppcheck", "c", 1, Some(476), Confidence::Medium),
            ]
        };
        let first: Vec<_> = merge(build())
            .iter()
            .map(|m| m.primary.native_id.clone())
            .collect();
        let second: Vec<_> = merge(build())
            .iter()
            .map(|m| m.primary.native_id.clone())
            .collect();
        assert_eq!(first, second);
        assert_eq!(first, vec!["b", "c", "a"]); // high, medium, low
    }
}
