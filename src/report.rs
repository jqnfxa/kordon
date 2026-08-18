//! Report rendering.
//!
//! The governing rule: **a clean report must never imply coverage Kordon did
//! not achieve.** Every way the analysis fell short -- an engine that was not
//! installed, a translation unit that failed to compile, a check with no CWE
//! mapping, a defect class no configured engine can see -- is stated in the
//! report itself, not left for the reader to infer from silence.

use std::collections::BTreeMap;

use crate::ctu::CallGraph;
use crate::cwe::CweTable;
use crate::dedup::MergedFinding;
use crate::finding::{Confidence, CweSource, Proof};
use crate::tools::{ToolOutcome, ToolRun};

pub struct Report<'a> {
    pub runs: &'a [ToolRun],
    pub merged: &'a [MergedFinding],
    pub table: &'a CweTable,
    /// Files Kordon handed to the engines.
    pub analyzed_files: usize,
    /// Sources found on disk but absent from the compile database, so not part
    /// of the build and deliberately not analyzed.
    pub unlisted_files: usize,
    /// Cross-TU dependencies observed during the CTU pass. Empty without --ctu.
    pub call_graph: &'a CallGraph,
}

impl<'a> Report<'a> {
    /// Findings whose CWE is one Kordon claims to target.
    ///
    /// Excludes anything an analyzer explicitly could not decide. "I could not
    /// prove this either way" is a statement about the analysis, not a claim
    /// about the code, and mixing the two would let the honest admission of a
    /// limit read as an accusation. Those are reported separately, and only on
    /// request -- see [`Self::unproven`].
    pub fn in_scope(&self) -> Vec<&MergedFinding> {
        self.merged
            .iter()
            .filter(|m| !all_unproven(m))
            .filter(|m| m.primary.cwe.is_some_and(|c| self.table.in_scope(c)))
            .collect()
    }

    /// Checks no contributing engine could settle.
    ///
    /// Every contributor must be unproven. If one engine merely failed to
    /// prove something that another engine reported outright, that is a
    /// finding, and hiding it because the merge happened to pick the
    /// undecided report as representative would lose it entirely.
    pub fn unproven(&self) -> Vec<&MergedFinding> {
        self.merged.iter().filter(|m| all_unproven(m)).collect()
    }

    /// Findings an analyzer *proved*, rather than pattern-matched.
    #[allow(dead_code)]
    pub fn proved(&self) -> Vec<&MergedFinding> {
        self.merged
            .iter()
            .filter(|m| m.primary.proof == Some(Proof::Refuted))
            .collect()
    }

    /// Findings with a CWE that is deliberately outside Kordon's scope, or a
    /// style-only indicator. Counted, not detailed.
    pub fn out_of_scope(&self) -> Vec<&MergedFinding> {
        self.merged
            .iter()
            .filter(|m| m.primary.cwe.is_some_and(|c| !self.table.in_scope(c)))
            .collect()
    }

    /// Findings no rule could classify. These are gaps in Kordon's mapping
    /// table, and are reported as such rather than dropped.
    pub fn unmapped(&self) -> Vec<&MergedFinding> {
        self.merged
            .iter()
            .filter(|m| m.primary.cwe_source == CweSource::Unmapped)
            .collect()
    }

    pub fn render_text(&self, verbose: bool, show_all: bool, show_unproven: bool) -> String {
        let mut out = String::new();

        out.push_str(&self.render_engines());
        out.push_str(&self.render_findings(verbose, show_all));
        out.push_str(&self.render_call_graph());
        out.push_str(&self.render_gaps());
        // Last, and only on request: a list of things a tool could not decide
        // is noise to most readers and the whole point to a few.
        out.push_str(&self.render_unproven(show_unproven));
        out.push_str(&self.render_caveats());

        out
    }

    /// Checks no analyzer could settle.
    ///
    /// Off by default. Summarized either way, because a silent omission would
    /// be the same mistake as reporting them as defects: the reader cannot tell
    /// "nothing to say" from "nothing was looked at".
    fn render_unproven(&self, show: bool) -> String {
        let unproven = self.unproven();
        if unproven.is_empty() {
            return String::new();
        }

        let mut out = String::new();
        out.push_str("\n═══ Unproven ═══\n\n");
        out.push_str(&format!(
            "  {} check(s) an analyzer could prove neither safe nor unsafe.\n\
             \x20 This is a limit of the analysis, not a defect claim.\n",
            unproven.len()
        ));

        if !show {
            let mut by_check: BTreeMap<String, usize> = BTreeMap::new();
            for m in &unproven {
                *by_check.entry(m.primary.native_id.clone()).or_default() += 1;
            }
            for (check, count) in by_check {
                out.push_str(&format!("    {count:>6}  {check}\n"));
            }
            out.push_str("  Re-run with --show-unproven to list them.\n");
            return out;
        }

        out.push('\n');
        for m in &unproven {
            let f = &m.primary;
            out.push_str(&format!(
                "    {}:{}:{}  [{}]\n      {}\n",
                f.file.display(),
                f.line,
                f.column,
                f.native_id,
                f.message
            ));
        }
        out
    }

    fn render_engines(&self) -> String {
        let mut out = String::new();
        out.push_str("\n═══ Engines ═══\n\n");

        for run in self.runs {
            let status = match &run.outcome {
                ToolOutcome::Ran => format!("ok, {} raw findings", run.findings.len()),
                ToolOutcome::Skipped(why) => format!("SKIPPED — {why}"),
                ToolOutcome::Failed(why) => format!("FAILED — {why}"),
            };
            out.push_str(&format!("  {:<14} {}\n", run.tool.as_str(), status));
            for note in &run.notes {
                out.push_str(&format!("  {:<14} note: {}\n", "", note));
            }
        }

        out.push_str(&format!("\n  {} file(s) analyzed\n", self.analyzed_files));
        if self.unlisted_files > 0 {
            out.push_str(&format!(
                "  {} file(s) skipped — absent from compile_commands.json, so not\n\
             \x20 part of the build. They were NOT analyzed; this is not a clean result.\n",
                self.unlisted_files
            ));
        }
        out
    }

    fn render_findings(&self, verbose: bool, show_all: bool) -> String {
        let in_scope = self.in_scope();
        let mut out = String::new();

        out.push_str("\n═══ In-scope findings ═══\n\n");

        if in_scope.is_empty() {
            out.push_str("  none\n");
            return out;
        }

        // Split by confidence before grouping. Low-confidence findings come
        // from checks that flag a risky *shape* rather than a proven defect;
        // they fire once per raw pointer, cast or uninitialized declaration and
        // on a real codebase outnumber the path-sensitive results by an order
        // of magnitude. Measured on a 486-file tree: 1543 of 1802 in-scope
        // findings came from three such checks, burying seven analyzer
        // results. They are counted and summarized below, never dropped.
        let (substantive, risk_patterns): (Vec<&MergedFinding>, Vec<&MergedFinding>) = in_scope
            .into_iter()
            .partition(|m| m.confidence > Confidence::Low || show_all);

        // Group by CWE so a reviewer sees defect classes, not a flat list.
        let mut by_cwe: BTreeMap<u32, Vec<&MergedFinding>> = BTreeMap::new();
        for m in &substantive {
            by_cwe.entry(m.primary.cwe.unwrap()).or_default().push(*m);
        }

        for (cwe, group) in &by_cwe {
            let name = self.table.name_of(*cwe).unwrap_or("(unnamed)");
            out.push_str(&format!("  CWE-{cwe}  {name}  [{}]\n", group.len()));

            for m in group {
                let f = &m.primary;
                let corroboration = if m.agreement() > 1 {
                    format!(" ({} engines agree)", m.agreement())
                } else {
                    String::new()
                };
                // A proof outranks any amount of agreement between matchers.
                let proved = if m.primary.proof == Some(Proof::Refuted) {
                    "  PROVED"
                } else {
                    ""
                };

                out.push_str(&format!(
                    "    {}:{}:{}  {}{}\n",
                    f.file.display(),
                    f.line,
                    f.column,
                    confidence_tag(m.confidence),
                    format!("{corroboration}{proved}"),
                ));
                out.push_str(&format!("      {}\n", f.message));
                out.push_str(&format!(
                    "      via {} [{}]\n",
                    m.tools().join(" + "),
                    f.native_id
                ));

                if verbose {
                    for event in &f.events {
                        out.push_str(&format!(
                            "        ↳ {}:{}  {}\n",
                            event.file.display(),
                            event.line,
                            event.message
                        ));
                    }
                }
                out.push('\n');
            }
        }

        let total: usize = by_cwe.values().map(|g| g.len()).sum();
        if total == 0 {
            out.push_str("  none above low confidence\n");
        }
        out.push_str(&format!(
            "  {total} defect(s) across {} CWE class(es)\n",
            by_cwe.len()
        ));

        if !risk_patterns.is_empty() {
            let mut by_check: BTreeMap<String, usize> = BTreeMap::new();
            for m in &risk_patterns {
                *by_check.entry(m.primary.native_id.clone()).or_default() += 1;
            }
            out.push_str(&format!(
                "\n  Plus {} low-confidence finding(s) from risk-pattern checks, not detailed.\n  \
                 These flag a shape that *can* become the defect, not one that was proven.\n  \
                 Re-run with --all to list them:\n",
                risk_patterns.len()
            ));
            for (check, count) in by_check {
                out.push_str(&format!("    {count:>6}  {check}\n"));
            }
        }

        out
    }

    /// Cross-TU dependency structure, when CTU ran.
    ///
    /// These are dependencies the analyzer actually had to follow to reason
    /// about a unit, not every symbol a file mentions -- so a unit high in this
    /// ranking is one whose defects propagate furthest.
    fn render_call_graph(&self) -> String {
        if self.call_graph.is_empty() {
            return String::new();
        }

        let mut out = String::new();
        out.push_str("\n═══ Cross-TU dependencies ═══\n\n");
        out.push_str(&format!(
            "  {} unit(s) pulled definitions from {} edge(s)\n\n",
            self.call_graph.edges.len(),
            self.call_graph.edge_count()
        ));

        out.push_str("  Most depended upon — a defect here reaches every dependent:\n");
        for (path, count) in self.call_graph.most_depended_upon(10) {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            out.push_str(&format!("    {count:>4}  {name}\n"));
        }
        out.push('\n');
        out
    }

    /// Everything Kordon knows it did not cover. This section is the point of
    /// the report as much as the findings are.
    fn render_gaps(&self) -> String {
        let mut out = String::new();
        out.push_str("\n═══ Coverage gaps ═══\n\n");

        let out_of_scope = self.out_of_scope();
        if !out_of_scope.is_empty() {
            let mut by_cwe: BTreeMap<u32, usize> = BTreeMap::new();
            for m in &out_of_scope {
                *by_cwe.entry(m.primary.cwe.unwrap()).or_default() += 1;
            }
            out.push_str(&format!(
                "  {} finding(s) outside Kordon's target scope, not detailed:\n",
                out_of_scope.len()
            ));
            for (cwe, count) in by_cwe {
                let name = self.table.name_of(cwe).unwrap_or("(unnamed)");
                out.push_str(&format!("    CWE-{cwe:<6} {count:>4}  {name}\n"));
            }
            out.push('\n');
        }

        let unmapped = self.unmapped();
        if !unmapped.is_empty() {
            let mut by_check: BTreeMap<String, usize> = BTreeMap::new();
            for m in &unmapped {
                *by_check.entry(m.primary.native_id.clone()).or_default() += 1;
            }
            out.push_str(&format!(
                "  {} finding(s) from checks with no CWE mapping — these are gaps in\n  \
                 data/cwe_map.toml, not clean results:\n",
                unmapped.len()
            ));
            for (check, count) in by_check {
                out.push_str(&format!("    {count:>4}  {check}\n"));
            }
            out.push('\n');
        }

        let missing: Vec<_> = self.runs.iter().filter(|r| !r.ran()).collect();
        if !missing.is_empty() {
            out.push_str(
                "  Engines that did not run — their defect classes were NOT checked:\n",
            );
            for run in missing {
                out.push_str(&format!("    {}\n", run.tool.as_str()));
            }
            out.push('\n');
        }

        if out_of_scope.is_empty() && unmapped.is_empty() {
            out.push_str("  no unclassified findings\n\n");
        }

        out
    }

    /// Limits that hold even on a completely clean run.
    fn render_caveats(&self) -> String {
        let mut out = String::new();
        out.push_str("═══ What this report does not cover ═══\n\n");
        // Must track what actually ran: claiming "no CTU" after a CTU pass, or
        // vice versa, is exactly the kind of quiet inaccuracy this section
        // exists to prevent.
        if self.call_graph.is_empty() {
            out.push_str(
                "  • Single translation unit only. Cross-TU analysis did not run, so any\n    \
                 function defined in another .cpp was opaque to the analyzer. Pass --ctu.\n",
            );
        } else {
            out.push_str(
                "  • Cross-TU analysis ran, but only over units that compiled and were\n    \
                 indexed. Definitions in any unindexed unit stayed opaque everywhere.\n",
            );
        }
        out.push_str(
            "  • Static analysis only. No sanitizer run, so bounds/UAF/overflow defects\n    \
             that depend on runtime values are unproven either way.\n",
        );
        out.push_str(
            "  • No sound absence proof. Nothing here says the code IS safe; only that\n    \
             these engines did not flag it.\n\n",
        );
        out
    }

    /// Machine-readable form, for CI and for diffing runs against each other.
    pub fn render_json(&self) -> serde_json::Value {
        let findings: Vec<_> = self
            .merged
            .iter()
            .map(|m| {
                serde_json::json!({
                    "cwe": m.primary.cwe,
                    "cwe_name": m.primary.cwe.and_then(|c| self.table.name_of(c)),
                    "cwe_source": m.primary.cwe_source.to_string(),
                    "in_scope": m.primary.cwe.is_some_and(|c| self.table.in_scope(c)),
                    "file": m.primary.file,
                    "line": m.primary.line,
                    "column": m.primary.column,
                    "severity": m.severity().to_string(),
                    "confidence": m.confidence.to_string(),
                    "message": m.primary.message,
                    "unproven": all_unproven(m),
                    "tools": m.tools(),
                    "agreement": m.agreement(),
                    "native_ids": std::iter::once(&m.primary)
                        .chain(m.others.iter())
                        .map(|f| f.native_id.clone())
                        .collect::<Vec<_>>(),
                    "events": m.primary.events,
                })
            })
            .collect();

        let engines: Vec<_> = self
            .runs
            .iter()
            .map(|run| {
                let (status, detail) = match &run.outcome {
                    ToolOutcome::Ran => ("ran", None),
                    ToolOutcome::Skipped(why) => ("skipped", Some(why.clone())),
                    ToolOutcome::Failed(why) => ("failed", Some(why.clone())),
                };
                serde_json::json!({
                    "tool": run.tool.as_str(),
                    "status": status,
                    "detail": detail,
                    "raw_findings": run.findings.len(),
                    "notes": run.notes,
                })
            })
            .collect();

        serde_json::json!({
            "kordon_version": env!("CARGO_PKG_VERSION"),
            "analyzed_files": self.analyzed_files,
            "unlisted_files": self.unlisted_files,
            "engines": engines,
            "findings": findings,
            "summary": {
                "proved": self.proved().len(),
                "unproven": self.unproven().len(),
                "in_scope": self.in_scope().len(),
                "out_of_scope": self.out_of_scope().len(),
                "unmapped": self.unmapped().len(),
            },
            // Machine-readable form of the caveats section, so CI cannot treat
            // an empty finding list as proof of safety.
            "coverage_caveats": [
                "single-translation-unit analysis only; CTU not enabled",
                "static analysis only; no sanitizer or dynamic evidence",
                "absence of findings is not a proof of absence of defects",
            ],
        })
    }
}

/// True when no contributing engine could decide this one.
fn all_unproven(m: &MergedFinding) -> bool {
    std::iter::once(&m.primary)
        .chain(m.others.iter())
        .all(|f| f.proof == Some(Proof::Unproven))
}

fn confidence_tag(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "confidence: high",
        Confidence::Medium => "confidence: medium",
        Confidence::Low => "confidence: low",
    }
}
