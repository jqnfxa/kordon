//! Clang Static Analyzer driven directly, with cross-TU analysis.
//!
//! Separate from the clang-tidy runner on purpose. clang-tidy exposes the
//! analyzer, but its only structured output (`--export-fixes` YAML) cannot
//! represent a diagnostic whose path crosses a file boundary -- which is every
//! CTU finding. Driving `clang --analyze` directly with
//! `--analyzer-output plist-multi-file` is the only way to get them out intact.
//!
//! Verified against `testdata/uninit_owner/`: with the plain `plist` format
//! clang prints "Path diagnostic report is not generated. Current output format
//! does not support diagnostics that cross file boundaries" and emits an empty
//! report; with `plist-multi-file` the same run yields the full chain with
//! 8-26 step paths spanning three files.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::compile_db::CompileDb;
use crate::ctu::{driver_for, parse_ctu_progress, CallGraph, CtuIndex};
use crate::cwe::CweTable;
use crate::finding::{Confidence, Event, Finding, Severity, Tool};
use crate::tools::{ToolOutcome, ToolRun};

pub fn tool() -> Tool {
    Tool::new("clang-sa-ctu")
}

/// Checkers enabled for the CTU pass.
///
/// Deliberately narrower than the clang-tidy check set: CTU multiplies analysis
/// cost, so this pass runs only the path-sensitive checkers that actually
/// benefit from seeing across translation units. AST-matcher checks gain
/// nothing from CTU and already run in the clang-tidy pass.
pub const CTU_CHECKERS: &str = "core,cplusplus,unix,deadcode,nullability,\
optin.cplusplus.UninitializedObject,optin.portability.UnixAPI";

/// Run the analyzer over `sources` with the CTU index active.
pub fn run(
    sources: &[PathBuf],
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    index: &CtuIndex,
    out_dir: &Path,
    jobs: usize,
    table: &CweTable,
) -> (ToolRun, CallGraph) {
    if std::fs::create_dir_all(out_dir).is_err() {
        return (
            ToolRun::failed(tool(), format!("could not create {}", out_dir.display())),
            CallGraph::default(),
        );
    }

    let shards = jobs.clamp(1, sources.len().max(1));
    let chunk = sources.len().div_ceil(shards);

    let shard_results: Vec<(Vec<PathBuf>, usize, CallGraph)> = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .enumerate()
            .map(|(shard, files)| {
                scope.spawn(move || {
                    let mut reports = Vec::new();
                    let mut failed = 0usize;
                    let mut graph = CallGraph::default();
                    for (i, source) in files.iter().enumerate() {
                        let out = out_dir.join(format!("report-{shard}-{i}.plist"));
                        match analyze_one(source, compile_db, extra_args, index, &out) {
                            Ok((produced, imports)) => {
                                graph.merge(imports);
                                if produced {
                                    reports.push(out);
                                }
                            }
                            Err(_) => failed += 1,
                        }
                    }
                    (reports, failed, graph)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut findings = Vec::new();
    let mut notes = Vec::new();
    let mut failed_units = 0;

    let mut graph = CallGraph::default();
    for (reports, failed, shard_graph) in shard_results {
        graph.merge(shard_graph);
        failed_units += failed;
        for report in reports {
            match parse_plist(&report, table) {
                Ok(mut parsed) => findings.append(&mut parsed),
                Err(err) => notes.push(format!("could not parse {}: {err}", report.display())),
            }
        }
    }

    if failed_units > 0 {
        notes.push(format!(
            "{failed_units} of {} translation unit(s) could not be analyzed under CTU",
            sources.len()
        ));
    }
    if !index.failed.is_empty() {
        // The important one: a unit missing from the index is not merely
        // unanalyzed, it is invisible to *every other* unit's analysis too.
        notes.push(format!(
            "{} translation unit(s) are absent from the CTU index — definitions in them \
             stayed opaque to all other units",
            index.failed.len()
        ));
    }

    (
        ToolRun {
            tool: tool(),
            outcome: ToolOutcome::Ran,
            findings,
            notes,
        },
        graph,
    )
}

/// Analyze one translation unit.
///
/// Returns whether a report was produced, plus the units this one had to
/// import definitions from -- the analyzer reports those itself when
/// `display-ctu-progress` is on, which is where the call graph comes from.
fn analyze_one(
    source: &Path,
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    index: &CtuIndex,
    out: &Path,
) -> Result<(bool, CallGraph)> {
    let mut cmd = Command::new(driver_for(source));
    cmd.arg("--analyze")
        // Anything else silently discards cross-file diagnostics.
        .arg("--analyzer-output")
        .arg("plist-multi-file")
        .arg("-o")
        .arg(out)
        .arg("-Xanalyzer")
        .arg("-analyzer-checker")
        .arg("-Xanalyzer")
        .arg(CTU_CHECKERS)
        .arg("-Xanalyzer")
        .arg("-analyzer-config")
        .arg("-Xanalyzer")
        .arg(format!(
            "experimental-enable-naive-ctu-analysis=true,ctu-dir={},display-ctu-progress=true",
            index.dir.display()
        ));

    if let Some(db) = compile_db {
        if let Some(args) = db.args_for(source) {
            for arg in args {
                cmd.arg(arg);
            }
        }
    } else {
        for arg in extra_args {
            cmd.arg(arg);
        }
    }
    cmd.arg(source);

    // stderr carries the CTU import lines, so it has to be captured.
    let output = cmd.stdout(std::process::Stdio::null()).output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let imports = parse_ctu_progress(source, &stderr);

    // A non-zero exit means the unit did not compile; there is nothing to read.
    Ok((output.status.success() && out.exists(), imports))
}

/// Default trust for a Clang SA checker. Everything here is path-sensitive, so
/// the floor is higher than for AST matchers -- the analyzer has a concrete
/// path when it reports.
fn default_confidence(check: &str) -> Confidence {
    if check.starts_with("optin.") || check.starts_with("alpha.") {
        Confidence::Medium
    } else {
        Confidence::High
    }
}

/// Parse a `plist-multi-file` report.
///
/// Shape: a `files` array of paths, then `diagnostics`, each with a
/// `check_name`, `description`, a `location` (indices into `files`), and a
/// `path` of steps that may span several of those files.
pub fn parse_plist(path: &Path, table: &CweTable) -> Result<Vec<Finding>> {
    let value: plist::Value = plist::from_file(path)?;
    let root = match value.as_dictionary() {
        Some(dict) => dict,
        None => return Ok(Vec::new()),
    };

    let files: Vec<PathBuf> = root
        .get("files")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| PathBuf::from(v.as_string().unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default();

    let diagnostics = match root.get("diagnostics").and_then(|d| d.as_array()) {
        Some(list) => list,
        None => return Ok(Vec::new()),
    };

    let mut findings = Vec::new();

    for diag in diagnostics {
        let Some(dict) = diag.as_dictionary() else {
            continue;
        };

        let check = dict
            .get("check_name")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown")
            .to_string();
        let message = dict
            .get("description")
            .and_then(|v| v.as_string())
            .unwrap_or_default()
            .to_string();

        let Some((file, line, column)) = location_of(dict.get("location"), &files) else {
            continue;
        };

        // Report under the same `clang-analyzer-` prefix clang-tidy uses, so
        // one mapping-table entry serves both runners and findings from the
        // two passes dedup against each other.
        let native_id = format!("clang-analyzer-{check}");
        let class = table.classify(
            &tool(),
            &native_id,
            &message,
            None,
            default_confidence(&check),
        );

        let events = dict
            .get("path")
            .and_then(|p| p.as_array())
            .map(|steps| collect_events(steps, &files))
            .unwrap_or_default();

        findings.push(Finding {
            tool: tool(),
            native_id,
            cwe: class.cwe,
            cwe_source: class.source,
            file,
            line,
            column,
            severity: Severity::Warning,
            confidence: class.confidence,
            message,
            events,
        });
    }

    Ok(findings)
}

fn location_of(value: Option<&plist::Value>, files: &[PathBuf]) -> Option<(PathBuf, u32, u32)> {
    let dict = value?.as_dictionary()?;
    let index = dict.get("file")?.as_signed_integer()? as usize;
    let line = dict.get("line")?.as_signed_integer()? as u32;
    let column = dict.get("col")?.as_signed_integer().unwrap_or(1) as u32;
    let file = files.get(index)?.clone();
    Some((file, line, column))
}

/// Flatten the analyzer's path into the event list.
///
/// Only `kind == "event"` steps carry a human-readable message; `control`
/// steps are edge bookkeeping and would just be noise in a report.
fn collect_events(steps: &[plist::Value], files: &[PathBuf]) -> Vec<Event> {
    let mut events = Vec::new();
    for step in steps {
        let Some(dict) = step.as_dictionary() else {
            continue;
        };
        if dict.get("kind").and_then(|k| k.as_string()) != Some("event") {
            continue;
        }
        let message = dict
            .get("message")
            .and_then(|m| m.as_string())
            .unwrap_or_default()
            .to_string();
        if let Some((file, line, column)) = location_of(dict.get("location"), files) {
            events.push(Event {
                file,
                line,
                column,
                message,
            });
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctu_checkers_include_the_uninitialized_object_optin() {
        // The checker that finds a constructor leaving a member unassigned is
        // an optin.* one and is not part of any default group.
        assert!(CTU_CHECKERS.contains("optin.cplusplus.UninitializedObject"));
    }

    #[test]
    fn analyzer_checks_outrank_ast_matchers_by_default() {
        assert_eq!(default_confidence("core.NullDereference"), Confidence::High);
        // optin/alpha checkers are less battle-tested; do not claim high.
        assert_eq!(
            default_confidence("optin.cplusplus.UninitializedObject"),
            Confidence::Medium
        );
    }

    #[test]
    fn missing_plist_is_an_error_not_silent_success() {
        let table = CweTable::builtin().unwrap();
        assert!(parse_plist(Path::new("/nonexistent/kordon.plist"), &table).is_err());
    }
}
