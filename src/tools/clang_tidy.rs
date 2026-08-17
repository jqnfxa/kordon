//! clang-tidy runner and `--export-fixes` YAML parser.
//!
//! This covers both clang-tidy's own AST-matcher checks and the Clang Static
//! Analyzer, which clang-tidy exposes under the `clang-analyzer-*` prefix.
//!
//! Output format note: as of LLVM 18, clang-tidy has **no SARIF export**. The
//! only machine-readable output is the `--export-fixes` YAML, which despite
//! the name lists every diagnostic, including ones with no suggested fix. It
//! is preferred over scraping stdout, which is a human-facing format with no
//! stability guarantee -- but it costs us two things:
//!
//!   * locations are byte offsets, so [`crate::offsets`] has to resolve them;
//!   * there is no severity beyond `Level`, and no CWE at all.
//!
//! Running clang-tidy directly means one translation unit at a time, with no
//! cross-TU analysis. Clang SA then treats a function defined in another .cpp
//! as opaque. CodeChecker's `--ctu` mode is the fix; wiring it in is separate
//! work, and until then the report must not imply cross-TU coverage.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use serde::Deserialize;

use crate::cwe::CweTable;
use crate::finding::{Confidence, Event, Finding, Severity, Tool};
use crate::offsets::OffsetResolver;
use crate::tools::{ToolOutcome, ToolRun};

pub fn tool() -> Tool {
    Tool::new("clang-tidy")
}

/// Checks Kordon turns on by default.
///
/// Scoped to the families that map to tier-1 CWEs. `readability-*`,
/// `modernize-*` and friends are excluded outright: they generate volume with
/// no memory-safety signal, and every unmapped check shows up as a gap in the
/// report, so enabling them would bury the real gaps in noise.
///
/// `cppcoreguidelines-owning-memory` and `pro-bounds-*` are enabled despite
/// being noisy, which corrects an earlier mistake worth recording. They were
/// removed once because on a ten-function fixture they produced eight
/// low-confidence findings that buried the single genuine leak. Measured later
/// against a real module with an independent ground-truth list, those same two
/// checks accounted for 16 of 29 matched defects -- more than half the recall,
/// and every CWE-119 hit. Dropping them cost far more than the noise they made.
///
/// The noise was a reporting problem, not a check-selection problem, and it is
/// fixed in the right place now: both are mapped at `low` confidence, so the
/// report summarizes them by count rather than detailing them, while they still
/// contribute findings. Judging a check by its output volume on a toy corpus
/// was the error.
///
/// `special-member-functions` fires once per class, not per use, and is the
/// C.21 / Rule-of-Five check that catches a latent double free in an owning
/// class -- a defect no other configured check finds.
/// `clang-analyzer-*` does NOT include the `optin.*` checkers -- they must be
/// named explicitly. `optin.cplusplus.UninitializedObject` is enabled here
/// because it is the only configured check that finds a constructor leaving a
/// member unassigned on one path, which is the root of the fallible-init
/// defect chain (CWE-665 -> 824 -> 476/590). Measured on
/// testdata/uninit_owner: without it that class is invisible, with it the
/// analyzer names the exact field -- provided the constructor's call site is
/// in the same translation unit.
pub const DEFAULT_CHECKS: &str =
    "-*,clang-analyzer-*,bugprone-*,\
clang-analyzer-optin.cplusplus.UninitializedObject,\
cppcoreguidelines-special-member-functions,cppcoreguidelines-init-variables,\
cppcoreguidelines-narrowing-conversions,cppcoreguidelines-owning-memory,\
cppcoreguidelines-pro-bounds-pointer-arithmetic,\
cppcoreguidelines-pro-bounds-constant-array-index,\
cppcoreguidelines-pro-bounds-array-to-pointer-decay";

/// Default trust in a clang-tidy check, by family.
///
/// `clang-analyzer-*` is path-sensitive symbolic execution: when it reports a
/// defect it has a concrete path to it. `bugprone-*` is AST pattern matching.
/// `cppcoreguidelines-*` mostly flags risky shapes rather than defects. The
/// mapping table can override any of this per check.
fn default_confidence(check: &str) -> Confidence {
    if check.starts_with("clang-analyzer-") {
        Confidence::High
    } else if check.starts_with("bugprone-") {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

fn severity_of(level: &str) -> Severity {
    match level {
        "Error" => Severity::Error,
        "Warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Run clang-tidy over one or more sources.
///
/// `compile_db` is the build directory containing `compile_commands.json`. If
/// absent, `extra_args` are passed after `--` as the compilation command.
///
/// clang-tidy has **no internal parallelism** -- handed N files it analyzes
/// them one after another, which is why upstream ships `run-clang-tidy` as a
/// separate wrapper. Kordon shards the file list across `jobs` processes
/// instead. Measured on a 486-file tree: a single invocation took roughly
/// eight minutes of wall clock on an otherwise idle 20-core machine, nearly
/// all of it one busy core.
pub fn run(
    binary: &str,
    sources: &[PathBuf],
    compile_db: Option<&Path>,
    extra_args: &[String],
    checks: &str,
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

    let results: Vec<ShardResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .enumerate()
            .map(|(index, files)| {
                scope.spawn(move || {
                    run_shard(binary, files, compile_db, extra_args, checks, index)
                })
            })
            .collect();

        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .collect()
    });

    let mut yaml_chunks = Vec::new();
    let mut spawn_errors = Vec::new();
    let mut failed_units = 0usize;

    for result in results {
        match result {
            ShardResult::Ok { yaml, failed } => {
                failed_units += failed;
                if let Some(text) = yaml {
                    yaml_chunks.push(text);
                }
            }
            ShardResult::SpawnFailed(reason) => spawn_errors.push(reason),
        }
    }

    // Every shard failing to spawn means the engine never ran. Reporting that
    // as "ran, found nothing" would be a lie.
    if !spawn_errors.is_empty() && yaml_chunks.is_empty() && failed_units == 0 {
        return ToolRun::failed(tool(), spawn_errors.remove(0));
    }

    let mut notes = Vec::new();
    if failed_units > 0 {
        // The single most important note Kordon can emit. A translation unit
        // that failed to compile was not analyzed at all, so a quiet report
        // over such a tree means "we could not look", not "nothing is wrong".
        // Almost always a missing compile_commands.json.
        notes.push(format!(
            "{failed_units} of {} translation unit(s) FAILED TO COMPILE and were not analyzed \
             — findings for them are absent, not clean{}",
            sources.len(),
            if compile_db.is_none() {
                " (no compile_commands.json given; pass -p)"
            } else {
                ""
            }
        ));
    }
    for reason in spawn_errors {
        notes.push(reason);
    }

    let mut findings = Vec::new();
    for yaml in &yaml_chunks {
        match parse(yaml, table) {
            Ok(mut parsed) => findings.append(&mut parsed),
            Err(err) => {
                notes.push(format!("could not parse a clang-tidy YAML shard: {err}"));
            }
        }
    }

    ToolRun {
        tool: tool(),
        outcome: ToolOutcome::Ran,
        findings,
        notes,
    }
}

enum ShardResult {
    Ok {
        yaml: Option<String>,
        /// Translation units clang-tidy could not compile.
        failed: usize,
    },
    SpawnFailed(String),
}

fn run_shard(
    binary: &str,
    files: &[PathBuf],
    compile_db: Option<&Path>,
    extra_args: &[String],
    checks: &str,
    index: usize,
) -> ShardResult {
    let fixes_path = shard_fixes_path(index);

    let mut cmd = Command::new(binary);
    cmd.arg(format!("-checks={checks}"))
        .arg(format!("--export-fixes={}", fixes_path.display()))
        // Without this, findings in the project's own headers are dropped.
        .arg("-header-filter=.*")
        .arg("-quiet");

    if let Some(db) = compile_db {
        cmd.arg("-p").arg(db);
    }

    for file in files {
        cmd.arg(file);
    }

    if compile_db.is_none() && !extra_args.is_empty() {
        cmd.arg("--");
        for arg in extra_args {
            cmd.arg(arg);
        }
    }

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => return ShardResult::SpawnFailed(format!("could not run `{binary}`: {err}")),
    };

    // clang-tidy prints one "Error while processing <file>." per translation
    // unit it could not compile. Counting them turns a vague non-zero exit
    // into a number the report can state.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let failed = stderr
        .lines()
        .filter(|line| line.starts_with("Error while processing"))
        .count();

    // No diagnostics at all means no file is written.
    let yaml = std::fs::read_to_string(&fixes_path).ok();
    let _ = std::fs::remove_file(&fixes_path);

    ShardResult::Ok { yaml, failed }
}

fn shard_fixes_path(index: usize) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("kordon-fixes-{}-{index}.yaml", std::process::id()));
    path
}

#[allow(dead_code)]
fn tempfile_path() -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    // No randomness needed: one clang-tidy run per Kordon process, and the
    // pid keeps concurrent Kordon runs from colliding.
    path.push(format!("kordon-fixes-{}.yaml", std::process::id()));
    Ok(path)
}

// ------------------------------------------------------------- YAML shapes

#[derive(Debug, Deserialize)]
struct FixesFile {
    #[serde(default, rename = "Diagnostics")]
    diagnostics: Vec<RawDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct RawDiagnostic {
    #[serde(rename = "DiagnosticName")]
    name: String,
    #[serde(rename = "DiagnosticMessage")]
    message: RawMessage,
    #[serde(default, rename = "Notes")]
    notes: Vec<RawMessage>,
    #[serde(default, rename = "Level")]
    level: String,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(rename = "Message")]
    text: String,
    #[serde(rename = "FilePath")]
    file: String,
    #[serde(rename = "FileOffset")]
    offset: usize,
}

/// Parse a clang-tidy `--export-fixes` YAML report.
pub fn parse(yaml: &str, table: &CweTable) -> Result<Vec<Finding>> {
    let parsed: FixesFile = serde_yaml::from_str(yaml)?;
    let mut resolver = OffsetResolver::new();
    let mut findings = Vec::with_capacity(parsed.diagnostics.len());

    for diag in parsed.diagnostics {
        let file = PathBuf::from(&diag.message.file);
        let (line, column) = resolver.resolve(&file, diag.message.offset);

        let severity = severity_of(&diag.level);
        let class = table.classify(
            &tool(),
            &diag.name,
            &diag.message.text,
            None, // clang-tidy never reports a CWE
            default_confidence(&diag.name),
        );

        // clang-analyzer repeats the diagnostic itself as the first note.
        // Keeping it would show the defect site twice in the path.
        let events = diag
            .notes
            .iter()
            .filter(|note| {
                !(note.offset == diag.message.offset && note.text == diag.message.text)
            })
            .map(|note| {
                let note_file = PathBuf::from(&note.file);
                let (nline, ncol) = resolver.resolve(&note_file, note.offset);
                Event {
                    file: canonical(&note_file),
                    line: nline,
                    column: ncol,
                    message: note.text.clone(),
                }
            })
            .collect();

        findings.push(Finding {
            tool: tool(),
            native_id: diag.name,
            cwe: class.cwe,
            cwe_source: class.source,
            file: canonical(&file),
            line,
            column,
            severity,
            confidence: class.confidence,
            message: diag.message.text,
            events,
        });
    }

    Ok(findings)
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::CweSource;

    /// Offsets below point into this exact text, written to a temp file by the
    /// tests so the resolver has something real to index.
    const SOURCE: &str = "void f() {\n    int *p = new int;\n    delete p;\n    *p = 1;\n}\n";

    /// Each test gets its own file: the suite runs in parallel within one
    /// process, so a shared pid-derived name would have tests deleting the
    /// fixture out from under each other.
    fn write_source(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("kordon-test-{}-{tag}.cpp", std::process::id()));
        std::fs::write(&path, SOURCE).unwrap();
        path
    }

    fn yaml_for(path: &Path) -> String {
        let p = path.display();
        // Offset 51 is the '*' of `*p = 1;` (line 4, col 5); offset 15 is the
        // 'i' of `int *p` (line 2, col 5). Verified against SOURCE above.
        format!(
            "---\nMainSourceFile: '{p}'\nDiagnostics:\n  \
- DiagnosticName: clang-analyzer-cplusplus.NewDelete\n    \
DiagnosticMessage:\n      Message: 'Use of memory after it is freed'\n      \
FilePath: '{p}'\n      FileOffset: 51\n      Replacements: []\n    \
Notes:\n      - Message: 'Memory is allocated'\n        FilePath: '{p}'\n        \
FileOffset: 15\n        Replacements: []\n      \
- Message: 'Use of memory after it is freed'\n        FilePath: '{p}'\n        \
FileOffset: 51\n        Replacements: []\n    Level: Warning\n  \
- DiagnosticName: modernize-use-nullptr\n    \
DiagnosticMessage:\n      Message: 'use nullptr'\n      \
FilePath: '{p}'\n      FileOffset: 15\n      Replacements: []\n    Level: Warning\n"
        )
    }

    fn parsed(tag: &str) -> Vec<Finding> {
        let path = write_source(tag);
        let table = CweTable::builtin().unwrap();
        let out = parse(&yaml_for(&path), &table).expect("sample must parse");
        let _ = std::fs::remove_file(&path);
        out
    }

    #[test]
    fn byte_offsets_resolve_to_line_and_column() {
        let f = &parsed("offsets")[0];
        assert_eq!(f.line, 4); // `*p = 1;`
        assert_eq!(f.column, 5);
    }

    #[test]
    fn analyzer_checks_get_a_cwe_from_the_table() {
        let f = &parsed("cwe")[0];
        assert_eq!(f.cwe, Some(416));
        assert_eq!(f.cwe_source, CweSource::Mapped);
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn note_chain_becomes_the_event_path_without_the_duplicate() {
        let f = &parsed("notes")[0];
        // Two notes in, one out: the note echoing the diagnostic is dropped.
        assert_eq!(f.events.len(), 1);
        assert_eq!(f.events[0].message, "Memory is allocated");
        assert_eq!(f.events[0].line, 2);
    }

    #[test]
    fn unmapped_check_is_kept_and_marked() {
        let f = &parsed("unmapped")[1];
        assert_eq!(f.native_id, "modernize-use-nullptr");
        assert_eq!(f.cwe, None);
        assert_eq!(f.cwe_source, CweSource::Unmapped);
    }

    #[test]
    fn empty_report_is_not_an_error() {
        let table = CweTable::builtin().unwrap();
        assert!(parse("---\nMainSourceFile: 'x.cpp'\nDiagnostics:\n", &table)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn confidence_defaults_track_the_check_family() {
        assert_eq!(
            default_confidence("clang-analyzer-core.NullDereference"),
            Confidence::High
        );
        assert_eq!(default_confidence("bugprone-use-after-move"), Confidence::Medium);
        assert_eq!(
            default_confidence("cppcoreguidelines-pro-bounds-pointer-arithmetic"),
            Confidence::Low
        );
    }
}
