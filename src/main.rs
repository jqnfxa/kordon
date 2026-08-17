//! Kordon -- static+dynamic analysis orchestrator for C/C++.
//!
//! Kordon does not implement program analysis. It drives mature engines
//! (clang-tidy / Clang Static Analyzer, cppcheck, and later IKOS and the
//! sanitizers), normalizes their disagreeing output into one schema, maps
//! every finding to a CWE, merges what the engines independently agree on,
//! and reports honestly on what none of them covered.

mod ctu;
mod cwe;
mod dedup;
mod finding;
mod offsets;
mod report;
mod tools;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::cwe::CweTable;
use crate::report::Report;
use crate::tools::{ToolRun, ToolOutcome};

/// File extensions Kordon treats as C/C++ sources when scanning a directory.
const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "c++"];

/// Directory names never worth analyzing. Skipping these is not a silent cap
/// on coverage -- they hold build artifacts and third-party code, not the
/// sources under review.
const SKIP_DIRS: &[&str] = &[
    ".git", ".svn", ".hg", "build", "cmake-build-debug", "cmake-build-release",
    "node_modules", "target", "third_party", "external", "vendor", ".cache",
];

#[derive(Parser, Debug)]
#[command(
    name = "kordon",
    version,
    about = "Static analysis orchestrator for C/C++ — one CWE-mapped report from several engines"
)]
struct Cli {
    /// Directory to analyze recursively, or a single source file.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Build directory containing compile_commands.json. Without it, Kordon
    /// analyzes each file standalone, which loses project include paths and
    /// defines.
    #[arg(short = 'p', long)]
    compile_db: Option<PathBuf>,

    /// Emit JSON instead of the text report.
    #[arg(long)]
    json: bool,

    /// Show each finding's full event path.
    #[arg(short, long)]
    verbose: bool,

    /// Detail every finding, including low-confidence risk-pattern checks that
    /// are otherwise only counted and summarized.
    #[arg(long)]
    all: bool,

    /// Override the built-in CWE mapping table.
    #[arg(long)]
    cwe_map: Option<PathBuf>,

    /// C++ standard passed to the engines.
    #[arg(long, default_value = "c++17")]
    std: String,

    /// Parallel jobs for engines that support it.
    #[arg(short, long, default_value_t = default_jobs())]
    jobs: usize,

    /// Deeper cppcheck value-flow analysis. Considerably slower.
    #[arg(long)]
    exhaustive: bool,

    /// Enable cross-translation-unit analysis. Builds a CTU index (one
    /// serialized AST per unit plus a definition map) and runs Clang SA over
    /// it, so a function defined in another .cpp stops being opaque. This is
    /// the only way to reach the fallible-constructor defect class. Costs
    /// noticeably more time and disk.
    #[arg(long)]
    ctu: bool,

    /// Where to keep CTU artifacts. Defaults to a temporary directory that is
    /// removed afterwards; give a path to inspect the index.
    #[arg(long)]
    ctu_dir: Option<PathBuf>,

    /// Skip cppcheck.
    #[arg(long)]
    no_cppcheck: bool,

    /// Skip clang-tidy.
    #[arg(long)]
    no_clang_tidy: bool,

    /// Exit non-zero if any in-scope finding is reported. Off by default: a
    /// report is not a build gate until its findings have been triaged.
    #[arg(long)]
    fail_on_finding: bool,

    /// Comma-separated CWEs that MUST be found, else exit non-zero. Used
    /// against testdata/ to verify Kordon's own configuration still detects
    /// what it claims to. A silent regression here looks like clean code.
    #[arg(long)]
    require_cwe: Option<String>,
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let table = match &cli.cwe_map {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("could not read CWE map {}", path.display()))?;
            CweTable::from_toml(&text)
                .with_context(|| format!("could not parse CWE map {}", path.display()))?
        }
        None => CweTable::builtin()?,
    };

    let sources = collect_sources(&cli.path)?;
    if sources.is_empty() {
        bail!("no C/C++ sources found under {}", cli.path.display());
    }

    let mut runs: Vec<ToolRun> = Vec::new();
    let mut call_graph = ctu::CallGraph::default();

    if cli.no_cppcheck {
        runs.push(ToolRun::skipped(tools::cppcheck::tool(), "--no-cppcheck"));
    } else if !tools::available("cppcheck") {
        runs.push(ToolRun::skipped(
            tools::cppcheck::tool(),
            "binary not found in PATH",
        ));
    } else {
        let target = match &cli.compile_db {
            Some(db) => tools::cppcheck::Target::CompileDb(compile_db_path(db)),
            None => tools::cppcheck::Target::Sources(sources.clone()),
        };
        runs.push(tools::cppcheck::run(
            "cppcheck",
            &target,
            &cli.std,
            cli.jobs,
            cli.exhaustive,
            &table,
        ));
    }

    if cli.no_clang_tidy {
        runs.push(ToolRun::skipped(
            tools::clang_tidy::tool(),
            "--no-clang-tidy",
        ));
    } else if !tools::available("clang-tidy") {
        runs.push(ToolRun::skipped(
            tools::clang_tidy::tool(),
            "binary not found in PATH",
        ));
    } else {
        let extra = vec![format!("-std={}", cli.std)];
        runs.push(tools::clang_tidy::run(
            "clang-tidy",
            &sources,
            cli.compile_db.as_deref(),
            &extra,
            tools::clang_tidy::DEFAULT_CHECKS,
            cli.jobs,
            &table,
        ));
    }

    // CTU pass. Kept separate from the clang-tidy pass because it needs its own
    // index, its own output format, and costs far more -- so it is opt-in.
    let ctu_scratch = cli.ctu_dir.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("kordon-ctu-{}", std::process::id()))
    });

    if cli.ctu {
        let extra = vec![format!("-std={}", cli.std)];
        match ctu::build_index(
            &sources,
            cli.compile_db.as_deref(),
            &extra,
            &ctu_scratch,
            cli.jobs,
        ) {
            Ok(index) => {
                eprintln!(
                    "kordon: CTU index built — {} unit(s) indexed, {} failed, {} definitions",
                    index.indexed.len(),
                    index.failed.len(),
                    index.definition_count()
                );
                let (run, graph) = tools::clang_sa::run(
                    &sources,
                    cli.compile_db.as_deref(),
                    &extra,
                    &index,
                    &ctu_scratch.join("reports"),
                    cli.jobs,
                    &table,
                );
                runs.push(run);
                call_graph = graph;
            }
            Err(err) => {
                runs.push(ToolRun::failed(
                    tools::clang_sa::tool(),
                    format!("could not build CTU index: {err}"),
                ));
            }
        }
    } else {
        runs.push(ToolRun::skipped(
            tools::clang_sa::tool(),
            "--ctu not given; cross-TU defects are not covered",
        ));
    }

    // Only findings from engines that actually completed may enter the report.
    let raw: Vec<_> = runs
        .iter()
        .filter(|r| r.ran())
        .flat_map(|r| r.findings.iter().cloned())
        .collect();

    let merged = dedup::merge(raw);

    let report = Report {
        runs: &runs,
        merged: &merged,
        table: &table,
        analyzed_files: sources.len(),
        call_graph: &call_graph,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report.render_json())?);
    } else {
        print!("{}", report.render_text(cli.verbose, cli.all));
    }

    // Only clean up an index we created ourselves; an explicit --ctu-dir is
    // the user asking to keep it.
    if cli.ctu && cli.ctu_dir.is_none() {
        let _ = std::fs::remove_dir_all(&ctu_scratch);
    }

    if let Some(required) = &cli.require_cwe {
        return selftest(&report, required);
    }

    if cli.fail_on_finding && !report.in_scope().is_empty() {
        std::process::exit(1);
    }

    // An engine that failed outright means the run is not trustworthy, even if
    // the surviving engines found nothing.
    if runs
        .iter()
        .any(|r| matches!(r.outcome, ToolOutcome::Failed(_)))
    {
        std::process::exit(2);
    }

    Ok(())
}

/// Verify Kordon still detects the CWEs it claims to.
///
/// Run against the synthetic corpus in testdata/. If a configuration change
/// stops a class being detected, the report goes quiet -- which is
/// indistinguishable from the code being clean. This makes that failure loud.
fn selftest(report: &Report, required: &str) -> Result<()> {
    let wanted: Vec<u32> = required
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let found: Vec<u32> = report
        .in_scope()
        .iter()
        .filter_map(|m| m.primary.cwe)
        .collect();

    let missing: Vec<u32> = wanted
        .iter()
        .copied()
        .filter(|c| !found.contains(c))
        .collect();

    println!("\n═══ Selftest ═══\n");
    if missing.is_empty() {
        println!(
            "  passed — all {} required CWE class(es) detected\n",
            wanted.len()
        );
        Ok(())
    } else {
        println!(
            "  FAILED — not detected: {}",
            missing
                .iter()
                .map(|c| format!("CWE-{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  the analyzer configuration is broken, not the test corpus\n");
        std::process::exit(1);
    }
}

fn compile_db_path(given: &Path) -> PathBuf {
    if given.is_dir() {
        given.join("compile_commands.json")
    } else {
        given.to_path_buf()
    }
}

/// Recursively collect C/C++ sources under `root`.
///
/// Headers are deliberately not passed as compilation units -- they are
/// analyzed through the .cpp files that include them, via clang-tidy's
/// `-header-filter`. Handing a header to a compiler directly usually fails to
/// parse and produces a spurious engine failure.
fn collect_sources(root: &Path) -> Result<Vec<PathBuf>> {
    if root.is_file() {
        return Ok(vec![canonical(root)]);
    }
    if !root.exists() {
        bail!("{} does not exist", root.display());
    }

    let mut found = Vec::new();
    walk(root, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("could not read directory {}", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                continue;
            }
            walk(&path, found)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SOURCE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        {
            found.push(canonical(&path));
        }
    }
    Ok(())
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_cpp_extensions_and_ignores_headers() {
        assert!(SOURCE_EXTENSIONS.contains(&"cpp"));
        assert!(SOURCE_EXTENSIONS.contains(&"cc"));
        // Headers are reached through their including .cpp, not compiled alone.
        assert!(!SOURCE_EXTENSIONS.contains(&"h"));
        assert!(!SOURCE_EXTENSIONS.contains(&"hpp"));
    }

    #[test]
    fn missing_path_is_an_error_not_an_empty_clean_run() {
        assert!(collect_sources(Path::new("/nonexistent/kordon/xyz")).is_err());
    }

    #[test]
    fn compile_db_accepts_dir_or_file() {
        assert_eq!(
            compile_db_path(Path::new("/tmp/some-file.json")),
            PathBuf::from("/tmp/some-file.json")
        );
    }
}
