//! Kordon -- static+dynamic analysis orchestrator for C/C++.
//!
//! Kordon does not implement program analysis. It drives mature engines
//! (clang-tidy / Clang Static Analyzer, cppcheck, and later IKOS and the
//! sanitizers), normalizes their disagreeing output into one schema, maps
//! every finding to a CWE, merges what the engines independently agree on,
//! and reports honestly on what none of them covered.

mod compile_db;
mod ctu;
mod cwe;
mod dedup;
mod dynamic;
mod finding;
mod offsets;
mod report;
mod tools;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::compile_db::CompileDb;
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

    /// Run IKOS, the abstract-interpretation engine. It is the only engine that
    /// can *prove* an access safe rather than merely fail to flag it, and the
    /// only one whose findings can be proofs rather than pattern matches.
    /// Considerably slower, and needs scripts/setup-ikos.sh to have been run.
    #[arg(long)]
    ikos: bool,

    /// List every check an analyzer could prove neither safe nor unsafe. These
    /// are limits of the analysis rather than defect claims, so they are
    /// summarized but not detailed by default.
    #[arg(long)]
    show_unproven: bool,

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

    /// Run the dynamic layer: build instrumented variants and execute the
    /// command given by --run under each. Reports defects the program actually
    /// committed, which is a different and stronger claim than anything the
    /// static engines make -- and is bounded by whatever the command reaches.
    #[arg(long)]
    dynamic: bool,

    /// The command that exercises the code, run from each instrumented build
    /// directory. Whatever line coverage it reaches is the ceiling of this
    /// layer; there is no way around that.
    #[arg(long, value_name = "CMD", default_value = "ctest --output-on-failure")]
    run: String,

    /// Comma-separated dynamic profiles: asan, msan, valgrind.
    #[arg(long, value_name = "LIST", default_value = "asan,valgrind")]
    profiles: String,

    /// Seconds any single instrumented run may take. A sanitizer that hangs is
    /// not hypothetical -- MSan hangs symbolizing its own report on some hosts.
    #[arg(long, default_value_t = 900)]
    dynamic_timeout: u64,

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

    let compile_db = match &cli.compile_db {
        Some(path) => Some(CompileDb::load(path)?),
        None => None,
    };

    let discovered = collect_sources(&cli.path)?;
    if discovered.is_empty() {
        bail!("no C/C++ sources found under {}", cli.path.display());
    }

    // A file with no database entry is not part of the build. Compiling it with
    // no flags produces a parse failure and nothing else, so it is excluded and
    // reported rather than analyzed badly. On ACL this covers 212 of 486
    // discovered sources, 186 of them under tests/.
    let (sources, unlisted) = match &compile_db {
        Some(db) => db.partition(&discovered),
        None => (discovered.clone(), Vec::new()),
    };
    if sources.is_empty() {
        bail!(
            "none of the {} discovered source(s) appear in the compile database",
            discovered.len()
        );
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
        runs.push(tools::cppcheck::run(
            "cppcheck",
            &sources,
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
            compile_db.as_ref().map(|d| d.path()),
            &extra,
            tools::clang_tidy::DEFAULT_CHECKS,
            cli.jobs,
            &table,
        ));
    }

    // Kordon's own AST-matcher checks. These cover classes no configured engine
    // reaches at all, so skipping them silently would leave a gap that looks
    // like a clean result.
    match tools::clang_query::find_binary() {
        Some(binary) => {
            let extra = vec![format!("-std={}", cli.std)];
            let root = canonical(&cli.path);
            runs.push(tools::clang_query::run(
                &binary,
                &sources,
                compile_db.as_ref(),
                &extra,
                &root,
                cli.jobs,
                &table,
            ));
        }
        None => runs.push(ToolRun::skipped(
            tools::clang_query::tool(),
            "clang-query not found in PATH (apt install clang-tools); \
             CWE-191 is not covered by any other engine",
        )),
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
            compile_db.as_ref(),
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
                    compile_db.as_ref(),
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

    // IKOS. Opt-in: it needs its own toolchain, costs far more than the other
    // engines, and answers a different question from them.
    let ikos_scratch = std::env::temp_dir().join(format!("kordon-ikos-{}", std::process::id()));
    if cli.ikos {
        match tools::ikos::Ikos::find(Path::new(env!("CARGO_MANIFEST_DIR"))) {
            Some(engine) => runs.push(tools::ikos::run(
                &engine,
                &sources,
                compile_db.as_ref(),
                &ikos_scratch,
                cli.jobs,
                &table,
            )),
            None => runs.push(ToolRun::skipped(
                tools::ikos::tool(),
                "not installed — run scripts/setup-ikos.sh (needs ikos, clang-14, llvm-as-14)",
            )),
        }
    } else {
        runs.push(ToolRun::skipped(
            tools::ikos::tool(),
            "--ikos not given; nothing was proved safe or unsafe",
        ));
    }

    // The dynamic layer is kept out of `runs` on purpose. Its findings are
    // observations of a defect happening, and merging them into the static
    // tiers would let a pattern match inherit that standing.
    let dyn_scratch = std::env::temp_dir().join(format!("kordon-dyn-{}", std::process::id()));
    let dynamic_runs: Vec<ToolRun> = if cli.dynamic {
        let wanted: Vec<&dynamic::Profile> = cli
            .profiles
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|name| dynamic::PROFILES.iter().find(|p| p.name == name).copied())
            .collect();
        let config = dynamic::DynamicConfig {
            source: canonical(&cli.path),
            command: cli.run.clone(),
            scratch: dyn_scratch.clone(),
            timeout_secs: cli.dynamic_timeout,
            jobs: cli.jobs,
        };
        dynamic::run(&config, &canonical(&cli.path), &wanted, &table)
    } else {
        dynamic::PROFILES
            .iter()
            .map(|p| {
                ToolRun::skipped(
                    crate::finding::Tool::new(p.name),
                    "--dynamic not given; nothing was executed, so no defect was observed",
                )
            })
            .collect()
    };

    // Only findings from engines that actually completed may enter the report.
    let raw: Vec<_> = runs
        .iter()
        .filter(|r| r.ran())
        .flat_map(|r| r.findings.iter().cloned())
        .collect();

    // A defect in libstdc++ or Qt is not this project's defect and cannot be
    // acted on here. Engines report them freely -- on one Qt project 182 of 659
    // findings were in system headers, including *both* high-confidence ones,
    // so the most prominent results were the least actionable. They are dropped
    // and counted, never dropped silently.
    let analysis_root = canonical(&cli.path);
    let before = raw.len();
    let raw: Vec<_> = raw
        .into_iter()
        .filter(|f| f.file.starts_with(&analysis_root))
        .collect();
    let external = before - raw.len();

    let merged = dedup::merge(raw);

    let dynamic_findings: Vec<_> = dynamic_runs
        .iter()
        .filter(|r| r.ran())
        .flat_map(|r| r.findings.iter().cloned())
        .filter(|f| f.file.starts_with(&analysis_root))
        .collect();

    let report = Report {
        runs: &runs,
        dynamic_runs: &dynamic_runs,
        dynamic: &dynamic_findings,
        merged: &merged,
        table: &table,
        analyzed_files: sources.len(),
        unlisted_files: unlisted.len(),
        external_findings: external,
        call_graph: &call_graph,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report.render_json())?);
    } else {
        print!("{}", report.render_text(cli.verbose, cli.all, cli.show_unproven));
    }

    // Only clean up an index we created ourselves; an explicit --ctu-dir is
    // the user asking to keep it.
    if cli.ctu && cli.ctu_dir.is_none() {
        let _ = std::fs::remove_dir_all(&ctu_scratch);
    }
    if cli.ikos {
        let _ = std::fs::remove_dir_all(&ikos_scratch);
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

    // Both layers. The dynamic layer is kept out of the static findings list
    // so that a pattern match cannot borrow a runtime observation's standing,
    // but a class observed at run time is unambiguously detected -- and the
    // whole point of this flag is that a configuration regression must not be
    // able to look like clean code. Leaving the dynamic layer unguarded would
    // reintroduce exactly that.
    let found: Vec<u32> = report
        .in_scope()
        .iter()
        .filter_map(|m| m.primary.cwe)
        .chain(report.dynamic.iter().filter_map(|f| f.cwe))
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

}
