//! IKOS runner: abstract interpretation over LLVM bitcode.
//!
//! IKOS is the only engine Kordon drives that answers a different question from
//! the rest. cppcheck, clang-tidy and Clang SA all report *matches* -- a
//! pattern, or a path they managed to explore -- so their silence is ambiguous
//! between "safe" and "never looked". IKOS computes a sound over-approximation
//! of every value at every program point, so it distinguishes three outcomes:
//! proved safe, proved unsafe, and could not decide. Only the first two are
//! claims about the code; the third is a claim about the analysis.
//!
//! Everything here was established by running the tool, not from its docs:
//!
//!   * Bitcode must come from **clang-14**. IKOS 3.5 links LLVM 14 and rejects
//!     an LLVM 18 module outright.
//!   * It must be **-O0**, or clang folds arithmetic into address computations
//!     and the debug location no longer names the line the code was written on.
//!   * **`fneg` must be lowered.** IKOS 3.5's importer does not implement it,
//!     and clang emits it for every floating-point negation -- fatal for exactly
//!     the numerical code an interval analyser is worth running on. It is
//!     rewritten here to `fsub -0.0, x`, the pre-LLVM-8 spelling.
//!   * Library code has no `main`, so entry points must be named. They are read
//!     back out of IKOS's own AR rather than from `llvm-nm`, whose C++
//!     constructor aliases IKOS rejects, and only **call-graph roots** are used:
//!     an entry point's parameters are unconstrained, so naming every function
//!     fills the report with artifacts of that choice. Measured on one unit,
//!     roots-only cut warnings from 103 to 67 while keeping every real one.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::compile_db::CompileDb;
use crate::cwe::CweTable;
use crate::finding::{Confidence, Finding, Proof, Severity, Tool};
use crate::tools::{ToolOutcome, ToolRun};

pub fn tool() -> Tool {
    Tool::new("ikos")
}

/// Analyses to enable. `sound` and `dca` describe the analysis rather than the
/// code, and `pcmp`/`upa` cover classes outside Kordon's scope.
const ANALYSES: &str = "boa,uio,sio,dbz,nullity,uva,dfa";

pub struct Ikos {
    /// `<prefix>/bin`, holding ikos, ikos-pp and ikos-import.
    bin: PathBuf,
    clang14: String,
    llvm_as: String,
}

impl Ikos {
    /// Locate a usable IKOS installation, preferring the one the setup script
    /// builds into the repository.
    pub fn find(repo_root: &Path) -> Option<Self> {
        let local = repo_root.join("third_party/ikos/bin");
        let bin = if local.join("ikos").is_file() {
            local
        } else if let Ok(path) = which("ikos") {
            path.parent()?.to_path_buf()
        } else {
            return None;
        };

        // Both are hard requirements, and failing later with a confusing
        // bitcode error is worse than not offering the engine at all.
        let clang14 = first_available(&["clang-14", "clang"])?;
        let llvm_as = first_available(&["llvm-as-14", "llvm-as"])?;

        Some(Ikos { bin, clang14, llvm_as })
    }

    fn exe(&self, name: &str) -> PathBuf {
        self.bin.join(name)
    }

    /// Analyze one translation unit.
    fn analyze_one(
        &self,
        source: &Path,
        db: Option<&CompileDb>,
        work: &Path,
        table: &CweTable,
    ) -> Result<Vec<Finding>, String> {
        let stem: String = source
            .file_name()
            .map(|n| n.to_string_lossy().replace('/', "_"))
            .unwrap_or_else(|| "unit".into());
        let ll = work.join(format!("{stem}.ll"));
        let bc = work.join(format!("{stem}.bc"));
        let sarif = work.join(format!("{stem}.sarif"));

        // 1. Emit textual IR so fneg can be rewritten before assembling.
        let mut cc = Command::new(&self.clang14);
        cc.arg("-emit-llvm").arg("-S").arg("-g").arg("-O0");
        if let Some(db) = db {
            if let Some(args) = db.args_for(source) {
                // -O would defeat the -O0 above; the db often carries one.
                for a in args.iter().filter(|a| !a.starts_with("-O")) {
                    cc.arg(a);
                }
            }
        }
        cc.arg(source).arg("-o").arg(&ll);
        let out = cc.output().map_err(|e| format!("{}: {e}", self.clang14))?;
        if !out.status.success() {
            return Err(format!("{} did not compile", source.display()));
        }

        // 2. Lower fneg, then assemble.
        let text = std::fs::read_to_string(&ll).map_err(|e| e.to_string())?;
        std::fs::write(&ll, lower_fneg(&text)).map_err(|e| e.to_string())?;
        let out = Command::new(&self.llvm_as)
            .arg(&ll)
            .arg("-o")
            .arg(&bc)
            .output()
            .map_err(|e| format!("{}: {e}", self.llvm_as))?;
        if !out.status.success() {
            return Err(format!("could not assemble bitcode for {}", source.display()));
        }

        // 3. Entry points, or IKOS stops at "could not find function 'main'".
        let entries = self.entry_points(&bc, work)?;
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        // 4. Analyze. SARIF rather than JSON: IKOS's JSON is index-normalized,
        //    with locations behind statement ids and integer status codes,
        //    while its SARIF carries resolved paths, lines and rule names.
        let mut cmd = Command::new(self.exe("ikos"));
        cmd.arg("--color=no").arg("-a").arg(ANALYSES);
        for e in &entries {
            cmd.arg("-e").arg(e);
        }
        cmd.arg("-f")
            .arg("sarif")
            .arg(format!("--report-file={}", sarif.display()))
            .arg(&bc)
            .arg("-o")
            .arg(work.join(format!("{stem}.db")));
        let out = cmd.output().map_err(|e| format!("ikos: {e}"))?;
        if !sarif.is_file() {
            let why = String::from_utf8_lossy(&out.stderr);
            let detail = why.lines().find(|l| l.contains("error")).unwrap_or("no report");
            return Err(format!("{}: {}", source.display(), detail.trim()));
        }

        let text = std::fs::read_to_string(&sarif).map_err(|e| e.to_string())?;
        parse_sarif(&text, source, table).map_err(|e| format!("{}: {e}", source.display()))
    }

    /// Call-graph roots, read out of IKOS's own AR.
    fn entry_points(&self, bc: &Path, work: &Path) -> Result<Vec<String>, String> {
        let pp = work.join("pp.bc");
        let ar = work.join("unit.ar");

        // ikos-import rejects constructs the preprocessor lowers -- on raw
        // bitcode it fails with "llvm select instructions are not supported"
        // even where a full ikos run on the same file succeeds.
        let ok = Command::new(self.exe("ikos-pp"))
            .arg(bc)
            .arg("-o")
            .arg(&pp)
            .output()
            .map_err(|e| format!("ikos-pp: {e}"))?;
        if !ok.status.success() {
            return Err("ikos-pp failed".into());
        }
        let ok = Command::new(self.exe("ikos-import"))
            .arg("--format=text")
            .arg(&pp)
            .arg("-o")
            .arg(&ar)
            .output()
            .map_err(|e| format!("ikos-import: {e}"))?;
        if !ok.status.success() {
            let why = String::from_utf8_lossy(&ok.stderr);
            return Err(why.lines().next().unwrap_or("ikos-import failed").trim().to_string());
        }

        let text = std::fs::read_to_string(&ar).map_err(|e| e.to_string())?;
        Ok(call_graph_roots(&text))
    }
}

/// Rewrite `fneg x` to `fsub -0.0, x`.
///
/// The two differ only in cases irrelevant to interval analysis: the NaN
/// payload produced, and `fneg(-0.0)` versus `fsub(-0.0, -0.0)`.
pub fn lower_fneg(ir: &str) -> String {
    let mut out = String::with_capacity(ir.len() + 64);
    for line in ir.split_inclusive('\n') {
        match line.split_once("= fneg ") {
            Some((lhs, rest)) => {
                // rest is "[fast-math flags ]<type> <operand>"; the type is the
                // last token before the operand.
                let mut parts = rest.rsplitn(2, ' ');
                match (parts.next(), parts.next()) {
                    (Some(operand), Some(flags_and_type)) => {
                        out.push_str(lhs);
                        out.push_str("= fsub ");
                        out.push_str(flags_and_type);
                        out.push_str(" -0.000000e+00, ");
                        out.push_str(operand);
                    }
                    _ => out.push_str(line),
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// Functions defined in the AR that nothing else in it calls.
///
/// A unit whose functions all call each other has no root; analysing every
/// function is then the only option, at the cost of parameter artifacts.
pub fn call_graph_roots(ar: &str) -> Vec<String> {
    let mut defined = BTreeSet::new();
    let mut called = BTreeSet::new();

    for line in ar.lines() {
        // `define <type> @name(` is a function; `define @name, align ...` with
        // no parameter list is a global variable.
        if let Some(rest) = line.strip_prefix("define ") {
            if let Some((_, after_at)) = rest.split_once('@') {
                if let Some((name, _)) = after_at.split_once('(') {
                    if !name.is_empty() {
                        defined.insert(name.to_string());
                    }
                }
            }
        }
        let mut hay = line;
        while let Some(idx) = hay.find("call @") {
            hay = &hay[idx + 6..];
            if let Some((name, _)) = hay.split_once('(') {
                called.insert(name.to_string());
            }
        }
    }

    let roots: Vec<String> = defined.difference(&called).cloned().collect();
    if roots.is_empty() {
        defined.into_iter().collect()
    } else {
        roots
    }
}

/// Parse IKOS's SARIF report.
pub fn parse_sarif(text: &str, source: &Path, table: &CweTable) -> Result<Vec<Finding>, String> {
    let doc: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut findings = Vec::new();

    let runs = doc.get("runs").and_then(|r| r.as_array()).ok_or("no runs")?;
    for run in runs {
        let Some(results) = run.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for result in results {
            let rule = result.get("ruleId").and_then(|r| r.as_str()).unwrap_or("unknown");
            let level = result.get("level").and_then(|l| l.as_str()).unwrap_or("warning");
            let message = result
                .get("message")
                .and_then(|m| m.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .trim_matches('"')
                .to_string();
            // IKOS escapes its messages for SARIF, so a range like
            // "(left <= 2147483647)" arrives as "&lt;=" and would be shown that
            // way in a terminal report.
            let message = unescape_entities(&message);

            let (file, line, column) = location_of(result).unwrap_or_else(|| {
                (source.to_path_buf(), 0, 0)
            });

            // `error` means IKOS proved the defect reachable -- stronger than
            // any pattern match, so it earns High. `warning` means it could
            // decide neither way, which is not a defect claim at all.
            let (proof, severity, confidence) = match level {
                "error" => (Proof::Refuted, Severity::Error, Confidence::High),
                _ => (Proof::Unproven, Severity::Warning, Confidence::Low),
            };

            let native_id = format!("ikos-{rule}");
            let class = table.classify(&tool(), &native_id, &message, None, confidence);

            findings.push(Finding {
                tool: tool(),
                native_id,
                cwe: class.cwe,
                cwe_source: class.source,
                file,
                line,
                column,
                severity,
                confidence,
                message,
                events: Vec::new(),
                proof: Some(proof),
            });
        }
    }
    Ok(findings)
}

/// Undo the XML entity escaping IKOS applies to SARIF message text.
fn unescape_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        // Last: an escaped ampersand must not re-introduce the others.
        .replace("&amp;", "&")
}

fn location_of(result: &serde_json::Value) -> Option<(PathBuf, u32, u32)> {
    let phys = result
        .get("locations")?
        .as_array()?
        .first()?
        .get("physicalLocation")?;
    let uri = phys.get("artifactLocation")?.get("uri")?.as_str()?;
    let region = phys.get("region")?;
    let line = region.get("startLine").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let column = region.get("startColumn").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    // SARIF paths are relative to IKOS's working directory; canonicalize so
    // dedup can match them against other engines' absolute paths.
    let path = PathBuf::from(uri);
    Some((std::fs::canonicalize(&path).unwrap_or(path), line, column))
}

/// Run IKOS over every source, sharded.
pub fn run(
    ikos: &Ikos,
    sources: &[PathBuf],
    db: Option<&CompileDb>,
    work_root: &Path,
    jobs: usize,
    table: &CweTable,
) -> ToolRun {
    if std::fs::create_dir_all(work_root).is_err() {
        return ToolRun::failed(tool(), format!("could not create {}", work_root.display()));
    }

    let shards = jobs.clamp(1, sources.len().max(1));
    let chunk = sources.len().div_ceil(shards);

    let per_shard: Vec<(Vec<Finding>, Vec<String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .enumerate()
            .map(|(i, files)| {
                let work = work_root.join(format!("shard-{i}"));
                scope.spawn(move || {
                    let _ = std::fs::create_dir_all(&work);
                    let mut found = Vec::new();
                    let mut failed = Vec::new();
                    for source in files {
                        match ikos.analyze_one(source, db, &work, table) {
                            Ok(mut f) => found.append(&mut f),
                            Err(why) => failed.push(why),
                        }
                    }
                    (found, failed)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut findings = Vec::new();
    let mut failures = Vec::new();
    for (mut f, mut fail) in per_shard {
        findings.append(&mut f);
        failures.append(&mut fail);
    }

    let mut notes = Vec::new();
    if !failures.is_empty() {
        // Naming the first reason matters: the usual cause is an LLVM
        // instruction the importer does not implement, which is a property of
        // IKOS rather than of the code, and looks nothing like a compile error.
        notes.push(format!(
            "{} of {} translation unit(s) could not be analyzed by IKOS — e.g. {}",
            failures.len(),
            sources.len(),
            failures[0]
        ));
    }

    ToolRun {
        tool: tool(),
        outcome: ToolOutcome::Ran,
        findings,
        notes,
    }
}

fn which(name: &str) -> Result<PathBuf, ()> {
    let out = Command::new("which").arg(name).output().map_err(|_| ())?;
    if !out.status.success() {
        return Err(());
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

fn first_available(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|n| which(n).is_ok())
        .map(|n| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowers_fneg_preserving_flags() {
        let ir = "  %3 = fneg double %2\n  %5 = fneg fast float %4\n  %6 = add i32 %1, 1\n";
        let out = lower_fneg(ir);
        assert!(out.contains("%3 = fsub double -0.000000e+00, %2"));
        // Fast-math flags sit between the opcode and the type and must survive.
        assert!(out.contains("%5 = fsub fast float -0.000000e+00, %4"));
        // Unrelated instructions are untouched.
        assert!(out.contains("%6 = add i32 %1, 1"));
    }

    #[test]
    fn roots_exclude_called_functions() {
        let ar = "\
define double @helper(double %0) {\n\
  return %0\n\
}\n\
define double @entry(double %0) {\n\
  double %1 = call @helper(%0)\n\
  return %1\n\
}\n";
        assert_eq!(call_graph_roots(ar), vec!["entry".to_string()]);
    }

    #[test]
    fn globals_are_not_mistaken_for_functions() {
        // `define @name, align ...` with no parameter list is a global.
        let ar = "define [6 x double]* @table.zv, align 16, init {\n}\n\
define void @f() {\n}\n";
        assert_eq!(call_graph_roots(ar), vec!["f".to_string()]);
    }

    #[test]
    fn mutual_recursion_falls_back_to_every_function() {
        // No root exists; analysing nothing would be worse than artifacts.
        let ar = "\
define void @a() {\n  call @b()\n}\n\
define void @b() {\n  call @a()\n}\n";
        let mut roots = call_graph_roots(ar);
        roots.sort();
        assert_eq!(roots, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn message_entities_are_unescaped() {
        assert_eq!(unescape_entities("left &lt;= 2147483647"), "left <= 2147483647");
        // &amp; is undone last, so an escaped ampersand cannot revive a tag.
        assert_eq!(unescape_entities("&amp;lt;"), "&lt;");
    }

    #[test]
    fn sarif_error_is_a_proof_and_warning_is_not() {
        let table = CweTable::builtin().unwrap();
        let sarif = r#"{"runs":[{"results":[
          {"ruleId":"buffer-overflow","level":"error",
           "message":{"text":"\"buffer overflow\""},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
             "region":{"startLine":11,"startColumn":12}}}]},
          {"ruleId":"unsigned-int-underflow","level":"warning",
           "message":{"text":"\"possible unsigned integer underflow\""},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
             "region":{"startLine":4,"startColumn":9}}}]}]}]}"#;
        let f = parse_sarif(sarif, Path::new("a.c"), &table).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].proof, Some(Proof::Refuted));
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!((f[0].line, f[0].column), (11, 12));
        assert_eq!(f[1].proof, Some(Proof::Unproven));
        // An undecided check is not a defect claim, so it never outranks one.
        assert_eq!(f[1].confidence, Confidence::Low);
    }
}
