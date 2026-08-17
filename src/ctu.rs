//! Cross-Translation-Unit (CTU) index construction.
//!
//! Without CTU, Clang SA sees one translation unit at a time and treats every
//! function defined elsewhere as opaque -- it assumes a call it cannot see
//! leaves everything in a valid state. That single assumption hides an entire
//! defect class: a constructor in `vector.cpp` that forgets to assign a member
//! is invisible to `algorithm.cpp`, which merely constructs the object and
//! uses it.
//!
//! Measured on `testdata/uninit_owner/`, which is built to need exactly this:
//! without CTU the analyzer reports nothing at all; with CTU it reports the
//! whole chain -- the uninitialized field at the end of each constructor
//! (CWE-665), the garbage branch condition in `init()` (CWE-824) and the null
//! dereference in `at()` (CWE-476).
//!
//! LLVM's own documentation calls the manual setup error-prone, and it is
//! fiddly in exactly two places, both handled here:
//!
//!   1. `clang-extdef-mapping` emits `<usr> <source path>`, but the analyzer
//!      wants the paths to point at serialized ASTs, relative to the CTU
//!      directory. The map has to be rewritten after the ASTs are emitted.
//!   2. The default diagnostic formats silently drop any report whose path
//!      crosses a file boundary -- which is every CTU finding. `plist` alone
//!      is not enough; it must be `plist-multi-file`. Getting this wrong looks
//!      exactly like CTU not working.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::compile_db::CompileDb;

/// Which translation units depend on definitions in which others.
///
/// Built from the analyzer's own CTU imports rather than from a parsed AST.
/// When Clang SA needs the body of a function defined elsewhere it loads that
/// unit's serialized AST and, with `display-ctu-progress` on, says so. Those
/// lines are the edges, and they are exactly the edges that matter: a
/// dependency the analyzer actually had to follow, not every name the file
/// mentions.
///
/// The alternative -- dumping each unit's AST as JSON and walking it -- was
/// measured and rejected: a single ACL translation unit produces 176 MB of
/// JSON, roughly 85 GB across the tree, for a less relevant answer.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// analyzed unit -> units it pulled definitions from.
    pub edges: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
}

impl CallGraph {
    pub fn add(&mut self, from: PathBuf, to: PathBuf) {
        if from != to {
            self.edges.entry(from).or_default().insert(to);
        }
    }

    pub fn merge(&mut self, other: CallGraph) {
        for (from, targets) in other.edges {
            self.edges.entry(from).or_default().extend(targets);
        }
    }

    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|t| t.len()).sum()
    }

    /// Units nothing else depends on -- roots of the dependency graph.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Units most depended upon, most-depended-on first. A defect in one of
    /// these reaches everything above it.
    pub fn most_depended_upon(&self, limit: usize) -> Vec<(PathBuf, usize)> {
        let mut counts: BTreeMap<&PathBuf, usize> = BTreeMap::new();
        for targets in self.edges.values() {
            for target in targets {
                *counts.entry(target).or_default() += 1;
            }
        }
        let mut ranked: Vec<(PathBuf, usize)> =
            counts.into_iter().map(|(p, n)| (p.clone(), n)).collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ranked.truncate(limit);
        ranked
    }
}

/// Turn one `-analyzer-config display-ctu-progress=true` stderr stream into
/// edges from `analyzed`.
///
/// Lines look like `CTU loaded AST file: ast/abs/path/to/unit.cpp.ast`; the
/// `ast/` prefix and `.ast` suffix are stripped back to the source path.
pub fn parse_ctu_progress(analyzed: &Path, stderr: &str) -> CallGraph {
    let mut graph = CallGraph::default();
    for line in stderr.lines() {
        let Some(rest) = line.trim().strip_prefix("CTU loaded AST file:") else {
            continue;
        };
        let raw = rest.trim();
        let without_prefix = raw.strip_prefix("ast/").unwrap_or(raw);
        let source = without_prefix
            .strip_suffix(".ast")
            .unwrap_or(without_prefix);
        let mut path = PathBuf::from("/");
        path.push(source);
        graph.add(analyzed.to_path_buf(), path);
    }
    graph
}

/// Result of building a CTU index over a set of translation units.
pub struct CtuIndex {
    /// Directory holding `externalDefMap.txt` and the `ast/` tree.
    pub dir: PathBuf,
    /// Translation units whose AST was serialized successfully.
    pub indexed: Vec<PathBuf>,
    /// Translation units that could not be turned into an AST -- almost always
    /// because they do not compile. They take no part in CTU, so anything
    /// defined in them stays opaque, and the report must say so.
    pub failed: Vec<PathBuf>,
    /// USR -> defining translation unit. This is the "which file defines what"
    /// index; the call graph is derived from it.
    pub definitions: BTreeMap<String, PathBuf>,
}

impl CtuIndex {
    pub fn definition_count(&self) -> usize {
        self.definitions.len()
    }
}

/// Locate the extdef mapping tool. Distributions ship it versioned much more
/// often than not, so an unversioned lookup alone would fail on stock Ubuntu.
pub fn find_extdef_tool() -> Option<String> {
    for candidate in [
        "clang-extdef-mapping",
        "clang-extdef-mapping-18",
        "clang-extdef-mapping-17",
        "clang-extdef-mapping-16",
    ] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Build a CTU index for `sources` into `dir`.
///
/// `compile_db` is strongly recommended: a translation unit that does not
/// compile cannot be serialized, and drops out of the index entirely.
pub fn build_index(
    sources: &[PathBuf],
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    dir: &Path,
    jobs: usize,
) -> Result<CtuIndex> {
    let extdef = find_extdef_tool()
        .context("clang-extdef-mapping not found; CTU needs it (apt install clang-tools)")?;

    let ast_root = dir.join("ast");
    std::fs::create_dir_all(&ast_root)
        .with_context(|| format!("could not create {}", ast_root.display()))?;

    let shards = jobs.clamp(1, sources.len().max(1));
    let chunk = sources.len().div_ceil(shards);

    let per_shard: Vec<ShardOutcome> = std::thread::scope(|scope| {
        let handles: Vec<_> = sources
            .chunks(chunk)
            .map(|files| {
                let extdef = extdef.clone();
                scope.spawn(move || index_shard(&extdef, files, compile_db, extra_args, dir))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut indexed = Vec::new();
    let mut failed = Vec::new();
    let mut map_lines = Vec::new();
    let mut definitions = BTreeMap::new();

    for shard in per_shard {
        indexed.extend(shard.indexed);
        failed.extend(shard.failed);
        for (usr, source) in shard.entries {
            // The analyzer resolves paths in the map relative to the CTU dir.
            let rel = ast_relative_path(&source);
            map_lines.push(format!("{usr} {}", rel.display()));
            definitions.insert(usr, source);
        }
    }

    if indexed.is_empty() {
        bail!(
            "no translation unit could be serialized for CTU ({} failed) — \
             check that the compile database is correct",
            failed.len()
        );
    }

    map_lines.sort();
    map_lines.dedup();
    let map_path = dir.join("externalDefMap.txt");
    std::fs::write(&map_path, map_lines.join("\n") + "\n")
        .with_context(|| format!("could not write {}", map_path.display()))?;

    indexed.sort();
    failed.sort();

    Ok(CtuIndex {
        dir: dir.to_path_buf(),
        indexed,
        failed,
        definitions,
    })
}

struct ShardOutcome {
    indexed: Vec<PathBuf>,
    failed: Vec<PathBuf>,
    /// (USR, defining source file)
    entries: Vec<(String, PathBuf)>,
}

fn index_shard(
    extdef: &str,
    files: &[PathBuf],
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    dir: &Path,
) -> ShardOutcome {
    let mut outcome = ShardOutcome {
        indexed: Vec::new(),
        failed: Vec::new(),
        entries: Vec::new(),
    };

    for source in files {
        if emit_ast(source, compile_db, extra_args, dir).is_err() {
            outcome.failed.push(source.clone());
            continue;
        }

        match extdef_entries(extdef, source, compile_db, extra_args) {
            Ok(entries) => {
                outcome.indexed.push(source.clone());
                outcome.entries.extend(entries);
            }
            Err(_) => outcome.failed.push(source.clone()),
        }
    }

    outcome
}

/// Serialize one translation unit's AST to `<dir>/ast/<abs source path>.ast`.
fn emit_ast(
    source: &Path,
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
    dir: &Path,
) -> Result<()> {
    let out = dir.join(ast_relative_path(source));
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut cmd = Command::new("clang++");
    cmd.arg("-emit-ast").arg("-o").arg(&out);

    // With a compile database, reuse that unit's real flags: include paths and
    // defines decide whether the unit parses at all.
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

    let status = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;

    if !status.success() || !out.exists() {
        bail!("could not serialize AST for {}", source.display());
    }
    Ok(())
}

fn extdef_entries(
    extdef: &str,
    source: &Path,
    compile_db: Option<&CompileDb>,
    extra_args: &[String],
) -> Result<Vec<(String, PathBuf)>> {
    let mut cmd = Command::new(extdef);
    if let Some(db) = compile_db {
        cmd.arg("-p").arg(db.path());
    }
    cmd.arg(source);
    if compile_db.is_none() {
        cmd.arg("--");
        for arg in extra_args {
            cmd.arg(arg);
        }
    }

    let output = cmd.output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_extdef_output(&text))
}

/// Parse `clang-extdef-mapping` output.
///
/// Each line is `<len>:<usr> <absolute source path>`, where the leading number
/// is the USR's length. The USR itself can contain spaces in rare cases, so
/// split from the right on the last space rather than the first.
pub fn parse_extdef_output(text: &str) -> Vec<(String, PathBuf)> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let (usr, path) = line.rsplit_once(' ')?;
            if usr.is_empty() || path.is_empty() {
                return None;
            }
            Some((usr.to_string(), PathBuf::from(path)))
        })
        .collect()
}

/// Path of a source file's serialized AST, relative to the CTU directory.
///
/// Mirrors the absolute source path underneath `ast/` so two files with the
/// same basename in different directories cannot collide.
fn ast_relative_path(source: &Path) -> PathBuf {
    let mut rel = PathBuf::from("ast");
    // Strip the leading separator so join() does not discard the prefix.
    let stripped = source.strip_prefix("/").unwrap_or(source);
    rel.push(stripped);
    rel.set_extension(match source.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.ast"),
        None => "ast".to_string(),
    });
    rel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extdef_lines() {
        let text = "41:c:@N@kordon_probe@S@Vector@F@Vector#I# /src/vector.cpp\n\
                    35:c:@N@kordon_probe@S@Vector@F@clear# /src/vector.cpp\n";
        let entries = parse_extdef_output(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, PathBuf::from("/src/vector.cpp"));
        assert!(entries[0].0.contains("Vector"));
    }

    #[test]
    fn ignores_blank_lines() {
        assert!(parse_extdef_output("\n  \n").is_empty());
    }

    #[test]
    fn ast_path_mirrors_source_tree() {
        // Two files sharing a basename must not collide in the AST tree.
        let a = ast_relative_path(Path::new("/src/math/vector.cpp"));
        let b = ast_relative_path(Path::new("/src/util/vector.cpp"));
        assert_ne!(a, b);
        assert_eq!(a, PathBuf::from("ast/src/math/vector.cpp.ast"));
    }

    #[test]
    fn parses_ctu_import_lines_into_edges() {
        let stderr = "CTU loaded AST file: ast/src/vector.cpp.ast\n\
                      some other diagnostic line\n\
                      CTU loaded AST file: ast/src/matrix.cpp.ast\n";
        let g = parse_ctu_progress(Path::new("/src/algorithm.cpp"), stderr);
        assert_eq!(g.edge_count(), 2);
        let targets = &g.edges[Path::new("/src/algorithm.cpp")];
        assert!(targets.contains(Path::new("/src/vector.cpp")));
        assert!(targets.contains(Path::new("/src/matrix.cpp")));
    }

    #[test]
    fn self_edges_are_dropped() {
        // A unit importing from itself is not a dependency worth reporting.
        let g = parse_ctu_progress(
            Path::new("/src/a.cpp"),
            "CTU loaded AST file: ast/src/a.cpp.ast\n",
        );
        assert!(g.is_empty());
    }

    #[test]
    fn ranks_units_by_how_many_depend_on_them() {
        let mut g = CallGraph::default();
        g.add("/a.cpp".into(), "/core.cpp".into());
        g.add("/b.cpp".into(), "/core.cpp".into());
        g.add("/b.cpp".into(), "/util.cpp".into());
        let ranked = g.most_depended_upon(5);
        assert_eq!(ranked[0], (PathBuf::from("/core.cpp"), 2));
        assert_eq!(ranked[1], (PathBuf::from("/util.cpp"), 1));
    }

    #[test]
    fn ast_path_keeps_original_extension() {
        // vector.cpp.ast, not vector.ast -- otherwise vector.c and vector.cpp
        // in one directory would overwrite each other.
        assert_eq!(
            ast_relative_path(Path::new("/s/a.c")),
            PathBuf::from("ast/s/a.c.ast")
        );
    }
}
