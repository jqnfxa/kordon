//! The compilation database.
//!
//! Two jobs, both of which caused real problems before this module existed.
//!
//! **Knowing which files are actually part of the build.** Walking a source
//! tree finds far more than the build compiles: on ACL, 212 of 486 discovered
//! sources had no entry in `compile_commands.json` -- 186 of them under
//! `tests/`. Handing those to a compiler with no flags means they fail to
//! parse, which inflated the "failed to compile" count to 159 and made a
//! configuration artifact look like a broken build. A file absent from the
//! database is not part of the build, and saying so is more useful than
//! pretending to analyze it.
//!
//! **Answering flag lookups cheaply.** The flags for one file used to be found
//! by re-reading and re-parsing the whole JSON per file -- quadratic, and the
//! database is a megabyte. It is parsed once here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Flags a GCC-built project puts in its compile database that clang refuses.
///
/// Kordon's static engines are clang frontends, but plenty of projects build
/// with GCC -- every out-of-tree kernel module, for a start. Their databases
/// carry flags clang has no equivalent for, and clang does not skip them: it
/// errors out, so *every* translation unit fails and the run looks like a
/// broken project rather than an incompatible one.
///
/// Measured on a 217-line kernel module: seven flags, and removing them takes
/// clang from "unknown argument" on every unit to a clean parse.
///
/// Prefix-matched, because several take values (`-mindirect-branch=thunk-extern`).
/// Deliberately a deny-list rather than an allow-list: dropping a flag that
/// clang would have accepted changes what gets analysed, so the conservative
/// error is to keep too much and let clang complain about one unit.
const CLANG_REJECTS: &[&str] = &[
    "-mpreferred-stack-boundary",
    "-mindirect-branch",
    "-mfunction-return",
    "-mrecord-mcount",
    "-mno-fp-ret-in-387",
    "-mskip-rax-setup",
    "-fno-allow-store-data-races",
    "-fconserve-stack",
    "-fsanitize=bounds-strict",
    "-fno-var-tracking-assignments",
    "-flive-patching",
    "-fmin-function-alignment",
    "-femit-struct-debug-baseonly",
    "-fno-inline-functions-called-once",
    "-Wno-alloc-size-larger-than",
    "-Wno-dangling-pointer",
    "-Wno-maybe-uninitialized",
    "-Wno-packed-not-aligned",
    "-Wno-format-truncation",
    "-Wno-format-overflow",
    "-Wno-restrict",
    "-Wno-stringop-truncation",
    "-Wno-stringop-overflow",
    "-Wno-unterminated-string-initialization",
    "-Werror=designated-init",
];

fn clang_rejects(arg: &str) -> bool {
    CLANG_REJECTS.iter().any(|bad| arg.starts_with(bad))
}

pub struct CompileDb {
    /// The path handed to tools that read the database themselves
    /// (clang-tidy `-p`, cppcheck `--project`).
    path: PathBuf,
    /// Source file -> compilation flags, with the pieces that make no sense
    /// when re-driving the compiler already stripped.
    args: HashMap<PathBuf, Vec<String>>,
    /// Distinct GCC-only flags removed so clang could read the database.
    /// Reported, never silent: the analysis ran on slightly different flags
    /// than the build used, and the reader is entitled to know which.
    dropped: Vec<String>,
    /// Set only when `path` is a rewritten copy Kordon wrote itself, so the
    /// caller knows which directory is safe to remove.
    owned: Option<PathBuf>,
}

impl CompileDb {
    /// Load from a build directory or a direct path to the JSON.
    pub fn load(given: &Path) -> Result<Self> {
        let path = if given.is_dir() {
            given.join("compile_commands.json")
        } else {
            given.to_path_buf()
        };

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let entries: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("could not parse {}", path.display()))?;

        let mut args = HashMap::new();
        let mut dropped: Vec<String> = Vec::new();
        if let Some(list) = entries.as_array() {
            for entry in list {
                if let Some((file, flags)) = parse_entry(entry) {
                    for f in flags.iter().filter(|f| clang_rejects(f)) {
                        if !dropped.contains(f) {
                            dropped.push(f.clone());
                        }
                    }
                    let kept = flags.into_iter().filter(|f| !clang_rejects(f)).collect();
                    // Later entries win, matching how a build system would
                    // last-write a duplicated unit.
                    args.insert(file, kept);
                }
            }
        }

        // Tools that read the database themselves get a rewritten copy, since
        // they never see `args`. Only written when something was actually
        // removed -- an already-clang database is passed through untouched.
        let path = if dropped.is_empty() {
            given.to_path_buf()
        } else {
            write_normalized(&entries)?
        };
        // Remembered so the caller can remove it. Only the rewritten copy is
        // ours; the path the user passed must never be deleted.
        let owned = if dropped.is_empty() {
            None
        } else {
            Some(path.clone())
        };

        Ok(CompileDb { path, args, dropped, owned })
    }

    /// GCC-only flags removed so clang could read this database.
    pub fn dropped_flags(&self) -> &[String] {
        &self.dropped
    }

    /// The rewritten database Kordon created, if it created one.
    ///
    /// A GCC project gets a normalized copy under the temp directory. The path
    /// the user passed is never returned here.
    pub fn owned_dir(&self) -> Option<&Path> {
        self.owned.as_deref()
    }

    /// Path to pass to tools that read the database themselves.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn contains(&self, file: &Path) -> bool {
        self.args.contains_key(file)
    }

    pub fn args_for(&self, file: &Path) -> Option<&[String]> {
        self.args.get(file).map(|v| v.as_slice())
    }

    /// Split discovered sources into those the build actually compiles and
    /// those it does not.
    ///
    /// The second list is not a silent drop: the caller reports it, because
    /// "not part of the build" and "analyzed and clean" must not look alike.
    pub fn partition(&self, sources: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
        sources
            .iter()
            .cloned()
            .partition(|source| self.contains(source))
    }
}

/// Remove the rewritten copy when the database goes out of scope.
///
/// On `Drop` rather than at the end of `main`: a GCC project leaves one
/// directory per run under the temp dir, and cleaning up at the end only
/// covers the path where everything succeeded. The first thing that goes
/// wrong after loading the database -- "none of the discovered sources appear
/// in the compile database" is an easy one to hit -- exits before reaching it.
///
/// Only ever the copy Kordon wrote. `owned` is None when the database was
/// usable as given, so the user's own directory cannot be reached from here.
impl Drop for CompileDb {
    fn drop(&mut self) {
        if let Some(dir) = &self.owned {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Extract `(file, flags)` from one database entry.
///
/// Drops the compiler binary, `-c`, `-o <output>`, the object file and the
/// input itself -- everything that stops the command being reusable to drive
/// a different frontend over the same unit.
fn parse_entry(entry: &serde_json::Value) -> Option<(PathBuf, Vec<String>)> {
    let file = entry.get("file")?.as_str()?;

    let raw: Vec<String> = match entry.get("command").and_then(|c| c.as_str()) {
        Some(command) => command.split_whitespace().map(String::from).collect(),
        None => entry
            .get("arguments")?
            .as_array()?
            .iter()
            .filter_map(|a| a.as_str().map(String::from))
            .collect(),
    };

    let mut flags = Vec::new();
    let mut skip_next = false;
    for (i, arg) in raw.iter().enumerate() {
        if i == 0 || skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-c" {
            continue;
        }
        if arg == "-o" {
            skip_next = true;
            continue;
        }
        if arg == file || arg.ends_with(".o") {
            continue;
        }
        flags.push(arg.clone());
    }

    Some((PathBuf::from(file), flags))
}

/// Write a copy of the database with the clang-incompatible flags removed.
///
/// Emitted in `arguments` form rather than `command`, so no quoting question
/// arises for a path containing a space.
fn write_normalized(entries: &serde_json::Value) -> Result<PathBuf> {
    let mut out = Vec::new();
    for entry in entries.as_array().into_iter().flatten() {
        let Some(obj) = entry.as_object() else { continue };
        let argv: Vec<String> = match obj.get("command").and_then(|c| c.as_str()) {
            Some(cmd) => cmd.split_whitespace().map(String::from).collect(),
            None => obj
                .get("arguments")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
        };
        let kept: Vec<String> = argv.into_iter().filter(|a| !clang_rejects(a)).collect();
        let mut new_entry = serde_json::Map::new();
        for key in ["directory", "file", "output"] {
            if let Some(v) = obj.get(key) {
                new_entry.insert(key.to_string(), v.clone());
            }
        }
        new_entry.insert("arguments".into(), serde_json::json!(kept));
        out.push(serde_json::Value::Object(new_entry));
    }

    // Unique per database, not just per process. Two databases loaded in one
    // process shared a directory, so dropping either deleted the other's file
    // -- harmless in production, where there is one, and an intermittent test
    // failure as soon as there are two.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("kordon-db-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("compile_commands.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out)?)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Removes the fixture directory when the test ends, however it ends.
    ///
    /// Without this each `cargo test` left one directory per test behind in
    /// the temp dir forever -- 49 of them had accumulated here. Tiny
    /// individually, and nothing ever collects them.
    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Unique per test: the suite runs in parallel inside one process, so a
    /// shared pid-derived path has tests truncating each other's fixture.
    ///
    /// The returned guard must be held for as long as the database is used --
    /// `let (db, _fixture) = db_from(...)` -- since dropping it deletes the
    /// file the database was loaded from.
    fn db_from(json: &str, tag: &str) -> (CompileDb, Fixture) {
        let dir = std::env::temp_dir()
            .join(format!("kordon-db-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("compile_commands.json"), json).unwrap();
        (CompileDb::load(&dir).unwrap(), Fixture(dir))
    }

    const SAMPLE: &str = r#"[
      {"directory":"/b","file":"/src/a.cpp",
       "command":"/usr/bin/clang++ -DFOO -I/inc -std=c++17 -c /src/a.cpp -o /b/a.o"},
      {"directory":"/b","file":"/src/b.cpp",
       "arguments":["/usr/bin/clang++","-I/other","-c","/src/b.cpp","-o","/b/b.o"]}
    ]"#;

    #[test]
    fn strips_compile_and_output_flags() {
        let (db, _fixture) = db_from(SAMPLE, "strip");
        let args = db.args_for(Path::new("/src/a.cpp")).unwrap();
        assert!(args.contains(&"-DFOO".to_string()));
        assert!(args.contains(&"-I/inc".to_string()));
        // These would make the command useless for driving another frontend.
        assert!(!args.contains(&"-c".to_string()));
        assert!(!args.contains(&"-o".to_string()));
        assert!(!args.iter().any(|a| a.ends_with(".o")));
        assert!(!args.iter().any(|a| a == "/src/a.cpp"));
    }

    #[test]
    fn supports_the_arguments_array_form() {
        let (db, _fixture) = db_from(SAMPLE, "argsform");
        let args = db.args_for(Path::new("/src/b.cpp")).unwrap();
        assert_eq!(args, ["-I/other"]);
    }

    #[test]
    fn partitions_sources_by_build_membership() {
        let (db, _fixture) = db_from(SAMPLE, "partition");
        let (built, unlisted) = db.partition(&[
            PathBuf::from("/src/a.cpp"),
            PathBuf::from("/tests/t.cpp"),
            PathBuf::from("/src/b.cpp"),
        ]);
        assert_eq!(built.len(), 2);
        assert_eq!(unlisted, vec![PathBuf::from("/tests/t.cpp")]);
    }

    #[test]
    fn unknown_file_has_no_flags() {
        let (db, _fixture) = db_from(SAMPLE, "unknown");
        assert!(db.args_for(Path::new("/nope.cpp")).is_none());
    }

    const GCC_KERNEL: &str = r#"[
      {"directory":"/b","file":"/src/dmp.c",
       "command":"gcc-13 -I/inc -mpreferred-stack-boundary=3 -mindirect-branch=thunk-extern -fconserve-stack -fno-allow-store-data-races -DKBUILD -c /src/dmp.c -o /b/dmp.o"}
    ]"#;

    #[test]
    fn gcc_only_flags_are_removed_so_clang_can_read_the_database() {
        let (db, _fixture) = db_from(GCC_KERNEL, "gccflags");
        let args = db.args_for(Path::new("/src/dmp.c")).unwrap();
        // clang errors rather than skipping these, so a single one left in
        // fails *every* translation unit and the run looks like a broken
        // project instead of an incompatible database.
        for bad in [
            "-mpreferred-stack-boundary=3",
            "-mindirect-branch=thunk-extern",
            "-fconserve-stack",
            "-fno-allow-store-data-races",
        ] {
            assert!(!args.iter().any(|a| a == bad), "{bad} survived");
        }
        // Everything the analysis actually needs is untouched.
        assert!(args.contains(&"-I/inc".to_string()));
        assert!(args.contains(&"-DKBUILD".to_string()));
        assert_eq!(db.dropped_flags().len(), 4);
    }

    #[test]
    fn a_clang_database_is_passed_through_untouched() {
        let (db, _fixture) = db_from(SAMPLE, "passthrough");
        // No rewrite, so tools read the project's own file and any path
        // assumption they make about it still holds.
        assert!(db.dropped_flags().is_empty());
        assert!(db.path().ends_with("kordon-db-test-".to_string()
            + &std::process::id().to_string()
            + "-passthrough"));
    }

    #[test]
    fn missing_database_is_an_error() {
        assert!(CompileDb::load(Path::new("/nonexistent/kordon-db")).is_err());
    }

    /// The rewritten copy is removed when the database is dropped, and the
    /// user's own directory never is.
    #[test]
    fn the_rewritten_copy_is_cleaned_up_and_the_original_is_not() {
        let (db, _fixture) = db_from(GCC_KERNEL, "ownedtmp");
        let rewritten = db.owned_dir().expect("gcc flags force a rewrite").to_path_buf();
        assert!(rewritten.exists());
        drop(db);
        assert!(!rewritten.exists(), "the copy Kordon wrote must not survive");

        // A clang database needs no rewrite, so there is nothing to own -- and
        // nothing that could delete the directory the user passed.
        let (clean, fixture) = db_from(SAMPLE, "ownednone");
        assert!(clean.owned_dir().is_none());
        let given = fixture.0.clone();
        drop(clean);
        assert!(given.exists(), "the user's own directory is never removed");
    }
}
