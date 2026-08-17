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

pub struct CompileDb {
    /// The path handed to tools that read the database themselves
    /// (clang-tidy `-p`, cppcheck `--project`).
    path: PathBuf,
    /// Source file -> compilation flags, with the pieces that make no sense
    /// when re-driving the compiler already stripped.
    args: HashMap<PathBuf, Vec<String>>,
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
        if let Some(list) = entries.as_array() {
            for entry in list {
                if let Some((file, flags)) = parse_entry(entry) {
                    // Later entries win, matching how a build system would
                    // last-write a duplicated unit.
                    args.insert(file, flags);
                }
            }
        }

        Ok(CompileDb {
            path: given.to_path_buf(),
            args,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn db_from(json: &str) -> CompileDb {
        let dir = std::env::temp_dir().join(format!("kordon-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("compile_commands.json"), json).unwrap();
        CompileDb::load(&dir).unwrap()
    }

    const SAMPLE: &str = r#"[
      {"directory":"/b","file":"/src/a.cpp",
       "command":"/usr/bin/clang++ -DFOO -I/inc -std=c++17 -c /src/a.cpp -o /b/a.o"},
      {"directory":"/b","file":"/src/b.cpp",
       "arguments":["/usr/bin/clang++","-I/other","-c","/src/b.cpp","-o","/b/b.o"]}
    ]"#;

    #[test]
    fn strips_compile_and_output_flags() {
        let db = db_from(SAMPLE);
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
        let db = db_from(SAMPLE);
        let args = db.args_for(Path::new("/src/b.cpp")).unwrap();
        assert_eq!(args, ["-I/other"]);
    }

    #[test]
    fn partitions_sources_by_build_membership() {
        let db = db_from(SAMPLE);
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
        assert!(db_from(SAMPLE).args_for(Path::new("/nope.cpp")).is_none());
    }

    #[test]
    fn missing_database_is_an_error() {
        assert!(CompileDb::load(Path::new("/nonexistent/kordon-db")).is_err());
    }
}
