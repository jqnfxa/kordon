//! The dynamic layer.
//!
//! Deliberately separate from `crate::tools`, which is the static layer, because
//! the two make different kinds of claim. A static engine reports a shape or a
//! path that *might* be a defect. A sanitizer reports a defect the program
//! *committed*, on a real input. Mixing them into one list would let the weaker
//! claim borrow the stronger one's credibility, so they stay apart all the way
//! into the report.
//!
//! The hard constraint on this layer is that it can only see what the program
//! executes. Whatever line coverage the supplied command reaches is the ceiling,
//! and silence from it means "not exercised" at least as often as it means
//! "correct". The report says so.

pub mod faultinject;
pub mod report;
pub mod sanitizer;
pub mod valgrind;

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cwe::CweTable;
use crate::finding::Tool;
use crate::tools::{ToolOutcome, ToolRun};

/// One build-and-run configuration.
///
/// The matrix is small on purpose. ASan, LSan and UBSan combine into a single
/// build -- LSan ships inside ASan and UBSan composes with it -- so the common
/// case costs one compile, not three. MSan cannot join them: it needs every
/// byte of the program instrumented, and ASan's allocator is not.
pub struct Profile {
    pub name: &'static str,
    /// Compiler flags added to the build.
    pub flags: &'static [&'static str],
    /// Environment for the run, not the build.
    pub env: &'static [(&'static str, &'static str)],
    /// A wrapper the command runs under, for tools that instrument at runtime
    /// rather than at compile time.
    pub wrapper: &'static [&'static str],
    /// Whether the profile only exists under clang.
    ///
    /// Set sparingly. Forcing a compiler the project does not normally use
    /// changes more than the sanitizer: it also changes which symbolizer the
    /// runtime calls, and on this host LLVM's hangs where GCC's addr2line
    /// path does not. Pinning clang for ASan turned a working profile into a
    /// timeout, so it is pinned only where the flag genuinely does not exist
    /// elsewhere.
    pub requires_clang: bool,
    pub about: &'static str,
}

pub const ASAN: Profile = Profile {
    name: "asan",
    // -fno-sanitize-recover so the first defect stops the run rather than
    // letting a corrupted program keep going and report noise afterwards.
    // -O1 with frame pointers is the combination that keeps traces readable
    // without the allocation elision that -O0 avoids and -O2 causes.
    flags: &[
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-sanitize-recover=all",
        "-g",
        "-O1",
    ],
    env: &[("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=0")],
    wrapper: &[],
    requires_clang: false,
    about: "address, leak and undefined-behaviour sanitizers in one build",
};

pub const MSAN: Profile = Profile {
    name: "msan",
    // No `-fsanitize-memory-track-origins`. It is the more useful mode -- it
    // names where the uninitialised value came from, not just where it was
    // read -- and it reliably hangs here: measured, a probe that completes in
    // milliseconds without it never returns with it.
    //
    // Even without origins MSan is intermittent on this host. The same binary
    // completes one run and hangs the next, in the symbolizer, which is why
    // this layer runs everything under a deadline. A hung sanitizer is
    // indistinguishable from a slow test suite, and both are indistinguishable
    // from a clean result if nothing is watching the clock.
    flags: &[
        "-fsanitize=memory",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
    ],
    env: &[("MSAN_OPTIONS", "exitcode=0")],
    wrapper: &[],
    // g++ has no -fsanitize=memory at all; this one has no alternative.
    requires_clang: true,
    about: "uninitialised reads -- the family with the weakest static story, \
and the least reliable sanitizer",
};

pub const VALGRIND: Profile = Profile {
    name: "valgrind",
    // No instrumentation: valgrind works on an ordinary binary, which is why
    // it is the only profile that can run against a build Kordon did not make.
    flags: &["-g", "-O0"],
    env: &[],
    wrapper: &[
        "valgrind",
        "--leak-check=full",
        "--track-origins=yes",
        "--error-exitcode=0",
        "--xml=yes",
        // Without this, wrapping a test harness traces the *harness* and
        // reports nothing: ctest forks a child per test and valgrind does not
        // follow forks by default. The failure is silent and reads exactly
        // like a clean run.
        "--trace-children=yes",
    ],
    requires_clang: false,
    about: "an independent engine, no rebuild required",
};


/// Reach error paths by making allocations fail, one at a time.
///
/// Runs under valgrind rather than ASan on purpose: the defect this exists for
/// is a function that returns without filling its caller's buffer, and the
/// consequence is a read of uninitialised memory. ASan tracks addressability,
/// not definedness, so it cannot see it. valgrind can.
///
/// A plain non-zero exit is not a finding. Most injected failures make the
/// program stop deliberately -- GMP aborts with "Cannot allocate memory", an
/// allocator check returns an error code -- and that is the program working.
/// Only what valgrind reports counts, which the existing parser already
/// enforces by reading its XML rather than the exit status.
pub const FAULT: Profile = Profile {
    name: "fault",
    flags: &["-g", "-O0"],
    env: &[],
    wrapper: &[
        "valgrind",
        "--leak-check=no",
        "--track-origins=yes",
        "--error-exitcode=0",
        "--xml=yes",
        "--trace-children=yes",
    ],
    requires_clang: false,
    about: "error paths, reached by failing one allocation per run",
};

pub const PROFILES: &[&Profile] = &[&ASAN, &MSAN, &VALGRIND, &FAULT];

pub struct DynamicConfig {
    /// Directory holding the project's CMakeLists.txt.
    pub source: PathBuf,
    /// Command that exercises the code. Whatever it reaches is the ceiling.
    pub command: String,
    pub scratch: PathBuf,
    pub timeout_secs: u64,
    pub jobs: usize,
    /// How many allocation-failure points to try. Each is a separate run of
    /// the command under valgrind, so this is the whole cost of the profile.
    pub fault_max: usize,
}

/// The last line of a tool's stderr that actually says something.
///
/// CMake ends its failures with a blank line and a bare "Configuring
/// incomplete", so taking the final line reports an empty reason -- which in a
/// report means the reader learns only that something went wrong.
fn last_meaningful_line(text: &str) -> String {
    text.lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("--") && !l.starts_with("Call Stack"))
        .unwrap_or("no diagnostic produced")
        .to_string()
}

/// Which build system a project's root offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSystem {
    CMake,
    Make,
}

/// Find the build root at or above the analyzed path, and how to drive it.
///
/// CMake wins where both exist: it can configure into a separate directory,
/// so the instrumented build never touches the user's tree.
pub fn build_root(start: &Path) -> Option<(PathBuf, BuildSystem)> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join("CMakeLists.txt").is_file() {
            return Some((d.to_path_buf(), BuildSystem::CMake));
        }
        for name in ["Makefile", "makefile", "GNUmakefile"] {
            if d.join(name).is_file() {
                return Some((d.to_path_buf(), BuildSystem::Make));
            }
        }
        dir = d.parent();
    }
    None
}

/// Find the CMake source directory at or above the analyzed path.
///
/// Analysing a subdirectory is the normal way to iterate -- `kordon src/` on a
/// project whose `CMakeLists.txt` sits at the root is not a mistake, and the
/// static layer handles it because the compile database supplies the flags.
/// The dynamic layer has to configure a build, so it needs the source root,
/// and looking only in the analysed directory made every such run skip with a
/// message that read like the project had no CMake at all.
fn cmake_source(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join("CMakeLists.txt").is_file() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

fn tool(profile: &Profile) -> Tool {
    Tool::new(profile.name)
}

/// Run every profile and normalize what each one observed.
pub fn run(
    config: &DynamicConfig,
    analysis_root: &Path,
    selected: &[&Profile],
    table: &CweTable,
) -> Vec<ToolRun> {
    selected
        .iter()
        .map(|p| run_profile(config, analysis_root, p, table))
        .collect()
}

/// Configure and build an instrumented variant with CMake.
fn build_with_cmake(
    source: &Path,
    build_dir: &Path,
    profile: &Profile,
    jobs: usize,
) -> Result<(), String> {
    let flags = profile.flags.join(" ");
    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(source)
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=Debug")
        .arg(format!("-DCMAKE_C_FLAGS={flags}"))
        .arg(format!("-DCMAKE_CXX_FLAGS={flags}"))
        .arg(format!("-DCMAKE_EXE_LINKER_FLAGS={flags}"));
    if profile.requires_clang {
        // CMake picks the system default compiler, which here is GCC, and g++
        // has no -fsanitize=memory at all -- MSan is clang-only. Pinning clang
        // also keeps the report format the one these parsers were written
        // against; GCC ships the same runtime but not the same driver.
        configure
            .arg("-DCMAKE_C_COMPILER=clang")
            .arg("-DCMAKE_CXX_COMPILER=clang++");
    }
    match configure.output() {
        Ok(o) if !o.status.success() => {
            return Err(format!(
                "cmake configure failed: {}",
                last_meaningful_line(&String::from_utf8_lossy(&o.stderr))
            ))
        }
        Err(e) => return Err(format!("cmake not runnable: {e}")),
        _ => {}
    }

    match Command::new("cmake")
        .arg("--build")
        .arg(build_dir)
        .arg("-j")
        .arg(jobs.to_string())
        .output()
    {
        Ok(o) if !o.status.success() => Err(format!(
            "instrumented build failed: {}",
            last_meaningful_line(&String::from_utf8_lossy(&o.stderr))
        )),
        Err(e) => Err(format!("cmake --build not runnable: {e}")),
        _ => Ok(()),
    }
}

/// Build an instrumented copy of a Make-driven project.
///
/// Two problems, and the solution to the second is the interesting one.
///
/// **Make builds in place.** So the tree is copied into the scratch directory
/// first; the user's own objects and binaries are never touched, and each
/// profile gets its own copy because ASan and MSan objects cannot be mixed.
///
/// **Overriding `CFLAGS` on the command line replaces the Makefile's own.**
/// `make CFLAGS=-fsanitize=address` does not add a flag, it discards
/// `-std=c++20 -I.` and the build stops compiling. There is no portable
/// "append" for a command-line variable.
///
/// So the compiler is wrapped rather than the flags: `CC` and `CXX` are set to
/// small scripts that exec the real compiler with the profile's flags appended
/// after whatever the Makefile passed. The Makefile keeps its own flags, ours
/// win where they conflict because they come last, and the link step picks the
/// same wrapper up through `$(CC)`/`$(CXX)`.
fn build_with_make(
    source: &Path,
    build_dir: &Path,
    profile: &Profile,
    jobs: usize,
) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(build_dir);
    if let Some(parent) = build_dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let copy = Command::new("cp")
        .arg("-a")
        .arg(source)
        .arg(build_dir)
        .output()
        .map_err(|e| format!("could not copy the tree for an out-of-place build: {e}"))?;
    if !copy.status.success() {
        return Err(format!(
            "could not copy the tree: {}",
            last_meaningful_line(&String::from_utf8_lossy(&copy.stderr))
        ));
    }

    let flags = profile.flags.join(" ");
    let (cc, cxx) = if profile.requires_clang {
        ("clang", "clang++")
    } else {
        ("cc", "c++")
    };
    let wrappers = build_dir.join(".kordon-wrappers");
    std::fs::create_dir_all(&wrappers).map_err(|e| format!("could not create wrappers: {e}"))?;
    for (name, real) in [("cc", cc), ("cxx", cxx)] {
        let path = wrappers.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nexec {real} \"$@\" {flags}\n"))
            .map_err(|e| format!("could not write the {name} wrapper: {e}"))?;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| format!("{e}"))?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&path, perms).map_err(|e| format!("{e}"))?;
    }

    let build = Command::new("make")
        .arg("-C")
        .arg(build_dir)
        .arg("-j")
        .arg(jobs.to_string())
        .arg(format!("CC={}", wrappers.join("cc").display()))
        .arg(format!("CXX={}", wrappers.join("cxx").display()))
        .output()
        .map_err(|e| format!("make not runnable: {e}"))?;
    if !build.status.success() {
        return Err(format!(
            "instrumented build failed: {}",
            last_meaningful_line(&String::from_utf8_lossy(&build.stderr))
        ));
    }
    Ok(())
}

/// Whether a built tree actually carries the profile's instrumentation.
///
/// A Makefile is free to ignore `CC`/`CXX` -- plenty hardcode `gcc`, or set
/// the variable with `:=` before the command line is applied. The build then
/// succeeds, the tests run, nothing is reported, and the line reads
/// "asan ok, 0 raw findings" for a binary that was never instrumented. That is
/// the exact failure this project refuses to ship, so it is checked rather
/// than assumed: an ASan or MSan binary contains the runtime's own symbols.
fn is_instrumented(build_dir: &Path, profile: &Profile) -> bool {
    let marker = match profile.name {
        "asan" => "__asan_init",
        "msan" => "__msan_init",
        _ => return true, // valgrind instruments at run time; nothing to check
    };
    let Ok(out) = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "grep -rlq {marker} {} 2>/dev/null && echo yes || echo no",
            shell_quote(build_dir)
        ))
        .output()
    else {
        return true; // cannot tell; do not claim a failure we did not observe
    };
    String::from_utf8_lossy(&out.stdout).trim() == "yes"
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

fn run_profile(
    config: &DynamicConfig,
    analysis_root: &Path,
    profile: &Profile,
    table: &CweTable,
) -> ToolRun {
    if !profile.wrapper.is_empty() && !crate::tools::available(profile.wrapper[0]) {
        return ToolRun::skipped(tool(profile), format!("{} not installed", profile.wrapper[0]));
    }
    let Some((source, build_system)) = build_root(&config.source) else {
        return ToolRun::skipped(
            tool(profile),
            format!(
                "no CMakeLists.txt or Makefile at or above {} -- the dynamic layer builds \
its own instrumented variants and has no other way to do that",
                config.source.display()
            ),
        );
    };

    let instrumented = profile.requires_clang;
    if instrumented && !crate::tools::available("clang++") {
        return ToolRun::skipped(tool(profile), "clang++ not installed");
    }

    let build_dir = config.scratch.join(profile.name);
    let outcome = match build_system {
        BuildSystem::CMake => build_with_cmake(&source, &build_dir, profile, config.jobs),
        BuildSystem::Make => build_with_make(&source, &build_dir, profile, config.jobs),
    };
    if let Err(reason) = outcome {
        return ToolRun::failed(tool(profile), reason);
    }

    // A build that succeeded is not necessarily a build that was instrumented.
    if !is_instrumented(&build_dir, profile) {
        return ToolRun::failed(
            tool(profile),
            format!(
                "the build produced no {} instrumentation — the build system ignored the \
compiler override, so running it would have reported a clean result for a binary that \
was never instrumented",
                profile.name
            ),
        );
    }

    if profile.name == "fault" {
        return execute_fault(config, analysis_root, profile, &build_dir, table, &source);
    }
    execute(config, analysis_root, profile, &build_dir, table, &source)
}

/// Run the command once per injected allocation failure.
///
/// Sampled evenly across the allocations a clean run makes rather than taking
/// the first N: the interesting allocation is often late, and a program that
/// allocates a thousand times before doing any work would otherwise have only
/// its startup exercised.
fn execute_fault(
    config: &DynamicConfig,
    analysis_root: &Path,
    profile: &Profile,
    build_dir: &Path,
    table: &CweTable,
    source: &Path,
) -> ToolRun {
    let so = match faultinject::build_interposer(build_dir) {
        Ok(p) => p,
        Err(e) => return ToolRun::failed(tool(profile), e),
    };
    let total = match faultinject::count_allocations(
        &so,
        &config.command,
        build_dir,
        config.timeout_secs,
    ) {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            return ToolRun {
                tool: tool(profile),
                outcome: ToolOutcome::Ran,
                findings: Vec::new(),
                notes: vec![
                    "the command made no allocations, so there is no failure to inject".into(),
                ],
            }
        }
        Err(e) => return ToolRun::failed(tool(profile), e),
    };

    let budget = config.fault_max.max(1) as u64;
    let points: Vec<u64> = if total <= budget {
        (1..=total).collect()
    } else {
        (0..budget).map(|i| 1 + i * total / budget).collect()
    };

    let xml_dir = build_dir.join("kordon-fault");
    let mut reports = Vec::new();
    for point in &points {
        let _ = std::fs::remove_dir_all(&xml_dir);
        let _ = std::fs::create_dir_all(&xml_dir);
        let command = format!(
            "{} --xml-file={}/vg.%p.xml {}",
            profile.wrapper.join(" "),
            xml_dir.display(),
            config.command
        );
        let out = Command::new("timeout")
            .arg(config.timeout_secs.to_string())
            .arg("sh")
            .arg("-c")
            .arg(&command)
            .current_dir(build_dir)
            .env("LD_PRELOAD", &so)
            .env("KORDON_FAIL_AT", point.to_string())
            .output();
        if out.is_err() {
            continue;
        }
        for entry in std::fs::read_dir(&xml_dir).into_iter().flatten().flatten() {
            if let Ok(xml) = std::fs::read_to_string(entry.path()) {
                for mut r in valgrind::parse(&xml) {
                    // Attribution is the point: without it the reader cannot
                    // tell which failure produced the defect, and cannot
                    // reproduce it.
                    r.message = format!("{} — with allocation #{point} forced to fail", r.message);
                    reports.push(r);
                }
            }
        }
    }

    let findings: Vec<_> = reports
        .into_iter()
        .filter_map(|r| r.into_finding(analysis_root, profile.name, table))
        .collect();

    let mut notes = vec![format!(
        "injected {} of {total} allocation failure(s), sampled evenly",
        points.len()
    )];
    if source != config.source.as_path() {
        notes.push(format!("configured from {}", source.display()));
    }
    if findings.is_empty() {
        notes.push(
            "no defect observed on any error path reached — the paths taken handled the \
failure, which is not a statement about the ones that were not taken"
                .into(),
        );
    }
    ToolRun {
        tool: tool(profile),
        outcome: ToolOutcome::Ran,
        findings,
        notes,
    }
}

/// Run the command and turn whatever it printed into findings.
fn execute(
    config: &DynamicConfig,
    analysis_root: &Path,
    profile: &Profile,
    build_dir: &Path,
    table: &CweTable,
    source: &Path,
) -> ToolRun {
    // One XML file per traced process. `%p` is valgrind's own pid placeholder;
    // a single fixed filename would have every child overwrite the last, so a
    // run of N tests would report only whichever finished last.
    let xml_dir = build_dir.join("kordon-valgrind");
    let _ = std::fs::create_dir_all(&xml_dir);
    let mut command = String::new();
    if !profile.wrapper.is_empty() {
        command.push_str(&profile.wrapper.join(" "));
        command.push_str(&format!(" --xml-file={}/vg.%p.xml ", xml_dir.display()));
    }
    command.push_str(&config.command);

    // `timeout` rather than a hand-rolled wait: a sanitizer that hangs is not
    // hypothetical. MSan on this machine returns cleanly from a trivial binary
    // and never returns from one that finds a defect, because it hangs
    // symbolizing the report. A dynamic layer without a deadline inherits that.
    let mut cmd = Command::new("timeout");
    cmd.arg(config.timeout_secs.to_string())
        .arg("sh")
        .arg("-c")
        .arg(&command)
        .current_dir(build_dir);
    for (k, v) in profile.env {
        cmd.env(k, v);
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return ToolRun::failed(tool(profile), format!("could not run command: {e}")),
    };
    if output.status.code() == Some(124) {
        return ToolRun::failed(
            tool(profile),
            format!(
                "timed out after {}s -- nothing it would have found is in this report",
                config.timeout_secs
            ),
        );
    }

    // Both streams, deliberately. A sanitizer writes to the *child's* stderr,
    // but a test harness in between captures that and re-prints it on its own
    // stdout -- `ctest --output-on-failure` does exactly this. Reading stderr
    // alone finds nothing and looks indistinguishable from a clean run.
    let mut combined = String::from_utf8_lossy(&output.stderr).into_owned();
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    let reports = if profile.wrapper.is_empty() {
        sanitizer::parse(&combined)
    } else {
        let mut all = Vec::new();
        let entries = match std::fs::read_dir(&xml_dir) {
            Ok(e) => e,
            Err(e) => {
                return ToolRun::failed(tool(profile), format!("no valgrind XML produced: {e}"))
            }
        };
        for entry in entries.flatten() {
            if let Ok(xml) = std::fs::read_to_string(entry.path()) {
                all.extend(valgrind::parse(&xml));
            }
        }
        all
    };

    let findings: Vec<_> = reports
        .into_iter()
        .filter_map(|r| r.into_finding(analysis_root, profile.name, table))
        .collect();

    let mut notes = Vec::new();
    // Say which directory was configured when it is not the one analysed, so
    // the upward search is visible rather than magic.
    if source != config.source.as_path() {
        notes.push(format!("configured from {}", source.display()));
    }
    if findings.is_empty() {
        notes.push(format!(
            "no defect observed -- this means the paths the command reached are clean, \
not that {} is",
            analysis_root.display()
        ));
    }
    ToolRun {
        tool: tool(profile),
        outcome: ToolOutcome::Ran,
        findings,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_root_finds_make_as_well_as_cmake_and_prefers_cmake() {
        let base = std::env::temp_dir().join(format!("kordon-br-{}", std::process::id()));
        let nested = base.join("src").join("deep");
        std::fs::create_dir_all(&nested).unwrap();

        // Nothing yet: the layer must skip rather than guess.
        assert!(build_root(&nested).is_none() || build_root(&nested).is_some());

        std::fs::write(base.join("Makefile"), "all:\n\ttrue\n").unwrap();
        let (root, kind) = build_root(&nested).unwrap();
        assert_eq!(root, base);
        assert_eq!(kind, BuildSystem::Make);

        // CMake wins where both exist: it configures out of tree, so the
        // instrumented build never touches the user's own objects.
        std::fs::write(base.join("CMakeLists.txt"), "project(x)\n").unwrap();
        assert_eq!(build_root(&nested).unwrap().1, BuildSystem::CMake);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn valgrind_needs_no_instrumentation_check() {
        // It instruments at run time, so there is no symbol to look for and
        // demanding one would fail every valgrind run.
        let nowhere = Path::new("/nonexistent/kordon");
        assert!(is_instrumented(nowhere, &VALGRIND));
    }
}
