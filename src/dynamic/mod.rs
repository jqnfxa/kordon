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

pub const PROFILES: &[&Profile] = &[&ASAN, &MSAN, &VALGRIND];

pub struct DynamicConfig {
    /// Directory holding the project's CMakeLists.txt.
    pub source: PathBuf,
    /// Command that exercises the code. Whatever it reaches is the ceiling.
    pub command: String,
    pub scratch: PathBuf,
    pub timeout_secs: u64,
    pub jobs: usize,
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

fn run_profile(
    config: &DynamicConfig,
    analysis_root: &Path,
    profile: &Profile,
    table: &CweTable,
) -> ToolRun {
    if !profile.wrapper.is_empty() && !crate::tools::available(profile.wrapper[0]) {
        return ToolRun::skipped(tool(profile), format!("{} not installed", profile.wrapper[0]));
    }
    if !config.source.join("CMakeLists.txt").is_file() {
        return ToolRun::skipped(
            tool(profile),
            "no CMakeLists.txt -- the dynamic layer builds its own instrumented \
variants and has no other way to do that",
        );
    }

    let instrumented = profile.requires_clang;
    if instrumented && !crate::tools::available("clang++") {
        return ToolRun::skipped(tool(profile), "clang++ not installed");
    }

    let build_dir = config.scratch.join(profile.name);
    let flags = profile.flags.join(" ");
    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&config.source)
        .arg("-B")
        .arg(&build_dir)
        .arg("-DCMAKE_BUILD_TYPE=Debug")
        .arg(format!("-DCMAKE_C_FLAGS={flags}"))
        .arg(format!("-DCMAKE_CXX_FLAGS={flags}"))
        .arg(format!("-DCMAKE_EXE_LINKER_FLAGS={flags}"));
    if instrumented {
        // CMake picks the system default compiler, which here is GCC, and g++
        // has no -fsanitize=memory at all -- MSan is clang-only. Pinning clang
        // also keeps the report format the one these parsers were written
        // against; GCC ships the same runtime but not the same driver.
        configure
            .arg("-DCMAKE_C_COMPILER=clang")
            .arg("-DCMAKE_CXX_COMPILER=clang++");
    }
    let configure = configure.output();
    match configure {
        Ok(o) if !o.status.success() => {
            return ToolRun::failed(
                tool(profile),
                format!(
                    "cmake configure failed: {}",
                    last_meaningful_line(&String::from_utf8_lossy(&o.stderr))
                ),
            )
        }
        Err(e) => return ToolRun::failed(tool(profile), format!("cmake not runnable: {e}")),
        _ => {}
    }

    let build = Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg("-j")
        .arg(config.jobs.to_string())
        .output();
    match build {
        Ok(o) if !o.status.success() => {
            return ToolRun::failed(
                tool(profile),
                format!(
                    "instrumented build failed: {}",
                    last_meaningful_line(&String::from_utf8_lossy(&o.stderr))
                ),
            )
        }
        Err(e) => return ToolRun::failed(tool(profile), format!("cmake --build not runnable: {e}")),
        _ => {}
    }

    execute(config, analysis_root, profile, &build_dir, table)
}

/// Run the command and turn whatever it printed into findings.
fn execute(
    config: &DynamicConfig,
    analysis_root: &Path,
    profile: &Profile,
    build_dir: &Path,
    table: &CweTable,
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
