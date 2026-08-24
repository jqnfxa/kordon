//! Reaching error paths by making allocations fail.
//!
//! The gap this closes was measured, not guessed. `split_vector_ozaki` in one
//! project returns `void` and bails out of a failed `malloc` without filling
//! its caller's output buffer, so the caller reads uninitialised memory. The
//! static layer found it by reading code. Every dynamic tool came back clean:
//! ASan and UBSan report nothing, valgrind with `--track-origins=yes` reports
//! zero errors from zero contexts, because on a machine with memory available
//! that `malloc` never fails and the branch is never taken.
//!
//! Error paths are the least tested code in most programs and the most likely
//! to be wrong, and no sanitizer reaches them, because a sanitizer observes
//! what the program does rather than changing what it is asked to do.
//!
//! The mechanism is an `LD_PRELOAD` interposer that fails the *n*th allocation
//! and passes every other one through, run once per value of *n*. That turns
//! "this error path is never exercised" into "this error path is exercised
//! exactly once per run", which is what makes the failure attributable: the
//! report can say which allocation had to fail.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The interposer. Kept as source and compiled into the scratch directory
/// rather than shipped as a binary, so it matches the host's libc.
///
/// Counting and failing are the same build: `FAIL_AT` unset means count only,
/// which is how the sweep learns how many allocations a run makes before
/// deciding how many times to run it.
const INTERPOSER: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static long counter = 0;
static long fail_at = -1;
static int  initialised = 0;
static int  active = 1;
static const char *report_path = NULL;

/* dlsym itself allocates on some libcs. A small static arena answers those
   first calls so the interposer cannot recurse into itself. */
static char bootstrap[65536];
static size_t bootstrap_used = 0;
static int in_dlsym = 0;

/* LD_PRELOAD is inherited by every descendant, so a run command like
   `ctest` puts the shell and the runner under the interposer alongside the
   program being tested. Only processes whose executable lives in the build
   tree are ours; the rest pass through untouched. */
static int is_target(void) {
    const char *root = getenv("KORDON_FAULT_ROOT");
    if (!root || !*root) return 1;
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0) return 0;
    exe[n] = '\0';
    size_t len = strlen(root);
    return strncmp(exe, root, len) == 0;
}

static void init(void) {
    if (initialised) return;
    if (in_dlsym) return;
    in_dlsym = 1;
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    const char *e = getenv("KORDON_FAIL_AT");
    fail_at = e ? atol(e) : -1;
    report_path = getenv("KORDON_ALLOC_COUNT");
    active = is_target();
    in_dlsym = 0;
    initialised = 1;
}

static void *from_bootstrap(size_t size) {
    size_t aligned = (size + 15u) & ~(size_t)15u;
    if (bootstrap_used + aligned > sizeof bootstrap) return NULL;
    void *p = bootstrap + bootstrap_used;
    bootstrap_used += aligned;
    return p;
}

/* Written at exit so the sweep knows how many allocations the run makes. */
/* Appended, not truncated: a suite that runs several of its own binaries has
   several targets, and truncating meant the count came from whichever exited
   last rather than from the one that allocates most. */
__attribute__((destructor)) static void report(void) {
    if (!report_path || !active) return;
    FILE *f = fopen(report_path, "a");
    if (!f) return;
    fprintf(f, "%ld\n", counter);
    fclose(f);
}

void *malloc(size_t size) {
    init();
    if (!real_malloc) return from_bootstrap(size);
    if (!active) return real_malloc(size);
    if (++counter == fail_at) return NULL;
    return real_malloc(size);
}

void *calloc(size_t n, size_t size) {
    init();
    if (!real_calloc) {
        void *p = from_bootstrap(n * size);
        if (p) memset(p, 0, n * size);
        return p;
    }
    if (!active) return real_calloc(n, size);
    if (++counter == fail_at) return NULL;
    return real_calloc(n, size);
}

void *realloc(void *ptr, size_t size) {
    init();
    if (!real_realloc) return from_bootstrap(size);
    if (!active) return real_realloc(ptr, size);
    if (++counter == fail_at) return NULL;
    return real_realloc(ptr, size);
}
"#;

/// Compile the interposer next to the instrumented build.
pub fn build_interposer(scratch: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(scratch).map_err(|e| format!("{e}"))?;
    let src = scratch.join("kordon-failmalloc.c");
    let so = scratch.join("kordon-failmalloc.so");
    std::fs::write(&src, INTERPOSER).map_err(|e| format!("could not write interposer: {e}"))?;
    let out = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-O1")
        .arg("-o")
        .arg(&so)
        .arg(&src)
        .arg("-ldl")
        .output()
        .map_err(|e| format!("cc not runnable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "could not build the interposer: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or("")
        ));
    }
    Ok(so)
}

/// How many allocations one clean run makes.
///
/// Needed before sweeping: failing allocation 500 of a run that makes 80 tells
/// you nothing, and sweeping a fixed range wastes most of its runs.
pub fn count_allocations(
    so: &Path,
    command: &str,
    dir: &Path,
    timeout_secs: u64,
) -> Result<u64, String> {
    let count_file = dir.join("kordon-alloc-count");
    let _ = std::fs::remove_file(&count_file);
    let status = Command::new("timeout")
        .arg(timeout_secs.to_string())
        .arg("sh")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .env("LD_PRELOAD", so)
        .env("KORDON_FAULT_ROOT", dir)
        .env("KORDON_ALLOC_COUNT", &count_file)
        .output()
        .map_err(|e| format!("could not run the command: {e}"))?;
    let _ = status;

    // One line per target process. The largest is the one worth sweeping:
    // sampling across a smaller sibling's range would leave the bigger one's
    // later allocations untouched.
    let text = std::fs::read_to_string(&count_file)
        .map_err(|e| format!("the interposer wrote no count: {e}"))?;
    text.lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .max()
        .ok_or_else(|| "unreadable allocation count".to_string())
}

/// Whether injecting a failure actually changes what the program does.
///
/// This is the fault-injection equivalent of checking that a build carried its
/// sanitizer flags, and it exists for the same reason: a sweep that injects
/// nothing produces zero findings, which is indistinguishable from a program
/// with no error-path defects.
///
/// It is not hypothetical, and the cause is now known: valgrind replaces
/// `malloc` itself, and its replacement wins over an `LD_PRELOAD` interposer.
/// Measured -- forcing allocation #2 to fail makes this project print "Failed
/// to load fk6" when run directly, and changes nothing at all under valgrind.
///
/// The "same 1051 allocations" that made this look like a counting problem was
/// a separate bug: `LD_PRELOAD` is inherited by every descendant, so the count
/// came from the `sh` wrapping the run command rather than from the program.
/// The program made 21. See [`is_target`] in the interposer.
///
/// The check compares a clean run against ones with a chosen allocation forced
/// to fail. It samples several points rather than only the first: measured on
/// this project, failing allocation #1 changed nothing observable while #2
/// through #5 drove the program down its load-failure path and #10 aborted it.
/// Probing only #1 concluded the mechanism was broken and abandoned a sweep
/// that would have found all of those.
pub fn injection_takes_effect(
    so: &Path,
    command: &str,
    dir: &Path,
    wrapper: &[&str],
    timeout_secs: u64,
    total: u64,
) -> bool {
    let run = |fail_at: Option<u64>| -> (Option<i32>, usize) {
        let full = if wrapper.is_empty() {
            command.to_string()
        } else {
            format!("{} {command}", wrapper.join(" "))
        };
        let mut cmd = Command::new("timeout");
        cmd.arg(timeout_secs.to_string())
            .arg("sh")
            .arg("-c")
            .arg(&full)
            .current_dir(dir)
            .env("LD_PRELOAD", so)
            .env("KORDON_FAULT_ROOT", dir);
        if let Some(n) = fail_at {
            cmd.env("KORDON_FAIL_AT", n.to_string());
        }
        match cmd.output() {
            Ok(o) => (o.status.code(), o.stdout.len() + o.stderr.len()),
            Err(_) => (None, 0),
        }
    };
    let clean = run(None);
    // Spread over the run rather than clustering at the start: early
    // allocations are often a runtime's own and can be absorbed without the
    // program noticing.
    let probes: Vec<u64> = if total <= 4 {
        (1..=total.max(1)).collect()
    } else {
        (0..4).map(|i| 1 + i * total / 4).collect()
    };
    probes.into_iter().any(|n| run(Some(n)) != clean)
}
