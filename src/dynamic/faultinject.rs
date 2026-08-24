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
static const char *report_path = NULL;

/* dlsym itself allocates on some libcs. A small static arena answers those
   first calls so the interposer cannot recurse into itself. */
static char bootstrap[65536];
static size_t bootstrap_used = 0;
static int in_dlsym = 0;

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
__attribute__((destructor)) static void report(void) {
    if (!report_path) return;
    FILE *f = fopen(report_path, "w");
    if (!f) return;
    fprintf(f, "%ld\n", counter);
    fclose(f);
}

void *malloc(size_t size) {
    init();
    if (!real_malloc) return from_bootstrap(size);
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
    if (++counter == fail_at) return NULL;
    return real_calloc(n, size);
}

void *realloc(void *ptr, size_t size) {
    init();
    if (!real_realloc) return from_bootstrap(size);
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
        .env("KORDON_ALLOC_COUNT", &count_file)
        .output()
        .map_err(|e| format!("could not run the command: {e}"))?;
    let _ = status;
    std::fs::read_to_string(&count_file)
        .map_err(|e| format!("the interposer wrote no count: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("unreadable allocation count: {e}"))
}
