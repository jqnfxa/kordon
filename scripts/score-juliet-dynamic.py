#!/usr/bin/env python3
"""Score Kordon's dynamic layer against the NIST Juliet suite.

The static scorer measures what the engines infer from the code. This measures
what the program actually does when it runs, which is a different and stronger
claim -- and a differently limited one.

Juliet is unusually well suited to it: every case has a `main()` that calls the
flawed function and the corrected ones, each behind its own guard. Building
twice separates them cleanly:

  * `-DOMITGOOD` leaves only `bad()`   -> did the sanitizer report? = recall
  * `-DOMITBAD`  leaves only `good()`  -> did it report anyway?     = false positive

**Recall here is bounded by reachability, not by the sanitizer.** Juliet seeds
with `srand(time(NULL))` and many cases derive the flaw from `rand()`, so the
bad branch is taken only on some runs -- `if (data >= 0) buffer[data]` does
nothing at all when `data` comes back negative. Each case is therefore run
several times and counts as caught if any run reports. A case that never takes
its flawed path is recorded as `unreached`, not as a miss: "the sanitizer did
not fire" and "the code never ran" mean opposite things and must not be summed.

Cases that need input or a network peer (`fscanf`, `connect_socket`) mostly
fall into `unreached` for the same reason. That is the honest ceiling of a
dynamic layer driven by a fixed command, and it is the number worth knowing.

Usage:
    scripts/score-juliet-dynamic.py <juliet-root> --profile asan --cwe 121
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Kept in step with src/dynamic/mod.rs by hand. Measuring flags Kordon does not
# use would report a tool nobody runs.
#
# One deliberate difference: `symbolize=0`. This host's sandbox breaks ASan's
# symbolizer subprocess -- a one-line `int a[4]; return a[5];` hangs forever,
# while llvm-symbolizer works standalone -- so the default options either
# truncate the report mid-trace or, for LeakSanitizer, produce nothing at all
# before the deadline. CWE-401 scored 0% that way and scores 95%+ with
# symbolization off.
#
# Turning it off is right for *this* measurement and wrong for Kordon: the
# question here is "can the sanitizer detect this defect", which needs only the
# banner, whereas Kordon needs frames to place a finding at a line. Kordon's
# behaviour on such a host is a separate problem, recorded in CLAUDE.md.
PROFILES = {
    "asan": {
        "cc": "clang",
        "flags": ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                  "-fno-sanitize-recover=all", "-g", "-O1"],
        "env": {"ASAN_OPTIONS": "detect_leaks=1:abort_on_error=0:symbolize=0"},
        "wrapper": [],
    },
    "msan": {
        "cc": "clang",
        "flags": ["-fsanitize=memory", "-fno-omit-frame-pointer", "-g", "-O1"],
        "env": {"MSAN_OPTIONS": "exitcode=0:symbolize=0"},
        "wrapper": [],
    },
    # File descriptors are not memory: LeakSanitizer does not track them at
    # all, and CWE-775 scored 0% under ASan for that reason alone. valgrind
    # does, given --track-fds.
    "valgrind-fds": {
        "cc": "clang",
        "flags": ["-g", "-O0"],
        "env": {},
        "wrapper": ["valgrind", "--track-fds=yes", "-q"],
    },
    "valgrind": {
        "cc": "clang",
        "flags": ["-g", "-O0"],
        "env": {},
        "wrapper": ["valgrind", "--error-exitcode=42", "--leak-check=full",
                    "--errors-for-leak-kinds=definite", "-q"],
    },
}

# Which profile is the ground truth for which class. Scoring MSan on a double
# free, or ASan on an uninitialised read, measures the wrong instrument.
DEFAULT_PROFILE = {
    121: "asan", 122: "asan", 124: "asan", 126: "asan", 127: "asan",
    190: "asan", 191: "asan",          # UBSan rides along in the asan build
    401: "asan", 415: "asan", 416: "asan", 590: "asan", 762: "asan",
    775: "valgrind-fds", 562: "asan",
    457: "msan",
}

# Only a sanitizer's own banner counts. Juliet's cases print their own
# diagnostics -- "ERROR: Array index is negative." is the *corrected* path
# doing its job -- and matching bare "ERROR" scores those as detections.
REPORT_RE = re.compile(
    r"ERROR: AddressSanitizer|ERROR: LeakSanitizer|WARNING: MemorySanitizer"
    r"|runtime error:|SUMMARY: (?:Address|Memory|Undefined|Leak)Sanitizer"
)

# What the sanitizer must actually have said for it to count as detecting the
# CWE under test.
#
# Without this, CWE-416 read 96% false positives: its `goodG2B` deliberately
# does not free -- that is what makes it a good *use-after-free* case -- so it
# leaks, and LeakSanitizer correctly reports a real leak in a function labelled
# good for a different defect. Crediting or charging a report of the wrong
# class measures the wrong thing in both directions.
def _fd_leaked(text):
    """True when more descriptors were open at exit than the three standard ones.

    valgrind prints `FILE DESCRIPTORS: 4 open (3 std) at exit.` and lists each
    one. It is not an error in valgrind's sense -- the exit code stays 0 -- so
    there is no banner to match and nothing for --error-exitcode to catch; the
    count is the whole signal.
    """
    m = re.search(r"FILE DESCRIPTORS: (\d+) open \((\d+) std\)", text)
    if m:
        return int(m.group(1)) > int(m.group(2))
    m = re.search(r"FILE DESCRIPTORS: (\d+) open", text)
    return bool(m) and int(m.group(1)) > 3


CLASS_RE = {
    121: r"stack-buffer-overflow|dynamic-stack-buffer-overflow|stack-buffer-underflow",
    122: r"heap-buffer-overflow",
    124: r"buffer-underflow|buffer-overflow",
    126: r"buffer-overflow|stack-buffer-overflow|heap-buffer-overflow|global-buffer-overflow",
    127: r"buffer-underflow|buffer-overflow",
    190: r"runtime error:.*(signed integer overflow|cannot be represented)",
    191: r"runtime error:.*(unsigned integer overflow|negation of|signed integer overflow)",
    401: r"LeakSanitizer|detected memory leaks",
    415: r"double-free|attempting double-free",
    416: r"heap-use-after-free|use-after-poison",
    457: r"use-of-uninitialized-value|MemorySanitizer",
    562: r"stack-use-after-return|stack-use-after-scope",
    590: r"bad-free|attempting free on address which was not malloc",
    762: r"alloc-dealloc-mismatch|bad-free|new-delete-type-mismatch",
    775: _fd_leaked,
}


def sample(base, limit):
    files = []
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            if not n.endswith((".c", ".cpp")):
                continue
            # Multi-file cases need every part linked; skip rather than
            # half-build them. Both spellings: `_54b.c` splits by letter, and
            # the 81-84 class variants split as `_82_bad.cpp` /
            # `_84_goodB2G.cpp`, which have no main() of their own.
            if re.search(r"_\d+[a-e]\.(c|cpp)$", n):
                continue
            if re.search(r"_\d+_(bad|good\w*)\.(c|cpp)$", n):
                continue
            # Windows-only cases. `w32CreateFile`, `w32*Thread` and friends
            # cannot build on this platform, and counting them as unbuilt
            # reports a gap in Kordon where the gap is in the test suite's
            # portability -- 8 of 25 CWE-775 cases are these.
            if "w32" in n or "wchar_t_w32" in n:
                continue
            files.append(os.path.join(dirpath, n))
    files.sort()
    if len(files) > limit:
        stride = len(files) / limit
        files = [files[int(i * stride)] for i in range(limit)]
    return files


def build_and_run(src, support, prof, side, repeats, timeout, workdir, want):
    """Return 'caught', 'clean', 'unbuilt' or 'timeout' for one side."""
    spec = PROFILES[prof]
    cc = spec["cc"] + ("++" if src.endswith(".cpp") else "")
    exe = os.path.join(workdir, os.path.basename(src) + "." + side)
    define = "-DOMITGOOD" if side == "bad" else "-DOMITBAD"

    io = os.path.join(support, "io.c")
    cmd = [cc, *spec["flags"], "-I", support, define, "-DINCLUDEMAIN",
           src, io, "-o", exe]
    built = subprocess.run(cmd, capture_output=True, text=True)
    if built.returncode != 0 or not os.path.exists(exe):
        return "unbuilt"

    env = dict(os.environ, **spec["env"])
    saw_timeout = False
    try:
        for _ in range(repeats):
            try:
                run = subprocess.run(
                    [*spec["wrapper"], exe], capture_output=True, text=True,
                    timeout=timeout, env=env, stdin=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired as e:
                # A killed run has usually already said what it found. ASan on
                # this host prints its entire report and then hangs symbolizing
                # it, so treating a deadline as "nothing happened" scores a
                # located stack-buffer-overflow as a miss.
                partial = (e.stdout or b"") + (e.stderr or b"")
                if isinstance(partial, bytes):
                    partial = partial.decode("utf-8", "replace")
                if want(partial):
                    return "caught"
                # No retry otherwise. A case that blocks blocks every time --
                # `listen_socket` waits on accept() for a peer that never comes.
                saw_timeout = True
                break
            blob = (run.stdout or "") + (run.stderr or "")
            if want(blob):
                return "caught"
    finally:
        if os.path.exists(exe):
            os.unlink(exe)
    return "timeout" if saw_timeout else "clean"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--cwe", action="append", type=int)
    ap.add_argument("--profile", help="override the per-CWE default")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--repeats", type=int, default=3,
                    help="runs per case; rand-sourced flaws are taken only "
                         "on some runs")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--json-out")
    args = ap.parse_args()

    testcases = os.path.join(args.root, "testcases")
    support = os.path.join(args.root, "testcasesupport")

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "sj", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "score-juliet.py"))
    sj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sj)

    wanted = {d: c for d, c in sj.TARGETS.items()
              if (not args.cwe or c in args.cwe) and c in DEFAULT_PROFILE}

    results = {}
    for dirname, cwe in sorted(wanted.items(), key=lambda kv: kv[1]):
        base = os.path.join(testcases, dirname)
        if not os.path.isdir(base):
            continue
        prof = args.profile or DEFAULT_PROFILE[cwe]
        files = sample(base, args.limit)
        if not files:
            continue

        with tempfile.TemporaryDirectory() as work:
            spec_cls = CLASS_RE.get(cwe, r".")
            if callable(spec_cls):
                want = spec_cls
            else:
                rx = re.compile(spec_cls, re.I)
                # Both must hold: a sanitizer said something, and what it said
                # is the class under test.
                want = lambda t, rx=rx: bool(REPORT_RE.search(t) and rx.search(t))

            def score(src):
                return (build_and_run(src, support, prof, "bad",
                                      args.repeats, args.timeout, work, want),
                        build_and_run(src, support, prof, "good",
                                      args.repeats, args.timeout, work, want))
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                outcomes = list(pool.map(score, files))

        bad = [b for b, _ in outcomes]
        good = [g for _, g in outcomes]
        runnable = sum(1 for b in bad if b in ("caught", "clean"))
        caught = bad.count("caught")
        fp = good.count("caught")
        good_runnable = sum(1 for g in good if g in ("caught", "clean"))

        results[cwe] = {
            "profile": prof, "cases": len(files),
            "caught": caught, "runnable": runnable,
            "unbuilt": bad.count("unbuilt"), "timeout": bad.count("timeout"),
            "false_positives": fp, "good_runnable": good_runnable,
        }
        rec = 100.0 * caught / runnable if runnable else 0.0
        fpr = 100.0 * fp / good_runnable if good_runnable else 0.0
        print(f"CWE-{cwe:<4} [{prof:<8}] caught {caught:>3}/{runnable:<3} "
              f"({rec:5.1f}% of runnable)   FP {fp:>3}/{good_runnable:<3} "
              f"({fpr:5.1f}%)   unreached {len(files)-runnable:>3}/{len(files)}"
              f"  [unbuilt {bad.count('unbuilt')}, timeout {bad.count('timeout')}]")

    if results:
        c = sum(r["caught"] for r in results.values())
        n = sum(r["runnable"] for r in results.values())
        f = sum(r["false_positives"] for r in results.values())
        g = sum(r["good_runnable"] for r in results.values())
        tot = sum(r["cases"] for r in results.values())
        print(f"\nTOTAL    caught {c}/{n} ({100.0*c/n if n else 0:.1f}% of runnable)"
              f"   FP {f}/{g} ({100.0*f/g if g else 0:.1f}%)"
              f"   unreached {tot-n}/{tot}")
        print("\n'runnable' excludes cases that would not build or timed out. "
              "'unreached'\nis the dynamic layer's real ceiling: a flaw behind "
              "input or a random value\nis not a miss, it is a path the run "
              "never took.")

    if args.json_out:
        json.dump(results, open(args.json_out, "w"), indent=1)


if __name__ == "__main__":
    main()
