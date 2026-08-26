#!/usr/bin/env python3
"""Score ESBMC, a bounded model checker, against the Juliet suite.

Scored the same way as the sanitizers: `-DOMITGOOD` leaves only the flawed
function, `-DOMITBAD` only the corrected ones, so recall and false positives
come from the same cases.

ESBMC is a different kind of engine from anything else Kordon runs. It encodes
the program as an SMT formula and asks a solver whether a property can be
violated, so when it reports something it hands back a concrete counterexample,
and when it *fails* to report something within its bound that is a bounded
proof rather than an absence of evidence.

Two things about the output have to be handled or the numbers are nonsense:

  * an **unwinding assertion** is ESBMC saying "I could not unroll this loop
    far enough", not "there is a defect here". It arrives through the same
    `VERIFICATION FAILED` channel as a real violation and must never be counted
    as one.
  * a **timeout** is not a clean result either. BMC cost grows sharply with
    the bound, and `--function` mode on a library routine with unconstrained
    parameters routinely does not terminate at all.
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

ESBMC = "third_party/esbmc/bin/esbmc"

# A real property violation. ESBMC names the class in the text and, usefully,
# prints the CWE ids itself -- the only engine here that does.
VIOLATION_RE = re.compile(
    r"dereference failure|array bounds violated|arithmetic overflow|"
    r"division by zero|invalid pointer|memory leak|"
    r"same object violation|NaN|assertion")

# "I gave up", not "I found something". Reported through the same channel.
GAVE_UP_RE = re.compile(r"unwinding assertion")


def sample(base, limit):
    files = []
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            if not n.endswith((".c", ".cpp")):
                continue
            if re.search(r"_\d+[a-e]\.(c|cpp)$", n):
                continue
            if re.search(r"_\d+_(bad|good\w*)\.(c|cpp)$", n):
                continue
            if "w32" in n:
                continue
            files.append(os.path.join(dirpath, n))
    files.sort()
    if len(files) > limit:
        stride = len(files) / limit
        files = [files[int(i * stride)] for i in range(limit)]
    return files


def run_one(src, support, side, unwind, timeout):
    """'violation', 'clean', 'gave_up', 'timeout' or 'error' for one side."""
    define = "-DOMITGOOD" if side == "bad" else "-DOMITBAD"
    cmd = [ESBMC, src, "--z3", "--unwind", str(unwind),
           "-I", support, "-DINCLUDEMAIN", define, "--no-library"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timeout"
    blob = (r.stdout or "") + (r.stderr or "")

    if "VERIFICATION SUCCESSFUL" in blob:
        return "clean"
    if "VERIFICATION FAILED" in blob:
        # Order matters: a run can hit its unwinding limit *and* find a real
        # violation, and the real one is what counts.
        if VIOLATION_RE.search(blob):
            return "violation"
        if GAVE_UP_RE.search(blob):
            return "gave_up"
        return "gave_up"
    return "error"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--cwe", action="append", type=int)
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--unwind", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--json-out")
    args = ap.parse_args()

    args.root = os.path.abspath(args.root)
    testcases = os.path.join(args.root, "testcases")
    support = os.path.join(args.root, "testcasesupport")

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "sj", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "score-juliet.py"))
    sj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sj)

    wanted = {d: c for d, c in sj.target_dirs(testcases).items()
              if not args.cwe or c in args.cwe}

    results = {}
    for dirname, cwe in sorted(wanted.items(), key=lambda kv: kv[1]):
        base = os.path.join(testcases, dirname)
        files = sample(base, args.limit)
        if not files:
            continue

        def score(src):
            return (run_one(src, support, "bad", args.unwind, args.timeout),
                    run_one(src, support, "good", args.unwind, args.timeout))

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            out = list(pool.map(score, files))

        bad = [b for b, _ in out]
        good = [g for _, g in out]
        # Only cases where ESBMC reached a verdict at all are scorable.
        decided = sum(1 for b in bad if b in ("violation", "clean"))
        found = bad.count("violation")
        fp = good.count("violation")
        good_decided = sum(1 for g in good if g in ("violation", "clean"))

        results[cwe] = {
            "cases": len(files), "found": found, "decided": decided,
            "fp": fp, "good_decided": good_decided,
            "gave_up": bad.count("gave_up"), "timeout": bad.count("timeout"),
            "error": bad.count("error"),
        }
        r = results[cwe]
        rec = 100.0 * found / decided if decided else 0.0
        fpr = 100.0 * fp / good_decided if good_decided else 0.0
        print(f"CWE-{cwe:<4} found {found:>3}/{decided:<3} ({rec:5.1f}% of decided)   "
              f"FP {fp:>3}/{good_decided:<3} ({fpr:5.1f}%)   "
              f"undecided {len(files)-decided:>3}/{len(files)} "
              f"[gave up {r['gave_up']}, timeout {r['timeout']}, error {r['error']}]")

    if results:
        f = sum(r["found"] for r in results.values())
        d = sum(r["decided"] for r in results.values())
        p = sum(r["fp"] for r in results.values())
        g = sum(r["good_decided"] for r in results.values())
        t = sum(r["cases"] for r in results.values())
        print(f"\nTOTAL   found {f}/{d} ({100.0*f/d if d else 0:.1f}% of decided)   "
              f"FP {p}/{g} ({100.0*p/g if g else 0:.1f}%)   undecided {t-d}/{t}")
        print("\n'undecided' is the honest ceiling: an unwinding assertion means the")
        print("bound was too small, and a timeout means the formula was too big. Neither")
        print("is a clean result and neither is a finding.")

    if args.json_out:
        json.dump(results, open(args.json_out, "w"), indent=1)


if __name__ == "__main__":
    main()
