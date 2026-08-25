#!/usr/bin/env python3
"""Score Kordon against the NIST Juliet C/C++ test suite.

Juliet is the only labelled ground truth of any size for this defect class.
Every test case ships a flawed function and a corrected counterpart in the same
file, named `..._bad` and `..._good*`, so a finding can be scored without
anyone deciding by hand whether it is real:

  * a finding inside a `_bad` function is a **hit**;
  * a finding inside a `_good*` function is a **false positive**, unambiguously
    -- the whole point of those functions is that the defect is not there.

That second number is the one Kordon has never been able to produce. Measuring
on real projects gives a count of findings and no way to know how many are
wrong; measuring on the raw/fixed pair of one real project gives responsiveness
but not precision.

**Juliet is synthetic, and its scores do not transfer to real code.** Cases are
wrapped in flow-variant scaffolding (`if(GLOBAL_CONST_TRUE)`, `goodG2B` and
`goodB2G` splits) that exists to defeat pattern matching and looks like nothing
anyone writes. A tool can score well here and still miss what matters: the
defects this project found by comparing a function against a correct sibling
have no analogue anywhere in the suite. Read these numbers as per-CWE coverage
of the *mechanical* cases, and keep the real-project measurements alongside.

Usage:
    scripts/setup-juliet.sh                 # fetch and unpack the suite
    scripts/score-juliet.py <juliet-root>   # e.g. /tmp/.../juliet/C
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

# Juliet directory name -> the CWE Kordon should report for it.
#
# Restricted to Kordon's Tier 1 scope. The suite also covers injection and
# access-control classes that are deliberately out of scope, and scoring those
# would measure a promise Kordon never made.
TARGETS = {
    "CWE121_Stack_Based_Buffer_Overflow": 121,
    "CWE122_Heap_Based_Buffer_Overflow": 122,
    "CWE124_Buffer_Underwrite": 124,
    "CWE126_Buffer_Overread": 126,
    "CWE127_Buffer_Underread": 127,
    "CWE190_Integer_Overflow": 190,
    "CWE191_Integer_Underflow": 191,
    "CWE369_Divide_By_Zero": 369,
    "CWE401_Memory_Leak": 401,
    "CWE415_Double_Free": 415,
    "CWE416_Use_After_Free": 416,
    "CWE457_Use_of_Uninitialized_Variable": 457,
    "CWE476_NULL_Pointer_Dereference": 476,
    "CWE562_Return_of_Stack_Variable_Address": 562,
    "CWE563_Unused_Variable": 563,
    "CWE590_Free_Memory_Not_on_Heap": 590,
    "CWE762_Mismatched_Memory_Management_Routines": 762,
    "CWE775_Missing_Release_of_File_Descriptor_or_Handle": 775,
}

# CWEs that count as reporting the target. A tool that calls a stack overflow
# CWE-787 rather than CWE-121 has found the defect; insisting on the exact id
# would measure the mapping table's vocabulary rather than detection.
EQUIVALENT = {
    121: {121, 787, 788, 119, 125, 129, 786},
    122: {122, 787, 788, 119, 125, 129, 786},
    124: {124, 786, 787, 119, 125, 129},
    126: {126, 125, 788, 119, 129},
    127: {127, 125, 786, 119, 129},
    # Not 197. `bugprone-narrowing-conversions` fires on `data + 1` being
    # narrowed back to char, which is a different observation that happens to
    # land on the same line -- and it fires identically on goodG2B and goodB2G,
    # where the overflow is guarded. Counting it credited a check that does not
    # discriminate, and read as 64% recall where real detection was zero.
    190: {190, 680},
    191: {191},
    401: {401, 772},
    415: {415, 416},
    416: {416, 415, 825},
    457: {457, 824, 908},
    476: {476, 690, 252},
    562: {562, 825},
    563: {563},
    590: {590, 762, 763},
    762: {762, 763, 590},
    775: {775, 772, 404},
    369: {369},
}

# Any function definition at file scope. The name decides whether it is
# ground truth, and which side.
FUNC_RE = re.compile(
    r"^\s*(?:static\s+)?(?:void|int|char|short|long|float|double|unsigned)"
    r"[\w\s\*]*?\b(\w+)\s*\("
)

# `..._bad` holds the flaw. The corrected code lives in `goodG2B` / `goodB2G`,
# which carry no underscore prefix -- requiring one counted only the `..._good`
# wrapper, and that wrapper just calls the others, so every false positive
# landed in a function the scorer was not looking at.
# Also `_54e_badSink` / `_54b_goodG2BSink`: in the multi-file cases the defect
# does not live in a function called `..._bad`, it lives in a sink several
# translation units away that the entry function feeds.
NAME_RE = re.compile(r"(?:_bad\w*|_good\w*)$|^(?:good|bad)\w*$")


def function_ranges(path):
    """Map each bad/good function to its (start, end) line range.

    Juliet's formatting is machine-generated and uniform -- one statement per
    line, braces in column zero at function scope -- so counting braces is
    reliable here in a way it would not be on hand-written code.
    """
    ranges = []
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ranges

    i = 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        if not NAME_RE.search(name):
            i += 1
            continue
        # Find the opening brace, then track depth to the matching close.
        depth, started, start = 0, False, i + 1
        j = i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        ranges.append((name, start, j + 1))
        i = j + 1
    return ranges


def classify(name):
    # The C variants name the flawed function `<testcase>_bad`; the C++ ones
    # put a bare `bad()` inside a namespace. Testing only for the underscore
    # form scored every C++ flaw as a correct function, which turned real
    # detections into false positives and left those CWEs reporting no flawed
    # functions at all.
    # Every function on the flawed path carries `bad` and every one on a
    # corrected path carries `good` -- including `goodG2B`, whose *sink* is the
    # bad one but whose source makes the whole thing safe. Matching the
    # substring rather than a suffix covers `_bad`, the bare `bad()` the C++
    # variants put in a namespace, and `_54e_badSink` alike.
    return "bad" if "bad" in name and "good" not in name else "good"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="Juliet C directory (contains testcases/)")
    ap.add_argument("--kordon", default="./target/release/kordon")
    ap.add_argument("--cwe", action="append", type=int,
                    help="only these CWEs (repeatable); default all in TARGETS")
    ap.add_argument("--limit", type=int, default=60,
                    help="max test files per CWE (the suite has thousands)")
    ap.add_argument("--jobs", type=int, default=20)
    ap.add_argument("--json-out", help="write the raw per-CWE result here")
    ap.add_argument("--multifile", action="store_true",
                    help="score ONLY the cases split across translation units "
                         "(_54a.._54e, _81.._84). The defect sits in a sink "
                         "several units from the value that makes it a defect, "
                         "so this is what --ctu exists for; the default sample "
                         "excludes them and cannot show CTU any credit.")
    ap.add_argument("--kordon-arg", action="append", default=[],
                    help="extra flag for kordon, repeatable (e.g. --kordon-arg=--ikos). "
                         "CWE-190 scores zero without --ikos and is caught with a proof "
                         "with it, so the baseline must say which was used.")
    args = ap.parse_args()

    testcases = os.path.join(args.root, "testcases")
    support = os.path.join(args.root, "testcasesupport")
    if not os.path.isdir(testcases):
        sys.exit(f"no testcases/ under {args.root}")

    wanted = {d: c for d, c in TARGETS.items()
              if not args.cwe or c in args.cwe}

    results = {}
    for dirname, cwe in sorted(wanted.items(), key=lambda kv: kv[1]):
        base = os.path.join(testcases, dirname)
        if not os.path.isdir(base):
            print(f"CWE-{cwe}: not present in this suite", file=sys.stderr)
            continue

        # Single-file variants only. Juliet splits some cases across `_54a.c`
        # .. `_54e.c` to force inter-procedural, cross-file reasoning; those
        # measure the CTU gap rather than the checks, and Kordon reports that
        # gap separately.
        files = []
        groups = {}
        for dirpath, _, names in os.walk(base):
            for n in sorted(names):
                if not n.endswith((".c", ".cpp")):
                    continue
                split = re.search(r"_(\d+)[a-e]\.(c|cpp)$", n) or \
                    re.search(r"_(8\d)(?:_\w+)?\.(c|cpp)$", n)
                if args.multifile:
                    if not split:
                        continue
                    # Every part of one case must be in the database together,
                    # or the analyzer never sees the unit holding the sink.
                    key = os.path.join(dirpath, n[: split.start()] + split.group(1))
                    groups.setdefault(key, []).append(os.path.join(dirpath, n))
                else:
                    if split:
                        continue
                    files.append(os.path.join(dirpath, n))

        if args.multifile:
            chosen = sorted(groups)
            if len(chosen) > args.limit:
                stride = len(chosen) / args.limit
                chosen = [chosen[int(i * stride)] for i in range(args.limit)]
            files = [f for k in chosen for f in sorted(groups[k])]
        files.sort()
        # Sample evenly, never a prefix. Juliet names cases
        # `<type>_<source>_<operation>`, so a sorted prefix is entirely one
        # type and one source: the first 20 CWE-190 files are all `char_*`,
        # where `data + 1` promotes to int and no overflow exists. Taking a
        # prefix measured that corner and called it the CWE.
        if not args.multifile and len(files) > args.limit:
            stride = len(files) / args.limit
            files = [files[int(i * stride)] for i in range(args.limit)]
        if not files:
            continue

        # Ground truth first: which lines belong to a flawed function.
        truth = {}
        for f in files:
            truth[os.path.realpath(f)] = function_ranges(f)

        with tempfile.TemporaryDirectory() as db_dir:
            db = [{
                "directory": os.path.dirname(f),
                "file": os.path.realpath(f),
                "arguments": [
                    "clang++" if f.endswith(".cpp") else "clang",
                    "-I", support, "-D", "INCLUDEMAIN",
                    "-c", os.path.realpath(f), "-o", "/dev/null",
                ],
            } for f in files]
            with open(os.path.join(db_dir, "compile_commands.json"), "w") as fh:
                json.dump(db, fh)

            proc = subprocess.run(
                [args.kordon, base, "-p", db_dir, "--json",
                 "-j", str(args.jobs), "--all", *args.kordon_arg],
                capture_output=True, text=True,
            )
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError:
                print(f"CWE-{cwe}: kordon produced no JSON", file=sys.stderr)
                print(proc.stderr[-400:], file=sys.stderr)
                continue

        accept = EQUIVALENT.get(cwe, {cwe})
        # Scored twice: over everything, and over the tiers the report details
        # by default. Kordon counts low-confidence risk patterns but does not
        # show them without --all, so charging them as false positives at full
        # weight measures a different tool than the one a reader sees.
        hits_by_func, fps_by_func = set(), set()
        hits_hi, fps_hi = set(), set()
        for f in report.get("findings", []):
            if f.get("cwe") not in accept:
                continue
            path, line = os.path.realpath(f["file"]), f["line"]
            surfaced = f.get("confidence") in ("high", "medium")
            for name, start, end in truth.get(path, []):
                if start <= line <= end:
                    key = (path, name)
                    bad = classify(name) == "bad"
                    (hits_by_func if bad else fps_by_func).add(key)
                    if surfaced:
                        (hits_hi if bad else fps_hi).add(key)

        all_bad = {(p, n) for p, rs in truth.items()
                   for n, _, _ in rs if classify(n) == "bad"}
        all_good = {(p, n) for p, rs in truth.items()
                    for n, _, _ in rs if classify(n) == "good"}

        results[cwe] = {
            "files": len(files),
            "bad_total": len(all_bad),
            "bad_found": len(hits_by_func & all_bad),
            "good_total": len(all_good),
            "good_flagged": len(fps_by_func & all_good),
            "bad_found_surfaced": len(hits_hi & all_bad),
            "good_flagged_surfaced": len(fps_hi & all_good),
            "failed_units": next(
                (n for e in report.get("engines", [])
                 for n in e.get("notes", []) if "FAILED TO COMPILE" in n),
                None),
        }
        r = results[cwe]
        recall = 100.0 * r["bad_found"] / r["bad_total"] if r["bad_total"] else 0.0
        fpr = 100.0 * r["good_flagged"] / r["good_total"] if r["good_total"] else 0.0
        rec_s = (100.0 * r["bad_found_surfaced"] / r["bad_total"]
                 if r["bad_total"] else 0.0)
        fpr_s = (100.0 * r["good_flagged_surfaced"] / r["good_total"]
                 if r["good_total"] else 0.0)
        # Recall alone flatters a check that fires on everything. What matters
        # is how much more often the flawed function is flagged than the
        # corrected one sitting beside it.
        print(f"CWE-{cwe:<4} recall {recall:5.1f}% ({rec_s:5.1f}% surfaced)   "
              f"FP {fpr:5.1f}% ({fpr_s:5.1f}% surfaced)   "
              f"discrim {recall - fpr:+6.1f}%   "
              f"[{r['bad_found']}/{r['bad_total']} bad, "
              f"{r['good_flagged']}/{r['good_total']} good]")
        if r["failed_units"]:
            print(f"          ! {r['failed_units']}")

    if results:
        tb = sum(r["bad_total"] for r in results.values())
        tf = sum(r["bad_found"] for r in results.values())
        gt = sum(r["good_total"] for r in results.values())
        gf = sum(r["good_flagged"] for r in results.values())
        tfs = sum(r["bad_found_surfaced"] for r in results.values())
        gfs = sum(r["good_flagged_surfaced"] for r in results.values())
        print(f"\nTOTAL    recall {100.0*tf/tb if tb else 0:.1f}% "
              f"({100.0*tfs/tb if tb else 0:.1f}% surfaced)   "
              f"FP {100.0*gf/gt if gt else 0:.1f}% "
              f"({100.0*gfs/gt if gt else 0:.1f}% surfaced)")
        print(f"         {tf}/{tb} flawed functions found, "
              f"{gf}/{gt} correct ones flagged")
        print("\n'surfaced' counts only high- and medium-confidence findings, "
              "the tiers\nthe report details without --all.")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(results, fh, indent=1)


if __name__ == "__main__":
    main()
