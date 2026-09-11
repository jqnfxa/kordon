#!/usr/bin/env python3
"""Regression harness for testdata/: does Kordon still find what each fixture
says it must, and stay silent where it says it must?

`--require-cwe` only asks "was this class found somewhere in the directory".
That cannot see a check firing on the corrected twin beside the defect, and a
check that flags both has found nothing -- the discrimination that every
fixture in this repo was written to assert was, until now, checked by hand.

A fixture is one directory under testdata/. It is run as a project: a
compile database is generated for it (one entry per .c/.cpp, with the fixture
directory on the include path), exactly as score-juliet.py does for Juliet,
because without one clang-tidy and the bounds analyzer fail to compile a .c
file and report nothing -- which looks like silence.

Expectations live in comments in the fixture's own sources:

    // @kordon cwe: 129, 124          the class(es) this fixture is about
    // @kordon flags: --ctu            extra kordon flags (default: none)
    // @kordon confidence: low         floor: low | medium (default) | high
    // @kordon xfail: <why>            a known flaw is pinned here: failures are
                                       listed but do not fail the run, and a
                                       fixture that passes is reported as XPASS
                                       so the directive gets removed

    // @bad [787]                      on or just above a function: its body
                                       must draw >= 1 finding in the class
    // @good [787]                     ... must draw none
    buf[n] = 0;   // @expect 124       this exact line must draw one
    buf[n] = 0;   // @silent 124       this exact line must draw none

With `cwe:` declared, any function whose name contains `bad` or `good` (any
casing, Juliet's convention) is classified implicitly -- so a fixture written
as `guard_form_bad` / `guard_form_good` needs no per-function markers at all.
Explicit markers win over the name.

A class is accepted through the same EQUIVALENT table score-juliet.py uses,
so a stack overflow reported as CWE-787 satisfies `@bad 121`. Silence is
always silence *with respect to the fixture's class*: a correct CWE-120 on a
function marked `@good 457` is reported as information, never as a failure.

    scripts/check-fixtures.py                 # every fixture
    scripts/check-fixtures.py --only one_sided_index --verbose
    scripts/check-fixtures.py --compile-only  # just the syntax check

Exit status is non-zero if any expectation failed or any fixture failed to
compile. Fixtures with no markers at all are listed as unmarked, which is a
to-do rather than a failure.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TESTDATA = os.path.join(REPO, "testdata")

spec = importlib.util.spec_from_file_location("sj", os.path.join(HERE, "score-juliet.py"))
sj = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sj)

SOURCES = (".c", ".cpp", ".cc", ".cxx")
HEADERS = (".h", ".hpp", ".hh")
RANK = {"low": 0, "medium": 1, "high": 2}

DIRECTIVE_RE = re.compile(r"@kordon\s+(cwe|flags|confidence|xfail)\s*:\s*(.*?)\s*(?:\*/)?\s*$")
MARKER_RE = re.compile(r"@(bad|good|expect|silent)\b\s*([\d,\s]*)")


def parse_cwes(text, default):
    ids = [int(x) for x in re.findall(r"\d+", text or "")]
    return ids or list(default)


def accept_set(cwes):
    out = set()
    for c in cwes:
        out |= sj.EQUIVALENT.get(c, {c})
        out.add(c)
    return out


def body_range(lines, start):
    """(first, last) 1-based line range of the function body whose signature
    is at or just after `start` (0-based). Scans forward for the opening brace,
    then tracks depth. Hand-written fixtures keep braces balanced per line
    closely enough for this; a string literal containing a brace would break it
    and none of the fixtures has one."""
    j, depth, started = start, 0, False
    limit = min(len(lines), start + 12)
    while j < len(lines):
        line = lines[j]
        if not started and j >= limit:
            return None
        if not started and ";" in line and "{" not in line and j > start:
            # a prototype or a statement, not a definition
            return None
        depth += line.count("{") - line.count("}")
        if "{" in line:
            started = True
        if started and depth <= 0:
            return (start + 1, j + 1)
        j += 1
    return None


def load_fixture(fdir):
    """Directives, explicit markers and implicit (name-based) functions."""
    fx = {"cwe": [], "flags": [], "confidence": "medium", "xfail": None,
          "funcs": [], "lines": [], "files": []}
    for name in sorted(os.listdir(fdir)):
        path = os.path.join(fdir, name)
        if not name.endswith(SOURCES + HEADERS) or not os.path.isfile(path):
            continue
        fx["files"].append(path)
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        explicit = set()
        for i, line in enumerate(lines):
            d = DIRECTIVE_RE.search(line)
            if d:
                key, val = d.group(1), d.group(2)
                if key == "cwe":
                    fx["cwe"] = parse_cwes(val, [])
                elif key == "flags":
                    fx["flags"] = val.split()
                elif key == "confidence":
                    fx["confidence"] = val.strip().lower()
                elif key == "xfail":
                    fx["xfail"] = val.strip() or "known flaw"
                continue
            for m in MARKER_RE.finditer(line):
                kind, ids = m.group(1), m.group(2)
                if kind in ("expect", "silent"):
                    fx["lines"].append({"kind": kind, "file": path, "line": i + 1,
                                        "cwe": parse_cwes(ids, fx["cwe"])})
                else:
                    rng = body_range(lines, i)
                    if not rng:
                        fx["lines"].append({"kind": "broken", "file": path, "line": i + 1,
                                            "cwe": [], "why": f"@{kind}: no function body follows"})
                        continue
                    fx["funcs"].append({"kind": kind, "file": path, "range": rng,
                                        "name": func_name(lines, i), "cwe": parse_cwes(ids, []),
                                        "explicit": True})
                    explicit.add(rng)
        # Implicit classification by name, Juliet style, only where the fixture
        # says which class it is about.
        if fx["cwe"] and name.endswith(SOURCES + HEADERS):
            for fname, a, b in sj.function_ranges(path):
                if any(a <= r[0] <= b or r[0] <= a <= r[1] for r in explicit):
                    continue
                fx["funcs"].append({"kind": sj.classify(fname), "file": path, "range": (a, b),
                                    "name": fname, "cwe": [], "explicit": False})
    # Markers without their own ids inherit the fixture's class.
    for f in fx["funcs"]:
        if not f["cwe"]:
            f["cwe"] = list(fx["cwe"])
    return fx


def func_name(lines, i):
    for j in range(i, min(len(lines), i + 12)):
        m = sj.FUNC_RE.match(lines[j])
        if m and not lines[j].rstrip().endswith(";"):
            # keep a qualifier if there is one: `Buffer::init`
            q = re.search(r"([\w:~]+)\s*\(", lines[j])
            return q.group(1) if q else m.group(1)
    return f"<line {i + 1}>"


def compile_check(fdir, files):
    """Every source must parse. A fixture that does not still produces
    findings -- clang analyses the wreckage -- so findings alone are not
    evidence that a fixture is valid."""
    errors = []
    for f in files:
        if not f.endswith(SOURCES):
            continue
        cc = ["clang", "-std=c11"] if f.endswith(".c") else ["clang++", "-std=c++17"]
        r = subprocess.run([*cc, "-fsyntax-only", "-UNDEBUG", "-I", fdir, f],
                           capture_output=True, text=True)
        if r.returncode != 0:
            first = (r.stderr.strip().split("\n") or ["?"])[0]
            errors.append(f"{os.path.relpath(f, fdir)}: {first}")
    return errors


def run_kordon(kordon, fdir, files, flags, jobs):
    with tempfile.TemporaryDirectory() as db:
        entries = []
        for f in files:
            if not f.endswith(SOURCES):
                continue
            cc = ["clang", "-std=c11"] if f.endswith(".c") else ["clang++", "-std=c++17"]
            entries.append({"directory": fdir, "file": f,
                            "arguments": [*cc, "-I", fdir, "-UNDEBUG", "-c", f, "-o", "/dev/null"]})
        with open(os.path.join(db, "compile_commands.json"), "w") as fh:
            json.dump(entries, fh)
        proc = subprocess.run([kordon, fdir, "-p", db, "--json", "--all", "-j", str(jobs), *flags],
                              capture_output=True, text=True, cwd=REPO)
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, proc.stderr[-600:]


def evaluate(fx, report):
    floor = RANK.get(fx["confidence"], 1)
    findings = []
    for f in report.get("findings", []):
        if not f.get("in_scope") or f.get("cwe") is None:
            continue
        findings.append({"file": os.path.realpath(f["file"]), "line": f["line"],
                         "cwe": f["cwe"], "conf": f.get("confidence"),
                         "rank": RANK.get(f.get("confidence"), 0),
                         "ids": f.get("native_ids") or []})
    for d in report.get("dynamic_findings", []) or []:
        if d.get("cwe") is not None:
            findings.append({"file": os.path.realpath(d["file"]), "line": d["line"],
                             "cwe": d["cwe"], "conf": "high", "rank": 2,
                             "ids": [d.get("native_id", "dynamic")]})

    failures, passes, notes = [], 0, []

    def in_class(f, acc):
        return f["cwe"] in acc and f["rank"] >= floor

    for fn in fx["funcs"]:
        acc = accept_set(fn["cwe"])
        path = os.path.realpath(fn["file"])
        a, b = fn["range"]
        inside = [f for f in findings if f["file"] == path and a <= f["line"] <= b]
        hits = [f for f in inside if in_class(f, acc)]
        where = f"{os.path.basename(fn['file'])}:{a}-{b}"
        cls = ",".join(str(c) for c in fn["cwe"]) or "?"
        if fn["kind"] == "bad":
            if hits:
                passes += 1
            else:
                below = [f for f in inside if f["cwe"] in acc]
                extra = (f" (only below the {fx['confidence']} floor: "
                         + ", ".join(f"{f['conf']} {'/'.join(f['ids'])}" for f in below) + ")"
                         if below else "")
                failures.append(f"bad  {fn['name']} {where}: no CWE-{cls} finding{extra}")
        else:
            if hits:
                failures.append(f"good {fn['name']} {where}: flagged CWE-{cls} -- "
                                + "; ".join(f"line {f['line']} {f['conf']} {'/'.join(f['ids'])}"
                                            for f in hits))
            else:
                passes += 1
                other = {f["cwe"] for f in inside if f["rank"] >= floor} - acc
                if other:
                    notes.append(f"{fn['name']}: also draws CWE-"
                                 + ",".join(str(c) for c in sorted(other))
                                 + " (a different class; not judged here)")

    for lm in fx["lines"]:
        if lm["kind"] == "broken":
            failures.append(f"{os.path.basename(lm['file'])}:{lm['line']}: {lm['why']}")
            continue
        acc = accept_set(lm["cwe"])
        path = os.path.realpath(lm["file"])
        at = [f for f in findings if f["file"] == path and f["line"] == lm["line"]
              and in_class(f, acc)]
        cls = ",".join(str(c) for c in lm["cwe"])
        where = f"{os.path.basename(lm['file'])}:{lm['line']}"
        if lm["kind"] == "expect":
            if at:
                passes += 1
            else:
                failures.append(f"expect {where}: no CWE-{cls} finding on this line")
        else:
            if at:
                failures.append(f"silent {where}: flagged CWE-{cls} by "
                                + ", ".join("/".join(f["ids"]) for f in at))
            else:
                passes += 1
    return failures, passes, notes, findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", help="fixture directory name (repeatable)")
    ap.add_argument("--kordon", default=os.path.join(REPO, "target", "release", "kordon"))
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--compile-only", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print every in-scope finding in each fixture")
    ap.add_argument("--flags", default="", help="extra kordon flags for every fixture, "
                    "e.g. --flags=--ctu (a fixture's own flags are added too)")
    args = ap.parse_args()

    if not args.compile_only and not os.access(args.kordon, os.X_OK):
        sys.exit(f"no kordon binary at {args.kordon} -- run cargo build --release")

    names = sorted(d for d in os.listdir(TESTDATA) if os.path.isdir(os.path.join(TESTDATA, d)))
    if args.only:
        missing = [n for n in args.only if n not in names]
        if missing:
            sys.exit(f"no such fixture: {', '.join(missing)}")
        names = [n for n in names if n in args.only]

    bad, unmarked, total_checks = 0, [], 0
    for name in names:
        fdir = os.path.join(TESTDATA, name)
        fx = load_fixture(fdir)
        if not fx["files"] or name == "dynamic":
            # testdata/dynamic is a CMake project for the sanitizer layer and
            # is exercised by its own path, not this one.
            continue
        errs = compile_check(fdir, fx["files"])
        if errs:
            bad += 1
            print(f"  FAIL  {name:<26} does not compile")
            for e in errs:
                print(f"          {e}")
            continue
        if args.compile_only:
            print(f"  ok    {name:<26} compiles")
            continue
        if not fx["funcs"] and not fx["lines"]:
            unmarked.append(name)
            print(f"  ----  {name:<26} unmarked (no @kordon cwe / @bad / @good / @expect)")
            continue

        flags = [*fx["flags"], *args.flags.split()]
        report, err = run_kordon(args.kordon, fdir, fx["files"], flags, args.jobs)
        if report is None:
            bad += 1
            print(f"  FAIL  {name:<26} kordon produced no JSON\n          {err}")
            continue
        failures, passes, notes, findings = evaluate(fx, report)
        total_checks += passes + len(failures)
        nb = sum(1 for f in fx["funcs"] if f["kind"] == "bad")
        ng = sum(1 for f in fx["funcs"] if f["kind"] == "good")
        nl = len(fx["lines"])
        summary = (f"{passes}/{passes + len(failures)} checks "
                   f"({nb} bad, {ng} good, {nl} line)"
                   + (f"  floor={fx['confidence']}" if fx["confidence"] != "medium" else "")
                   + (f"  [{' '.join(flags)}]" if flags else ""))
        failed_units = [n for e in report.get("engines", []) for n in e.get("notes", [])
                        if "FAILED TO COMPILE" in n]
        if failures and fx["xfail"]:
            # A pinned flaw. The failures are the point of the fixture; they
            # are shown so the lane fixing it can watch them go, and they do
            # not fail the run.
            print(f"  xfail {name:<26} {summary}  ({len(failures)} known: {fx['xfail']})")
            for f in failures:
                print(f"          {f}")
        elif failures:
            bad += 1
            print(f"  FAIL  {name:<26} {summary}")
            for f in failures:
                print(f"          {f}")
        elif fx["xfail"]:
            bad += 1
            print(f"  XPASS {name:<26} {summary} -- the pinned flaw no longer reproduces; "
                  f"remove the `@kordon xfail:` directive")
        else:
            print(f"  ok    {name:<26} {summary}")
        for n in failed_units:
            print(f"          ! {n}")
        for n in notes:
            print(f"          . {n}")
        if args.verbose:
            for f in sorted(findings, key=lambda f: (f["file"], f["line"])):
                print(f"            {os.path.basename(f['file'])}:{f['line']:<4} "
                      f"CWE-{f['cwe']:<4} {f['conf']:<7} {'/'.join(f['ids'])}")

    print()
    if unmarked:
        print(f"{len(unmarked)} unmarked fixture(s) -- add `@kordon cwe:` or explicit markers: "
              + ", ".join(unmarked))
    if bad:
        print(f"{bad} fixture(s) FAILED")
    else:
        print(f"all marked fixtures pass ({total_checks} checks)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
