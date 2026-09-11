#!/usr/bin/env python3
"""Why isn't recall 100%? Bucket every flawed function by the *shape* of its
defect and show the detection rate for each.

Juliet states the shape in every file's header -- `BadSource:` for where the
bad value comes from, `BadSink :` for what is done with it -- and that pairing,
not the CWE, is what decides whether any engine can see the defect.

Grouping by the `Flow Variant:` line instead was tried first and is useless:
the buckets hold one to four cases each, and each mixes unrelated shapes, so
the baseline variant came out looking harder than a goto.

    scripts/explain-misses.py 121                    # 40 files, default flags
    scripts/explain-misses.py 121 --limit 60 --misses
    scripts/explain-misses.py 121 -- --ctu           # flags after -- go to kordon

`--misses` lists the flawed functions nothing reported, one per line as
`file:line name`, which is where a lane picks the case to reduce into a
fixture. `--found` lists the hits the same way.

The Juliet root is `third_party/juliet/C` under the repo (or a lane's symlink
to it), overridable with `--root` or `$KORDON_JULIET`. It is always made
absolute -- see the note in score-juliet.py on what a relative root silently
does to the measurement.
"""
import argparse
import collections
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

spec = importlib.util.spec_from_file_location("sj", os.path.join(HERE, "score-juliet.py"))
sj = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sj)


def resolve_dir(testcases, cwe_or_name):
    """Accept a CWE number or a directory name; match on the number only,
    because the suite's own spelling is not stable (`Divide_by_Zero`)."""
    if os.path.isdir(os.path.join(testcases, cwe_or_name)):
        name = cwe_or_name
    else:
        n = int(re.sub(r"\D", "", cwe_or_name))
        hits = [d for d in os.listdir(testcases) if re.match(rf"CWE{n}_", d)]
        if not hits:
            sys.exit(f"no CWE-{n} directory under {testcases}")
        name = hits[0]
    return name, int(re.match(r"CWE(\d+)_", name).group(1))


def variant(path):
    """Group by the shape of the defect -- what decides whether any engine can
    see it -- rather than the control-flow wrapper, whose buckets are too small
    to read and which mixes shapes together."""
    try:
        head = open(path, encoding="utf-8", errors="replace").read(4000)
    except OSError:
        return "?"
    m = re.search(r"BadSource:\s*(\S*)", head)
    s = m.group(1) if m and m.group(1) else "direct"
    n = re.search(r"BadSink\s*:\s*(.*)", head)
    k = n.group(1).strip()[:44] if n else "-"
    return f"{s:<14} {k}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cwe", help="CWE number (121) or Juliet directory name")
    ap.add_argument("--root", default=os.environ.get("KORDON_JULIET")
                    or os.path.join(REPO, "third_party", "juliet", "C"))
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--kordon", default=os.path.join(REPO, "target", "release", "kordon"))
    ap.add_argument("--jobs", type=int, default=20)
    ap.add_argument("--misses", action="store_true", help="list the flawed functions not found")
    ap.add_argument("--found", action="store_true", help="list the flawed functions found")
    ap.add_argument("--multifile", action="store_true",
                    help="the split cases (_54a.._54e, _81.._84) instead of single-file ones")
    ap.add_argument("kordon_args", nargs="*", help="extra kordon flags, after --")
    # Split at `--` ourselves. argparse consumes a trailing `nargs="*"`
    # positional greedily at the first positional chunk, so `590 --misses --
    # --ctu` leaves `-- --ctu` unrecognised rather than handing `--ctu` on.
    argv = sys.argv[1:]
    passthrough = []
    if "--" in argv:
        i = argv.index("--")
        argv, passthrough = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    args.kordon_args = [*args.kordon_args, *passthrough]

    root = os.path.abspath(args.root)
    testcases, support = os.path.join(root, "testcases"), os.path.join(root, "testcasesupport")
    if not os.path.isdir(testcases):
        sys.exit(f"no testcases/ under {root} -- run scripts/setup-juliet.sh")
    dirname, cwe = resolve_dir(testcases, args.cwe)
    base = os.path.join(testcases, dirname)

    files, groups = [], {}
    for dp, _, ns in os.walk(base):
        for n in sorted(ns):
            if not n.endswith((".c", ".cpp")):
                continue
            split = re.search(r"_(\d+)[a-e]\.(c|cpp)$", n) or \
                re.search(r"_(8\d)(?:_\w+)?\.(c|cpp)$", n)
            if args.multifile:
                if split:
                    key = os.path.join(dp, n[: split.start()] + split.group(1))
                    groups.setdefault(key, []).append(os.path.join(dp, n))
            elif not split:
                files.append(os.path.join(dp, n))
    if args.multifile:
        chosen = sorted(groups)
        if len(chosen) > args.limit:
            stride = len(chosen) / args.limit
            chosen = [chosen[int(i * stride)] for i in range(args.limit)]
        files = [f for k in chosen for f in sorted(groups[k])]
    if cwe in sj.EXCLUDED:
        pat, _ = sj.EXCLUDED[cwe]
        files = [f for f in files if not pat.search(os.path.basename(f))]
    files.sort()
    if not args.multifile and len(files) > args.limit:
        stride = len(files) / args.limit
        files = [files[int(i * stride)] for i in range(args.limit)]

    if not files:
        sys.exit(f"CWE-{cwe}: no {'multi-file' if args.multifile else 'single-file'} cases "
                 f"in {dirname}")

    truth = {os.path.realpath(f): sj.function_ranges(f) for f in files}
    with tempfile.TemporaryDirectory() as db:
        json.dump([{"directory": os.path.dirname(f), "file": os.path.realpath(f),
                    "arguments": ["clang++" if f.endswith(".cpp") else "clang",
                                  "-I", support, "-D", "INCLUDEMAIN", "-c",
                                  os.path.realpath(f), "-o", "/dev/null"]} for f in files],
                  open(os.path.join(db, "compile_commands.json"), "w"))
        out = subprocess.run([args.kordon, base, "-p", db, "--json", "-j", str(args.jobs),
                              "--all", *args.kordon_args],
                             capture_output=True, text=True, cwd=REPO)
    try:
        rep = json.loads(out.stdout)
    except json.JSONDecodeError:
        sys.exit(f"kordon produced no JSON:\n{out.stderr[-600:]}")
    for e in rep.get("engines", []):
        for note in e.get("notes", []):
            if "FAILED TO COMPILE" in note:
                print(f"! {e['tool']}: {note}", file=sys.stderr)

    accept = sj.EQUIVALENT.get(cwe, {cwe})
    hit = set()
    for f in rep.get("findings", []):
        if f.get("cwe") not in accept:
            continue
        p, l = os.path.realpath(f["file"]), f["line"]
        for name, a, b in truth.get(p, []):
            if a <= l <= b and sj.classify(name) == "bad":
                hit.add((p, name))

    stats = collections.defaultdict(lambda: [0, 0])   # variant -> [found, total]
    listing = []
    for p, rs in truth.items():
        v = variant(p)
        for name, a, b in rs:
            if sj.classify(name) != "bad":
                continue
            stats[v][1] += 1
            found = (p, name) in hit
            if found:
                stats[v][0] += 1
            listing.append((found, os.path.relpath(p, root), a, name))

    total = sum(t for _, t in stats.values())
    found_n = sum(f for f, _ in stats.values())
    print(f"CWE-{cwe} ({dirname}): {found_n}/{total} flawed functions found over "
          f"{len(files)} files{' (multi-file cases)' if args.multifile else ''}"
          f"{' with ' + ' '.join(args.kordon_args) if args.kordon_args else ''}\n")
    print("detection rate by defect shape (source | sink)\n")
    for v, (f_, t) in sorted(stats.items(),
                             key=lambda kv: (-kv[1][0] / kv[1][1] if kv[1][1] else 0, kv[0])):
        bar = "#" * round(10 * f_ / t) if t else ""
        print(f"  {100 * f_ / t if t else 0:5.0f}%  {f_:2d}/{t:<2d} {bar:<10}  {v[:66]}")

    if args.misses or args.found:
        print()
        for found, rel, line, name in sorted(listing, key=lambda r: (r[1], r[2])):
            if (found and args.found) or (not found and args.misses):
                tag = "found " if found else "MISSED"
                print(f"  {tag}  {rel}:{line}  {name}")


if __name__ == "__main__":
    main()
