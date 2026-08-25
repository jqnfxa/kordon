#!/usr/bin/env python3
"""Why isn't recall 100%? Bucket every flawed function by the *shape* of its
defect and show the detection rate for each.

Juliet states the shape in every file's header -- `BadSource:` for where the
bad value comes from, `BadSink :` for what is done with it -- and that pairing,
not the CWE, is what decides whether any engine can see the defect.

Grouping by the `Flow Variant:` line instead was tried first and is useless:
the buckets hold one to four cases each, and each mixes unrelated shapes, so
the baseline variant came out looking harder than a goto.

    scripts/explain-misses.py CWE121_Stack_Based_Buffer_Overflow 121 60
"""
import json, os, re, subprocess, sys, tempfile, importlib.util, collections

SCR = "/tmp/claude-1000/-home-shard-VsCode-kordon/abdbfaa5-65e4-47f1-a544-5f75063ab55a/scratchpad"
spec = importlib.util.spec_from_file_location("sj", "/home/shard/VsCode/kordon/scripts/score-juliet.py")
sj = importlib.util.module_from_spec(spec); spec.loader.exec_module(sj)

root = f"{SCR}/juliet/C"; support = f"{root}/testcasesupport"
dirname, cwe, limit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
base = os.path.join(root, "testcases", dirname)

files = []
for dp, _, ns in os.walk(base):
    for n in sorted(ns):
        if not n.endswith((".c", ".cpp")): continue
        if re.search(r"_(\d+)[a-e]\.(c|cpp)$", n) or re.search(r"_(8\d)(?:_\w+)?\.(c|cpp)$", n): continue
        files.append(os.path.join(dp, n))
files.sort()
if len(files) > limit:
    stride = len(files)/limit
    files = [files[int(i*stride)] for i in range(limit)]

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

truth = {os.path.realpath(f): sj.function_ranges(f) for f in files}
with tempfile.TemporaryDirectory() as db:
    json.dump([{"directory": os.path.dirname(f), "file": os.path.realpath(f),
                "arguments": ["clang++" if f.endswith(".cpp") else "clang",
                              "-I", support, "-D", "INCLUDEMAIN", "-c",
                              os.path.realpath(f), "-o", "/dev/null"]} for f in files],
              open(os.path.join(db, "compile_commands.json"), "w"))
    out = subprocess.run(["./target/release/kordon", base, "-p", db, "--json",
                          "-j", "20", "--all", *sys.argv[4:]],
                         capture_output=True, text=True, cwd="/home/shard/VsCode/kordon")
rep = json.loads(out.stdout)
accept = sj.EQUIVALENT.get(cwe, {cwe})

hit = set()
for f in rep.get("findings", []):
    if f.get("cwe") not in accept: continue
    p, l = os.path.realpath(f["file"]), f["line"]
    for name, a, b in truth.get(p, []):
        if a <= l <= b and sj.classify(name) == "bad":
            hit.add((p, name))

stats = collections.defaultdict(lambda: [0, 0])   # variant -> [found, total]
for p, rs in truth.items():
    v = variant(p)
    for name, a, b in rs:
        if sj.classify(name) != "bad": continue
        stats[v][1] += 1
        if (p, name) in hit: stats[v][0] += 1

print(f"CWE-{cwe}: detection rate by defect shape (source | sink)\n")
for v, (f_, t) in sorted(stats.items(), key=lambda kv: (-kv[1][0]/kv[1][1] if kv[1][1] else 0, kv[0])):
    bar = "#" * round(10*f_/t) if t else ""
    print(f"  {100*f_/t if t else 0:5.0f}%  {f_:2d}/{t:<2d} {bar:<10}  {v[:66]}")
