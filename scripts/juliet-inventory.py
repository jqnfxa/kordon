#!/usr/bin/env python3
"""Regenerate docs/juliet-inventory.md from the suite and the stored baselines.

Counts come from the corpus, tiers from data/cwe_map.toml, and the two recall
columns from data/juliet-baseline.json and data/juliet-dynamic-baseline.json.
Nothing here runs an analysis -- re-run the scorers first if the baselines are
stale, which they silently become whenever a mapping or a check set changes.

    scripts/juliet-inventory.py <juliet-root>      # e.g. third_party/juliet/C
"""
import json, os, re, sys

WHY = {
    "197": "narrowing conversions; `bugprone-narrowing-conversions` already emits these",
    "252": "unchecked return value — the first half of the CWE-690 chain",
    "369": "divide by zero; `kordon-query` already has a guard check for it",
    "483": "incorrect block delimitation; moved to tier 1 on 2026-08-17",
    "665": "improper initialisation — the fallible-constructor class `--ctu` was built for",
    "672": "operation after release; overlaps CWE-416",
    "680": "integer overflow *leading to* buffer overflow — the 190→122 chain",
    "690": "null deref from an unchecked return; CLAUDE.md classifies this chain explicitly",
    "843": "type confusion",
}


def scan(testcases):
    inv = {}
    for d in sorted(os.listdir(testcases)):
        p = os.path.join(testcases, d)
        m = re.match(r"CWE(\d+)_(.*)", d)
        if not os.path.isdir(p) or not m:
            continue
        single = multi = 0
        for dp, _, ns in os.walk(p):
            for n in ns:
                if not n.endswith((".c", ".cpp")):
                    continue
                # Same split the scorers use: a case whose defect crosses
                # translation units is a different measurement.
                if re.search(r"_(\d+)[a-e]\.(c|cpp)$", n) or \
                   re.search(r"_(8\d)(?:_\w+)?\.(c|cpp)$", n):
                    multi += 1
                else:
                    single += 1
        inv[m.group(1)] = {"name": m.group(2).replace("_", " "),
                           "single": single, "multi": multi,
                           "total": single + multi}
    return inv


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "third_party/juliet/C"
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inv = scan(os.path.join(root, "testcases"))

    for m in re.finditer(r'\[\[cwe\]\]\nid = (\d+)\nname = "([^"]+)"\ntier = (\d+)',
                         open(os.path.join(here, "data/cwe_map.toml")).read()):
        if m.group(1) in inv:
            inv[m.group(1)]["tier"] = int(m.group(3))
            inv[m.group(1)]["catalog_name"] = m.group(2)

    base = json.load(open(os.path.join(here, "data/juliet-baseline.json")))
    dyn = json.load(open(os.path.join(here, "data/juliet-dynamic-baseline.json")))
    for k, v in inv.items():
        v.setdefault("tier", None)
        v.setdefault("catalog_name", v["name"])
        b = base.get(k)
        if b and b["bad_total"]:
            v["static"] = round(100 * b["bad_found"] / b["bad_total"], 1)
            v["surfaced"] = round(100 * b["bad_found_surfaced"] / b["bad_total"], 1)
        e = dyn.get(k)
        if e and e["runnable"]:
            v["dyn"] = round(100 * e["caught"] / e["runnable"], 1)

    t1 = sorted((k for k, v in inv.items() if v["tier"] == 1),
                key=lambda k: -inv[k]["total"])
    done = [k for k in t1 if "static" in inv[k]]
    todo = sorted((k for k in t1 if "static" not in inv[k]), key=int)
    rest = sorted((k for k, v in inv.items() if v["tier"] != 1),
                  key=lambda k: -inv[k]["total"])
    print(f"{len(inv)} dirs, {sum(v['total'] for v in inv.values()):,} files; "
          f"tier 1: {len(t1)} ({len(done)} measured, {len(todo)} not)")


if __name__ == "__main__":
    main()
