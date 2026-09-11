#!/usr/bin/env python3
"""Diff two score-juliet.py JSON outputs, per CWE.

    scripts/compare-baselines.py data/juliet-baseline.json /tmp/after.json

The whole method is "change one thing and see whether the count moved", and a
check built for one class routinely moves another -- so every change is
judged against the *whole* baseline, and this is what reads the difference.

Only CWEs present in both files are compared. A CWE whose flawed-function
denominator differs between the two runs is flagged: the samples are not the
same and the numbers are not comparable (different --limit, a scorer fix, or a
different Juliet root).

Exit status is 1 if any CWE regressed: fewer flawed functions found, or more
correct ones flagged, in either the raw or the surfaced column.
"""
import json
import sys


def pct(n, d):
    return 100.0 * n / d if d else 0.0


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
    common = sorted(set(a) & set(b), key=int)
    if not common:
        sys.exit("no CWE in common between the two files")

    print(f"{'CWE':<6}{'recall':>16}{'surfaced':>16}{'FP':>16}{'discrim':>14}  note")
    regressed, moved = [], 0
    ta = {"bt": 0, "bf": 0, "gt": 0, "gf": 0, "bs": 0, "gs": 0}
    tb = dict(ta)
    for k in common:
        x, y = a[k], b[k]
        if x["bad_total"] != y["bad_total"] or x["good_total"] != y["good_total"]:
            print(f"{k:<6}{'':>62}  ! different sample ({x['bad_total']}/{x['good_total']} vs "
                  f"{y['bad_total']}/{y['good_total']} functions) -- not comparable")
            continue
        for t, r in ((ta, x), (tb, y)):
            t["bt"] += r["bad_total"]; t["bf"] += r["bad_found"]
            t["gt"] += r["good_total"]; t["gf"] += r["good_flagged"]
            t["bs"] += r["bad_found_surfaced"]; t["gs"] += r["good_flagged_surfaced"]
        ra, rb = pct(x["bad_found"], x["bad_total"]), pct(y["bad_found"], y["bad_total"])
        sa, sb = pct(x["bad_found_surfaced"], x["bad_total"]), pct(y["bad_found_surfaced"], y["bad_total"])
        fa, fb = pct(x["good_flagged"], x["good_total"]), pct(y["good_flagged"], y["good_total"])
        da, db = ra - fa, rb - fb
        note = ""
        worse = (y["bad_found"] < x["bad_found"] or y["good_flagged"] > x["good_flagged"]
                 or y["bad_found_surfaced"] < x["bad_found_surfaced"]
                 or y["good_flagged_surfaced"] > x["good_flagged_surfaced"])
        better = (y["bad_found"] > x["bad_found"] or y["good_flagged"] < x["good_flagged"])
        if worse:
            note = "REGRESSED"
            regressed.append(k)
        elif better:
            note = "improved"
        changed = (x["bad_found"], x["good_flagged"], x["bad_found_surfaced"],
                   x["good_flagged_surfaced"]) != \
                  (y["bad_found"], y["good_flagged"], y["bad_found_surfaced"],
                   y["good_flagged_surfaced"])
        if changed:
            moved += 1
        arrow = lambda p, q: f"{p:5.1f}->{q:5.1f}" if abs(p - q) > 0.05 else f"{q:5.1f}      "
        print(f"{k:<6}{arrow(ra, rb):>16}{arrow(sa, sb):>16}{arrow(fa, fb):>16}"
              f"{arrow(da, db):>14}  {note}")

    print()
    print(f"TOTAL  recall {pct(ta['bf'], ta['bt']):.1f}% -> {pct(tb['bf'], tb['bt']):.1f}%   "
          f"surfaced {pct(ta['bs'], ta['bt']):.1f}% -> {pct(tb['bs'], tb['bt']):.1f}%   "
          f"FP {pct(ta['gf'], ta['gt']):.1f}% -> {pct(tb['gf'], tb['gt']):.1f}%")
    print(f"       {moved} CWE(s) moved, {len(regressed)} regressed"
          + (": CWE-" + ", CWE-".join(regressed) if regressed else ""))
    sys.exit(1 if regressed else 0)


if __name__ == "__main__":
    main()
