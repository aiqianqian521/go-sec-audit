#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
go-sec-audit :: test_scan_sinks.py

Falsifiable assertions for the scanner. Every assertion is written so that it
FAILS if the corresponding rule is broken or removed.

  positive sample -> must produce the named rule id
  negative sample -> must produce no E1..E6 hit at all

Run:  python3 test_scan_sinks.py
Exit: 0 all pass, 1 any failure
"""
import copy
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import scan_sinks as S  # noqa: E402

SAMPLES = HERE.parent / "assets" / "selftest"

POSITIVE = {
    "pos_e1_shell.go.txt": "E1-SHELL-C",
    "pos_e1_shell_expr.go.txt": "E1-SHELL-EXPR",
    "pos_e4_hook.go.txt": "E4-HOOK-WRITE",
    "pos_e2_funcmap.go.txt": "E2-FUNCMAP-EXEC",
    "pos_e2_funcmap_var.go.txt": "E2-FUNCMAP-DEF",
    "pos_e2_tpl_import.go.txt": "E2-TPL-USERSTRING",
    "pos_e5_gitopt.go.txt": "E5-GIT-OPT",
}
NEGATIVE = ["neg_e1_argsep.go.txt", "neg_sqli.go.txt", "neg_e2_literal_tpl.go.txt",
            "neg_e1_literal_sh.go.txt", "neg_e2_time_parse.go.txt",
            "neg_e4_extract_iface.go.txt", "neg_e1_git_dashc.go.txt",
            "neg_e2_jwt_cron_parse.go.txt", "neg_e2_funcmap_benign.go.txt"]


def run_on(files):
    """Copy samples into a temp dir with .go extension so the walker sees them."""
    tmp = tempfile.mkdtemp(prefix="gorcehunt-")
    for f in files:
        src = SAMPLES / f
        dst = Path(tmp) / f.replace(".txt", "")
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return S.scan(tmp, include_vendor=False, include_tests=False,
                  paths_filter=None, min_sev="low")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    failures = []

    for name, expect in POSITIVE.items():
        res = run_on([name])
        ids = {h["rule"]["id"] for h in res["hits"]}
        if expect not in ids:
            failures.append(f"POSITIVE FAIL {name}: expected {expect}, got {sorted(ids) or 'none'}")
        else:
            print(f"  ok  {name:28s} -> {expect}")

    for name in NEGATIVE:
        res = run_on([name])
        bad = sorted({h["rule"]["id"] for h in res["hits"] if h["rule"]["path"] != "X"})
        if bad:
            failures.append(f"NEGATIVE FAIL {name}: unexpected {bad}")
        else:
            print(f"  ok  {name:28s} -> no E-class hit")

    # guard: a file with no Go at all must yield nothing
    tmp = tempfile.mkdtemp(prefix="gorcehunt-")
    (Path(tmp) / "empty.go").write_text("package x\n", encoding="utf-8")
    if S.scan(tmp, False, False, None, "low")["hits"]:
        failures.append("EMPTY FAIL: bare package produced hits")
    else:
        print("  ok  empty.go                     -> no hit")

    # mutation test: break each rule's anchor, its positive sample must stop
    # matching. Without this, the assertions above could pass on a scanner whose
    # rules do nothing at all.
    for name, expect in POSITIVE.items():
        saved = copy.deepcopy(S.RULES)
        for r in S.RULES:
            if r["id"] == expect:
                r["anchor"] = r"@@@never-matches@@@"
        still = {h["rule"]["id"] for h in run_on([name])["hits"]}
        S.RULES[:] = saved
        if expect in still:
            failures.append(f"MUTATION FAIL {expect}: sample matched with rule anchor disabled")
        else:
            print(f"  ok  mutation/{expect:24s} -> rule genuinely required")

    print()
    if failures:
        for f in failures:
            print("FAIL " + f)
        print(f"\n{len(failures)} assertion(s) failed")
        return 1
    print("all assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
