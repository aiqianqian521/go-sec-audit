#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stress_kwcheck.py -- keyword-channel stress checker (stdlib only)

Parses the `rg -n 'PATTERN' -t go` regexes out of the ```bash blocks in
references/vuln-features.md, applies them line by line to the assets/stress/
corpus, and prints the matching lines per file.
Single source of truth: the regexes live only in vuln-features.md; this script
just parses and applies them, so the document can change without touching this
file (drift-proof by design).

Usage: python assets/stress/stress_kwcheck.py [--corpus=assets/stress]
"""

from __future__ import print_function
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(os.path.dirname(HERE))
FEATURES = os.path.join(SKILL_ROOT, "references", "vuln-features.md")


def extract_patterns(md_path):
    """Extract the rg -n 'PATTERN' regexes from the bash blocks of vuln-features.md."""
    text = open(md_path, encoding="utf-8").read()
    pats = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_block = not in_block
            continue
        if not in_block:
            continue
        m = re.match(r"rg -n '(.+?)' -t go", s)
        if m:
            pats.append(m.group(1))
    return pats


def main():
    corpus = HERE
    for a in sys.argv[1:]:
        if a.startswith("--corpus="):
            corpus = a.split("=", 1)[1]

    pats = extract_patterns(FEATURES)
    print("extracted %d keyword regexes from vuln-features.md" % len(pats))

    go_files = sorted(f for f in os.listdir(corpus) if f.endswith(".go"))
    compiled = [(p, re.compile(p)) for p in pats]

    hit_count = 0
    for fname in go_files:
        lines = open(os.path.join(corpus, fname), encoding="utf-8").read().splitlines()
        for i, ln in enumerate(lines, 1):
            hits = [p for p, c in compiled if c.search(ln)]
            if hits:
                hit_count += 1
                print("%s:%d  <- %s" % (fname, i, " ; ".join(sorted(set(hits))[:3])))
    print("---- %d matching lines in total (wake-ups allowed)" % hit_count)


if __name__ == "__main__":
    main()
