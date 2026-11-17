#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stress_kwcheck.py — 关键词通道压力测试检查器（stdlib only）

从 references/vuln-features.md 的 ```bash 代码块里解析 `rg -n 'PATTERN' -t go` 的正则，
逐条应用到 assets/stress/ 语料上，输出每文件命中行。
单一事实来源：正则只存在 vuln-features.md 里，本脚本只做解析与应用，
文档改动后无需改本脚本（防漂移设计）。

用法: python assets/stress/stress_kwcheck.py [--corpus assets/stress]
"""

from __future__ import print_function
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(os.path.dirname(HERE))
FEATURES = os.path.join(SKILL_ROOT, "references", "vuln-features.md")


def extract_patterns(md_path):
    """从 vuln-features.md 的 bash 代码块里抽 rg -n 'PATTERN' 的正则。"""
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
    print("vuln-features.md 提取到 %d 条关键词正则" % len(pats))

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
    print("---- 总计 %d 个文件命中行（含允许的唤醒）" % hit_count)


if __name__ == "__main__":
    main()
