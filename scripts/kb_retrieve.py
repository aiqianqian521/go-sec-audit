#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kb_retrieve.py -- go-sec-audit 的符号检索层 (stdlib only, py3.6+)

问题：references/ 有 8 份文档、2000+ 行。全读挤爆上下文，全不读等于没有。
本脚本把文档切成 chunk，提供两条互相独立的检索通道：

  通道 A 指纹唤醒（确定性）
      输入一个项目目录，检测框架/部署形态/已出现的 sink 形态，
      按 FINGERPRINTS 表硬映射到必读 chunk。不参与打分，直接置顶。

  通道 B 关键词检索（概率性）
      BM25 over chunk 正文，heading 命中加权。中文按 2-gram 切，
      英文按词切，所以 "路径穿越" 和 "path traversal" 都能召回。

输出带 file:start-end，可直接喂给 Read 的 offset/limit，**只加载命中的那几段**。

用法:
    python3 kb_retrieve.py --project /opt/corpus2/gogs_gogs
    python3 kb_retrieve.py --project . --hits E1-SHELL-C,X-PATHTRAV-JOIN
    python3 kb_retrieve.py --q "路径穿越 写 hook 谁执行"
    python3 kb_retrieve.py --list          # 看索引里有哪些 chunk
"""

from __future__ import print_function

import argparse
import math
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REF = os.path.join(os.path.dirname(HERE), "references")

CJK = re.compile(u"[\u4e00-\u9fff]")
TOKEN_EN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
TOKEN_CJK = re.compile(u"[\u4e00-\u9fff]{1,}")


# ---------------------------------------------------------------- 索引构建

def tokenize(text):
    """英文词 + 中文 2-gram。中文单字不成词，2-gram 足够覆盖 '路径穿越' 这类术语。"""
    toks = [t.lower() for t in TOKEN_EN.findall(text)]
    for run in TOKEN_CJK.findall(text):
        if len(run) == 1:
            toks.append(run)
        else:
            for i in range(len(run) - 1):
                toks.append(run[i:i + 2])
    return toks


def load_chunks(ref_dir):
    """按 ## / ### 标题切 chunk，记录行号范围。"""
    chunks = []
    if not os.path.isdir(ref_dir):
        return chunks
    for fn in sorted(os.listdir(ref_dir)):
        if not fn.endswith(".md"):
            continue
        path = os.path.join(ref_dir, fn)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        cur = None
        for i, line in enumerate(lines, 1):
            m = re.match(r"^(#{1,3})\s+(.*\S)\s*$", line)
            if m and len(m.group(1)) >= 2:
                if cur:
                    cur["end"] = i - 1
                    chunks.append(cur)
                cur = dict(file=fn, heading=m.group(2), level=len(m.group(1)),
                           start=i, end=len(lines), body=[])
            elif cur is not None:
                cur["body"].append(line)
        if cur:
            cur["end"] = len(lines)
            chunks.append(cur)

    for c in chunks:
        text = c["heading"] + "\n" + "\n".join(c["body"])
        c["id"] = "%s#%s" % (c["file"], c["heading"])
        c["tokens"] = tokenize(text)
        c["tf"] = Counter(c["tokens"])
        c["len"] = max(1, len(c["tokens"]))
    return chunks


# ---------------------------------------------------------------- 通道 B: BM25

def bm25_search(chunks, query, top=6, k1=1.5, b=0.75):
    q = tokenize(query)
    if not q or not chunks:
        return []
    n = len(chunks)
    avg = sum(c["len"] for c in chunks) / float(n)
    df = Counter()
    for c in chunks:
        for t in set(q):
            if t in c["tf"]:
                df[t] += 1
    scored = []
    for c in chunks:
        if c["len"] < 5:          # 纯标题节，正文为空，检索时无意义
            continue
        s = 0.0
        for t in q:
            f = c["tf"].get(t)
            if not f:
                continue
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * c["len"] / avg))
        if c["heading"] and any(t in tokenize(c["heading"]) for t in q):
            s *= 2.0                      # heading 命中翻倍：标题是人工写的主题标签
        if s > 0:
            scored.append((s, c))
    scored.sort(key=lambda x: -x[0])
    return scored[:top]


# ---------------------------------------------------------------- 通道 A: 指纹

def _read(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read() if limit is None else fh.read(limit)
    except OSError:
        return ""


class Ctx(object):
    """项目指纹上下文。只抽取判断路由/形态所需的少量事实，不建全量 AST。"""

    def __init__(self, root):
        self.root = root
        self.deps = ""
        self.go_version = ""
        self.files = []
        self.dirs = set()
        self.syms = ""            # 抽样文件的符号文本
        self.dockerfile = ""
        self.fw = set()
        self.hits = set()
        self._scan()

    def _scan(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames
                           if d not in ("vendor", "node_modules", "testdata", ".git")]
            rel = os.path.relpath(dirpath, self.root)
            self.dirs.add(rel.split(os.sep)[0])
            for fn in filenames:
                if fn == "go.mod":
                    g = _read(os.path.join(dirpath, fn))
                    self.deps += g
                    m = re.search(r"^go\s+([\d.]+)", g, re.M)
                    if m:
                        self.go_version = m.group(1)
                elif fn.lower().startswith("dockerfile"):
                    self.dockerfile += _read(os.path.join(dirpath, fn))
                elif fn.endswith(".go"):
                    self.files.append(os.path.join(dirpath, fn))

        # 框架与形态符号：优先读路由文件与 main.go，读不到再抽样
        priority = [f for f in self.files
                    if re.search(r"(^|[/\\])(main|routes|routers?|router|server)\.go$", f)]
        rest = [f for f in self.files if f not in priority]
        sample = priority[:60] + rest[:140]
        buf = []
        for f in sample:
            buf.append(_read(f, 200000))
        self.syms = "\n".join(buf)

        checks = [
            ("gin", r"gin-gonic/gin|gin\.Default\(\)|gin\.New\(\)"),
            ("echo", r"labstack/echo|echo\.New\(\)"),
            ("chi", r"go-chi/chi|chi\.NewRouter\(\)"),
            ("macaron", r"go-macaron/macaron|macaron\.Classic\(\)"),
            ("fiber", r"gofiber/fiber|fiber\.New\(\)"),
            ("beego", r"astaxie/beego|beego\.Router"),
            ("gorilla", r"gorilla/mux"),
            ("nethttp", r"http\.HandleFunc|http\.ListenAndServe"),
            ("has_router_dir", r""),
        ]
        for name, pat in checks:
            if name == "has_router_dir":
                if any(d in ("router", "routers", "routes", "internal") for d in self.dirs):
                    self.fw.add(name)
            elif re.search(pat, self.deps + "\n" + self.syms):
                self.fw.add(name)
        if "FROM scratch" in self.dockerfile or "distroless" in self.dockerfile:
            self.hits.add("no_shell")


FINGERPRINTS = [
    # (说明, 匹配函数, 必读 chunk 的 heading 片段)
    ("框架是 gin", lambda c: "gin" in c.fw,
     ["1. 框架指纹", "2. 入口形态"]),
    ("框架是 echo", lambda c: "echo" in c.fw,
     ["1. 框架指纹"]),
    ("框架是 chi", lambda c: "chi" in c.fw,
     ["1. 框架指纹"]),
    ("框架是 macaron（Gitea/Gogs 系）", lambda c: "macaron" in c.fw,
     ["1. 框架指纹", "A4.", "A7."]),
    ("裸 net/http，无统一认证层", lambda c: ("nethttp" in c.fw and not (c.fw & set(["gin", "echo", "chi", "macaron", "beego"]))),
     ["1. 框架指纹", "优先看这些端点"]),
    ("镜像无 shell，E1 类结论要打折", lambda c: "no_shell" in c.hits,
     ["5. 已知闸门清单"]),
    ("项目带 router 目录", lambda c: "has_router_dir" in c.fw,
     ["1. 框架指纹"]),
]


def fingerprint_chunks(chunks, ctx, hits):
    """确定性通道：命中即置顶，不参与打分。"""
    wanted = []
    reasons = []
    for label, match, targets in FINGERPRINTS:
        try:
            ok = match(ctx)
        except Exception:
            ok = False
        if not ok:
            continue
        for t in targets:
            wanted.append((t, label))
            reasons.append(label)

    # 扫描器命中 → 规则详情 + 对应案例
    for h in hits:
        h = h.strip().upper()
        if not h:
            continue
        if h.startswith("E1"):
            wanted += [("E1", "命中 %s" % h), ("E1", "命中 %s" % h)]
        elif h.startswith("E2"):
            wanted += [("E2", "命中 %s" % h)]
        elif h.startswith("E3"):
            wanted += [("E3", "命中 %s" % h)]
        elif h.startswith("E4"):
            wanted += [("E4", "命中 %s" % h)]
        elif h.startswith("E5"):
            wanted += [("E5", "命中 %s" % h)]
        elif h.startswith("E6"):
            wanted += [("E6", "命中 %s" % h)]
        elif h.startswith("X-PATHTRAV"):
            wanted += [("X-PATHTRAV", "命中 %s：先看写侧闸门" % h), ("A7.", "命中 %s" % h)]

    out, seen = [], set()
    for needle, why in wanted:
        for c in chunks:
            if needle.lower() in (c["heading"] or "").lower() and c["id"] not in seen \
                    and c["len"] >= 5:
                seen.add(c["id"])
                out.append((c, why))
                break
    return out


# ---------------------------------------------------------------- 输出

def emit(rows, chunks_by_id, header):
    print("")
    print("== %s" % header)
    print("")
    if not rows:
        print("  (无命中)")
        return
    for i, item in enumerate(rows, 1):
        if isinstance(item[0], dict):
            c, why = item
            score = None
        else:
            score, c = item
            why = "关键词"
        loc = "%s:%d-%d" % (c["file"], c["start"], c["end"])
        tag = "  score=%.2f" % score if score is not None else ""
        print("  %2d. %-42s %s" % (i, c["heading"][:42], tag))
        print("      load Read(file_path=references/%s, offset=%d, limit=%d)  # %s"
              % (c["file"], c["start"], max(1, c["end"] - c["start"] + 1), why))
    print("")


def main():
    ap = argparse.ArgumentParser(description="go-sec-audit reference 检索层")
    ap.add_argument("--project", help="项目根目录，走指纹通道")
    ap.add_argument("--q", help="关键词查询，走 BM25 通道")
    ap.add_argument("--hits", help="扫描器命中规则 id，逗号分隔，如 E1-SHELL-C,X-PATHTRAV-JOIN")
    ap.add_argument("--ref", default=DEFAULT_REF, help="references 目录")
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--list", action="store_true", help="列出全部 chunk")
    args = ap.parse_args()

    chunks = load_chunks(args.ref)
    if not chunks:
        print("ERROR: no chunks under %s" % args.ref)
        return 1

    if args.list:
        for c in chunks:
            print("%-46s %s:%d-%d" % (c["heading"][:46], c["file"], c["start"], c["end"]))
        print("\ntotal %d chunks, %d tokens" % (len(chunks), sum(c["len"] for c in chunks)))
        return 0

    hits = [h for h in (args.hits or "").split(",") if h.strip()]

    if args.project:
        ctx = Ctx(args.project)
        print("== 项目指纹 %s" % args.project)
        print("  go %s | deps=%d chars | go files=%d | dirs=%s"
              % (ctx.go_version or "?", len(ctx.deps), len(ctx.files),
                 ",".join(sorted(d for d in ctx.dirs if d and not d.startswith("."))[:8])))
        print("  framework: %s" % (", ".join(sorted(ctx.fw)) or "未识别"))
        if "no_shell" in ctx.hits:
            print("  WARN: 镜像无 shell / distroless，E1 类结论在运行时可能不成立")
        rows = fingerprint_chunks(chunks, ctx, hits)
        emit(rows, None, "通道 A 指纹唤醒（确定性，必读）")
        q = args.q or " ".join(
            ["%s 闸门 证伪" % f for f in sorted(ctx.fw) if f != "has_router_dir"] or ["路线 闸门"])
        if args.q:
            q = args.q
        bm_rows = bm25_search(chunks, q, top=args.top)
        emit(bm_rows, None, "通道 B 关键词补足")

    elif args.q or hits:
        if hits:
            class _E(object):
                fw, hits, dirs = set(), set(), set()
            emit(fingerprint_chunks(chunks, _E(), hits), None, "通道 A 命中规则映射")
        if args.q:
            emit(bm25_search(chunks, args.q, top=args.top), None, "通道 B BM25")
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
