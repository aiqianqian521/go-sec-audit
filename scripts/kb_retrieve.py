#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kb_retrieve.py -- symbol retrieval layer for go-sec-audit (stdlib only, py3.6+)

Problem: references/ holds 24 documents and 3000+ lines. Reading all of it blows
the context; reading none of it is the same as not having it.
This script cuts the documents into chunks and exposes two independent channels:

  Channel A  fingerprint wake-up (deterministic)
      Give it a project directory; it detects framework / deployment shape /
      sink shapes already present, then hard-maps them through the FINGERPRINTS
      table to must-read chunks. No scoring, pinned to the top.

  Channel B  keyword retrieval (probabilistic)
      BM25 over chunk bodies, with heading matches weighted. Chinese text is
      split into 2-grams, English into words, so a Chinese-language query still
      tokenizes. Note the reference corpus itself is English: a query written in
      Chinese only recalls on the tokens it shares with the corpus, so English
      queries retrieve best.

Output carries file:start-end so it feeds straight into Read's offset/limit --
**load only the matched segments**.

Usage:
    python3 kb_retrieve.py --project /opt/corpus2/gogs_gogs
    python3 kb_retrieve.py --project . --hits E1-SHELL-C,X-PATHTRAV-JOIN
    python3 kb_retrieve.py --q "path traversal write hook who executes"
    python3 kb_retrieve.py --list          # see which chunks are in the index
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


# ---------------------------------------------------------------- index build

def tokenize(text):
    """English words + Chinese 2-grams. A single CJK char is not a word, so CJK
    runs are emitted as overlapping bigrams -- enough for multi-char terms."""
    toks = [t.lower() for t in TOKEN_EN.findall(text)]
    for run in TOKEN_CJK.findall(text):
        if len(run) == 1:
            toks.append(run)
        else:
            for i in range(len(run) - 1):
                toks.append(run[i:i + 2])
    return toks


def load_chunks(ref_dir):
    """Split into chunks on ## / ### headings, recording the line range."""
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


# ---------------------------------------------------------------- channel B: BM25

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
        if c["len"] < 5:          # heading-only section, empty body: useless for retrieval
            continue
        s = 0.0
        for t in q:
            f = c["tf"].get(t)
            if not f:
                continue
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * c["len"] / avg))
        if c["heading"] and any(t in tokenize(c["heading"]) for t in q):
            s *= 2.0                      # heading hit doubles the score: headings are hand-written topic labels
        if s > 0:
            scored.append((s, c))
    scored.sort(key=lambda x: -x[0])
    return scored[:top]


# ---------------------------------------------------------------- channel A: fingerprints

def _read(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read() if limit is None else fh.read(limit)
    except OSError:
        return ""


class Ctx(object):
    """Project fingerprint context. Extracts only the few facts needed to route,
    without building a full AST."""

    def __init__(self, root):
        self.root = root
        self.deps = ""
        self.go_version = ""
        self.files = []
        self.dirs = set()
        self.syms = ""            # symbol text of the sampled files
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

        # Framework and shape symbols: read routing files and main.go first,
        # fall back to sampling when they are absent.
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
    # (label, matcher, heading fragments of the must-read chunks)
    ("framework is gin", lambda c: "gin" in c.fw,
     ["1. Framework Fingerprint", "2. Entry Shapes"]),
    ("framework is echo", lambda c: "echo" in c.fw,
     ["1. Framework Fingerprint"]),
    ("framework is chi", lambda c: "chi" in c.fw,
     ["1. Framework Fingerprint"]),
    ("framework is macaron (Gitea/Gogs family)", lambda c: "macaron" in c.fw,
     ["1. Framework Fingerprint", "A4.", "A7."]),
    ("bare net/http, no unified auth layer", lambda c: ("nethttp" in c.fw and not (c.fw & set(["gin", "echo", "chi", "macaron", "beego"]))),
     ["1. Framework Fingerprint", "Prioritized endpoints"]),
    ("image has no shell, discount E1-class conclusions", lambda c: "no_shell" in c.hits,
     ["5. Known Gate Inventory"]),
    ("project ships a router directory", lambda c: "has_router_dir" in c.fw,
     ["1. Framework Fingerprint"]),
]


def fingerprint_chunks(chunks, ctx, hits):
    """Deterministic channel: a match is pinned to the top, no scoring."""
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

    # scanner hit -> rule detail + matching case
    for h in hits:
        h = h.strip().upper()
        if not h:
            continue
        if h.startswith("E1"):
            wanted += [("E1", "hit %s" % h), ("E1", "hit %s" % h)]
        elif h.startswith("E2"):
            wanted += [("E2", "hit %s" % h)]
        elif h.startswith("E3"):
            wanted += [("E3", "hit %s" % h)]
        elif h.startswith("E4"):
            wanted += [("E4", "hit %s" % h)]
        elif h.startswith("E5"):
            wanted += [("E5", "hit %s" % h)]
        elif h.startswith("E6"):
            wanted += [("E6", "hit %s" % h)]
        elif h.startswith("X-PATHTRAV"):
            wanted += [("X-PATHTRAV", "hit %s: check the write-side gate first" % h), ("A7.", "hit %s" % h)]

    out, seen = [], set()
    for needle, why in wanted:
        for c in chunks:
            if needle.lower() in (c["heading"] or "").lower() and c["id"] not in seen \
                    and c["len"] >= 5:
                seen.add(c["id"])
                out.append((c, why))
                break
    return out


# ---------------------------------------------------------------- output

def emit(rows, chunks_by_id, header):
    print("")
    print("== %s" % header)
    print("")
    if not rows:
        print("  (no match)")
        return
    for i, item in enumerate(rows, 1):
        if isinstance(item[0], dict):
            c, why = item
            score = None
        else:
            score, c = item
            why = "keyword"
        loc = "%s:%d-%d" % (c["file"], c["start"], c["end"])
        tag = "  score=%.2f" % score if score is not None else ""
        print("  %2d. %-42s %s" % (i, c["heading"][:42], tag))
        print("      load Read(file_path=references/%s, offset=%d, limit=%d)  # %s"
              % (c["file"], c["start"], max(1, c["end"] - c["start"] + 1), why))
    print("")


def main():
    ap = argparse.ArgumentParser(description="go-sec-audit reference retrieval layer")
    ap.add_argument("--project", help="project root; uses the fingerprint channel")
    ap.add_argument("--q", help="keyword query; uses the BM25 channel")
    ap.add_argument("--hits", help="scanner rule ids, comma separated, e.g. E1-SHELL-C,X-PATHTRAV-JOIN")
    ap.add_argument("--ref", default=DEFAULT_REF, help="references directory")
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--list", action="store_true", help="list every chunk")
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
        print("== project fingerprint %s" % args.project)
        print("  go %s | deps=%d chars | go files=%d | dirs=%s"
              % (ctx.go_version or "?", len(ctx.deps), len(ctx.files),
                 ",".join(sorted(d for d in ctx.dirs if d and not d.startswith("."))[:8])))
        print("  framework: %s" % (", ".join(sorted(ctx.fw)) or "not identified"))
        if "no_shell" in ctx.hits:
            print("  WARN: image has no shell / is distroless; E1-class conclusions may not hold at runtime")
        rows = fingerprint_chunks(chunks, ctx, hits)
        emit(rows, None, "Channel A fingerprint wake-up (deterministic, must read)")
        q = args.q or " ".join(
            ["%s gate falsify" % f for f in sorted(ctx.fw) if f != "has_router_dir"] or ["route gate"])
        if args.q:
            q = args.q
        bm_rows = bm25_search(chunks, q, top=args.top)
        emit(bm_rows, None, "Channel B keyword top-up")

    elif args.q or hits:
        if hits:
            class _E(object):
                fw, hits, dirs = set(), set(), set()
            emit(fingerprint_chunks(chunks, _E(), hits), None, "Channel A rule-id mapping")
        if args.q:
            emit(bm25_search(chunks, args.q, top=args.top), None, "Channel B BM25")
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
