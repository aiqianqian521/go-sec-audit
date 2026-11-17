#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
go-sec-audit :: scan_sinks.py

Purpose
-------
Turn a Go source tree into a *candidate list* for RCE review. It does NOT decide
whether a vulnerability exists. It produces, per hit:

  - which of the six RCE paths (E1..E6) the sink belongs to
  - the enclosing top-level func (so a reviewer can reason about one unit)
  - whether any taint source appears in that same func
  - the raw call text (bracket-matched, string-aware) for judging by eye
  - caller call-sites, so the reviewer can see what the previous hop passed in

Design constraints
------------------
  - stdlib only, Python 3.9+
  - no AST: Go's parser is not available and a wrong AST is worse than a
    conservative regex. Extraction is bracket-matched and string-aware so that
    multi-line calls are read as one unit.
  - deliberately biased toward FALSE NEGATIVES at the sink level and toward
    human review at the verdict level. A scanner that reports "vulnerable"
    is a liability; one that reports "go look here" is a tool.

Usage
-----
  python3 scan_sinks.py <root> [--out report.md] [--json out.json]
                        [--include-vendor] [--include-tests]
                        [--paths E1,E2] [--min-severity high]
                        [--no-callers] [--quiet]

Exit codes
----------
  0 = scan completed (findings are NOT a vulnerability verdict)
  2 = root missing / not a directory
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Rule set. Keep IDs stable: references/sink-catalog.md refers to them.
#   kind="call"  -> locate `anchor` call, extract the whole call text, then test
#                   all_of / any_of / none_of against it
#   kind="line"  -> single-line regex over the file
# --------------------------------------------------------------------------
RULES = [
    # ---------------- E1 shell concatenation ----------------
    dict(id="E1-SHELL-C", path="E1", sev="critical", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         all_of=[r'["`](?:/bin/|/usr/bin/|/bin/sh|/bash)?(?:sh|bash|zsh|dash|ash|ksh)["`]',
                 r'["`]-c["`]'],
         # 纯字面量脚本串不可能被注入，必须排除。语料实测（760k LOC）里
         # `exec.Command("sh","-c","eval echo ~$USER")` 这类会白占 critical 命中。
         none_of=[r'["`](?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ash|ksh)["`]\s*,\s*'
                  r'["`]-c["`]\s*,\s*["`][^"`]*["`]\s*\)'],
         why="shell 解释器收到 -c 脚本串，分隔符由 shell 解析"),

    dict(id="E1-SHELL-EXPR", path="E1", sev="high", kind="call",
         anchor=r"\b\w*(?:[Cc]ommand|[Cc]md)\w*\s*\(",
         all_of=[r'["`]-c["`]\s*,\s*[^"`\s]'],
         why="`-c` 后面的脚本参数不是字面量：shell 在变量里 / 被包装函数转发，"
             "仍会把该表达式整段交给 shell 解析。"
             "E1-SHELL-C 要求 shell 是字面量，这一形态在它之外"),

    dict(id="E1-SHELL-WIN", path="E1", sev="critical", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         all_of=[r'(?i)["`](?:cmd|cmd\.exe|powershell|powershell\.exe|pwsh)["`]',
                 r'(?i)["`](?:/c|/k|-command|-c)["`]'],
         why="Windows shell 收到命令串（cmd /c 或 powershell -Command）"),

    dict(id="E1-STARTPROC", path="E1", sev="high", kind="call",
         anchor=r"\bos\.StartProcess\s*\(",
         why="直接起进程，argv 由调用方构造，需查是否拼接"),

    dict(id="E1-CMD-INTERP", path="E1", sev="high", kind="line",
         rx=r'(?i)(?:/bin/)?(?:sh|bash)\s+-c\s+["`][^"`]*["`]\s*\+',
         why="字面量 + 拼接的 shell 命令串"),

    # ---------------- E5 argument injection ----------------
    dict(id="E5-ARG-NONCONST", path="E5", sev="low", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         bare_arg=True,
         none_of=[r'["`]-c["`]'],
         why="实参是裸变量：外部程序可能把它当选项解析（tar -I / cat -A / ssh -o），选项注入未必到 RCE"),

    dict(id="E5-GIT-OPT", path="E5", sev="high", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         all_of=[r'(?i)["`](?:git|hg|svn|pandoc|ffmpeg|tar|zip|rsync|curl|wget|ssh)["`]'],
         any_of=[r'(?:\+|fmt\.Sprintf)', r'(?i)--upload-pack|--receive-pack|-exec|--filter|--config|--pager|--output'],
         why="外部程序 + 可控参数：参数注入常直接升级为命令执行"),

    # ---------------- E2 template evaluation ----------------
    dict(id="E2-TPL-USERSTRING", path="E2", sev="high", kind="call",
         anchor=r"\.(?:Parse|ParseFiles|ParseGlob)\s*\(",
         scope="callee",
         skip_literal_arg=True,
         # 只在这两个包被 import 的文件里成立。包名黑名单（time/url/json/...）
         # 天然追不上生态：jwt.Parse / cron.Parse / 自造环境变量解析器
         # 都叫 Parse，但永远评不出代码。用 import 做正向判据，而不是列黑名单。
         file_all_of=[r'"(?:text|html)/template"'],
         none_of=[r"\b(?:time|url|xml|json|yaml|toml|ini|schema|net|netip|strconv|flag|"
                  r"http|mime|multipart|regexp|tls|x509|asn1|csv|mail|textproto|path|"
                  r"filepath|big|decimal|uuid|semver|duration|dateparse|jwt|cron)\s*\.\s*Parse\b"],
         why="模板文本非字面量：若来自请求体即为 SSTI"
             "（文件必须 import text/template 或 html/template，否则 Parse 不是模板求值）"),

    dict(id="E2-FUNCMAP-EXEC", path="E2", sev="critical", kind="call",
         anchor=r"\.Funcs\s*\(",
         any_of=[r'(?i)"(?:exec|sh|bash|shell|cmd|command|run|system|popen|readfile|readFile|writefile|open|load)"\s*:',
                r'(?i):\s*(?:exec\.|os\.|syscall\.|os/exec)'],
         why="FuncMap 注册了可执行/文件类函数：模板即代码"),

    # 2026-11-16 压力测试发现：FuncMap 作为独立 var 定义、在别处 .Funcs(fmap)
    # 注册时，E2-FUNCMAP-EXEC 的锚（.Funcs( 调用点）看不到键名。
    # 本规则直接锚 FuncMap{ 字面量；scope=func 覆盖 top-level var（func_at 归
    # "<top>" 整文件）。any_of 以「带引号的执行类键 + 冒号」或「冒号后紧跟
    # exec./os./syscall.」为界，避免与同文件无关 exec 混淆（x := exec. 的
    # ":=" 不匹配 :\s*exec\.）。
    dict(id="E2-FUNCMAP-DEF", path="E2", sev="critical", kind="call", scope="func",
         anchor=r"\bFuncMap\s*\{",
         any_of=[r'(?i)"(?:exec|sh|bash|shell|cmd|command|run|system|popen|readfile|readFile|writefile|open|load)"\s*:',
                r'(?i):\s*(?:exec\.|os\.|syscall\.|os/exec)'],
         why="FuncMap 定义与 .Funcs() 分离时仍能锚到：键名即执行能力"),

    dict(id="E2-SPRIG", path="E2", sev="high", kind="line",
         rx=r'\b(?:sprig\.(?:TxtFuncMap|GenericFuncMap|HermeticTxtFuncMap))\b',
         why="sprig 函数集含 env/expandenv/getHostByName，模板可控时放大幅度"),

    dict(id="E2-TPL-CALL", path="E2", sev="medium", kind="line",
         rx=r'\{\{[^}]*\bcall\b',
         why="模板内使用 call，可调用 FuncMap 暴露的任意函数值"),

    # ---------------- E3 deserialization ----------------
    dict(id="E3-GOB-NET", path="E3", sev="high", kind="call",
         anchor=r"\bgob\.NewDecoder\s*\(",
         any_of=[r'\.Body', r'\bconn\b', r'\.Accept\(\)', r'PostBody', r'Request\(\)\.Body'],
         why="gob 直接解码网络输入：类型实例化 + 内存耗尽，且常被当作命令/路径使用"),

    dict(id="E3-SESSION-DECODE", path="E3", sev="high", kind="line",
         rx=r'\b(?:securecookie\.Decode|sessions\.NewCookieStore|gorilla/sessions)',
         why="cookie session 编解码：历史 CVE 的入口，查 key 是否硬编码/可预测"),

    dict(id="E3-YAML-IFACE", path="E3", sev="low", kind="call",
         anchor=r"\byaml\.Unmarshal\s*\(",
         any_of=[r'interface\{\}', r'map\[string\]interface\{\}', r'&raw', r'&out'],
         why="yaml 反序列化到泛型容器：需查后续是否 reflect/动态调用"),

    # ---------------- E4 write-then-execute ----------------
    dict(id="E4-HOOK-WRITE", path="E4", sev="critical", kind="call", scope="func",
         anchor=r"\b(?:os\.WriteFile|ioutil\.WriteFile|os\.Create|os\.OpenFile|os\.Rename|io\.Copy)\s*\(",
         any_of=[r'(?i)hooks[/\\]', r'(?i)["`]hooks["`]', r'(?i)\.git[/\\]'],
         why="写入 git hooks 目录：下一次 git 操作即以服务账号执行"),

    dict(id="E4-EXECPATH-WRITE", path="E4", sev="critical", kind="call", scope="func",
         anchor=r"\b(?:os\.WriteFile|ioutil\.WriteFile|os\.Create|os\.OpenFile)\s*\(",
         any_of=[r'(?i)crontab|/etc/cron', r'authorized_keys', r'\.bashrc|\.profile|\.zshrc',
                 r'(?i)/etc/systemd|\.service["`]', r'(?i)\.ssh[/\\]', r'(?i)bin[/\\]'],
         why="写入会被系统/解释器执行的位置"),

    dict(id="E4-ZIPSLIP", path="E4", sev="high", kind="line",
         # `Extract` alone is a method name on every driver interface in the wild
         # (alist: 22/22 tier-B hits were driver.Extract definitions, cloudreve
         # 18/18 the same). Only an extract *call* whose name is unambiguous, or a
         # real archive reader, is a candidate.
         rx=r'\b(?:zip\.NewReader|tar\.NewReader|archiver\.(?:Unarchive|Extract)'
            r'|Extract(?:All|To)\s*\()',
         why="归档解压：查 filepath.Join 后是否校验 Clean+前缀（Zip Slip 落点写入）"),

    # ------- X path-traversal families: not an RCE phase on its own, but the -------
    # ------- usual entry that turns "write anywhere" into "write a hook/template" ---
    dict(id="X-PATHTRAV-JOIN", path="X", sev="high", kind="call", scope="func",
         anchor=r"\b(?:os\.Open|os\.OpenFile|os\.ReadFile|ioutil\.ReadFile|os\.WriteFile|"
                r"ioutil\.WriteFile|os\.Create|os\.Stat|os\.RemoveAll)\s*\(",
         any_of=[r"\b(?:filepath|path)\.Join\s*\("],
         none_of=[r'\b(?:filepath|path)\.Join\s*\(\s*"[^"]*"\s*(?:,\s*"[^"]*"\s*)*\)'],
         why="文件路径由 Join 拼接且含变量：查是否校验 .. 与 Clean 前缀"
             "（穿越→任意读写→可写 hook/模板，落点即 E4）"),

    dict(id="X-PATHTRAV-SLICE", path="X", sev="high", kind="line",
         rx=r"filepath\.Join\s*\(\s*\w+\[\s*\d+\s*:\s*\d+\s*\]",
         why="用下标切片重组路径片段：切片结果本身可能含 ..，"
             "父级校验常被绕过（Gitea 1.4.0 transformKey 即此形态）"),

    dict(id="E4-PLUGIN-DIR", path="E4", sev="high", kind="line",
         rx=r'(?i)plugins?[/\\]["`]|plugin\.Open',
         why="插件目录可写 + plugin.Open 可加载 = 代码执行"),

    # ---------------- E6 dynamic loading / reflection ----------------
    dict(id="E6-PLUGIN-OPEN", path="E6", sev="high", kind="call",
         anchor=r"\bplugin\.Open\s*\(",
         none_of=[r'plugin\.Open\s*\(\s*"[^"]*"\s*\)'],
         why="plugin.Open 的路径非字面量"),

    dict(id="E6-SYSCALL-EXEC", path="E6", sev="high", kind="call",
         anchor=r"\bsyscall\.Exec\s*\(",
         why="直接 execve，绕过 os/exec 的参数语义"),

    dict(id="E6-REFLECT-CALL", path="E6", sev="low", kind="line",
         rx=r'\.(?:MethodByName|Call|CallSlice)\s*\(',
         why="反射动态调用：查方法名/目标对象是否可控"),

    dict(id="E6-CGO", path="E6", sev="low", kind="line",
         rx=r'^\s*(?://\s*#cgo|import\s+"C")',
         why="cgo 边界：内存安全假设在此失效"),

    # ---------------- supporting signals (not RCE by themselves) ----------------
    dict(id="X-PPROF-EXPOSED", path="X", sev="low", kind="line",
         rx=r'pprof\.(?:Index|Handler)|net/http/pprof',
         why="pprof 暴露：信息泄漏与 DoS，常是链条前置"),

    dict(id="X-NETRPC", path="X", sev="low", kind="line",
         rx=r'\bnet/rpc\b|rpc\.NewServer\(',
         why="net/rpc 默认 gob 编解码，等价于 E3 入口"),
]

SOURCE_RULES = [
    (r'\br\.(?:FormValue|PostFormValue)\s*\(', "http form"),
    (r'\br\.URL\.Query\s*\(\s*\)', "http query"),
    (r'\br\.Header\.Get\s*\(', "http header"),
    (r'\br\.Body\b', "http body"),
    (r'\bc\.(?:Query|Param|PostForm|ShouldBind\w*|Bind\w*|GetHeader|GetRawData|FormFile|Body)\s*\(', "gin/fiber ctx"),
    (r'\bc\.Request\(\)', "echo ctx"),
    (r'\bctx\.(?:PostBody|QueryArgs|FormValue|RequestURI|URI\(\))', "fasthttp ctx"),
    (r'\bos\.(?:Args|Getenv)\b', "cli/env"),
    (r'\bflag\.(?:Arg|Args|Parse)\b', "flags"),
    (r'\bjson\.NewDecoder\s*\(', "json body"),
    (r'\bxml\.NewDecoder\s*\(', "xml body"),
    (r'\bmultipart\.', "multipart"),
    (r'\bio\.ReadAll\s*\(', "raw read"),
]

ENTRY_HINTS = [
    (r'http\.ResponseWriter', "http handler"),
    (r'\*http\.Request', "http handler"),
    (r'\*gin\.Context', "gin handler"),
    (r'echo\.Context', "echo handler"),
    (r'fiber\.Ctx', "fiber handler"),
    (r'fasthttp\.RequestCtx', "fasthttp handler"),
    (r'grpc\.', "grpc"),
    (r'cobra\.Command', "cli"),
]

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SKIP_DIRS = {".git", "node_modules", "testdata", "third_party", "dist", ".idea", ".vscode"}
VENDOR_DIRS = {"vendor"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def split_top_level_funcs(lines):
    """Return [(start_line_idx, end_line_idx, func_name)] for top-level `func`."""
    starts = []
    for i, line in enumerate(lines):
        if line.startswith("func ") or line.startswith("func("):
            name = "?"
            m = re.match(r'^func\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(', line)
            if m:
                name = m.group(1)
            starts.append((i, name))
    out = []
    for idx, (s, name) in enumerate(starts):
        e = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        out.append((s, e, name))
    return out


def call_text(text, open_paren_idx, max_len=4000):
    """Bracket-match from '(' to its ')' while skipping string/rune literals."""
    depth = 0
    i = open_paren_idx
    n = min(len(text), open_paren_idx + max_len)
    in_str = None
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_idx:i + 1]
        i += 1
    return text[open_paren_idx:open_paren_idx + 200]


def any_rx(pats, s):
    return any(re.search(p, s) for p in pats)


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def split_args(body):
    """Split a bracket-matched call body on top-level commas."""
    inner = body[1:-1] if body.endswith(")") else body[1:]
    args, depth, cur, in_str = [], 0, [], None
    i = 0
    while i < len(inner):
        ch = inner[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(inner):
                cur.append(inner[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            cur.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        args.append("".join(cur).strip())
    return args


def first_arg_is_literal(body):
    """True when the call's only/first argument is a plain string literal."""
    args = split_args(body)
    if len(args) != 1:
        return False
    return bool(re.fullmatch(r'`[^`]*`|"(?:[^"\\]|\\.)*"', args[0], re.S))


def has_bare_arg(body):
    """True when an argument after the program name is a bare identifier.

    This is the shape that enables option injection: the callee receives a token
    that starts with '-' and is parsed as a flag. A concatenation that starts
    with a literal prefix ("/reports/" + name) cannot do that and is excluded.
    """
    args = split_args(body)
    if len(args) < 2:
        return False
    rest = args[1:]
    if rest and re.fullmatch(r'ctx|context\.\w+|[\w.]+Context\(\)', rest[0] or ""):
        rest = rest[1:]
    if len(rest) < 2:
        return False
    return any(re.fullmatch(r'[A-Za-z_]\w*', a) for a in rest[1:])


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
def scan(root, include_vendor, include_tests, paths_filter, min_sev):
    root = Path(root)
    files = []
    skipped = {"vendor": 0, "tests": 0, "dirs": 0}
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for d in dirnames:
            if d in VENDOR_DIRS and not include_vendor:
                skipped["vendor"] += 1
                continue
            if d in SKIP_DIRS:
                skipped["dirs"] += 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            if (fn.endswith("_test.go") or "/testdata/" in str(dirpath)) and not include_tests:
                skipped["tests"] += 1
                continue
            files.append(Path(dirpath) / fn)

    file_cache = {}
    hits = []

    for fp in files:
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_cache[str(fp)] = raw
        lines = raw.splitlines()

        funcs = split_top_level_funcs(lines)

        def func_at(lineno):
            for (s, e, name) in funcs:
                if s + 1 <= lineno <= e:
                    return (s, e, name)
            return (0, len(lines), "<top>")

        for rule in RULES:
            if paths_filter and rule["path"] not in paths_filter:
                continue
            if SEV_ORDER.get(rule["sev"], 0) < SEV_ORDER[min_sev]:
                continue
            # file-level gate: some rules are only meaningful in a file that
            # imports the package they are about (`.Parse(` means template
            # evaluation only if text/template or html/template is imported;
            # otherwise it is jwt.Parse / cron.Parse / some custom parser).
            if "file_all_of" in rule and not all(re.search(p, raw) for p in rule["file_all_of"]):
                continue

            if rule["kind"] == "line":
                for li, line in enumerate(lines, 1):
                    if line.lstrip().startswith("//"):
                        continue
                    if re.search(rule["rx"], line):
                        txt = line.strip()
                        hits.append(dict(rule=rule, file=str(fp), line=li,
                                         code=txt, flat=txt[:240],
                                         func=func_at(li)[2],
                                         srcs=[]))
            else:
                for m in re.finditer(rule["anchor"], raw):
                    paren = raw.find("(", m.start())
                    if paren < 0:
                        continue
                    body = call_text(raw, paren)
                    ln = line_of(raw, m.start())
                    fs, fe, fname = func_at(ln)
                    # scope="func" lets a rule see a path/file target that was
                    # assigned to a variable a few lines above the write call.
                    # scope="callee" prefixes the target with the receiver chain
                    # (`time.Parse`, `a.b.Parse`) — without it a none_of cannot
                    # distinguish template.Parse from time.Parse, because
                    # `body` starts at the paren.
                    sc = rule.get("scope")
                    if sc == "func":
                        target = "\n".join(lines[fs:fe])
                    elif sc == "callee":
                        j = m.start()
                        while j > 0 and (raw[j - 1].isalnum() or raw[j - 1] in "_."):
                            j -= 1
                        target = raw[j:paren + len(body)]
                    else:
                        target = body

                    if rule.get("skip_literal_arg") and first_arg_is_literal(body):
                        continue
                    if rule.get("bare_arg") and not has_bare_arg(body):
                        continue
                    if "all_of" in rule and not all(re.search(p, target) for p in rule["all_of"]):
                        continue
                    if "any_of" in rule and not any_rx(rule["any_of"], target):
                        continue
                    if "none_of" in rule and any_rx(rule["none_of"], target):
                        continue
                    # keep the callee name: starting at the paren loses `exec.Command`
                    full = raw[m.start():paren + len(body)]
                    hits.append(dict(rule=rule, file=str(fp), line=ln,
                                     code=full, flat=body.replace("\n", " ")[:240],
                                     func=fname, srcs=[]))

    # per-hit enrichment: taint sources + entry hints inside the enclosing func
    for h in hits:
        raw = file_cache.get(h["file"], "")
        lines = raw.splitlines()
        funcs = split_top_level_funcs(lines)
        fs, fe = h["line"] - 1, h["line"]
        for (s, e, name) in funcs:
            if s <= h["line"] - 1 < e:
                fs, fe = s, e
                break
        fbody = "\n".join(lines[fs:fe])
        fhead = "\n".join(lines[fs:min(fs + 3, fe)])
        h["srcs"] = [tag for (rx, tag) in SOURCE_RULES if re.search(rx, fbody)]
        h["entry"] = list(dict.fromkeys(tag for (rx, tag) in ENTRY_HINTS if re.search(rx, fhead)))

    # caller lookup for the most interesting hits only
    if not os.environ.get("GORCEHUNT_NO_CALLERS"):
        index = {}
        for path, raw in file_cache.items():
            for m in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', raw):
                index.setdefault(m.group(1), []).append((path, line_of(raw, m.start()), raw))
        for h in hits:
            if h["func"] in ("<top>", "?", "main", "init"):
                h["callers"] = []
                continue
            sites = []
            for (path, ln, raw) in index.get(h["func"], [])[:12]:
                if path == h["file"] and abs(ln - h["line"]) < 3:
                    continue
                text = raw.splitlines()[ln - 1].strip()[:200]
                if text.startswith("func "):
                    continue
                sites.append({"file": path, "line": ln, "code": text})
                if len(sites) >= 3:
                    break
            h["callers"] = sites

    return dict(root=str(root), scanned=len(files), skipped=skipped, hits=hits)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def dedupe(hits, max_per_rule=40):
    seen, out = set(), []
    per_rule = {}
    for h in hits:
        key = (h["rule"]["id"], h["file"], h["line"])
        if key in seen:
            continue
        seen.add(key)
        rid = h["rule"]["id"]
        per_rule[rid] = per_rule.get(rid, 0) + 1
        if per_rule[rid] > max_per_rule:
            continue
        out.append(h)
    return out


def render_md(res, min_sev, paths_filter):
    hits = res["hits"]
    by_path = {}
    for h in hits:
        by_path[h["rule"]["path"]] = by_path.get(h["rule"]["path"], 0) + 1
    chained = [h for h in hits if h["srcs"]]
    plain = [h for h in hits if not h["srcs"]]

    L = []
    L.append("# go-sec-audit 扫描报告\n")
    L.append(f"- 根目录: `{res['root']}`")
    L.append(f"- 已扫描 `.go` 文件: **{res['scanned']}**")
    L.append(f"- 跳过: vendor 目录 {res['skipped']['vendor']} 个 / 测试文件 {res['skipped']['tests']} 个 / 其他目录 {res['skipped']['dirs']} 个")
    if res["skipped"]["vendor"] and min_sev in ("low", "medium"):
        L.append("  > 未扫描 vendor/ 与测试文件。**本报告对这两处不构成否定结论**，需要时加 `--include-vendor --include-tests` 重跑。")
    L.append(f"- 候选命中: **{len(hits)}**（函数内出现输入源 {len(chained)} / 仅命中 sink {len(plain)}）")
    L.append("- 分相统计: " + " / ".join(f"{k}={v}" for k, v in sorted(by_path.items())))
    L.append("\n> 本报告只是**候选清单**。命中不等于漏洞；未命中不等于安全。每个候选必须走 references/verification-gates.md 的 L0→L3 分级。\n")

    L.append("## A. 高优先级候选（同一函数内同时出现输入源）\n")
    if not chained:
        L.append("_无。这不代表项目安全，只代表这一轮规则没有在同一个函数内同时看到 source 与 sink；跨函数传播需要 Phase 2 人工追踪。_\n")
    else:
        L.append("| # | 相 | 规则 | 位置 | 函数 | 输入源 | 入口推测 | 判据 |")
        L.append("|---|----|------|------|------|--------|----------|------|")
        for i, h in enumerate(chained, 1):
            loc = f"{Path(h['file']).name}:{h['line']}"
            L.append(f"| {i} | {h['rule']['path']} | {h['rule']['id']} | `{loc}` | `{h['func']}` | "
                     f"{', '.join(h['srcs'])} | {', '.join(h['entry']) or '-'} | {h['rule']['why']} |")
        L.append("")

    L.append("## B. 仅命中 sink（跨函数传播待查）\n")
    if not plain:
        L.append("_无。_\n")
    else:
        L.append("| # | 相 | 规则 | 位置 | 函数 | 判据 |")
        L.append("|---|----|------|------|------|------|")
        for i, h in enumerate(plain, 1):
            loc = f"{Path(h['file']).name}:{h['line']}"
            L.append(f"| {i} | {h['rule']['path']} | {h['rule']['id']} | `{loc}` | `{h['func']}` | {h['rule']['why']} |")
        L.append("")

    callers = [(h, c) for h in hits for c in h.get("callers", [])]
    if callers:
        L.append("## C. 调用点线索（上一跳传了什么）\n")
        L.append("| sink 位置 | 函数 | 调用点 | 实参文本 |")
        L.append("|-----------|------|--------|----------|")
        for h, c in callers[:40]:
            L.append(f"| `{Path(h['file']).name}:{h['line']}` | `{h['func']}` | "
                     f"`{Path(c['file']).name}:{c['line']}` | `{c['code']}` |")
        L.append("")

    L.append("## D. 代码摘录\n")
    for i, h in enumerate(chained[:20], 1):
        rel = os.path.relpath(h["file"], res["root"]).replace("\\", "/")
        L.append(f"**{i}. {h['rule']['id']}** `{rel}:{h['line']}` — {h['rule']['why']}")
        L.append("```go")
        L.append(h["code"])
        L.append("```\n")
    return "\n".join(L)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Go RCE sink candidate scanner (candidates only)")
    ap.add_argument("root")
    ap.add_argument("--out", default=None, help="write markdown report to this path")
    ap.add_argument("--json", dest="json_out", default=None, help="write raw JSON to this path")
    ap.add_argument("--include-vendor", action="store_true")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--paths", default=None, help="comma list, e.g. E1,E4 (X = supporting signals)")
    ap.add_argument("--min-severity", default="low", choices=list(SEV_ORDER))
    ap.add_argument("--max-per-rule", type=int, default=40)
    ap.add_argument("--no-callers", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if not os.path.isdir(a.root):
        sys.stderr.write(f"error: not a directory: {a.root}\n")
        return 2

    paths_filter = set(p.strip().upper() for p in a.paths.split(",")) if a.paths else None
    if a.no_callers:
        os.environ["GORCEHUNT_NO_CALLERS"] = "1"

    res = scan(a.root, a.include_vendor, a.include_tests, paths_filter, a.min_severity)
    res["hits"] = dedupe(res["hits"], a.max_per_rule)

    md = render_md(res, a.min_severity, paths_filter)
    if a.out:
        Path(a.out).write_text(md, encoding="utf-8")
        if not a.quiet:
            print(f"[+] markdown -> {a.out}")
    elif not a.quiet:
        print(md)

    if a.json_out:
        slim = dict(root=res["root"], scanned=res["scanned"], skipped=res["skipped"],
                    hits=[dict(rule_id=h["rule"]["id"], path=h["rule"]["path"],
                               severity=h["rule"]["sev"], why=h["rule"]["why"],
                               file=h["file"], line=h["line"], func=h["func"],
                               code=h["code"], sources=h["srcs"],
                               entry=h.get("entry", []), callers=h.get("callers", []))
                          for h in res["hits"]])
        Path(a.json_out).write_text(json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")
        if not a.quiet:
            print(f"[+] json -> {a.json_out}")

    if not a.quiet:
        chained = sum(1 for h in res["hits"] if h["srcs"])
        print(f"[=] {res['scanned']} files scanned, {len(res['hits'])} candidates "
              f"({chained} with same-func source)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
