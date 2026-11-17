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
         # A fully literal script string cannot be injected, so it must be excluded.
         # Measured on a 760k-LOC corpus: shapes like
         # `exec.Command("sh","-c","eval echo ~$USER")` otherwise burn critical hits.
         none_of=[r'["`](?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ash|ksh)["`]\s*,\s*'
                  r'["`]-c["`]\s*,\s*["`][^"`]*["`]\s*\)'],
         why="shell interpreter receives a -c script string; separators are parsed by the shell"),

    dict(id="E1-SHELL-EXPR", path="E1", sev="high", kind="call",
         anchor=r"\b\w*(?:[Cc]ommand|[Cc]md)\w*\s*\(",
         all_of=[r'["`]-c["`]\s*,\s*[^"`\s]'],
         why="The script argument after `-c` is not a literal: the shell lives in a "
             "variable / is forwarded by a wrapper, so the whole expression still "
             "reaches the shell parser. E1-SHELL-C requires the shell itself to be a "
             "literal, so this shape falls outside it"),

    dict(id="E1-SHELL-WIN", path="E1", sev="critical", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         all_of=[r'(?i)["`](?:cmd|cmd\.exe|powershell|powershell\.exe|pwsh)["`]',
                 r'(?i)["`](?:/c|/k|-command|-c)["`]'],
         why="Windows shell receives a command string (cmd /c or powershell -Command)"),

    dict(id="E1-STARTPROC", path="E1", sev="high", kind="call",
         anchor=r"\bos\.StartProcess\s*\(",
         why="Launches a process directly; argv is built by the caller, so check for concatenation"),

    dict(id="E1-CMD-INTERP", path="E1", sev="high", kind="line",
         rx=r'(?i)(?:/bin/)?(?:sh|bash)\s+-c\s+["`][^"`]*["`]\s*\+',
         why="Shell command string built from a literal plus a concatenation"),

    # ---------------- E5 argument injection ----------------
    dict(id="E5-ARG-NONCONST", path="E5", sev="low", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         bare_arg=True,
         none_of=[r'["`]-c["`]'],
         why="Argument is a bare variable: the external program may parse it as an option "
             "(tar -I / cat -A / ssh -o). Option injection does not necessarily reach RCE"),

    dict(id="E5-GIT-OPT", path="E5", sev="high", kind="call",
         anchor=r"\b(?:exec\.Command|exec\.CommandContext)\s*\(",
         all_of=[r'(?i)["`](?:git|hg|svn|pandoc|ffmpeg|tar|zip|rsync|curl|wget|ssh)["`]'],
         any_of=[r'(?:\+|fmt\.Sprintf)', r'(?i)--upload-pack|--receive-pack|-exec|--filter|--config|--pager|--output'],
         why="External program plus controllable arguments: argument injection frequently "
             "escalates straight to command execution"),

    # ---------------- E2 template evaluation ----------------
    dict(id="E2-TPL-USERSTRING", path="E2", sev="high", kind="call",
         anchor=r"\.(?:Parse|ParseFiles|ParseGlob)\s*\(",
         scope="callee",
         skip_literal_arg=True,
         # Holds only in a file that imports one of these two packages. A package
         # denylist (time/url/json/...) can never keep up with the ecosystem:
         # jwt.Parse / cron.Parse / a home-grown env parser are all named Parse
         # yet never evaluate code. Use the import as a positive gate instead of
         # maintaining a denylist.
         file_all_of=[r'"(?:text|html)/template"'],
         none_of=[r"\b(?:time|url|xml|json|yaml|toml|ini|schema|net|netip|strconv|flag|"
                  r"http|mime|multipart|regexp|tls|x509|asn1|csv|mail|textproto|path|"
                  r"filepath|big|decimal|uuid|semver|duration|dateparse|jwt|cron)\s*\.\s*Parse\b"],
         why="Template text is not a literal: if it comes from the request body this is SSTI "
             "(the file must import text/template or html/template, otherwise Parse is not "
             "template evaluation)"),

    dict(id="E2-FUNCMAP-EXEC", path="E2", sev="critical", kind="call",
         anchor=r"\.Funcs\s*\(",
         any_of=[r'(?i)"(?:exec|sh|bash|shell|cmd|command|run|system|popen|readfile|readFile|writefile|open|load)"\s*:',
                r'(?i):\s*(?:exec\.|os\.|syscall\.|os/exec)'],
         why="FuncMap registers an exec/file function: the template is now code"),

    # Found during the 2026-11-16 stress test: when a FuncMap is defined as a
    # standalone var and registered elsewhere via .Funcs(fmap), the anchor of
    # E2-FUNCMAP-EXEC (the .Funcs( call site) never sees the key names.
    # This rule anchors the FuncMap{ literal directly; scope=func also covers a
    # top-level var (func_at maps it to "<top>", i.e. the whole file). any_of is
    # bounded by "quoted exec-class key followed by a colon" or "colon directly
    # followed by exec./os./syscall.", so an unrelated exec in the same file does
    # not confuse it (the ":=" in `x := exec.` does not match :\s*exec\.).
    dict(id="E2-FUNCMAP-DEF", path="E2", sev="critical", kind="call", scope="func",
         anchor=r"\bFuncMap\s*\{",
         any_of=[r'(?i)"(?:exec|sh|bash|shell|cmd|command|run|system|popen|readfile|readFile|writefile|open|load)"\s*:',
                r'(?i):\s*(?:exec\.|os\.|syscall\.|os/exec)'],
         why="Still anchored when the FuncMap definition is split from .Funcs(): the key name is the capability"),

    dict(id="E2-SPRIG", path="E2", sev="high", kind="line",
         rx=r'\b(?:sprig\.(?:TxtFuncMap|GenericFuncMap|HermeticTxtFuncMap))\b',
         why="sprig function set includes env/expandenv/getHostByName; amplifies impact when templates are controllable"),

    dict(id="E2-TPL-CALL", path="E2", sev="medium", kind="line",
         rx=r'\{\{[^}]*\bcall\b',
         why="call used inside a template: can invoke any function value exposed by the FuncMap"),

    # ---------------- E3 deserialization ----------------
    dict(id="E3-GOB-NET", path="E3", sev="high", kind="call",
         anchor=r"\bgob\.NewDecoder\s*\(",
         any_of=[r'\.Body', r'\bconn\b', r'\.Accept\(\)', r'PostBody', r'Request\(\)\.Body'],
         why="gob decodes network input directly: type instantiation plus memory exhaustion, and the result is often used as a command or path"),

    dict(id="E3-SESSION-DECODE", path="E3", sev="high", kind="line",
         rx=r'\b(?:securecookie\.Decode|sessions\.NewCookieStore|gorilla/sessions)',
         why="cookie session encode/decode: the entry point of several historical CVEs; check whether the key is hardcoded or predictable"),

    dict(id="E3-YAML-IFACE", path="E3", sev="low", kind="call",
         anchor=r"\byaml\.Unmarshal\s*\(",
         any_of=[r'interface\{\}', r'map\[string\]interface\{\}', r'&raw', r'&out'],
         why="yaml deserialization into a generic container: check whether the result is later reflect/dynamically invoked"),

    # ---------------- E4 write-then-execute ----------------
    dict(id="E4-HOOK-WRITE", path="E4", sev="critical", kind="call", scope="func",
         anchor=r"\b(?:os\.WriteFile|ioutil\.WriteFile|os\.Create|os\.OpenFile|os\.Rename|io\.Copy)\s*\(",
         any_of=[r'(?i)hooks[/\\]', r'(?i)["`]hooks["`]', r'(?i)\.git[/\\]'],
         why="Writes into the git hooks directory: the next git operation executes it as the service account"),

    dict(id="E4-EXECPATH-WRITE", path="E4", sev="critical", kind="call", scope="func",
         anchor=r"\b(?:os\.WriteFile|ioutil\.WriteFile|os\.Create|os\.OpenFile)\s*\(",
         any_of=[r'(?i)crontab|/etc/cron', r'authorized_keys', r'\.bashrc|\.profile|\.zshrc',
                 r'(?i)/etc/systemd|\.service["`]', r'(?i)\.ssh[/\\]', r'(?i)bin[/\\]'],
         why="Writes to a location the system or an interpreter will execute"),

    dict(id="E4-ZIPSLIP", path="E4", sev="high", kind="line",
         # `Extract` alone is a method name on every driver interface in the wild
         # (alist: 22/22 tier-B hits were driver.Extract definitions, cloudreve
         # 18/18 the same). Only an extract *call* whose name is unambiguous, or a
         # real archive reader, is a candidate.
         rx=r'\b(?:zip\.NewReader|tar\.NewReader|archiver\.(?:Unarchive|Extract)'
            r'|Extract(?:All|To)\s*\()',
         why="Archive extraction: check whether filepath.Join is followed by a Clean + prefix check (Zip Slip writes to an arbitrary path)"),

    # ------- X path-traversal families: not an RCE phase on its own, but the -------
    # ------- usual entry that turns "write anywhere" into "write a hook/template" ---
    dict(id="X-PATHTRAV-JOIN", path="X", sev="high", kind="call", scope="func",
         anchor=r"\b(?:os\.Open|os\.OpenFile|os\.ReadFile|ioutil\.ReadFile|os\.WriteFile|"
                r"ioutil\.WriteFile|os\.Create|os\.Stat|os\.RemoveAll)\s*\(",
         any_of=[r"\b(?:filepath|path)\.Join\s*\("],
         none_of=[r'\b(?:filepath|path)\.Join\s*\(\s*"[^"]*"\s*(?:,\s*"[^"]*"\s*)*\)'],
         why="File path built by Join and contains a variable: check whether .. and the Clean prefix are validated "
             "(traversal -> arbitrary read/write -> writable hook/template, i.e. lands in E4)"),

    dict(id="X-PATHTRAV-SLICE", path="X", sev="high", kind="line",
         rx=r"filepath\.Join\s*\(\s*\w+\[\s*\d+\s*:\s*\d+\s*\]",
         why="Reassembles a path fragment from an index slice: the slice result itself may contain .., "
             "and the parent check is often bypassed (this is exactly Gitea 1.4.0 transformKey)"),

    dict(id="E4-PLUGIN-DIR", path="E4", sev="high", kind="line",
         rx=r'(?i)plugins?[/\\]["`]|plugin\.Open',
         why="Writable plugin directory plus plugin.Open loadable = code execution"),

    # ---------------- E6 dynamic loading / reflection ----------------
    dict(id="E6-PLUGIN-OPEN", path="E6", sev="high", kind="call",
         anchor=r"\bplugin\.Open\s*\(",
         none_of=[r'plugin\.Open\s*\(\s*"[^"]*"\s*\)'],
         why="plugin.Open path is not a literal"),

    dict(id="E6-SYSCALL-EXEC", path="E6", sev="high", kind="call",
         anchor=r"\bsyscall\.Exec\s*\(",
         why="execve directly, bypassing the argument semantics of os/exec"),

    dict(id="E6-REFLECT-CALL", path="E6", sev="low", kind="line",
         rx=r'\.(?:MethodByName|Call|CallSlice)\s*\(',
         why="Reflective dynamic call: check whether the method name or target object is controllable"),

    dict(id="E6-CGO", path="E6", sev="low", kind="line",
         rx=r'^\s*(?://\s*#cgo|import\s+"C")',
         why="cgo boundary: memory-safety assumptions no longer hold here"),

    # ---------------- supporting signals (not RCE by themselves) ----------------
    dict(id="X-PPROF-EXPOSED", path="X", sev="low", kind="line",
         rx=r'pprof\.(?:Index|Handler)|net/http/pprof',
         why="pprof exposed: information leak and DoS, frequently a precursor in a chain"),

    dict(id="X-NETRPC", path="X", sev="low", kind="line",
         rx=r'\bnet/rpc\b|rpc\.NewServer\(',
         why="net/rpc uses gob encoding by default, equivalent to an E3 entry"),
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
    L.append("# go-sec-audit scan report\n")
    L.append(f"- Root: `{res['root']}`")
    L.append(f"- `.go` files scanned: **{res['scanned']}**")
    L.append(f"- Skipped: {res['skipped']['vendor']} vendor dir(s) / {res['skipped']['tests']} test file(s) / {res['skipped']['dirs']} other dir(s)")
    if res["skipped"]["vendor"] and min_sev in ("low", "medium"):
        L.append("  > vendor/ and test files were not scanned. **This report makes no negative claim about them**; rerun with `--include-vendor --include-tests` if needed.")
    L.append(f"- Candidate hits: **{len(hits)}** (input source present in the same func {len(chained)} / sink only {len(plain)})")
    L.append("- Per-phase counts: " + " / ".join(f"{k}={v}" for k, v in sorted(by_path.items())))
    L.append("\n> This report is a **candidate list only**. A hit is not a vulnerability; no hit is not safety. "
             "Every candidate must go through the L0 -> L3 grading in references/verification-gates.md.\n")

    L.append("## A. High-priority candidates (input source in the same function)\n")
    if not chained:
        L.append("_None. This does not mean the project is safe; it only means the rules did not see a source and a sink inside the same function this round. Cross-function propagation needs Phase 2 manual tracing._\n")
    else:
        L.append("| # | Phase | Rule | Location | Function | Input source | Entry guess | Rationale |")
        L.append("|---|-------|------|----------|----------|--------------|-------------|-----------|")
        for i, h in enumerate(chained, 1):
            loc = f"{Path(h['file']).name}:{h['line']}"
            L.append(f"| {i} | {h['rule']['path']} | {h['rule']['id']} | `{loc}` | `{h['func']}` | "
                     f"{', '.join(h['srcs'])} | {', '.join(h['entry']) or '-'} | {h['rule']['why']} |")
        L.append("")

    L.append("## B. Sink hits only (cross-function propagation pending)\n")
    if not plain:
        L.append("_None._\n")
    else:
        L.append("| # | Phase | Rule | Location | Function | Rationale |")
        L.append("|---|-------|------|----------|----------|-----------|")
        for i, h in enumerate(plain, 1):
            loc = f"{Path(h['file']).name}:{h['line']}"
            L.append(f"| {i} | {h['rule']['path']} | {h['rule']['id']} | `{loc}` | `{h['func']}` | {h['rule']['why']} |")
        L.append("")

    callers = [(h, c) for h in hits for c in h.get("callers", [])]
    if callers:
        L.append("## C. Call-site leads (what the previous hop passed in)\n")
        L.append("| Sink location | Function | Call site | Argument text |")
        L.append("|---------------|----------|-----------|---------------|")
        for h, c in callers[:40]:
            L.append(f"| `{Path(h['file']).name}:{h['line']}` | `{h['func']}` | "
                     f"`{Path(c['file']).name}:{c['line']}` | `{c['code']}` |")
        L.append("")

    L.append("## D. Code excerpts\n")
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
