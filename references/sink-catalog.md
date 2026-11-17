# Sink Rule Reference

Every rule here maps to `RULES` in `scripts/scan_sinks.py`. IDs are stable; when a rule changes, change this file in the same commit.

**How to read**: a rule answers only "worth a look", never "there is a vulnerability". Each entry gives three things: what it matches, what a true positive looks like, what noise looks like.

---

## E1 Command Concatenation

### `E1-SHELL-C` (critical)
- **Match**: the call text of `exec.Command` / `exec.CommandContext` contains both a shell name (sh/bash/zsh/dash/ash/ksh) and `-c`
- **True positive**: `exec.Command("sh", "-c", "cat /reports/"+name)` where `name` comes from the request
- **Noise**: ~~`exec.Command("sh", "-c", "nginx -s reload")`, a constant script~~
  **(Corrected by the 2026-11-16 stress test: constant scripts are excluded directly by the rule's `none_of`, never reach the candidate list, and the pure-literal form that wasted a critical slot was removed during the 760k LOC regression)**;
  residual noise = `exec.Command("bash", "-c", script)` where `script` is a variable holding repo-internal configuration
  — the rule cannot see data flow, so only this kind needs a manual KILL
- **Criteria**: does the script string contain user data? Is it wrapped in `shellescape.Quote`?

### `E1-SHELL-EXPR` (high)
- **Match**: any call whose name contains `Command`/`Cmd`, containing `-c`, where **the argument after `-c` is not a literal** (a variable, an expression, or `fmt.Sprintf(...)`)
- **Why listed separately**: `E1-SHELL-C` requires the shell to be a literal, and the two most common real-world shapes both dodge that requirement —
  ① `exec.Command(shell, "-c", script)` (shell in a variable, from config or `step.Image`);
  ② `newCmd(ctx, "/bin/sh", "-c", fmt.Sprintf(...))` (forwarded through a wrapper, so `exec.Command` is not on that line)
- **True positive**: Woodpecker `pipeline/backend/local/command.go:182`, `clone.go:103` (both hit in the field test)
- **Noise**: `script` is a constant (e.g. the probe script in `probeShellIsPosix`, a literal constant assigned to a variable);
  a non-shell `-c` (`git -c key=value`)
- **Criteria**: what is the **root** of the expression after `-c`? Constant -> downgrade; request/config -> keep tracing.
  **Note**: the rule sees shape, not data flow; a hit means "there is a shell interpretation point here", not injection
- **Known miss**: argv assembled **inside another function** and passed in —
  `genCmdByShell` returns `[]string{"-e", "-c", script}` (`command.go:122`),
  while the caller `newCmd(ctx, shellPath, args...)` (`:60`) contains no `-c` literal at all. This class needs `--callers` plus manual work


### `E1-SHELL-WIN` (critical)
- **Match**: cmd/powershell/pwsh + `/c`|`/k`|`-Command`|`-c`
- **True positive**: kubelet class — the arguments look "passed separately", but `cmd /c` and PowerShell re-parse `&`, `$()` and `|` inside the string
- **Noise**: `exec.Command("cmd", "/c", "ver")`, a constant
- **Criteria**: does the parsed token contain user data? Even as a separate argv, a Windows shell still interprets it

### `E1-STARTPROC` (high)
- **Match**: `os.StartProcess`
- **True positive**: argv built by `strings.Fields(userCmd)`
- **Noise**: launching a child process with a fixed argv
- **Criteria**: where does the argv slice come from

### `E1-CMD-INTERP` (high)
- **Match**: a literal shell command line immediately followed by `+` concatenation
- **True positive**: `"/bin/sh -c '" + userCmd + "'"` concatenated whole and handed to something that executes it
- **Noise**: a command string printed to the log (never executed)
- **Criteria**: does the string ever reach `exec`/`syscall`

---

## E5 Argument Injection

### `E5-GIT-OPT` (high)
- **Match**: external program (git/hg/svn/pandoc/ffmpeg/tar/zip/rsync/curl/wget/ssh) + concatenation or a known dangerous flag
- **True positive**: `exec.Command("git","clone","--upload-pack="+u)`; `exec.Command("git","clone",u)` where `u` is controllable and starts with `-` (this rule misses it; `E5-ARG-NONCONST` covers it)
- **Noise**: `exec.Command("git","log","--oneline", "-n", "10")`, entirely constant
- **Criteria**: the dangerous option inventory — git: `--upload-pack` `--receive-pack` `-c core.sshCommand` `-c core.pager`; tar: `-I` `--to-command`; ssh: `-o ProxyCommand`; pandoc: `--filter` `--lua-filter`; rsync: `-e`

### `E5-ARG-NONCONST` (low)
- **Match**: an argument after the program name is a **bare identifier** (not a literal, not a literal-prefix concatenation)
- **True positive**: `exec.Command("git", "clone", userRef)` — `userRef="-c core.pager=id"` does not work (git's `-c` must precede the subcommand), but `"--upload-pack=..."` does
- **Noise**: `exec.Command("cat", filename)` — a leading `-` on `filename` can at most make `cat` read a different file, it does not escalate to execution
- **Criteria**: does this program have an option that runs an argument value as a command. No -> downgrade

> This rule is deliberately `low`: its purpose is to make a human look at argument position, not to raise an alarm.

---

## E2 Templates

### `E2-FUNCMAP-EXEC` (critical)
- **Match**: keys registered in `.Funcs(` look like exec/run/shell/cmd/system/readfile/writefile, or the values come from `os.`/`exec.`/`syscall.`
- **True positive**: `{"run": func(c string) string { exec.Command("sh","-c",c) ... }}` — `{{ run "id" }}` in the template
- **Noise**: `{"upper": strings.ToUpper}`; `{"now": time.Now}`
- **Criteria**: read the implementation behind every FuncMap key. **The template may be entirely fixed while the door stays open** (if the template file is writable -> becomes E4)
- **Known miss (2026-11-16 stress test)**: when the FuncMap is defined as a standalone `var` and registered elsewhere with
  `.Funcs(fmap)`, this rule cannot anchor the key names — `E2-FUNCMAP-DEF` covers it (below)

### `E2-FUNCMAP-DEF` (critical) — `scope=func` (added 2026-11-16)
- **Match**: a `FuncMap{` literal (no `.Funcs(` required) inside a function or at top level, containing
  execution-class key names (`"run":`, `"exec":`...) or values immediately following `exec.`/`os.`/`syscall.`
- **Why listed separately**: real code often keeps the FuncMap in its own var, separating definition from registration,
  while `E2-FUNCMAP-EXEC` only anchors the call site
- **True positive**: `var fmap = template.FuncMap{"run": func(c string){ exec.Command("sh","-c",c) }}`
- **Noise**: all keys are pure functions (`upper`/`printf`); an unrelated `x := exec.Command` in the same file
  is not a key (the `:=` does not match `:\s*exec\.`)
- **Criteria**: same as E2-FUNCMAP-EXEC — read each key's implementation; negative sample `neg_e2_funcmap_benign.go.txt`

### `E2-TPL-USERSTRING` (high)
- **Match**: the only argument to `Parse`/`ParseFiles`/`ParseGlob` is not a string literal
- **True positive**: `template.New("x").Parse(r.FormValue("tpl"))`
- **Noise**: `ParseFS(embedFS, "*.tmpl")`; multi-argument `ParseFiles("a.tmpl","b.tmpl")` (`first_arg_is_literal` only skips single-argument calls, multi-argument cases need a human)
- **Historical noise (fixed 2026-11-13)**: `time.Parse` / `url.Parse` / `schema.Parse` / `ini.Parse`
  were once treated as template evaluation. 18 of gogs's 21 Tier A hits and 27 of alist's 40 were this class.
  The root cause was not only a loose regex — the scanner's `target` originally started after `(`, so `none_of`
  could not see the `time.` prefix, which made **the first fix ineffective**. The fix was `scope="callee"` plus
  excluding 22 non-template packages. Negative sample `assets/selftest/neg_e2_time_parse.go.txt`.
- **Criteria**: can the request influence the argument? If not, downgrade

### `E2-SPRIG` (high)
- **Match**: `sprig.TxtFuncMap` / `GenericFuncMap` / `HermeticTxtFuncMap`
- **True positive**: controllable template + sprig's `env`/`expandenv` -> secret disclosure; combined with Helm `tpl` it can evaluate recursively
- **Noise**: fixed template, fixed data
- **Criteria**: sprig does not execute commands by itself; it is an amplifier, not an origin

### `E2-TPL-CALL` (medium)
- **Match**: `{{ ... call ... }}` appears in template source
- **True positive**: `{{call .Cmd "id"}}` where `.Cmd` is a function value passed in
- **Noise**: `call` used as an ordinary field name
- **Criteria**: can you control the function value being called

---

## E3 Deserialization

> Every rule in this phase is only an "entrance" — **none of them constitutes RCE on its own**. A downstream use must follow.

### `E3-GOB-NET` (high)
- **Match**: `gob.NewDecoder(` where the argument involves `.Body` / `conn` / `Accept()` / `PostBody`
- **True positive**: `gob.NewDecoder(r.Body).Decode(&job)` — check DoS first (length-prefix preallocation), then where `job`'s fields go
- **Noise**: decoding a local file; decoding an in-memory buffer you just encoded
- **Criteria**: where does the decoded result go

### `E3-SESSION-DECODE` (high)
- **Match**: `securecookie.Decode` / `sessions.NewCookieStore` / importing `gorilla/sessions`
- **True positive**: key hard-coded in the repo -> forge a cookie -> privilege escalation -> feeds E4
- **Noise**: key comes from an environment variable with sufficient length, `MaxAge` is sane
- **Criteria**: is the key predictable? What privilege does forgery yield? What can that privilege do?

### `E3-YAML-IFACE` (low)
- **Match**: `yaml.Unmarshal` into `interface{}` / `map[string]interface{}`
- **True positive**: the decoded map is reflected into config, and that config has a `command` field -> E1
- **Noise**: config loading (local file, not a request)
- **Criteria**: is the source a request; does any decoded value enter an execution path

---

## E4 Write-Anywhere-Executed

> This phase is the easiest to miss because it contains **no exec**. All four conditions are required: controllable path or fixed location + controllable content + permissions + downstream executor.

### `E4-HOOK-WRITE` (critical) — `scope=func`
- **Match**: `hooks/` or `.git/` appears in the **function body** containing the write call
- **True positive**: `filepath.Join(repo, ".git", "hooks", "post-merge")` + `os.WriteFile(..., 0755)`
- **Noise**: reading the hooks directory for display; written then immediately deleted with no execution
- **Criteria**: can the write path escape to `.git/hooks` via `..`; does the content contain user data; who triggers git

### `E4-EXECPATH-WRITE` (critical) — `scope=func`
- **Match**: a file write plus crontab/cron, authorized_keys, .bashrc/.profile/.zshrc, systemd, .ssh, or bin in the function body
- **True positive**: `os.WriteFile("/etc/cron.d/x", []byte(userCron), 0644)`
- **Noise**: writing `~/.ssh/known_hosts` (never executed); writing a log to a name under `bin/` that is not an executable
- **Criteria**: is the landing spot read and executed by the system or an interpreter

### `E4-ZIPSLIP` (high)
- **Match**: `zip.NewReader` / `tar.NewReader` / `archiver.Unarchive|Extract` / `ExtractAll(` / `ExtractTo(`
- **Known miss (2026-11-16 stress test)**: when the reader arrives as a **function parameter** (`func unzip(dst string, zr *zip.Reader)`),
  the anchor `zip.NewReader` is absent and this rule does not fire — `X-PATHTRAV-JOIN` covers it by waking on
  `os.Create(filepath.Join(dst, f.Name))`. Judge extraction functions with the X criteria;
  never write "no extraction risk" merely because ZIPSLIP did not fire.
- **True positive**: `os.Create(filepath.Join(dst, hdr.Name))` where `hdr.Name = "../../etc/cron.d/x"`
- **Noise**: extracting into a temp directory with no validation (limited impact); `filepath.Clean` plus a prefix check already present
- **Historical noise (fixed 2026-11-13)**: the original regex was `Extract(?:All|To)?`, and the optional group made it
  degenerate into "matches any word called `Extract`". All 22 Tier B hits in alist were
  `func (d *Gofile) Extract(...)` cloud-drive method definitions, and cloudreve's 18 were the same.
  Lesson: **a method name is not a rule** — `Extract` is an interface method name in file-serving projects, not an extraction action.
  The fix removed the optional group and matches only `ExtractAll(` / `ExtractTo(` and the real archive readers.
  Negative sample `assets/selftest/neg_e4_extract_iface.go.txt`.
- **Criteria**: is the target directory an executable location; is there `..` validation
- **New criterion (Go >= 1.24)**: when the extraction root is an `*os.Root` from `os.OpenRoot(dst)`, subsequent
  `root.OpenFile(header.Name, ...)` calls go through kernel-level `RESOLVE_BENEATH`, and `../` returns an error directly.
  **Seeing `os.OpenRoot` means a structural fix; stop looking for `Clean` plus a prefix check**.
  Instance: Woodpecker `cli/update/tar.go:35` (`root, err := os.OpenRoot(dst)`) ->
  the same `UnTar` therefore cannot zip-slip, even though it does no string validation at all

### `E4-PLUGIN-DIR` (high)
- **Match**: `plugin`/`plugins` appears in a path, or `plugin.Open`
- **True positive**: upload -> lands in the plugin directory -> loaded next time
- **Noise**: the namespace is merely called plugins while storing configuration
- **Criteria**: will the directory contents be loaded

---

## E6 Dynamic Loading

### `E6-PLUGIN-OPEN` (high)
- **Match**: `plugin.Open(` with a non-literal argument
- **True positive**: `plugin.Open(r.FormValue("mod"))`
- **Noise**: `plugin.Open(fmt.Sprintf("plugins/%s.so", cfg.Name))` where `cfg` comes from a local config file
- **Criteria**: controllable path + writable file + build with CGO (`go env CGO_ENABLED`, and plugin is Linux-only)

### `E6-SYSCALL-EXEC` (high)
- **Match**: `syscall.Exec(`
- **True positive**: `syscall.Exec("/bin/sh", []string{"sh","-c",user}, env)`
- **Noise**: container init process switching (constant path, bootstrap scenario)
- **Criteria**: where the path and argv come from

### `E6-REFLECT-CALL` (low)
- **Match**: `.MethodByName(` / `.Call(` / `.CallSlice(`
- **True positive**: plugin-style routing `obj.MethodByName(cmd).Call(args)`
- **Noise**: reflection inside ORM/serialization libraries
- **Criteria**: is the method name controllable

### `E6-CGO` (low)
- **Match**: `#cgo` or `import "C"`
- **Purpose**: marks where memory-safety assumptions stop holding, and `plugin` requires CGO. Not a vulnerability signal
- **Criteria**: context only

---

## X Auxiliary Signals (not RCE)

### `X-PPROF-EXPOSED` (low)
- **Match**: `net/http/pprof`
- **Purpose**: an exposed `/debug/pprof/` is often pre-chain reconnaissance (goroutine stacks leak paths, heap dumps leak data). `/debug/pprof/symbol` plus large memory can DoS
- **Criteria**: is it bound to a public listener
- **One extra step is mandatory (measured 2026-11-16)**: this rule **cannot see route middleware**.
  All 6 Woodpecker hits landed in `server/api/debug/debug.go`, while
  `server/router/api.go:273` is `debugger.Use(session.MustAdmin())` and the whole route group
  is only mounted at debug log level -> all 6 were false positives.
  **Criterion addendum**: grep the handler's registration site first and look for auth on `Use(...)`/`Group(...)`;
  continue only when no auth middleware is present

### `X-NETRPC` (low)
- **Match**: `net/rpc` / `rpc.NewServer`
- **Purpose**: net/rpc defaults to gob encoding -> equivalent to an E3 entrance, with no auth by default
- **Criteria**: who can reach the service

### `X-PATHTRAV-JOIN` (high)
- **Match**: the path argument of `os.Open / OpenFile / ReadFile / WriteFile / Create / Stat / RemoveAll` is built, **inside the same function**, by `filepath.Join` or `path.Join` with at least one variable part (all-literal Joins are excluded)
- **Why listed separately**: Go RCE rarely walks from input to `exec` in one step, but "arbitrary file write" almost always completes into RCE — write git hooks (lands in E4), write templates (lands in E2), write `authorized_keys`. Path traversal is therefore the most common **first half** of an RCE chain
- **Criterion 1 (is it fixed)**: after the Join, is there `filepath.Clean` **and** a prefix check (`strings.HasPrefix(clean, base)`). **Clean without a prefix check is not a fix**; `../../` still escapes
- **Criterion 2 (is the write side usable)**: on a `WriteFile/OpenFile/Create` hit, **you must look back for a content gate before the write**. The textbook counterexample is Gitea 1.4.0 `content_store.go:67-72`: write `<path>.tmp`, then compare `sha256(content) == meta.Oid`, and on mismatch delete the tmp and skip the Rename. Here **"controllable path" and "controllable content" are mutually exclusive** — the path is derived from the Oid, and the Oid must be the hash of the content. **On sight of the "write temp file + verify + rename" pattern, rule it as not-arbitrary-write**
- **Criterion 3 (residual write-side effect)**: even with a content gate, `os.MkdirAll(dir)` usually sits **before** the gate (same Gitea function at `:56`) -> **arbitrary directory creation** still holds. Do not call it "writable file", but do not omit it either
- **Criterion 4 (can the read side get the bytes)**: if the read handler sets `Content-Length` from a `Size` stored in the DB and that `Size` is attacker-controlled, then **content longer than Size is discarded wholesale by net/http** (`http.response.Write` returns `ErrContentLength`), which shows up as "200 + 0 bytes". Check order: first 200 vs 404 (200 means `os.Open` succeeded), then compare `Size` against the real file length
- **Field test**: Gitea 1.4.0 `modules/lfs/content_store.go:29` (`Get`) and `:49` (`Put`) both hit — the read side holds (unauthenticated arbitrary file read), the write side is blocked by the sha256 gate


### `X-PATHTRAV-SLICE` (high)
- **Match**: path reassembly from index slices such as `filepath.Join(x[0:2], x[2:4], x[4:])`
- **Why it must be listed**: slicing looks like "take a fixed-length prefix as a shard directory", so reviewers tend to call it safe. But **the slice result itself can contain `..`**, and the parent-level check is usually done once and is a formality such as "confirm the first 4 characters are hex"
- **Field test**: Gitea 1.4.0 `transformKey()`:
  ```go
  if len(key) < 5 { return key }                      // short keys are not processed at all
  return filepath.Join(key[0:2], key[2:4], key[4:])   // no .. validation
  ```
  An attacker sends `....../../../../etc/passwd`: the first four dots are swallowed as two directory levels and the rest traverses as usual. **This also explains the odd prefix in the vulhub payload** — it is not padding, it is feeding arguments to the slicing function

---

## Three Classes Outside the Rules That Must Be Checked by Hand

1. **Generated code**: `*.pb.go`, `*_gen.go`, `wire_gen.go`. The rules will scan them, but you cannot fix the source; state in the report "generated artifact, fix upstream in .proto/idl".
2. **Build-tagged files**: a file with `//go:build linux` does not compile on your current machine. Either check the CI build matrix or explicitly state "platform not covered".
3. **`vendor/`**: skipped by default. If the project vendors its own fork (with modified source), you must re-run with `--include-vendor`, otherwise the report says nothing about vendor.

## Manual grep Supplement (run once, to cover rule blind spots)

```bash
rg -n 'sh", "-c|bash", "-c|/c", |-Command' -t go
rg -n 'hooks/|hooks\\\\|\.git/hooks|authorized_keys|cron\.d|crontab' -t go
rg -n 'Funcs\(|FuncMap\{|ParseFiles|ParseFS|plugin\.Open|syscall\.Exec' -t go
rg -n 'http\.ListenAndServe|gin\.Default|echo\.New|fiber\.New' -t go   # entry surface
```

A regex is not a scanner. It only proves "where the scanner did not look, I looked myself".
