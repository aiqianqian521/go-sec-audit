# Route Map: Where to Look First in a Go Project

This file solves a **sequencing** problem, not a knowledge problem. The six phases (E1-E6 + X) tell you what shapes exist, but a real project throws up a hundred candidates at a time; efficiency is decided by which 90 you rule out first.

Principle: **falsify first, confirm later**. Every route here is designed to be killed within 5 minutes, not confirmed within 5 minutes.

**Calibration data (2026-11-13, 10 real projects / 760k LOC / 586 hits)**: density 0.77 hits per thousand lines. Tier S was 14 hits (2.4%), Tier A 16 (2.7%), so **S+A together are only 5.1%**. The three rules with the most hits (E2 templates 40%, X path traversal 22%, E6 reflection 15%) happen to be the least directly exploitable. **Sorting by hit count is sorting by noise** — that is the entire reason this file exists.

---

## 0. Three Hard Orderings (violate any one and everything downstream is wasted)

1. **Route registration -> authentication state -> sink**. The order cannot be reversed.
   A handler that is never registered (config switch off, excluded by build tag, plugin not enabled)
   is dead code no matter what it contains.
   Field lesson: Gitea 1.4.0 ships the full LFS handler set, but with `LFS.StartServer=false`
   the routes are never registered and every request 404s — it took three wrong guesses
   before the git-version gate surfaced.
2. **Establish the deployment shape before discussing impact**. `FROM scratch` / distroless
   images have **no `sh`**: an E1 payload is fully valid at source level and fails instantly
   at runtime. Same for non-root, read-only rootfs, and seccomp.
3. **A sink with no entry point does not belong in the body**. If a library function is called
   from 40 packages but none of them traces back to request data, it is L0, and putting it in
   the body dilutes the whole report.

---

## 1. Framework Fingerprint -> Jump Straight to Route Files

| Fingerprint (grep these) | Framework | Where routes usually register | Where auth middleware lives |
|---|---|---|---|
| `http.HandleFunc` / `http.ListenAndServe` / `http.ServeMux` | net/http | same file as handlers, scattered | no unified layer; **each handler decides for itself** (most dangerous) |
| `gin.Default()` / `.GET(` / `.Group(` / `.Use(` | gin | `router/`, `routers/`, `internal/router` | `.Use(...)` chain; a group-level `Use` applies only inside that group |
| `echo.New()` / `e.Group(` / `e.Use(` | echo | same as above | same; the `mw` in `e.Group("/api", mw)` applies only inside it |
| `chi.NewRouter()` / `r.Route(` / `r.Group(func(r chi.Router)` | chi | `routes.go`, usually inside `func Routes()` | `r.Use(auth)` inside `r.Group`; **endpoints outside the group have no auth by default** |
| `macaron.Classic()` / `m.Get(` / `m.Group(` | macaron (Gitea/Gogs <=1.9) | `routers/routes/routes.go` | global `m.Use(...)` plus `reqSignIn` |
| `app.Get(` / `app.Use(` | fiber | centralized in `main.go` | global `Use`, mind the order |
| `web.Router("...", &ctrl{}, "post:Method")` | beego | `routers/router.go` | `web.InsertFilter` |
| `mux.HandleFunc(...).Methods(` / `r.Handle(` | gorilla/mux | scattered | no unified layer |

**Decision procedure**: `grep -rn "\.Use(\|\.Group(\|Middleware\|RequireSignIn\|BasicAuth\|csrf" --type go | head -40`
- Global `Use` present: treat "requires auth" as the default and hunt for **explicitly excluded** endpoints (allowlists, `/api/public`, webhooks, login pages)
- **No unified middleware found**: treat everything as unauthenticated. This is the most productive kind of project to audit.

**Prioritized endpoints** (highest to lowest unauthenticated probability):
public signup/login/password reset -> webhook receivers -> file upload/download -> import (URL/package/repository) -> preview/render -> export -> health check/debug -> static asset handlers

---

## 2. Entry Shapes -> Priority Phase (this decides 80% of the outcome)

| Entry trait | Check first | Why | One-line falsification |
|---|---|---|---|
| Calls an external command (git/tar/zip/ffmpeg/rsync/7z) | **E5** | once arguments reach argv, a single user-controlled `--upload-pack=...` is enough | every user-controlled argv item is preceded by a literal prefix or `--` |
| `exec.Command("sh"/"bash"/"cmd"/"powershell", ...)` | **E1** | the only "direct" shape | arguments are passed as a separate `[]string` and **the target platform is not Windows** |
| Template text comes from the user / FuncMap holds os, exec, readfile | **E2** | most Go SSTI is a shadow vulnerability with no CVE | template is a fixed literal + FuncMap holds pure functions |
| Can write files (upload, extract, checkout, patch, restore) | **E4** | write to the right place and it executes; `exec` can be absent the whole way | no executor lives under the write directory (hook/cron/webroot/plugin/template) |
| Decodes (gob/yaml/cookie/session/pickle-lite) | **E3** | decoding never executes; you must follow what the result is used for | the result is only displayed or compared; it never reaches a command, a path, or a permission check |
| Loads (`plugin.Open`, `dlopen`, extensions, interpreter built-in `LOAD`) | **E6** | a controllable target means code loading | the path is a literal, or signatures are verified |
| Plain numeric/ID/enum parameters | skip | unless it feeds one of the paths above | — |

**Note: label != phase**. CVE-2024-9264 is labelled SQL injection but is really E6 (an interpreter that can `LOAD` extensions); CVE-2026-60004 never calls `exec.Command` and is pure E4. **Auditing by label produces the wrong remediation.**

**Likewise, method name != rule** (blind-test lesson, 2026-11-13): `Extract` is a driver-interface method name in file-serving projects, not an extraction action; `Parse` in time/URL contexts is formatting, not template evaluation. Once a rule degrades into "matches a common word", Tier A/B floods — all 22 Tier B hits in alist were `func (d *X) Extract(...)` definitions. **When Tier A/B rates jump, suspect the rule before the project.**

---

## 3. Dangerous Functions Sorted by Executability Radius

Sort scanner hits with this table: spend time on Tier S/A, and look at Tier C only when a downstream consumer is explicit.

| Tier | Shape | Representative symbols | Distance to RCE |
|---|---|---|---|
| **S** | Direct execution | `exec.Command("sh","-c",...)`, `exec.Command(<var>, "-c", <expr>)` (rule `E1-SHELL-EXPR`, including wrappers such as `newCmd(...)`), `syscall.Exec`, `plugin.Open(var)`, `os.StartProcess` | 1 hop |
| **A** | Indirect execution | `exec.Command("git"/"tar"/"rsync", user args...)`, `template.Parse(user string)`, `Funcs(map containing exec)`, `text/template` rendering a user template | 1-2 hops, needs environment support |
| **B** | Writes into an executable location | `WriteFile` / `Create` / `OpenFile` / `Rename` landing in `hooks/`, `cron.d`, `authorized_keys`, `webroot`, `.git/config`, plugin directories | waits for one external trigger |
| **C** | Decode/reflection | `gob.Decode`, `yaml.Unmarshal`, `json.Unmarshal` (only when the result is used as a command/path/permission) | 3+ hops, mostly false positives |
| **X** | Precursor primitive | `filepath.Join` without a prefix check, unsanitized path parameters, `filepath.Join(x[0:2],...)` | not RCE itself; the first half of a chain |

**Tier B requirement**: you must name who executes files in that directory, and when. Cannot name the executor -> drop to L0. `hooks/` has git, `cron.d` has cron, `authorized_keys` has sshd; writes under `data/` or `uploads/` usually have no executor, so do not invent one.

---

## 4. The 35-Minute Standard Route

| Stage | Min | Action | Output | When to give up immediately |
|---|---|---|---|---|
| T0 Scope | 5 | `go.mod` version, framework, deployment shape (Dockerfile), public signup or not | one-page fact card | the project is a library with no entry point -> L0 appendix only |
| T1 Entry | 10 | locate route registration files, mark **unauthenticated** endpoints | endpoint list (URL + parameter names) | no routes at all (CLI/daemon) -> switch to the CLI entry point and redo T1 |
| T2 Candidates | 10 | run the scanner + the three fallback `rg` sweeps, look at Tier S/A only | candidate list (with `path:line`) | scanner and `rg` both at 0 -> record "no hits", never "secure" |
| T3 Chain | 5 each | for each candidate write: entry -> parameter -> transform chain -> gate | L1 or the reason for downgrade | any gate from the inventory applies and cannot be bypassed -> downgrade and record it |
| T4 Injectability | 5 each | write the concrete payload string + the characters that must survive | L2 | a character is stripped at some hop -> back to L1 |

Do L3 only when you can compile, start the service, and have an isolated environment. If you cannot, write "not reproduced" plainly; never substitute "should be exploitable".

---

## 5. Known Gate Inventory (what turns "looks like" into "cannot be reached")

If any gate applies you must state its **location** in the report, or the conclusion does not stand:

| Gate | Symptom | How to identify |
|---|---|---|
| Route not registered | request 404s while every handler exists in source | search config switches (`if cfg.XxxEnable`, conditions around `m.Group`), build tags |
| Version gate | the feature is switched off wholesale | startup-log warnings, version comparisons in `setting.go` (Gitea's git >= 2.1.2 is this) |
| Content gate | written, then deleted or never persisted | the "write temp file -> verify -> rename" pattern (sha256 must equal the filename) |
| Length gate | 200 response with 0 bytes | the handler sets `Content-Length` from a `Size` in the request or DB |
| No shell | valid at source, fails at runtime | `FROM scratch`/distroless images; `sh` not on PATH |
| Permissions | cannot write / cannot read | service account, directory mode, read-only rootfs |
| Argument allowlist | injection characters get stripped | look for a `--` separator, leading-`-` rejection, regex allowlists |
| Sandbox | syscalls are denied | seccomp/AppArmor config, container `--security-opt` |
| Authentication state | it was never unauthenticated | read the middleware at the **registration site**, not inside the handler |

---

## 6. Output: Write the Route into the Report

One line per candidate; a missing column means the work was not done:

```
F1 | E5 | repo/import.go:118 | POST /repo/import (unauthenticated) | param: clone_addr
   | chain: handler -> models.Migrate -> git clone <url> (argv concat) | gate: none
   | level: L2 | surviving chars: space / `-` / `/`
```

And there **must be a Rejected section** stating which candidate was blocked by which gate. A report that only lists confirmed findings leaves the reader unable to tell whether you checked or simply did not think of it.
