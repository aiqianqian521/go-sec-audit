# Vulnerability Keyword Feature Library (All Types)

**Position**: this file is the **wake-up layer**. Keywords answer only "worth a look here", never "there is a vulnerability here".
The verdict belongs to three layers: **criteria in this file -> per-dimension methodology files -> evidence gates (L0-L3)**.

Two disciplines, both mandatory:

1. **A keyword is not a verdict**. Scanner rules cover only the E/X phases (RCE class, 27 rules, see
   [sink-catalog.md](sink-catalog.md)); SQLi / SSRF / access control / secrets / memory have no mechanical
   rules and rely on this file's rg keyword channel plus manual tracing. A hit is not a vulnerability,
   and no hit is not safety.
2. **Methodology files outrank keywords**. The deep criteria for each class live in the matching
   methodology file (see "Deep read" in each section); keywords are only the entrance. The core lesson
   of this methodology: discover independently from application behavior, and never treat a keyword
   table as a complete checklist.

Usage: in Phase 2, run rg per class over the target tree, record hits in the candidate table (`C-###`, source tagged `KW`), then decide with each class's criteria. Three manually-checked blind spots (generated code / build tags / vendor) are covered at the end of [sink-catalog.md](sink-catalog.md).
Reading note: keyword hits on **comment lines and string literals are normal** (inherent to any grep channel; test markers and doc comments all wake it up) — filter them by hand when reading. That is not a channel defect, but **writing a comment hit into the report** is.

---

## E1 Command Concatenation (a shell participates in parsing)

- **Mechanical rules**: `E1-SHELL-C` / `E1-SHELL-EXPR` / `E1-SHELL-WIN` / `E1-STARTPROC` / `E1-CMD-INTERP` (covered by the scanner)
- **Supplementary keywords** (scanner blind spots):
  ```bash
  rg -n 'CommandContext\(' -t go                       # CommandContext wrapper sites
  rg -n 'sh", "-c|/bin/sh|/bin/bash' -t go        # shell path variants
  rg -n '"-c"\s*,\s*\w' -t go                      # -c followed by an identifier
  ```
- **True positive**: `exec.Command("sh","-c", "tar czf "+userDir)`; the shell name hidden in a variable (`step.Image`)
- **Noise**: fully constant scripts; wrapped in `shellescape.Quote`; value passed as a positional argument
- **Falsification**: argv passed separately with no shell (-> path traversal, not injection); shell string contains no user fragment
- **Deep read**: [six-paths.md](six-paths.md) §E1, [command-execution.md](command-execution.md), [sink-catalog.md](sink-catalog.md)

## E5 Argument Injection (an argv token becomes an option)

- **Mechanical rules**: `E5-GIT-OPT` / `E5-ARG-NONCONST`
- **Dangerous option inventory** (the core of the criteria): git `--upload-pack` `--receive-pack` `-c core.sshCommand`;
  tar `-I` `--to-command`; ssh `-o ProxyCommand`; pandoc `--filter` `--lua-filter`;
  rsync `-e`; find `-exec`
- **True positive**: `exec.Command("git","clone", userURL)` where `userURL` is controllable and starts with `-`
- **Noise**: user data appended to a literal prefix (`"/reports/"+n`) — cannot become an option, not E5
- **Falsification**: the target program has no option that runs an argument value as a command -> downgrade
- **Deep read**: [six-paths.md](six-paths.md) §E5, [command-execution.md](command-execution.md) §4

## E2 Template Evaluation (SSTI)

- **Mechanical rules**: `E2-FUNCMAP-EXEC` / `E2-TPL-USERSTRING` / `E2-SPRIG` / `E2-TPL-CALL`
- **Supplementary keywords**:
  ```bash
  rg -n 'FuncMap\{|\.Funcs\(' -t go                 # the door is the FuncMap, not Parse
  rg -n 'goja|otto|starlark|cel-go|expr\.' -t go    # embedded interpreters (audit like a FuncMap)
  rg -n 'tpl\s*=|\.tpl|render.*template' -t go       # where template files get loaded from
  ```
- **True positive**: `Parse(r.FormValue("tpl"))`; a FuncMap registering `run/exec/readfile` implementations
- **Noise**: `time.Parse` / `url.Parse` (past lesson, negative samples exist); `ParseFS(embedFS,...)`; pure-function FuncMap
- **Falsification**: template is a literal and the FuncMap holds only pure functions such as `upper/printf` -> drop
- **Deep read**: [six-paths.md](six-paths.md) §E2, [template-injection.md](template-injection.md)

## E3 Deserialization

- **Mechanical rules**: `E3-GOB-NET` / `E3-SESSION-DECODE` / `E3-YAML-IFACE`
- **Core criterion**: **decoding does not execute**. Go has no gadget chains. Ask: "is the decoded result used as a command, a path, a privilege, or a load target?"
- **True positive**: a hard-coded session key -> forge an identity -> feeds E4; decoded result reaches `exec`
- **Noise**: decoding a local file; after decoding, only logging or comparison
- **Falsification**: no downstream sensitive use after decoding -> at most DoS (gob length-prefix preallocation)
- **Deep read**: [six-paths.md](six-paths.md) §E3, [case-library.md](case-library.md) A1 (three-hop chain example)

## E4 Write-Anywhere-Executed (the dominant shape grep exec cannot find)

- **Mechanical rules**: `E4-HOOK-WRITE` / `E4-EXECPATH-WRITE` / `E4-ZIPSLIP` / `E4-PLUGIN-DIR`
- **Landing spot x downstream executor inventory** (all four conditions required, see six-paths):
  `.git/hooks`->git; `cron.d`/crontab->cron; `authorized_keys`->sshd;
  `.bashrc`/`.profile`->login shell; systemd->systemd; plugin directory->application;
  template directory (hot reload)->application; `.github/workflows`->CI; `go.mod replace`->build
- **True positive**: Zip Slip landing in `/etc/cron.d`; writing `.git/hooks/post-merge` with user data in the content
- **Noise**: reading the hooks directory for display; written then deleted with no executor
- **Falsification**: **no downstream executor + no trigger moment = only arbitrary file write**. This is the most falsifiable item in the file
- **Deep read**: [six-paths.md](six-paths.md) §E4, [file-transfers.md](file-transfers.md) (arbitrary-path write vs arbitrary-content write)

## E6 Dynamic Loading

- **Mechanical rules**: `E6-PLUGIN-OPEN` / `E6-SYSCALL-EXEC` / `E6-REFLECT-CALL` / `E6-CGO`
- **Supplementary keywords**: `INSTALL EXTENSION` / `LOAD\s+\w+fs` (database extensions, the Grafana CVE-2024-9264 shape)
- **Falsification**: the load path is a constant and the artifact is not writable
- **Deep read**: [six-paths.md](six-paths.md) §E6, [case-library.md](case-library.md) A4

## X Path Traversal / Arbitrary File Read-Write (the common first half of an RCE chain)

- **Mechanical rules**: `X-PATHTRAV-JOIN` / `X-PATHTRAV-SLICE`
- **Fix recognition**: `os.OpenRoot` (Go >=1.24, structural fix — downgrade on sight);
  `Clean` plus a prefix check (Clean alone does not count); the "write temp file + verify + rename" pattern (path and content are mutually exclusive, see criterion 2)
- **Deep read**: [sink-catalog.md](sink-catalog.md) X section (criteria 1-4 include the Gitea 1.4.0 field test)

---

## SQL Injection (no mechanical rules, keyword channel only)

- **Wake-up keywords**:
  ```bash
  rg -n 'fmt\.Sprintf.*(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER)' -t go -i
  rg -n '\.(Query|Exec|QueryRow)\([^)]*\+' -t go          # concatenated into an execution call
  rg -n '\.(Raw|Where|Order|Group|Having|Select)\([^)]*(\+|Sprintf)' -t go   # GORM/ORM concatenation
  rg -n 'Order\(\s*\w+\s*\)' -t go                        # sort field passed straight through (placeholders cannot protect identifiers)
  rg -n 'gorm\.Expr|clause\.Expr|AllowGlobalUpdate' -t go
  ```
- **True positive**: `db.Raw("SELECT * FROM t WHERE name = " + name)`;
  `Order(sortCol + " " + sortDir)` (identifier position, bound parameters cannot help); deferred execution (a stored query fragment interpolated later)
- **Noise**: `Where("name = ?", x)` (value binding); strings rendered by ORM debug output (not the SQL actually sent);
  calling `Prepare` after concatenation (concatenating untrusted text before Prepare does not restore the boundary)
- **Core criterion**: trace value positions and **identifier/fragment positions** separately. Placeholders protect only their own position.
  The report must state which SQL syntactic position the insertion lands in (value/identifier/condition/order/table name)
- **Falsification**: the attacker fragment enters only value positions and is bound correctly; conversion errors are handled (the `strconv.Atoi` error is not ignored)
- **Deep read**: [sql-injection.md](sql-injection.md), [sql-reference-notes.md](sql-reference-notes.md)

## SSRF (no mechanical rules, keyword channel only)

- **Wake-up keywords**:
  ```bash
  rg -n 'http\.(Get|Post|Head)\(' -t go
  rg -n 'NewRequest\(' -t go
  rg -n 'url\.Parse|ParseRequestURI' -t go
  rg -n 'webhook|callback|ReverseProxy|[Pp]roxy[Uu]rl' -t go -i
  rg -n '[Ff]etch(Url|URL|Remote|External)|Import(Data|File|URL|[Uu]rl)|\.Preview\(' -t go
  rg -n 'CheckRedirect|DialContext|ProxyURL|ReverseProxy' -t go
  ```
  > Lesson (2026-11-16 stress test): a bare `import` matches the import statement of every Go file — a word with
  > 100% noise does not belong in the keyword table; a feature word must carry a shape (`Import(Data|File|URL)`) to disambiguate.
  > **Any keyword change must run the `assets/stress/stress_kwcheck.py` regression** (the same discipline as scanner rules).
- **True positive**: a URL from the request body or config reaching `client.Do` directly, with validation that is substring matching (`strings.Contains(host,"internal")`);
  validating the original URL but not the target after `CheckRedirect`; the resolver used for validation and the one used for dialing are different (check/use gap)
- **Noise**: fixed literal URLs where the user controls only path/query (a fixed origin is not target control);
  `url.Parse` that only constructs without dispatching (constructor != dispatch; find the real consumer)
- **Core criterion**: what is reached is the **final target after dispatch** (verify redirects hop by hop, verify the resolved IP, run IPv6 and decimal encodings through it),
  and that target class is not authorized by application policy
- **Falsification**: the entry point is an authorized allowlist of fixed targets; the scheme is unsupported by the client
- **Deep read**: [ssrf.md](ssrf.md), [io-template-reference-notes.md](io-template-reference-notes.md)

## Authentication / Access Control (no mechanical rules, most dependent on manual chain tracing)

- **Wake-up keywords**:
  ```bash
  rg -n '\.Use\(|middleware' -t go              # middleware chain assembly
  rg -n 'session\.|GetCurrentUser|MustGet' -t go  # identity extraction point
  rg -n 'IsAdmin|isAdmin|role|tenant|owner' -t go -i
  rg -n 'ctx\.Param\(|FormValue|PostForm' -t go   # caller-controlled ID enters a data operation
  rg -n 'http\.Error\([^)]*40[13]|StatusUnauthorized|AbortWithStatus|unauthor' -t go -i
  # ^ decorative shape: the signal is in control flow, not in the name — after writing a 401/403, is there a return/Abort?
  ```
- **True positive** (three kinds, completely different criteria):
  1. **Functional privilege escalation**: an ordinary authenticated user can invoke a sensitive operation (and the downstream service layer does not stop it either)
  2. **Data-level privilege escalation (IDOR)**: `ctx.Param("id")` goes straight into a query, missing the "authenticated subject -> resource ownership" relationship
  3. **Decorative auth check**: `requireAuth` writes the response but **never returns/aborts**, so the function keeps running
     — Gitea 1.4.0 `server.go:221` and Woodpecker `org.go:127` (`if user == nil` placed after use) are both this class
- **Noise**: no check in the handler but **the downstream service/DB RLS has one** (read that layer before reporting "missing guard");
  public endpoints; a hidden button in the frontend
- **Core criterion**: rebuild the **actual execution order** as "entry -> effective middleware -> handler -> service -> data operation".
  A middleware named Auth is not proof it blocks (verify the failure semantics: after writing 403, does the code stop?)
- **Falsification**: an equivalent ownership control exists between the authenticated subject and the resource (it does not have to be an `owner_id` comparison)
- **Deep read**: [authorization.md](authorization.md), [capability-assessment.md](capability-assessment.md) (k8s/control plane)

## Credentials / Secrets (high frequency, low bar)

- **Wake-up keywords**:
  ```bash
  rg -n 'NewCookieStore\(\[\]byte|NewHMAC\(\[\]byte|\[\]byte\(".*"\)' -t go   # hard-coded key
  rg -n 'SECRET|API_KEY|TOKEN\s*(:=|=)\s*"' -t go -i
  rg -n 'expandenv|getenv' -t go        # env expansion inside templates (sprig)
  rg -n 'net/http/pprof|debug/' -t go   # reconnaissance surface (pairs with X-PPROF-EXPOSED)
  ```
- **Core criterion**: for a hard-coded key, state **what privilege forgery yields and what that privilege can do** (feeds E3/E4);
  "there is a key" is not enough
- **Redaction counterexample (you must trace to the consumption point before rating)**: patterns such as `Secret.Copy()` that do not copy the `Value` field
  mean plaintext never leaves over HTTP. Reporting High without tracing the consumption point is a textbook false positive (measured in Woodpecker `model/secret.go:112`)
- **Deep read**: [case-library.md](case-library.md) A1 (key -> forgery -> privilege escalation chain)

## Unsafe Memory / Panic Surface

- **Wake-up keywords**: `unsafe.Pointer` / `uintptr` / `import "C"` / `reflect.SliceHeader` / `syscall.Mmap`
- **True positive**: an unsafe conversion with a length taken from untrusted input; a cgo buffer contract mismatch
- **Noise (high frequency)**: an ordinary nil-dereference panic -> `gin.Recovery()`, net/http recovery -> 500.
  That is a **DoS / availability** problem, not memory corruption; report it in its own class (measured in Woodpecker F-001:
  `session.User(c)` returns nil -> `ForgeFromUser(user)` immediately reads a field -> panic)
- **Core criterion**: separate "out-of-bounds native access / dangling reference" (real memory corruption) from "recoverable panic" (availability).
  Never write the latter as RCE in a report
- **Deep read**: [unsafe-memory.md](unsafe-memory.md)

## Upload / Download / Archive

- **Mechanical rules**: `E4-ZIPSLIP` (extraction side); the rest use the keyword channel:
  ```bash
  rg -n 'FormFile|multipart' -t go
  rg -n 'zip\.NewReader|tar\.NewReader|Unarchive|ExtractTo' -t go
  rg -n 'Symlink|Lstat|O_NOFOLLOW' -t go          # traces of defense: do not rush to report
  ```
- **Core criterion**: **arbitrary-path write != arbitrary-content write** (with fixed content you can only overwrite/truncate/DoS, not plant an executable).
  What consumes the upload afterwards (execution/parsing/template loading) decides the rating; extension and MIME checks are neither a silver bullet nor decoration
- **Deep read**: [file-transfers.md](file-transfers.md)

## XML / External Entities

- Go `encoding/xml` does not resolve external entities by default (no classic XXE). On seeing XML decoding, first confirm whether
  `xml.Decoder` custom entity resolution or a third-party library is in play; by default treat it as noise and say so in one line.

---

## Chain Composition (real vulnerabilities are almost always chains)

```
E3 decode -> forge identity -> E4 write hook -> execute          (Gogs/Gitea 2018)
X traversal read -> obtain app.ini/credentials -> second takeover (Gitea 1.4.0)
E4 write -> E6 load -> execute                                    (plugin class)
E5 argument injection -> external tool re-exec                    (git/pandoc class)
access control (decorative requireAuth) -> X arbitrary read -> credential leak  (high frequency in first halves)
```

When writing the report, list it hop by hop, each hop with `path:line`. Collapsing hops is the most common way to lose credibility.
Calibration samples: [case-library.md](case-library.md) (includes the fabricated-CVE table — check it before citing any CVE).
