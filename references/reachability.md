# Reachability: Tracing from Entry Point to Sink in Go

The scanner only tells you "a sink exists in some function". The real work is answering: **who can reach this, carrying what data**.

Go has one advantage: no implicit binding like Spring's, so call chains are usually 2-5 hops. It also has a downside: the constructs below break naive taint tracking outright.

---

## 1. Build the Entry-Surface List First (do not start from the sink)

Reading down from route registration is 10x faster than guessing up from the sink.

```bash
rg -n 'HandleFunc|Handle\(|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(|\.Group\(' -t go
rg -n 'grpc\.NewServer|Register.*Server\(' -t go
rg -n 'cobra\.Command\{|flag\.' -t go
rg -n 'cron\.|time\.Ticker|fsnotify' -t go
```

Produce a table:

| Entry | Method + path | handler | Middleware chain | Auth state |
|------|-----------|---------|----------|----------|
| `routers/api/v1/repo/patch.go:31` | POST `/repos/:id/diffpatch` | `ApplyDiffPatch` | `repoAssignment` -> `ReqRepoWriter` | any logged-in user |

**Auth state matters more than the sink.** Unauthenticated reachable + E4 = severe; admin-only + E2 = usually not a vulnerability (admins can already change config).

To judge auth, do not read inside the handler — read the **registration site**:

```go
auth := r.Group("/api", middleware.Auth())   // the Use on this level decides everything below
auth.POST("/repos/:id/diffpatch", handler)    // inherits auth
```

If the handler is attached to the parent `r` instead of `auth`, it is unauthenticated.

---

## 2. Backward Tracing: sink -> entry

The scanner already lists 3 call sites for each sink function (report section C). Continue by hand:

```bash
rg -n '\bWriteHook\(' -t go          # who calls it
rg -n 'func WriteHook' -t go         # its signature (parameter types decide what can be passed)
```

Classify each call site's arguments into exactly three kinds:
- **Constant**: `WriteHook("post-merge", tmpl)` -> this path is dead
- **Config**: `WriteHook(cfg.HookName, ...)` -> trace where the config comes from (file? environment variable? changeable via API?)
- **Request data**: `WriteHook(r.FormValue("x"), ...)` -> live

---

## 3. Seven Go Constructs That Break Tracing

### 3.1 Dynamic interface dispatch
```go
type Runner interface{ Run(ctx context.Context, spec Spec) error }
```
The `sink` lives in some implementation, while the call site only sees the interface. You must find every implementation:
```bash
rg -n 'func \([a-z]+ \*?\w+\) Run\(' -t go
```
Miss an implementation = miss a path. State in the report "the interface has N implementations, each checked".

### 3.2 Middleware reordering and short-circuiting
```go
r.Use(Auth(), RateLimit())
r.POST("/x", h)
```
The path inside `Auth()` that calls `c.Abort()` is unreachable; code after `c.Next()` runs only after the handler returns. Echo/Fiber/gin semantics differ — do not transplant one onto another.

### 3.3 Goroutine closure capture
```go
for _, job := range jobs {
    go func() { exec.Command("sh","-c", job.Cmd).Run() }()   // job is captured
}
```
The scanner sees the sink inside an anonymous function named `func1`, and finds no call site. This class **must be read by hand**: where does `job.Cmd` come from.

### 3.4 Callback registry
```go
var handlers = map[string]func(string) error{"export": exportCmd}
fn := handlers[r.URL.Query().Get("action")]
fn(r.FormValue("arg"))
```
Controllable key -> controllable target function. Trace the implementation of every value in the table, not the call chain.

### 3.5 Reflection and struct tags
```go
reflect.ValueOf(obj).MethodByName(action).Call(args)
```
Controllable method name = arbitrary method invocation. List the target type's **exported methods** and find the ones with side effects.

### 3.6 Generated code
A sink inside `*.pb.go` / `*_gen.go` / `wire_gen.go` cannot be fixed there; the fix lives in the `.proto` or the generator template. The report must say "generated artifact, source at X", otherwise the developers fix it, regenerate, and it comes back.

### 3.7 Build tags
```go
//go:build linux && cgo
```
This file does not compile on Windows. Reading code on Windows, you are not looking at what ships.
```bash
rg -n '^//go:build|^// \+build' -t go
```
The report must declare "platform/tag combinations covered by this audit", otherwise the sentence "no issues found" is meaningless.

---

## 4. Data Shape at the Sink (the last meter)

Reaching the sink, one line is not enough; walk back to the **last transform**:

```go
name := r.FormValue("f")            // raw
name = filepath.Base(name)          // filename only -> path traversal is dead
name = strings.TrimSuffix(name,".txt")
cmd := exec.Command("sh","-c","cat "+name)   // still E1, because Base does not stop shell metacharacters
```

Criteria table:

| Transform | Stops | Does not stop |
|------|---------|-----------|
| `filepath.Base` | path traversal | shell metacharacters, a leading `-` |
| `filepath.Clean` + prefix check | path traversal | shell metacharacters |
| successful `strconv.Atoi` | all string injection | numeric boundary issues |
| allowlist `switch` | everything | dangerous values inside the allowlist itself |
| `shellescape.Quote` | E1 injection | E5 argument injection, path traversal |
| `html.EscapeString` | XSS | every RCE phase |
| `url.QueryEscape` | URL injection | every RCE phase |

**This table is where mistakes concentrate**: in an RCE context, `html.EscapeString` and `url.QueryEscape` amount to doing nothing.

---

## 5. Format for Writing a Reachability Conclusion

Do not write "user input flows into exec". Write:

```
entry   POST /api/repos/:id/hooks         routers/api/repo.go:44
auth    under auth.Group, any logged-in user   routers/api/repo.go:12
hop1    c.PostForm("content") -> body      api/hooks.go:31
hop2    hookBody -> writeHook(body)        api/hooks.go:37
hop3    filepath.Join(repo,".git","hooks","post-receive")  hooks.go:41
sink    os.WriteFile(target, body, 0755)   hooks.go:41
valid   none (no Clean, no prefix check, no content check)
```

Numbered hops, `path:line` each, and a validation conclusion. Missing any of these keeps it at L0/L1 and blocks promotion to L2.

---

## 6. Common "Looks Reachable But Is Not"

- The function is called nowhere (dead code) — run `rg` and confirm the call-site count is 0
- Called only from `_test.go`
- Only inside a `//go:build ignore` tool file
- Disabled by `if false` / a compile-time constant
- Registered in a route group that is never enabled (feature flag off by default)
- The handler exists but the route was never registered (written and never mounted)

The last one is more common in Go projects than you would expect. **Confirm the route is actually registered** before discussing reachability.
