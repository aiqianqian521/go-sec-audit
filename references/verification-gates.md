# Evidence Gates: L0 -> L3

The value of a Go RCE conclusion depends on whether it can be **falsified**. This file defines what each level requires, when to downgrade, and the final check before publishing.

Principle: **write "not verified" rather than "suspected critical"**. The former is a state, the latter a judgment — and a wrong judgment costs the whole report its credibility.

---

## Tier Definitions

| Tier | Name | Proven | Allowed wording | Where in the report |
|----|------|--------|-----------|---------|
| L0 | SUSPECT | sink hit | candidate | appendix |
| L1 | REACHABLE | a source->sink path holds, entry point and auth state confirmed | suspected reachable | body (tagged L1) |
| L2 | INJECTABLE | injection characters survive every transform, payload shape holds | suspected vulnerability | body |
| L3 | DEMONSTRATED | reproduced in an isolated environment + negative control | reproduced | body (may serve as a conclusion) |

**Writing an L0 as a vulnerability is a process failure**, not a style issue.

---

## L1 Checklist

All boxes must be ticked before promoting to L1:

- [ ] The entry point is confirmed to be **actually registered** (present in the route table, not merely a defined handler)
- [ ] Auth state confirmed (read the middleware chain at the registration site, not inside the handler)
- [ ] Every hop of the data flow has a `path:line`, no skipped steps
- [ ] No function along the way "looks like validation but is formatting" (`TrimSpace` is not validation)
- [ ] The target is actually compiled in (passed the build-tag check)
- [ ] The call site is not dead code (call-site count from `rg` > 0, and not inside `_test.go`)

Any missing item -> stay at L0 and state which item is missing.

---

## L2 Checklist

On top of L1:

- [ ] Write the **concrete payload string**, not "a malicious input could be constructed"
- [ ] List the characters the payload must keep alive (space / `;` / `|` / `{{` / `..` / leading `-` / `/`)
- [ ] Trace each of those characters through every transform and give the `path:line` evidence that it is **not** stripped
- [ ] Explain why a **simpler** explanation does not apply (maybe it is really path traversal, maybe XSS)
- [ ] State the preconditions: permissions, configuration, platform, dependency version

**Failing example**:
> "`filename` is unfiltered and may lead to command injection" — no payload, no character-survival analysis -> this is only L1.

**Passing example**:
> form value `name` = `x;id>/tmp/p`, through `hooks.go:31` (no filter) -> `hooks.go:37` (no filter) -> `hooks.go:41` `exec.Command("sh","-c","tar czf out.tgz "+dir)`. `;`, space and `/` are all preserved. Precondition: any logged-in user.

---

## L3 Checklist

- [ ] Isolated environment (container/VM), no outbound network (or outbound declared with a reason)
- [ ] Commit pinned, build command and Go version recorded
- [ ] Each payload maps one-to-one to an observed side effect (`touch /tmp/p` -> the file exists)
- [ ] **Negative control**: the same request with the payload neutralized (`x;id>/tmp/p` -> `x`) does not trigger
- [ ] Repeated at least once with identical results
- [ ] Deployment user identity confirmed (this decides the impact)

Missing the negative control = not reproduced, merely "something happened". Common fake reproductions: a string from the payload appearing in a log, a cache hit, a leftover file from the previous test run.

**Use harmless verification only**: `id`, `touch /tmp/poc`, `echo`. No reverse shells, no downloading external payloads, no changing system state.

### L3 Troubleshooting Order (when the response is empty or there is no side effect, check in this order instead of guessing)

1. **Read the status code's meaning, not "did it work"**
   - Read-side handler: `200` means `os.Open` **succeeded** (a failure would be 404); `200 + 0 bytes` = opened fine but truncated by a length gate
   - Write-side handler: `200 + empty body` may also mean **the method matched no branch** (the route exists but the handler falls through silently for an unexpected method)
2. **Confirm the request method is really the one you think**
   - `curl --data-binary` implies **POST**, not PUT. Always pass `-X PUT` explicitly
   - With the wrong method, `m.Any` matches the route but every `if method == ...` inside the handler fails -> silent 200
3. **Confirm who sets `Content-Length`**
   - If the handler sets `Content-Length` from a `Size` in the DB or the request, and the real content is longer: Go's `http.response.Write` **discards the whole block** and returns `ErrContentLength`, so the client receives 0 bytes
   - Workaround: raise `Size` far above the target file and accept a truncated response (curl exit code 18); the bytes already sent remain valid
4. **Separate "the side effect never happened" from "the side effect was undone"**
   - Look for `defer os.Remove(tmpPath)`, transaction rollback, compensating deletes on failure branches
5. **Do not trust state left by the previous run**
   - Reusing a unique key in the DB makes the second `POST` take the "already exists" branch (measured in Gitea: returns 404), so this run validates against **last run's `Size`**. Clean the test data before each run


---

## What Does Not Count as Evidence

A model will treat these as "I am quite sure"; not one of them is evidence:

| Looks like evidence | Why it is not |
|---------|-----------|
| A scanner hit / rule score | the rule matches text shape only |
| `govulncheck` reports a dependency CVE | a vulnerable dependency != you call that path, and != exploitable |
| The CVE description says "allows RCE" | the description is PR, the patch is fact |
| A lab directory name / database label containing `-rce` | naming is a filing habit (`vulhub/gitea/1.4-rce` measured as file read only). Impact follows the source-level gate |
| A public PoC repository exists | a PoC existing != your version/configuration is affected |
| The model says "this is obviously exploitable" | model confidence has no evidentiary weight |
| `unsafe` / `reflect` appears in the code | in Go these usually do not lead to RCE |
| Command output appears in an error message | may be log echo, not execution |

---

## Downgrade and Deletion

When a judgment turns out wrong, **record it explicitly**; never remove it silently:

```markdown
- F3 candidate E1-SHELL-C hooks.go:88 — downgrade L0 -> delete
  Reason: `shellescape.Quote(dir)` is already applied at cmd.go:120; the injection character `;` becomes `';'`
  Evidence: cmd.go:120
```

A silently deleted entry looks exactly like "never looked at it" in the report. A reviewer cannot tell the difference and will treat it as a miss — correctly, because from the outside the two are indeed indistinguishable.

---

## Pre-Publish Final Check

- [ ] Every conclusion has a tier; no L0/L1 appears in the "vulnerabilities" section
- [ ] Every `path:line` has been **read back** (`sed -n 'Np' file`), not recorded from grep output
- [ ] Version numbers, CVE IDs and affected ranges all have a clickable primary source; anything unverifiable is deleted
- [ ] Coverage gaps are stated: directories not scanned, platforms not covered, build tags not exercised
- [ ] No real keys, tokens, production data or complete exploit code pasted
- [ ] The remediation targets the **root phase** (do not suggest "escape the shell argument" for an E4 bug)
- [ ] Rejected candidates are preserved in the report

The last item is the most often omitted and the most damaging to credibility: a report listing only "confirmed vulnerabilities" leaves the reader unable to tell whether you **checked** or **never thought of it**.

---

## Remediation Must Match the Phase

| Phase | Effective fix | Ineffective fix (common mistake) |
|----|---------|--------------------|
| E1 | pass arguments separately / drop the shell / allowlist | escaping `;` (does not stop `$()`, newlines, encodings) |
| E2 | fix the template text + FuncMap allowlist | escaping the data (data is not the door) |
| E3 | switch to JSON / signature verification / minimize what the decoded result feeds | limiting body size (does not stop type instantiation) |
| E4 | path allowlist + prefix check + forbid writes to executable locations + drop privileges | only changing permission bits (cron needs no x bit) |
| E5 | add a `--` separator / reject a leading `-` / allowlist | escaping spaces (argument injection needs no space) |
| E6 | fix the load path + signature verification + forbid writes | restricting the extension |

A wrong remediation tells the developers "you do not really need to fix this".
