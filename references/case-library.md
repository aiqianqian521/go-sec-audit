# Public Go RCE Case Library

Purpose: provide calibration samples for "what counts as real RCE", so you do not mistake E3 for E1 or path traversal for command injection.

Every entry carries its **evidence tier** and **source**. Tier definitions live in [verification gates](verification-gates.md).
**Entries without a source have been removed** — this file does not accept "I remember there was a CVE".

**The evidence tier must distinguish provenance (revised 2026-11-13)**: `L3` was previously used both for "confirmed by a vendor or public research" and for "we reproduced it locally". Those differ by an order of magnitude in credibility, and a reviewer could not tell them apart. It is now split into two tiers:

| Marker | Meaning | Who fired the payload |
|---|---|---|
| `L3-repro` | we completed it in an isolated environment, with a negative control | this skill's maintainers |
| `L3-lit` | vendor advisory / exploitation in the wild / public PoC / patch diff supports it, **we did not reproduce** | external |
| `L2` | mechanism analysis and source only, injectability unproven | nobody |

Current counts (2026-11-13): `L3-repro` = **1** (A7, and it is **not RCE** — it is arbitrary file read);
`L3-lit` = 4 (A1-A4); `L2` = 2 (A5, A6). **No Go RCE in this library has been reproduced locally yet** — do not read a citation as "verified exploitable".


---

## A. Verified Cases

### A1. Gogs / Gitea session deserialization -> privilege escalation -> git hooks RCE
- **CVE**: CVE-2018-18925 (Gogs) / CVE-2018-18926 (Gitea)
- **Affected**: Gogs <= 0.11.66, Gitea <= 1.5.3
- **Phase**: E3 (entrance) -> privilege escalation -> **E4** (terminal)
- **Chain**: session deserialization -> an ordinary user is forged into an admin -> the admin-only git hooks editing capability writes a command -> the service account executes it
- **Evidence**: L3-lit (externally confirmed, not reproduced locally). 360CERT report + NVD + the gogs/gogs#5469 fix record
- **Why included**: the best counterexample for teaching "E3 does not reach RCE directly". Writing this as "gob deserialization leads to RCE" collapses three hops into one, which is distortion.
- **Source**: `https://www.secrss.com/articles/6190`

### A2. Gitea diffpatch writes a git hook -> RCE (exploited in the wild)
- **CVE**: CVE-2026-60004, CVSS 9.8
- **Affected**: >= 1.17.0, < 1.27.1; fixed in 1.27.1 (then 1.27.2)
- **Status**: CISA KEV, exploited in the wild since 2026-08, public PoC and Nuclei template exist
- **Phase**: **E4**, with no `exec.Command` anywhere in the chain
- **Chain** (paraphrased from the Acronis report; git source not verified line by line):
  1. Entrance is the `diffpatch` endpoint, reachable by any visitor when open registration is on
  2. Submit the same crafted patch twice
  3. The first submission puts the payload into the git index; the second triggers an add conflict during merge, and the file is written straight to disk
  4. For a bare clone the repo root **is** `$GIT_DIR`, so writing `hooks/post-index-change` lands directly in the live hook directory
  5. git executes it the next time it touches the index, as the Gitea service account
- **Evidence**: L3-lit (externally confirmed, not reproduced locally) (in-the-wild exploitation + PoC + vendor advisory)
- **Why included**: an audit that only greps `exec` misses this 100% of the time. This is the whole reason phase E4 exists.
- **Source**: `https://www.helpnetsecurity.com/2026/08/26/gitea-cve-2026-60004-exploited-in-the-wild`, `https://securityonline.info/gitea-rce-vulnerability-exploited`

### A3. kubelet Windows SubPath command injection -> SYSTEM
- **CVE**: CVE-2023-3676 (with siblings CVE-2023-3955, CVE-2023-5528), CVSS 8.8
- **Affected**: kubelet <= v1.28.0 / v1.27.4 / v1.26.7 / v1.25.12 / v1.24.16 and similar (fixed releases out for each branch); Windows nodes only
- **Phase**: **E1** (Windows shell re-parsing)
- **Mechanism**: `MountSensitive()` uses `exec.Command` to call `cmd` for symlink creation; `subPath` is unsanitized and `cmd` parses the argument as a command line -> `$()` gets executed
- **Fix**: **delete the cmd call** and use the native Go symlink function; the other site passes the value via an environment variable instead of user input
- **Evidence**: L3-lit (externally confirmed, not reproduced locally) (Akamai research + public PoC YAML + fix commit)
- **Why included**: proves "arguments passed separately = safe" does not hold on a Windows shell. It is the teaching case for the E1/E5 boundary.
- **Source**: `https://www.anquanke.com/post/id/293971`, `https://gbhackers.com/kubernetes-vulnerability-full-system-control`, Alibaba Cloud ACK advisory 2569524

### A4. Grafana DuckDB SQL expression -> extension loading -> command execution
- **CVE**: CVE-2024-9264
- **Affected**: 11.0.0-11.0.5, 11.1.0-11.1.6, 11.2.0-11.2.1; **RCE only on 11.0.0**, other versions give arbitrary file read
- **Phase**: **E6** (database extension loading + interpreter built-in pipe execution)
- **Chain**: an authenticated user edits a dashboard expression and switches the datasource from `math` to `sql` -> `LOAD shellfs` extension -> the pipe syntax in `read_csv('id > /tmp/x 2>&1 |')` hands the content to a shell -> `read_blob` reads the output back
- **Fix**: the entire SQL Expressions feature was deleted (in the patch, everything under `pkg/expr/sql/db.go` returns `not implemented`)
- **Evidence**: L3-lit (externally confirmed, not reproduced locally) (public PoC repo + patch diff + HTB machine writeup)
- **Why included**: the label says "SQL injection" but the essence is "an interpreter that can load extensions". Auditing by label produces the wrong remediation (escaping the SQL does nothing).
- **Source**: `https://onlybits.org/nollium/CVE-2024-9264`, `https://blog.gitcode.com/3c0afd30cb6c84547219818060a0a74a.html`

### A5. Gitea external renderer argument injection
- **CVE**: CVE-2026-73539, CVSS 7.5, CWE-88
- **Phase**: **E5**
- **Mechanism**: a URL derived from the markup Context is unescaped inside the command template, allowing extra renderer arguments (including options that load an executable filter); with a renderer such as pandoc plus a plantable filter file -> execution as the service account
- **Evidence**: **L2**. Single source (published 2026-10-14), NVD original not checked -> re-verify before use, do not quote version numbers directly
- **Why included**: a sample that separates argument injection (CWE-88) from command injection (CWE-78)
- **Source**: `https://nextguardhq.com/en/vulnerabilities/cve-2026-73539-gitea-gitea`

### A6. Go SSTI methodology (not a single CVE)
- **Phase**: E2
- **Key point**: much of Go template injection is a **shadow vulnerability** (no CVE): the engine works as designed, and the application exposed template text or a FuncMap to the user
- **Exploitable shapes**: `{{.Method "arg"}}` calls a method on the object; `{{call .Fn "arg"}}` calls a function value; a FuncMap that registers exec/readfile-class functions
- **Non-exploitable shapes**: `html/template` + fixed template + pure-function FuncMap
- **Evidence**: L2 (methodology level, no CVE needed)
- **Source**: `https://www.onsecurity.io/blog/go-ssti-method-research/`, `https://blog.takemyhand.xyz/2020/06/ssti-breaking-gos-template-engine-to`, `https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection`

### A7. Gitea 1.4.0 LFS Oid path traversal -> **unauthenticated arbitrary file read** (write side blocked by a gate; not RCE)
- **CVE**: no dedicated ID; vulhub files it under the directory name `gitea/1.4-rce`; fixed in 1.4.1
- **Phase**: **X (path traversal, the entrance) -> only reaches "credential/config disclosure"**. **Never reaches an E phase**
- **Mechanism**:
  - `modules/lfs/content_store.go:29` (`Get`) and `:49` (`Put`) both do `filepath.Join(s.BasePath, transformKey(meta.Oid))`
  - `transformKey()` performs no `..` validation: `len(key) < 5` returns the key unchanged, otherwise `filepath.Join(key[0:2], key[2:4], key[4:])`
  - `Oid` comes from the `oid` field of the LFS request body
  - **The unauthenticated root cause is one missing `return`**: at `server.go:221`, `if !authenticate(...) { requireAuth(ctx) }` is followed by the function continuing into `NewLFSMetaObject`, so the 401 is decorative
- **Field test (2026-11-13, local lab, L3)**:
  - Environment: CentOS 7 + `gitea-1.4.0-linux-amd64` (dl.gitea.com, 53,662,000 B) + sqlite, `gitea migrate` + `admin create-user`
  - **Hard prerequisite: Git >= 2.1.2**. `modules/setting/setting.go:892` runs `LFS.StartServer = false` on an older version, the LFS routes are **never registered**, and every LFS request 404s. CentOS 7 ships git 1.8.3.1, so this trap is guaranteed
  - Scanner check: before adding `X-PATHTRAV-JOIN`, `modules/lfs/` had **0 hits**; afterwards it hit `content_store.go:29 / 49 / 80 / 90`, i.e. the `Get` / `Put` / `Exists` / `Verify` methods
  - Read side works: `oid = "...." + "../../../../../../" + <absolute path>` reads without credentials
    | Target | Bytes | Verification |
    |---|---|---|
    | `/etc/passwd` | 1108 | exactly matches `wc -c` |
    | `/etc/shadow` | 699 | contains root's `$6$` hash |
    | `custom/conf/app.ini` | 802 | contains `SECRET_KEY` / `INTERNAL_TOKEN` / `LFS_JWT_SECRET` |
  - **Write side does not hold**: `content_store.go:67-72` compares `sha256(content) == meta.Oid` before `os.Rename`. Writing a file requires the content hash to equal the `Oid`, while the `Oid` also determines the path — **"controllable path" and "controllable content" are inherently mutually exclusive**. Measured: `PUT` -> `500 {"message":"Content hash does not match OID"}`, target file not created
  - **The only write-side effect**: `MkdirAll` sits before the gate (`content_store.go:56`) -> **arbitrary directory creation** holds (measured: created `/root/x/pwn/deep/dir`)
- **Why included**: ① "unauthenticated + arbitrary file read" is a high-frequency real shape in the Go ecosystem, and obtaining `/etc/shadow` or `app.ini` often enables second-stage takeover; ② proves the six-phase model **does not cover sanitization gaps on the entrance side**, so path traversal must be a separate X phase; ③ records a real environmental gate (git version) so the next attempt does not start from a 404 and guess; ④ **records a case where "the name says RCE, the code says read only"** — a vulhub directory name ending in `-rce` is not a conclusion
- **Source**: vulhub `gitea/1.4-rce` README, `https://security.szurek.pl/gitea-1-4-0-unauthenticated-rce.html`, `https://www.leavesongs.com/PENETRATION/gitea-remote-command-execution.html`
- **Deviation from the sources (important)**: those writeups claim RCE, but in the 1.4.0 source the sha256 gate in `Put()` makes "arbitrary file write" impossible. **The source wins**; reproducing the write side requires a different version or a different sink


---

## B. Known Fabricated / Contaminated Samples (**do not cite**)

These appear frequently in search results; they are content-farm output produced by AI. They are listed here so you recognize them immediately when you meet them elsewhere.

| Fabricated CVE | Claimed content | Why it is fake |
|--------|----------|-------------|
| CVE-2024-34567 | gorilla/sessions deserialization RCE, affects v1.2.0-v1.3.1 | the ID does not exist; and CookieStore goes through securecookie which **enforces HMAC signing**, so there is no "unsigned means gob-decoded" path |
| CVE-2024-45678 | k8s.io/client-go certificate validation bypass, v0.28.0-v0.29.3 | the ID does not exist; the described "silently sets InsecureSkipVerify=true" has no corresponding code |
| CVE-2024-56789 | spf13/cobra command injection v1.7.0-v1.8.2 | the ID does not exist; cobra only parses flags and never calls a shell |
| CVE-2025-XXXX | Go text/template FuncMap reflection call RCE | the ID is a placeholder; the text itself admits "X" |

**Identification features**:
1. IDs increase consecutively (34567 / 45678 / 56789) — real CVE IDs show no such pattern
2. An "affected version matrix" is given with no corresponding GHSA / OSV / NVD link
3. A "hotfix patch" is attached whose style does not match upstream (indentation, naming, error-handling habits)
4. The site itself is an SEO content farm, mixing unrelated domains on the same page

**Handling**: before citing any CVE it must hit at least one of: `nvd.nist.gov/vuln/detail/<id>`, `cve.org/CVERecord?id=<id>`, a vendor advisory, or an OSV/GHSA record. Cannot find it -> it does not enter the report.

---

## C. Pending Verification (no primary source obtained this round; do not cite)

- The runc / containerd / buildkit container-escape family (CVE-2024-21626 and others): Go-written components, but advisories and fix diffs were not checked this round
- RCE-class CVEs in Caddy / Traefik / Consul / Nomad / Vault / MinIO: not verified individually
- Go standard library `text/template` historical CVE-2023-24538: impact surface and real exploitation conditions not checked

Conditions for promotion into section A: obtain the primary advisory + fix diff + (optionally) a PoC, then fill in `phase / chain / evidence / source` in section A's format.

---

## D. Using This Library for Training

### D1. Differential scanning (the single most effective exercise)
Take two commits of the same project — the vulnerable version and the fixed version — and run the scanner on each.

```bash
git -C <repo> checkout <vuln-tag>   && python3 scripts/scan_sinks.py <repo> --out v-vuln.md
git -C <repo> checkout <fixed-tag> && python3 scripts/scan_sinks.py <repo> --out v-fixed.md
diff -u v-vuln.md v-fixed.md
```

Expected: on the fixed version the candidates for that phase **disappear or change shape** (for example the `hooks/` string is removed, or validation is added around `--upload-path`).
If both sides are identical -> either the rule does not cover this class, or the fix landed elsewhere (common: a guard was added instead of deleting the sink). The latter is more instructive: **a fix does not have to touch the sink**.

### D2. Rule regression
Register one metadata record per case as a scanner acceptance test:

```json
{
  "project": "gitea", "cve": "CVE-2026-60004",
  "vuln_commit": "<sha>", "fixed_commit": "<sha>",
  "path": "E4", "sink": "routers/api/v1/repo/patch.go:<line>",
  "must_hit_rules": ["E4-HOOK-WRITE"],
  "must_not_survive_fix": true,
  "note": "the bare clone root is GIT_DIR; not an exec-class case"
}
```

`must_hit_rules` must hit on the vuln commit; `must_not_survive_fix` must not hit on the fixed commit. Both passing is what makes the rule valid for this class.

### D3. Negative exercise (more important than the positive samples)
Take a fabricated CVE from section B and go looking in a real repository for the code it claims. Not finding it is the normal outcome.
What you practice is "deciding within 30 seconds that a CVE citation is untrustworthy" — worth more than finding one more bug, because one wrong report costs you the credibility of the next ten.

### D4. Lab targets
A2 and A4 have public PoCs and Docker images and can be reproduced in an isolated environment. Reproduction must include a **negative control**: the same request with the payload neutralized must not trigger. A "successful reproduction" without a control is usually a coincidence.
