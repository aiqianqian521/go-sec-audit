# Report Contract (Fused)

The output is not "write something that looks good" — it is something the next person can verify. The fixed structure serves exactly one purpose:
**making "checked / never checked" externally testable**.

Two contracts are merged here: the 8-section skeleton (section structure + four-state coverage matrix) plus
verdict counts and evidence gates (five-state verdict / L0-L3). The two ID systems are unified in this file, with a fixed mapping.

## 0. Four Iron Rules (no scale exempts you)

1. **Counts must reconcile**. Total candidates = `F` (confirmed) + `HOLD-evidence` (C) + `HOLD-capability` (R)
   + `KILL` + `undecided`. If it does not add up, the books are wrong, and the gap must be stated explicitly.
2. **Read every `path:line` back once before it enters the report**; for a range, verify the first and last line.
   Writing line numbers from grep impressions is this skill's hard-won lesson (done wrong 7 times in a row).
3. **`L3-repro` and `L3-lit` must never be blurred**. "Upstream confirmed" and "I got it working" differ by an order of magnitude.
   The `L3-repro` count may only come from `EV-###` records, and each carries a negative control.
4. **Every dynamic action declares its authorization source**. Who approved it, on which host, and the rollback path. Missing one item -> it goes to `GAP-###` only.

Four-piece delivery (user template standard L0): **conclusion / evidence / risk rating / next step**.
The full 8-section form covers the four by construction: §3+§4 are the conclusion, each table's `path:line` is the evidence,
evidence tiers L0-L3 are the rating, §8 is the next step.

## 1. Two Scales

| Situation | Which form |
|---|---|
| Single question ("can this function be injected"), < 200 Go files, <= 30 minutes | **short form** |
| Full project audit, multi-dimension request, or something another person must review | **full 8-section form**, no omissions |

Do not wrap a 5-minute question in the 8-section template — that turns "coverage" into padding.

### Short form

```markdown
**Conclusion**: <one sentence, with evidence tier>
**Target**: <repo> @ <commit or "tarball, commit unknown">, scanned <N> .go files
**Candidate**: <C-###> `<rule_id or KW-class>` `path:line` — <verdict + one-line gate>
**Next step**: <the single highest-priority action>
**Coverage boundary**: <trees skipped, tiers undecided, gates unchecked>
```

## 2. Full Form (8 sections)

Use paper-style numbering in headings; keep empty sections and write one line of scope, do not pad them with tables.
For a surface-mapping-only request: use only §1, §5, §7, and never imply a security review happened.

```markdown
# <project> — Go Security Audit Report

- Target / source root: {repo and audit path}
- Version / revision: {commit or "tarball, commit unknown"; Go version}
- Audit date: {YYYY-MM-DD HH:MM timezone}
- Requested scope: {directories, dimensions (E1-E6/X/SQLi/SSRF/authz/secrets/memory/files), explicit exclusions}
- Analysis mode: {static | static + authorized dynamic verification (authorization source: ...)}
- Coverage: {full | partial} (a statement about coverage, not about safety)
- Result counts: F {n} / C(HOLD-evidence) {n} / R(HOLD-capability) {n} / KILL {n} / undecided {n}
- Evidence tiers: L3-repro {n} / L3-lit {n} / L2 {n} / L1 {n} / L0 {n}
- Scan baseline: {27 rules, {n} hits, {LOC}k lines, {x} hits per thousand lines; keyword channel {n} hits}

## 1. Project Overview and Architecture

### 1.1 Application and components
{what this program is; which executables exist; startup path; listeners and protocols; data stores; deployment evidence}

| App (APP-###) | Role | Entry | Listener / target | Protocol / identity | Evidence |
|---|---|---|---|---|---|

{listener values must cite a source: literal / default / config / environment variable / unresolved. Never write a default port as if it were listening}

### 1.2 Trust boundaries and threat model
{subject and attacker position; assets and security goals; public/internal/admin entry points; identity transition points;
abuse paths relevant to the requested dimensions (with preconditions); unverified deployment assumptions}

| Subject | Privilege needed to reach an execution primitive / sensitive operation | Boundary evidence | Who defends it |
|---|---|---|---|

## 2. Confirmed Findings (F-###)

| ID | Severity | Type/title | Entry (EP/CMD-###) | Key location | Evidence tier | Runtime verification |
|---|---|---|---|---|---|---|

### 2.x F-###: <specific defect and effect>

- Severity: {Critical/High/Medium/Low + impact and preconditions} (never invent a CVSS unless the user asks and it can be supported)
- Confidence: {high/medium/low} (independent of severity)
- Evidence state: source-confirmed (the code establishes the defect under the stated preconditions; this is not proof of exploitation in production)
- Affected surface: {APP/EP/CMD-###, method/path or CLI entry}

**Preconditions and controllable input**: {caller privilege, input fields, deployment/credential preconditions}

**Evidence and data flow**:
{numbered steps, each with the real `path:line` and symbol; short source excerpts where needed (keep the guards)}

**Existing protection and how it fails**: {gates checked; the specific boundary or invariant that is violated}

**Impact and boundary**: {the effect that is supported; conditional downstream effects marked separately}

**Fix and regression**: {narrowest fix; accept/reject regression cases; separate proposed from executed}

## 3. Candidates and Policy Concerns (C-### / R-###)

| ID | Type/title | Location | Established facts | Missing evidence | Next bounded verification |
|---|---|---|---|---|---|

Verdict mapping (the two vocabularies are equivalent; pick one per report but never mix them without saying so):

| Verdict | Equivalent | Meaning | Hard requirement |
|---|---|---|---|
| `GO` | — | promote to F | complete evidence chain |
| `HOLD-evidence` | `C-###` candidate | one key piece of evidence is missing | state which one and how to obtain it |
| `HOLD-capability` | `R-###` policy concern | a capability, not a defect; the **policy statement** is missing | state the sensitivity and the policy question |
| `KILL` | — | falsified | **must give the gate `path:line`**; if you cannot -> HOLD-evidence |

KILL detail (the gate location is mandatory):

| ID | Verdict | Reason (including the gate `path:line`, or "not found") |
|---|---|---|

## 4. Application Surface

{APP/L/EP/CMD-###: HTTP routes, RPC methods, CLI commands as separate lists; unresolved associations preserved explicitly}
{field definitions in application-surface.md; never write a static registration as if it were deployed}

## 5. Review Coverage and Evidence

| Requested dimension/scope | State | Entries/consumers examined | F/C/R | Gap |
|---|---|---|---|---|

Only four states: `reviewed` / `partial` / `not-assessed` / `not-applicable`.
`not-assessed` is **not** "clean"; it must be distinguishable at a glance in the report.

| ID | Gap | Why it was not done | What closing it would require |
|---|---|---|---|
| GAP-### | | | |

## 6. Reproduction Records (L3-repro)

If there are none, omit this section and write "no dynamic verification performed" in §7.

### EV-### — {one line}

- Target: {version} @ {host}, authorization source: {who approved}, rollback path: {how to restore}
- Trigger command: {complete and copy-pasteable}
- Expected / actual: {byte counts, response codes, content summary}
- **Negative control**: {the same request with the payload neutralized} — without this line, L3 is void
- **Interpretation**: {write here when the upstream writeup disagrees with the measurement. Do not trust a lab directory name}

## 7. Limitations and Verification

- Static evidence: {trees read, trees skipped, how line numbers were read back}
- Dynamic verification: {what was executed / not executed, and why}
- Dependency acquisition: {what source was fetched, from where, whether verified} (fetching source != runtime verification)
- Target modification: {should be "none"; never claim the whole worktree is clean merely because you did not modify it}
- Methodology limits: {inherent blind spots of single-rule scanning, e.g. argv assembled across functions, keyword channel with no data flow}

## 8. Fixes and Regression

| Priority | ID | Action | Regression criterion | State |
|---|---|---|---|---|
| P1 | | | | proposed |

proposed and executed must be separated. A regression that was never run cannot be written as passing.
Scope entries (F/C/R) stay separate: candidate verification, policy decisions and fixes for confirmed defects are three different things.
```

## 3. Evidence Integrity and Pre-Delivery Consistency Check

- Use real repo-relative `path:line` and symbols. Never fabricate code, line numbers, versions, run results or complete call chains.
- Mark inferred behavior and dead links. Source excerpts stay short but keep the relevant guard — never delete a check to make an example look exploitable.
- Redact credentials and tokens and say so. Production keys must not appear in a report as proof or as a runnable reproduction.
- `unknown` carries a reason; `not-applicable` carries a reason; the delivered report contains no unresolved template placeholders.
- Deduplicate one root cause across route aliases/transports/modules; keep genuinely different boundaries separate.

Tick every item before delivery:

- [ ] Total candidates = sum of the five verdicts (F + HOLD-evidence + HOLD-capability + KILL + undecided)
- [ ] Every `path:line` was read back individually, ranges verified at both ends
- [ ] Every `KILL` has a gate location; every `HOLD` states which evidence is missing
- [ ] The `L3-repro` count equals the number of `EV-###` entries, each with a negative control and an authorization source
- [ ] `not-assessed` and "reviewed with no findings" are not blurred
- [ ] "Scanner skipped / keyword missed" is never written as "no vulnerability"
- [ ] Every dimension has a row in the §5 coverage table (including not-applicable with a reason)
- [ ] No `<placeholder>` left in the report; secrets redacted
- [ ] F-IDs unique, cross-references valid, counts consistent with the metadata
- [ ] With zero findings, state "no confirmed findings within the checked scope" plus residual uncertainty; never derive "secure" from "did not find"
