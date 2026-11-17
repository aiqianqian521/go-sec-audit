# go-sec-audit

English | [简体中文](README.zh-CN.md)

**Not another Go vulnerability scanner — it is the stretch that turns a "candidate" into a verdict you can put in a report.**

A Go source-code security audit skill for LLM agents. Scanners produce candidates; this skill
produces verdicts, and only after a named evidence gate. Every finding is graded L0→L3, every
rejection is recorded with its reason, and the rules are guarded by falsifiable assertions
(break a rule, the test must fail).

- 27 mechanical sink rules (E1-E6 + X, the RCE families) + 29 keyword-channel regexes (SQLi / SSRF / authorization / credentials / memory / archive)
- Five verdicts: `FINDING` / `HOLD-evidence` / `HOLD-capability` / `KILL` / `undecided`
- Four evidence gates: L0 (sink hit) → L1 (entry reachable) → L2 (data shape survives) → L3 (reproduced in an isolated environment)
- Report contract: 8-section skeleton + four-state coverage matrix + count reconciliation + 10 pre-delivery checks
- Pure standard library, Python 3.9+, zero third-party dependencies

---

## Why this exists separately

Existing tools all stop at the "report a spot" layer:

| Tool | Output | What is missing |
|---|---|---|
| gosec | AST rule hits + CWE IDs | no reachability judgement; an internal function no route ever references still gets reported |
| semgrep | pattern-match hits | same; the more rules, the more noise |
| gitleaks | suspected credentials | covers the credential class only |
| **go-sec-audit** | **candidate → call chain → evidence gate → verdict** | needs an LLM agent driving it; it is not a one-command report generator |

The first three answer "does this look wrong". This one answers "can this go into the report, and on what grounds". It also forces a record of
**what was rejected and why** — because in security auditing the time lost to false positives usually exceeds the time lost to misses.

## Install

A skill is the directory convention `SKILL.md` + `references/`, portable across the mainstream agent hosts.

```bash
# WorkBuddy
git clone <this-repo> ~/.workbuddy/skills/go-sec-audit

# Claude Code
git clone <this-repo> ~/.claude/skills/go-sec-audit
```

On Windows the path is `%USERPROFILE%\.workbuddy\skills\go-sec-audit`. After cloning, `SKILL.md`
must sit directly in that directory (do not nest another level).

## Quick start

```bash
# 1. Run the mechanical rules once to get the candidate list (Python only, no LLM needed)
python scripts/scan_sinks.py /path/to/go/repo --out scans/report.md --json scans/report.json

# 2. Self-test: confirm the rules themselves are not broken (includes mutation testing)
python scripts/test_scan_sinks.py

# 3. Keyword-channel regression (parses regexes straight out of vuln-features.md, so docs and code cannot drift)
python assets/stress/stress_kwcheck.py
```

Scanner output looks like this (synthetic corpus, example):

```
- `.go` files scanned: 3
- Candidate hits: 12 (input source present in the same func 4 / sink only 8)
- Per-phase counts: E1=4 / E2=2 / E4=1 / E5=2 / X=3

| # | Phase | Rule | Location | Function | Input source | Rationale |
|---|-------|------|----------|----------|--------------|-----------|
| 1 | E1 | E1-SHELL-C | pos_rce.go:40 | renderUserTpl | http form | shell receives a -c script string; separators are parsed by the shell |
```

**The scanner produces candidates only.** Reachability tracing, data-shape judgement and evidence
grading are carried out by the agent following Phase 0-6 of `SKILL.md` — that is the design premise
of this project, not a defect.

## Running an audit with it

Tell the agent "do a security audit of this Go project", or trigger a keyword directly (Go code
audit / RCE / command injection / SQL injection / SSTI / SSRF / authorization / CVE reproduction
check). The workflow:

| Phase | What happens | Key constraint |
|---|---|---|
| 0 Scope and authorization | record commit SHA, Go version, entry surface, **deployment user** | without the deployment user you cannot state impact |
| 1 Surface mapping | APP/L/EP/CMD numbering + trust-boundary table | a default port is not a listener |
| 2 Candidate generation | scanner + keywords + fixed rg triple | rules are leads, not a checklist |
| 3 Reachability | trace callers **backwards** from the sink, stop at the handler boundary | Go is usually 2-5 hops; 8 hops is most likely a false positive |
| 4 Verdict | write out why the payload survives each transform | any single filter falsifies it — say so |
| 5 Evidence gate | L0→L3, evidence demanded level by level | no evidence means `HOLD-evidence`, not "probably critical" |
| 6 Report | 8-section contract + coverage matrix + count reconciliation | 10 pre-delivery checks |

Execution is **read-only** by default: no build / no run / no requests / no file edits. Dynamic
validation must state its authorization source.
See [references/execution-policy.md](references/execution-policy.md).

## Layout

```
SKILL.md                        main file: non-negotiables / 13 dimensions × tooling / Phase 0-6 / output contract
references/                     24 documents
  six-paths.md                  six-phase RCE model (E1-E6 + X) + fake-CVE identification
  sink-catalog.md               the 27 rules: match / true positive / noise / criterion
  vuln-features.md              keyword feature library for 14 vulnerability classes (wake-up / noise / falsification / deep-read pointer)
  verification-gates.md         L0-L3 evidence gates
  report-template.md            report contract: 8-section skeleton + five verdicts + 10 checks
  case-library.md               historical RCE cases (split into L3-repro / L3-lit / fake samples / unverified)
  application-surface.md        surface mapping
  authorization.md              authentication and authorization
  sql-injection.md  ssrf.md  template-injection.md  command-execution.md
  unsafe-memory.md  file-transfers.md  capability-assessment.md  framework-signals.md
  reachability.md  route-map.md  rag-index.md  execution-policy.md  acceptance-cases.md
  execution-reference-notes.md  sql-reference-notes.md  io-template-reference-notes.md
scripts/
  scan_sinks.py                 candidate scanner (27 rules, stdlib)
  test_scan_sinks.py            24 assertions, includes mutation testing
  kb_retrieve.py                two-channel reference retrieval (BM25 + fingerprints)
assets/
  selftest/                     16 rule samples (7 positive / 9 negative)
  stress/                       planted corpus: 13 positive points + 7 counter-examples + keyword regressor
prompts/architect-intake.md     agent role and worked examples
```

## Measurements (reproducible)

| Item | Result | Repro command |
|---|---|---|
| Rule assertions | **24/24 pass, 0 fail** (7 positive + 9 negative + 7 mutation + 1 empty file) | `python scripts/test_scan_sinks.py` |
| Planted-point capture | **13/13** (8 by the scanner + 5 by the keyword channel, complementary) | `python scripts/scan_sinks.py assets/stress` |
| Negative-sample false positives | **0** (7 counter-examples: separated argv, constant script, embedded template, time.Parse, os.OpenRoot, value binding, env-sourced key) | same as above; `neg_safe.go` yields zero hits |
| Keyword channel | 29 regexes, 5/5 classes hit their planted positive samples | `python assets/stress/stress_kwcheck.py` |

Mutation testing means: remove a rule's anchor and the corresponding sample must **stop** matching.
Otherwise the assertion was vacuously true and measures nothing — a very common form of pseudo-test
in security rule libraries.

## Limitations (read this before use)

1. **Mechanical rules cover the RCE families only (E/X phases).** SQLi / SSRF / authorization /
   credentials / memory / archive rely on keyword-channel wake-up plus manual chain tracing, with no
   rule as a backstop. No keyword hit does **not** mean safe.
2. **Recall is validated on synthetic corpora only** (13/13). Recall on real projects is unknown;
   do not treat "ran it and it reported nothing" as a conclusion.
3. **Only one real project has been sampled** (Woodpecker CI: 57 candidates → 0 confirmed). That
   sample demonstrates "a clean project does not get flooded with criticals"; it is not evidence of recall.
4. **It needs an agent to drive it.** The scripts only produce a candidate list; the verdict is made
   by the LLM following SKILL.md. If you want one command that emits SARIF, use gosec/semgrep.
5. **The keyword channel depends on ripgrep** (`rg`). Provide it yourself when it is not on PATH; the
   regressor uses Python `re` and is unaffected.
6. **Reports echo the absolute paths of the input**; sanitize them before pasting into a public issue.
7. **It does not replace a human.** What it compresses is the time from candidate to verdict, not judgement.

## Contributing

The most valuable contribution is a **counter-example**: a shape that gets falsely reported, an
assertion that is vacuously true, a real vulnerability the rules cannot reach.
Before opening a PR, make sure both `test_scan_sinks.py` and `stress_kwcheck.py` pass — a PR that
changes a rule without changing its test will not be merged. That is this project's only hard requirement.

## License

MIT, see [LICENSE](LICENSE).

> **Provenance note**: some methodology documents in this project derive from internal audit practice;
> the author must confirm the scope of authorization before public release.
> If you are a rights holder or are aware of a provenance dispute, contact the maintainer first; do not
> use this commercially until provenance is confirmed.

## Disclaimer

For **authorized** code auditing and security research only. Obtain written authorization before
performing any validation action against a third-party system.

## Related Projects

`go-sec-audit` is a domain skill in the `aiqianqian521` agent-skill family. The sibling
repositories supply the execution discipline, the report structure and the orchestration that
drive it; this one supplies the Go security verdict.

| Repository | What it is | Relation to `go-sec-audit` |
| --- | --- | --- |
| [aiqianqian521/github-project-evaluation](https://github.com/aiqianqian521/github-project-evaluation) | Cross-source project discovery, frozen-repo static first pass, per-project test design | Its first pass can call this skill as the Go security dimension |
| [aiqianqian521/ai-skill-output-template](https://github.com/aiqianqian521/ai-skill-output-template) | Declarative output-template registry | Same contract idea: stable, verifiable, regression-checked report structure |
| [aiqianqian521/ooda_skill](https://github.com/aiqianqian521/ooda_skill) | OODA execution discipline (purpose, evidence, verify, close) | The round loop that drives an audit; verdicts feed its per-round records |
| [aiqianqian521/sloth-loop](https://github.com/aiqianqian521/sloth-loop) | Zero-LLM task orchestration engine | Orchestrates repeated audits; this skill is one domain capability inside a run |

> Sibling skill kept local for now: `go-rce-hunt` (remote code execution hunting in Go source trees).
